# Wake-on-LAN on a card whose driver keeps it: qemu's e1000, the wire's card
# under VM_WIRE_NIC=e1000 (project.md 10.917). Run by `make vm-wol`.
#
# The reader is the old ioctl, ETHTOOL_GWOL, from Python: independent of the
# netlink messages netcfgd sends, so a fault in its encoder cannot be agreed
# with by its own decoder.
#
# HOW IT STOPS: every command is a bounded one-shot, and run.sh's timeout
# bounds the guest.
set -u
failures=0
fail() { echo "  FAIL: $1"; failures=$((failures + 1)); }
wolinfo() { # $1: device, $2: wolopts to set (optional) -> "supported wolopts"
	python3 - "$@" <<'PY'
import ctypes, fcntl, socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
def call(cmd, wolopts=0):
	buf = ctypes.create_string_buffer(struct.pack('III6s', cmd, 0, wolopts, b'\0' * 6), 18)
	fcntl.ioctl(s.fileno(), 0x8946, struct.pack('16sP', sys.argv[1].encode(),
	    ctypes.addressof(buf)))                                  # SIOCETHTOOL
	return struct.unpack('III6s', buf.raw)
if len(sys.argv) > 2:
	call(6, int(sys.argv[2]))                                    # ETHTOOL_SWOL
_, supported, wolopts, _ = call(5)                               # ETHTOOL_GWOL
print(supported, wolopts)
PY
}
card=$(for d in /sys/class/net/*; do
	case "$(readlink -f "$d/device/driver" 2>/dev/null | sed "s#.*/##")" in e1000|e1000e|igb|8139too|8139cp) echo "$(basename "$d") $(readlink -f "$d/device/driver" | sed "s#.*/##")" ;; esac
done | head -1)
driver=${card#* }
card=${card%% *}
echo "  kernel: $(uname -r); card: ${card:-none} (${driver:-no driver})"
[ -n "$card" ] || { fail "no e1000 card, so VM_WIRE_NIC did not reach qemu or the kernel has no e1000"; exit 1; }
supported=$(wolinfo "$card" | cut -d' ' -f1)
echo "  driver says it supports $supported (47: phy, unicast, multicast, broadcast, magic)"
[ "$supported" -gt 0 ] || { fail "the card supports no mode, so this guest cannot test wake-on-LAN"; exit 1; }

work=$(mktemp -d)
mkdir -p "$work/etc" "$work/run"
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
ncfg=/mnt/repo/c/ncfg
apply() { # $1: the wol value; the apply's output goes to $work/said
	printf 'device %s {\n\tethtool { wol = "%s" }\n}\n' "$card" "$1" > "$work/etc/netcfgd.conf"
	timeout 60 "$ncfg" apply > "$work/said" 2>&1
	sed 's/^/    | /' "$work/said" | grep -v '\[observe\]'
}
expect() { # $1 what, $2 wanted wolopts
	got=$(wolinfo "$card" | cut -d' ' -f2)
	if [ "$got" = "$2" ]; then echo "  ok: $1 ($got)"; else fail "$1: wolopts $got, wanted $2"; fi
}

apply g
grep -q 'link.set_wol' "$work/said" || fail "the first apply planned no link.set_wol"
expect "wol = g sets the magic packet, read back by the ioctl" 32
apply g
grep -q 'link.set_wol' "$work/said" && fail "a second apply set it again"
echo "  ok: a second apply has nothing to set"
apply pg
expect "wol = pg adds a PHY event" 33
apply a
# Warnings are the plan's to print; an apply with nothing to do says only that.
timeout 60 "$ncfg" plan 2>&1 | grep -q "can wake on \`pumbg\` only" ||
	fail "an unsupported mode was not warned about by the plan"
expect "wol = a, which this card cannot, is warned about and changes nothing" 33
apply off
expect "wol = off clears them" 0
exit "$failures"
