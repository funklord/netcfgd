#!/bin/sh
# Does netcfgd see a Bluetooth adapter, and read the right switch?
#
#     sudo sh tests/live/bluetooth.sh
#
# Needs real root: creating a virtual controller means opening /dev/vhci, which
# is root-only, and the module autoloads on that open.
#
# ## WHY A VIRTUAL CONTROLLER AND NOT THE REAL ONE
#
# The machine this was written on has a real `hci0`, and testing against it
# would prove nothing portable and would touch somebody's actual radio. A
# virtual controller is `mac80211_hwsim`'s equivalent for Bluetooth and costs
# nothing: `hci_vhci` creates one per open file descriptor, and it goes away
# when the descriptor closes.
#
# ## WHAT THIS DOES TO THE MACHINE, AND WHAT IT UNDOES
#
# It opens /dev/vhci, which autoloads `hci_vhci` and creates one adapter. That
# adapter exists for exactly as long as the helper below holds the descriptor,
# so killing it removes the adapter -- there is no unload step and nothing to
# leave behind if this is interrupted.
#
# It does not touch the real adapter. It does not start bluetoothd. It reads
# sysfs and nothing else, because that is all netcfgd's core does.
#
# ## WHAT IT CANNOT DO YET, SAID PLAINLY
#
# **Pairing and audio are not tested here and this rig cannot reach them.** One
# virtual controller has nobody to talk to, and Debian's bluez ships no
# `btvirt`, which is the tool that links two of them. Until that is built from
# source, this covers adapter observation and nothing further -- which is worth
# saying because a green run here must not be read as "Bluetooth works".

set -eu

repo=$(cd "$(dirname "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "bluetooth.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "bluetooth.sh: skipping: $1"
	exit 0
}

[ "$(id -u)" = 0 ] || skip "needs real root (/dev/vhci is root-only)"
[ -c /dev/vhci ] || skip "no /dev/vhci on this kernel"
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed"
[ -x "$repo/target/debug/ncfg" ] || skip "netcfgd is not built (cargo build --workspace)"

before=$(ls /sys/class/bluetooth 2>/dev/null | sort | tr '\n' ' ')

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-bt.XXXXXX")
helper=
daemon=
cleanup() {
	status=$?
	set +e
	# The adapter lives exactly as long as this descriptor. Killing the helper
	# is the whole teardown: there is no module to unload, because whoever else
	# may be using hci_vhci keeps it loaded and this test never asked for it by
	# name.
	if [ -n "${daemon:-}" ]; then
		kill "$daemon" 2>/dev/null
		wait "$daemon" 2>/dev/null
	fi
	if [ -n "$helper" ]; then
		kill "$helper" 2>/dev/null
		wait "$helper" 2>/dev/null
	fi
	rm -rf "$work"
	exit "$status"
}
trap cleanup EXIT INT TERM

# One virtual controller.
#
# The kernel wants an HCI_VENDOR_PKT (0xff) carrying the device type, and
# creates the adapter on that write. Holding the descriptor open is what keeps
# it alive, so this sleeps rather than exiting -- and reads nothing, so a
# closed stdin cannot take the adapter away mid-test.
cat > "$work/vhci.py" <<'PY'
import os, signal, sys, time
fd = os.open("/dev/vhci", os.O_RDWR)
os.write(fd, bytes([0xff, 0x00]))
sys.stderr.write("up\n")
sys.stderr.flush()
signal.pause()
PY

python3 "$work/vhci.py" 2> "$work/helper.err" &
helper=$!

waited=0
while ! grep -q '^up$' "$work/helper.err" 2>/dev/null; do
	waited=$((waited + 1))
	if [ "$waited" -gt 100 ]; then
		echo "bluetooth.sh: the virtual controller never came up:" >&2
		sed 's/^/  /' "$work/helper.err" >&2
		exit 1
	fi
	sleep 0.1
done

# udev names it asynchronously, so wait for the directory rather than assuming.
waited=0
while :; do
	after=$(ls /sys/class/bluetooth 2>/dev/null | sort | tr '\n' ' ')
	[ "$after" != "$before" ] && break
	waited=$((waited + 1))
	if [ "$waited" -gt 100 ]; then
		echo "bluetooth.sh: no new adapter appeared (before: $before)" >&2
		exit 1
	fi
	sleep 0.1
done

failures=0
check() {
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1"
		echo "       expected: $3"
		echo "       actual:   $2"
		failures=$((failures + 1))
	fi
}
contains() {
	case "$2" in
	*"$3"*) echo "ok   $1" ;;
	*)
		echo "FAIL $1"
		echo "       expected to contain: $3"
		echo "       actual:              $2"
		failures=$((failures + 1))
		;;
	esac
}

# Whichever name is there now and was not before. Not "the last one sorted":
# a machine with a real hci0 gets hci1 and a machine without gets hci0, and a
# rule that assumed either would be right on one of them by luck.
new=$(for a in $(ls /sys/class/bluetooth | sort); do
	case " $before " in
	*" $a "*) ;;
	*) echo "$a" ;;
	esac
done | head -1)
[ -n "$new" ] || { echo "bluetooth.sh: could not name the new adapter" >&2; exit 1; }
echo "bluetooth.sh: virtual adapter $new"

# **This build's daemon, not the installed one.** `ncfg status` asks whichever
# netcfgd owns /run/netcfgd, and on a developer's machine that is the packaged
# build -- which would answer about adapters using code this test was written
# to exercise and does not contain. The first version of this script did
# exactly that and would have passed or failed for reasons unrelated to the
# change under it.
mkdir -p "$work/etc" "$work/run"
: > "$work/etc/netcfgd.conf"
NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run" \
	"$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
daemon=$!

waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 100 ]; then
		echo "bluetooth.sh: the daemon never bound its socket:" >&2
		sed 's/^/  /' "$work/daemon.log" >&2
		exit 1
	fi
	sleep 0.1
done

# **netcfgd's own observer, not this script's reading of sysfs.** A test that
# listed the directory itself would pass whether or not netcfgd looked.
seen=$(NCFG_RUN_DIR="$work/run" "$repo/target/debug/ncfg" status 2>&1 || true)
contains "netcfgd reports the adapter it can see" "$seen" "$new"

# And the switch it read is the adapter's own. On a laptop there is a platform
# button in /sys/class/rfkill with a different name, and reporting that one
# would be reporting a different radio's state -- the mistake the wifi reader
# records having made.
observed=$(cat "$work/run/observed.json" 2>/dev/null || true)
contains "and the switch it read is the adapter's own" "$observed" "\"$new\""

echo
if [ "$failures" -eq 0 ]; then
	echo "bluetooth.sh: all checks passed"
else
	echo "bluetooth.sh: $failures failed"
	exit 1
fi
