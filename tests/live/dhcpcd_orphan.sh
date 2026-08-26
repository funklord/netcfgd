#!/bin/sh
# Adopting the dhcpcd netcfgd left running -- the one backend whose mark cannot
# be read from the process.
#
# WHY THIS FILE EXISTS
#   0140 recovers the supplicant, and udhcpc_orphan.sh the DHCP client, by
#   finding a path netcfgd chose as a whole argv element. dhcpcd calls
#   setproctitle and destroys BOTH argv and the environment block: measured,
#   /proc/PID/cmdline reads "dhcpcd: <iface> [ip4]", and environ comes back
#   4494 bytes of NUL against a control process that kept its variables.
#   Nothing netcfgd passed survives in the process image.
#
#   What survives is dhcpcd's own memory of its `-f` argument, which it recites
#   verbatim -- symlink and all, no realpath -- to anyone who asks
#   --getconfigfile on its control socket. So netcfgd starts it with an `-f`
#   under netcfgd's run directory and asks for it back. Decision 0143.
#
# WHY THIS MATTERS MORE THAN THE OTHER TWO
#   A second `dhcpcd -b` against a running one is a SILENT no-op: measured, it
#   prints "sending commands to dhcpcd process" and exits 0 having started
#   nothing. So without adoption netcfgd reports success on every reconcile
#   while the orphan holds the lease and netcfgd holds no handle on it.
#
# THIS SCRIPT MAKES ITS OWN NAMESPACE
#   dhcpcd needs a writable /run to lock its pid file, so this unshares mount
#   as well as net -- the same shape tests/live/dhcpcd.sh uses, and for the
#   same reason.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "dhcpcd_orphan.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "dhcpcd_orphan.sh: skipping: $1"
	exit 0
}

if [ "${NCFG_DHCPCD_INNER:-}" != "1" ]; then
	command -v dhcpcd >/dev/null 2>&1 || command -v /sbin/dhcpcd >/dev/null 2>&1 ||
		skip "dhcpcd is not installed"
	[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
	unshare --map-root-user --map-auto --mount --uts --net true 2>/dev/null ||
		skip "cannot make a user, mount and network namespace here"
	NCFG_DHCPCD_INNER=1 exec unshare --map-root-user --map-auto --mount --uts --net \
		-- sh "$0" "$@"
fi

export PATH=/sbin:/usr/sbin:$PATH
mount -t tmpfs tmpfs /run 2>/dev/null || skip "cannot put a tmpfs over /run"
mount -t tmpfs tmpfs /var/lib/dhcpcd 2>/dev/null || true

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

# Every dhcpcd CLIENT running -- by executable rather than command line, since
# the command line is exactly what this test cannot trust.
#
# **Only the top-level ones.** dhcpcd forks a privileged proxy, a control proxy
# and a BOOTP proxy per lease, all running the same executable, so a naive count
# reads four for one client and this check said "four clients" the first time it
# ran. A helper's parent is a dhcpcd; a client's is not.
clients() {
	for d in /proc/[0-9]*; do
		case "$(readlink "$d/exe" 2>/dev/null)" in
		*dhcpcd*) ;;
		*) continue ;;
		esac
		parent=$(awk '{print $4}' "$d/stat" 2>/dev/null || echo 1)
		case "$(readlink "/proc/$parent/exe" 2>/dev/null)" in
		*dhcpcd*) continue ;;
		esac
		echo "${d#/proc/}"
	done
	true
}

cleanup() {
	for p in $(clients); do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM

ip link add probe0 type dummy 2>/dev/null || skip "cannot create a dummy link"
ip link set probe0 up

conf=/run/netcfgd/dhcpcd/probe0-4.conf
mkdir -p /run/netcfgd/dhcpcd
ln -sf /etc/dhcpcd.conf "$conf"

# A client netcfgd started, standing in for one it started before it stopped.
# No DHCP server is needed: what is under test is recognition, not leasing.
dhcpcd -c /bin/true -f "$conf" -b -4 probe0 >/dev/null 2>&1 || true
waited=0
while [ -z "$(clients)" ] && [ "$waited" -lt 50 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
first=$(clients | head -1)
check "a dhcpcd is running" "$([ -n "$first" ] && echo yes || echo no)" "yes"
[ -n "$first" ] || exit 1

# The premise, asserted rather than assumed -- everything below is only
# interesting because this is true.
check "and netcfgd's mark is NOT in its argv" \
	"$(tr '\0' '\n' < "/proc/$first/cmdline" 2>/dev/null | grep -c "^$conf$")" "0"
check "nor anywhere in its environment" \
	"$(tr -d '\0' < "/proc/$first/environ" 2>/dev/null | grep -c netcfgd || true)" "0"

# ---------------------------------------------------------------------------
# The stop takes /run/netcfgd with it. The client lives, and so does the one
# thing that identifies it: the string in dhcpcd's own memory.
rm -rf /run/netcfgd
check "the run directory is gone" \
	"$([ -e "$conf" ] && echo present || echo gone)" "gone"
check "but the client is not" \
	"$([ -e "/proc/$first" ] && echo alive || echo gone)" "alive"

# ---------------------------------------------------------------------------
# netcfgd's apply. It must recognise the client and adopt it, not spawn.
mkdir -p /run/work/etc/conf.d
: > /run/work/etc/netcfgd.conf
cat > /run/work/etc/conf.d/probe0.conf <<'CONF'
interface probe0 {
	config = "dhcp"
}
CONF
NCFG_CONFIG_DIR=/run/work/etc NCFG_RUN_DIR=/run/netcfgd \
	NCFG_DHCPCD_RUN_DIR=/run/dhcpcd \
	"$repo/target/debug/ncfg" apply > /run/work/apply.log 2>&1 || true

# **This count cannot discriminate, and saying so is the point.** A second
# `dhcpcd -b` against a running one is a silent no-op -- measured, it prints
# "sending commands to dhcpcd process" and exits 0 having started nothing -- so
# the client count reads 1 whether netcfgd adopted or blindly re-ran. It is
# asserted anyway because a *second* client would be a serious regression; it
# is just not what proves the fix. The two checks below are.
check "there is still exactly one client" \
	"$(clients | wc -l)" "1"
check "and it is the same process -- the lease was never dropped" \
	"$([ -e "/proc/$first" ] && echo alive || echo gone)" "alive"
check "and says so" \
	"$(grep -c 'adopted the dhcp client' /run/work/apply.log || true)" "1"
# The other half of adoption: the symlink is re-created, or a later
# `dhcpcd -n` reload reads a dangling path and silently drops the operator's
# options.
check "and the symlink is put back for a later reload" \
	"$([ -L "$conf" ] && echo yes || echo no)" "yes"

# ---------------------------------------------------------------------------
# **The half that matters more: a stranger is NOT adopted.**
#
# Adoption's whole value is telling netcfgd's own client from somebody else's,
# and a probe that matched too widely would hand netcfgd an operator's dhcpcd
# to signal. So: a client started with a config path netcfgd did not choose
# must be refused, on the same interface, through the same probe.
for p in $(clients); do kill "$p" 2>/dev/null || true; done
waited=0
while [ -n "$(clients)" ] && [ "$waited" -lt 50 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
rm -rf /run/netcfgd

: > /run/operator.conf
dhcpcd -c /bin/true -f /run/operator.conf -b -4 probe0 >/dev/null 2>&1 || true
waited=0
while [ -z "$(clients)" ] && [ "$waited" -lt 50 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
stranger=$(clients | head -1)
check "an operator's own dhcpcd is running" \
	"$([ -n "$stranger" ] && echo yes || echo no)" "yes"

NCFG_CONFIG_DIR=/run/work/etc NCFG_RUN_DIR=/run/netcfgd \
	NCFG_DHCPCD_RUN_DIR=/run/dhcpcd \
	"$repo/target/debug/ncfg" apply > /run/work/stranger.log 2>&1 || true

check "netcfgd does NOT adopt it" \
	"$(grep -c 'adopted the dhcp client' /run/work/stranger.log || true)" "0"
check "and leaves it running" \
	"$([ -e "/proc/$stranger" ] && echo alive || echo gone)" "alive"
check "and its config is still the operator's" \
	"$(python3 -c "
import socket,sys
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(0.5)
s.connect('/run/dhcpcd/probe0-4.sock'); s.sendall(b'--getconfigfile\n\0')
print(s.recv(4200).rstrip(b'\0').split(b'\0')[-1].decode())" 2>/dev/null)" \
	"/run/operator.conf"

echo
if [ "$failures" -eq 0 ]; then
	echo "dhcpcd_orphan.sh: all checks passed"
else
	echo "dhcpcd_orphan.sh: $failures failed"
	exit 1
fi
