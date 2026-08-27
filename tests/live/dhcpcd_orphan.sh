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
# THIS SCRIPT MAKES ITS OWN NAMESPACE, AND MUST INCLUDE PID
#   dhcpcd needs a writable /run to lock its pid file, so this unshares mount
#   as well as net -- the same shape tests/live/dhcpcd.sh uses.
#
#   **It also unshares pid and remounts /proc, and that is not tidiness.**
#   `clients()` below finds dhcpcd by its EXECUTABLE, because dhcpcd destroys
#   its own argv with setproctitle and leaves nothing unique to match on. Every
#   other test here filters on a path under its own mktemp directory, which no
#   process outside can carry. This one cannot, so without a pid namespace its
#   cleanup trap would signal every dhcpcd on the machine -- including one
#   holding the operator's default route.
#
#   The first version had exactly that hole. Under `unshare -r` the kills
#   failed with EPERM against real root, which is luck rather than design; run
#   as root they would have landed. Measured after the fact: the host had four
#   dhcpcd processes and this namespace now sees zero.
#
#   The backend with no marker is the one whose test has no safe filter. That
#   is not a coincidence, and it is why the isolation has to do the work
#   instead.
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
	# **`--pid --fork` and a fresh /proc, or this script can kill processes on
	# the host.** Without a pid namespace, `/proc` shows the whole machine, and
	# `clients()` below scans `/proc/[0-9]*` for anything whose executable is
	# dhcpcd -- so the cleanup trap would signal every dhcpcd on the box,
	# including one holding the operator's default route. Under `unshare -r`
	# those kills fail with EPERM against real root, which is luck rather than
	# design; run as root they would land.
	#
	# Measured after the fact on the machine this was written on, where the
	# operator's route came from exactly such a process.
	NCFG_DHCPCD_INNER=1 exec unshare --map-root-user --map-auto --mount --uts --net \
		--pid --fork -- sh "$0" "$@"
fi

# **Check isolation before mounting anything.** As root, re-entering this half
# by hand with NCFG_DHCPCD_INNER=1 would otherwise stack a proc mount on the
# HOST's /proc before any guard looked -- a side effect on the operator's
# machine from a script that had not yet decided it was allowed to run.
[ "$$" = "1" ] || {
	echo "$(basename "$0"): FATAL: pid $$, expected 1 -- not in a pid namespace" >&2
	echo "  This test finds dhcpcd by executable name, so on a shared /proc it" >&2
	echo "  would kill the operator's dhcpcd. Re-run without NCFG_DHCPCD_INNER." >&2
	exit 1
}

export PATH=/sbin:/usr/sbin:$PATH
# The pid namespace only takes effect for /proc once /proc is remounted: the
# inherited one still shows the host's processes, which is the whole hazard.
mount -t proc proc /proc 2>/dev/null || skip "cannot remount /proc, so this cannot be isolated"
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
# **The isolation proof lives here, not only in the unshare above.**
# `clients()` matches on the executable rather than on a path under this
# script's own mktemp directory -- every other scanning test here can filter
# that way and this one cannot, because dhcpcd destroys its argv with
# setproctitle. So on a shared /proc it finds the operator's dhcpcd, and the
# cleanup trap kills it.
#
# The unshare is defeated by one env var: `NCFG_DHCPCD_INNER=1 sh $0` re-enters
# this half directly and scans the host. That is a real way in, not a
# hypothetical one, so the guard sits in the function that does the damage
# rather than only at the entry point.
#
# `unshare --pid --fork` makes the exec'd shell pid 1. Measured on the machine
# this was written on: 1 inside, 1994326 outside -- so the test discriminates
# rather than passing either way.
isolated() {
	[ "$$" = "1" ]
}

clients() {
	isolated || {
		echo "FATAL: /proc is not isolated, refusing to enumerate dhcpcd" >&2
		echo "       (pid $$, expected 1; re-run without NCFG_DHCPCD_INNER)" >&2
		exit 1
	}
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
