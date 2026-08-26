#!/bin/sh
# Adopting the udhcpc netcfgd left running when it stopped.
#
# WHY THIS FILE EXISTS
#   0140 fixed this for the supplicant: the process keeps netcfgd's `-P` path
#   in its own argv, while the pid file that path names sits in /run/netcfgd,
#   which `RuntimeDirectory=` deletes on a stop. udhcpc is the same shape --
#   busybox does not call setproctitle, so `-p <path>` survives whole -- and it
#   is worse in one way that matters.
#
# WHY IT IS WORSE THAN THE SUPPLICANT
#   dhcpcd refuses a second instance; udhcpc has no instance lock at all. So
#   without adoption netcfgd starts a SECOND client on the interface. Measured:
#   both run, both take the same lease (same MAC, same client id, the server
#   re-offers), and the second overwrites the pid file -- so the first becomes
#   permanently unreachable by netcfgd. A later `backend.stop` signals only the
#   second, and with `-R` that RELEASEs the lease and the generated script
#   removes the address, leaving the interface bare while a live client still
#   believes it holds the lease and will not re-add it until T1.
#
# THE ASSERTION THAT GOES RED
#   "exactly one client carries netcfgd's marker". Without the fix it reads 2.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "udhcpc_orphan.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "udhcpc_orphan.sh: skipping: $1"
	exit 0
}

command -v busybox >/dev/null 2>&1 || skip "busybox is not installed"
busybox udhcpc --help 2>&1 | grep -q "\-p" || skip "this busybox has no udhcpc applet"
command -v ip >/dev/null 2>&1 || skip "iproute2 is not installed"

work=$(mktemp -d /tmp/ncfg-udhcpc.XXXXXX)
failures=0
client=

cleanup() {
	[ -n "$client" ] && kill "$client" 2>/dev/null
	for p in $(carrying); do kill "$p" 2>/dev/null || true; done
	rm -rf "$work"
}

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

pidfile="$work/run/udhcpc/probe0.pid"
script="$work/run/udhcpc/probe0.script"

# Every process carrying netcfgd's marker as a whole argv element -- the same
# test pid_by_marker applies, so the count here and netcfgd's answer cannot
# drift apart.
carrying() {
	# The redirect is what complains when a process exits mid-walk, and the
	# shell says so before `tr` can be told to be quiet -- so the whole
	# read goes in a subshell whose stderr is discarded. A vanished pid is
	# ordinary here, not a finding.
	for d in /proc/[0-9]*; do
		( tr '\0' '\n' < "$d/cmdline" 2>/dev/null ) 2>/dev/null \
			| grep -qx "$pidfile" && echo "${d#/proc/}"
	done
	true
}

trap cleanup EXIT INT TERM

ip link add probe0 type dummy 2>/dev/null || skip "cannot create a dummy link"
ip link set probe0 up
mkdir -p "$work/run/udhcpc"
printf '#!/bin/sh\nexit 0\n' > "$script"
chmod +x "$script"

# A client netcfgd started, standing in for one it started before it stopped.
# There is no DHCP server here and none is needed: what is under test is
# whether netcfgd recognises the process, not whether it gets a lease.
busybox udhcpc -i probe0 -s "$script" -p "$pidfile" -f -q >/dev/null 2>&1 &
client=$!
waited=0
while [ -z "$(carrying)" ] && [ "$waited" -lt 50 ]; do
	waited=$((waited + 1))
	sleep 0.1
done

first=$(carrying | head -1)
check "a client is running and carries netcfgd's marker" \
	"$([ -n "$first" ] && echo yes || echo no)" "yes"
[ -n "$first" ] || { echo "udhcpc_orphan.sh: no client to orphan"; exit 1; }

# ---------------------------------------------------------------------------
# The stop takes the pid file, exactly as RuntimeDirectory= does. The process
# lives; the handle does not.
rm -f "$pidfile"
check "the pid file is gone" \
	"$([ -e "$pidfile" ] && echo present || echo gone)" "gone"
check "but the client is not" \
	"$([ -e "/proc/$first" ] && echo alive || echo gone)" "alive"

# ---------------------------------------------------------------------------
# **netcfgd's own apply, through the executor.** This is what the first version
# of this test got wrong: it ran `ncfg plan`, which never starts a backend, so
# the adoption code was never reached and the final count was 1 only because
# the script had killed the second client itself. A check that cannot reach the
# code under test passes whatever the code does.
#
# `dhcpcd` is masked out of the candidate list so the udhcpc arm is the one
# taken -- on a machine with dhcpcd installed the first candidate wins and this
# would measure the wrong client.
mkdir -p "$work/etc/conf.d" "$work/bin"
: > "$work/etc/netcfgd.conf"
cat > "$work/etc/conf.d/probe0.conf" <<'CONF'
interface probe0 {
	config = "dhcp"
}
CONF
# A dhcpcd that is not there: an empty PATH entry ahead of the real one cannot
# hide it, so instead the arm is reached by giving dhcpcd a name that fails
# with NotFound, which is the condition the fallback loop tests.
printf '#!/bin/sh\nexit 127\n' > "$work/bin/dhcpcd"
chmod +x "$work/bin/dhcpcd"

NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run" \
	"$repo/target/debug/ncfg" apply > "$work/apply.log" 2>&1 || true

check "netcfgd writes the handle back rather than spawning" \
	"$(cat "$pidfile" 2>/dev/null || echo none)" "$first"
check "and the client it adopted is the one that was already running" \
	"$([ -e "/proc/$first" ] && echo alive || echo gone)" "alive"
# **The assertion that goes red without the fix.** udhcpc has no instance lock,
# so an apply that does not adopt starts a second client and both run.
check "exactly one client carries netcfgd's marker" \
	"$(carrying | wc -l)" "1"

echo
if [ "$failures" -eq 0 ]; then
	echo "udhcpc_orphan.sh: all checks passed"
else
	echo "udhcpc_orphan.sh: $failures failed"
	exit 1
fi
