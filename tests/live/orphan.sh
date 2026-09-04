#!/bin/sh
# Adopting the supplicant netcfgd left running when it stopped.
#
# WHY THIS FILE EXISTS
#   0134 decided an unannounced stop holds: netcfgd tears nothing down on exit,
#   so a crash or an upgrade does not take the network away. The supplicant it
#   started therefore keeps running -- which is correct, and is what keeps a
#   VPN over wifi up across a netcfgd restart.
#
#   What nothing covered is that netcfgd's only handle on that supplicant is
#   the pid file, and the pid file lives in `/run/netcfgd`, which
#   `RuntimeDirectory=` deletes on a real stop. So the process survives and the
#   handle does not. A restarted netcfgd then cannot recognise its own child,
#   falls through to the foreign-supplicant guard, and refuses the radio --
#   naming NetworkManager for a process netcfgd started itself. It never
#   recovers: the error returns before the restart counter is touched, so
#   0079's give-up path never runs either, and every reconcile repeats it.
#
#   Measured on a real machine before this test existed: an orphaned supplicant
#   and an orphaned dhcpcd fought NetworkManager for one radio, taking a fresh
#   DHCP lease roughly once a minute and burning thirteen addresses.
#
# THE STEP NO OTHER TEST PERFORMS
#   `rm -rf "$work/run"`. revive.sh removes the control socket and adopt.sh
#   removes owned.json; both leave the pid file in place, so both exercise
#   0080's dead-supplicant case rather than this one. 0135's table claimed
#   backends survive a wiped /run and cited revive.sh for it -- that row was a
#   vacuous pass, and this file is what it should have said.
#
# THE HALF THAT MUST NOT MOVE
#   The guard still has to refuse a stranger. `displace.sh` covers that, and
#   the adoption here must not widen it: netcfgd's mark is the absolute path in
#   `-P`, which no other manager's command line carries.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "orphan.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "orphan.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed"
command -v ip >/dev/null 2>&1 || skip "iproute2 is not installed"

work=$(mktemp -d /tmp/ncfg-revive.XXXXXX)
ncfg="$repo/target/debug/ncfg"
[ -x "$ncfg" ] || ncfg="$repo/target/debug/netcfgd"
daemon=
failures=0

cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	wait "$daemon" 2>/dev/null || true
	# **Every client netcfgd started, not only the supplicants.** netcfgd
	# records a pid at `$work/run/<program>/<iface>.pid` for udhcpc, odhcp6c,
	# dhcpcd and pppd exactly as it does for the supplicant, and a loop that
	# globbed `supplicant` alone left the rest orphaned to init -- holding a
	# work directory this trap then deleted, so they ran on with their stdout
	# pointing at a log that no longer existed. Measured across a day of
	# running the suite: 55 such processes, the oldest 23 hours.
	#
	# Killed only where the pid is still the process the file names. A pid
	# file outlives the process it names and pids are recycled, so a blind
	# kill can reach something else entirely; requiring this run's work
	# directory in the command line is netcfgd's own ownership test, and it
	# costs one read. `cat | tr` rather than a redirection because with `<`
	# it is the shell that complains about a missing file, and its complaint
	# does not go through the redirection -- which `helper.sh` found first.
	for pidfile in "$work"/run/*/*.pid; do
		[ -e "$pidfile" ] || continue
		pid=$(cat "$pidfile" 2>/dev/null) || continue
		case "$(cat "/proc/$pid/cmdline" 2>/dev/null | tr -d '\0')" in
		*"$work"*) kill "$pid" 2>/dev/null || true ;;
		esac
	done
	# **And a sweep by work directory, because this script destroys the
	# records on purpose.** The scenario is netcfgd's run directory going
	# while the supplicant lives -- `rm -rf "$work/run"` below is the whole
	# point of the file -- so by the time this trap runs there is no pid file
	# left to read, and the loop above finds nothing. Without this the script
	# leaked one supplicant per run.
	#
	# Precise despite being a sweep: `$work` is this run's own `mktemp -d`
	# path, so it cannot match a concurrent run's processes, and matching a
	# command line is the same ownership test the loop above makes.
	for proc in /proc/[0-9]*; do
		case "$(cat "$proc/cmdline" 2>/dev/null | tr -d '\0')" in
		*"$work"*) kill "${proc#/proc/}" 2>/dev/null || true ;;
		esac
	done
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

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
differs() {
	if [ "$2" != "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1"
		echo "       expected something other than: $3"
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

# Waits for a supplicant pid file to name a live process other than $1.
# Bounded by the loop counter, which is the only thing that ends it.
await_pid_other_than() {
	previous=$1
	waited=0
	while [ "$waited" -le 200 ]; do
		current=$(cat "$work/run/supplicant/radio0.pid" 2>/dev/null || echo '')
		if [ -n "$current" ] && [ "$current" != "$previous" ] && [ -e "/proc/$current" ]; then
			echo "$current"
			return 0
		fi
		waited=$((waited + 1))
		sleep 0.1
	done
	echo ''
}

ip link add radio0 type dummy 2>/dev/null || skip "cannot create a dummy link"
ip link set radio0 up
mkdir -p "$work/sys/radio0/wireless" "$work/etc/conf.d" "$work/run" "$work/ctrl"
cp "$repo/tests/live/fake_supplicant.py" "$work/fake_supplicant"
chmod +x "$work/fake_supplicant"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_SYS_CLASS_NET="$work/sys"
export NCFG_WPA_CTRL_DIR="$work/ctrl"
# **Isolated from the host's NetworkManager state.** netcfgd refuses to start a
# supplicant on an interface another manager claims, and it learns that from the
# files NM leaves under `/run/NetworkManager/devices/<ifindex>`. On a developer
# machine those exist for real interfaces -- including `lo`, index 1 -- so
# without this a test would read the host's NM and be refused for reasons that
# have nothing to do with what it is testing. `displace.sh` points this at a
# tree it populates on purpose; everything else points it at an empty one.
mkdir -p "$work/runroot"
export NCFG_RUN_ROOT="$work/runroot"
export NCFG_WPA_SUPPLICANT="$work/fake_supplicant"

cat > "$work/etc/netcfgd.conf" <<'CONF'
device radio0 {
	wifi { autoconnect = true }
}
interface radio0 {
	config = "null"
}
CONF

# Starts the daemon and waits for its socket. Bounded by the counter; named so
# that the two runs write separate logs, since the second run's output is what
# the last check reads.
start_daemon() {
	"$repo/target/debug/netcfgd" > "$work/$1.log" 2>&1 &
	daemon=$!
	waited=0
	while [ ! -e "$work/run/netcfgd.sock" ]; do
		waited=$((waited + 1))
		if [ "$waited" -gt 60 ]; then
			cat "$work/$1.log" >&2
			echo "orphan.sh: the daemon never started" >&2
			exit 1
		fi
		sleep 0.1
	done
}

start_daemon d1

# ---------------------------------------------------------------------------
# 1. netcfgd owns the radio and has a supplicant. Baseline.
first=$(await_pid_other_than '')
check "netcfgd starts a supplicant on the radio it owns" \
	"$([ -n "$first" ] && echo yes || echo no)" "yes"
[ -n "$first" ] || { echo "orphan.sh: no supplicant to orphan"; cat "$work/d1.log" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 2. netcfgd stops. 0134 says the supplicant stays -- assert it, rather than
#    assuming it, because everything below depends on it.
kill "$daemon" 2>/dev/null
wait "$daemon" 2>/dev/null || true
daemon=
rm -f "$work/run/netcfgd.sock"
check "stopping netcfgd leaves its supplicant running" \
	"$([ -e "/proc/$first" ] && echo alive || echo gone)" "alive"
check "and it still holds the control socket" \
	"$([ -e "$work/ctrl/radio0" ] && echo yes || echo no)" "yes"

# ---------------------------------------------------------------------------
# 3. The run directory goes, the way `RuntimeDirectory=` takes it on a real
#    stop. The process lives; the handle to it does not.
rm -rf "$work/run"
check "the pid file is gone" \
	"$([ -e "$work/run/supplicant/radio0.pid" ] && echo present || echo gone)" "gone"
check "but the process is not" \
	"$([ -e "/proc/$first" ] && echo alive || echo gone)" "alive"
check "and it still carries netcfgd's mark in its own argv" \
	"$(tr '\0' '\n' < "/proc/$first/cmdline" 2>/dev/null | grep -c "^$work/run/supplicant/radio0.pid$")" "1"

# ---------------------------------------------------------------------------
# 4. netcfgd comes back and must recognise its own child. No apply: 0132's
#    reconcile is what has to do it.
mkdir -p "$work/run"
start_daemon d2
sleep 3

adopted=$(cat "$work/run/supplicant/radio0.pid" 2>/dev/null || echo '')
check "the restarted daemon writes the pid file back" \
	"$([ -n "$adopted" ] && echo yes || echo no)" "yes"
check "and it names the process that was already running" "$adopted" "$first"
check "nothing was restarted -- the association was never dropped" \
	"$([ -e "/proc/$first" ] && echo alive || echo gone)" "alive"
check "and there is exactly one supplicant carrying that mark" \
	"$(grep -lc . /proc/[0-9]*/cmdline 2>/dev/null >/dev/null; c=0; for d in /proc/[0-9]*; do tr '\0' '\n' < "$d/cmdline" 2>/dev/null | grep -q "^$work/run/supplicant/radio0.pid$" && c=$((c+1)); done; echo $c)" "1"
check "and it did not blame another manager for its own process" \
	"$(grep -ci 'did not start' "$work/d2.log" 2>/dev/null | head -1)" "0"
contains "and the radio is netcfgd's" "$("$ncfg" wifi radios 2>&1)" "netcfgd's"

# ---------------------------------------------------------------------------
# 5. **A supplicant that is netcfgd's and no longer answers must NOT be
#    adopted.**
#
#    Measured on a real machine: netcfgd adopted a supplicant left alive by
#    `KillMode=process`, could not talk to it, displaced NetworkManager's
#    working one in doing so, and then declined to restart it because 0141
#    makes that a person's decision. The radio was captured by a dead process
#    and NetworkManager was locked out with it. Three defensible changes --
#    hold across a stop, adopt on restart, do not kill what may only be busy --
#    composing into a trap.
#
#    Declining to adopt costs nothing by comparison: netcfgd refuses the radio,
#    says why, and whoever can still drive it keeps it.
kill "$daemon" 2>/dev/null || true
wait "$daemon" 2>/dev/null || true
daemon=
rm -f "$work/run/netcfgd.sock"
# The supplicant stays, and stops answering: its socket is replaced by one that
# binds and never replies, which is what a wedged wpa_supplicant looks like
# from outside and what NetworkManager's D-Bus-driven one looks like always.
kill -STOP "$adopted" 2>/dev/null || true
rm -f "$work/ctrl/radio0"
python3 -c "
import socket, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind('$work/ctrl/radio0')
time.sleep(60)" >/dev/null 2>&1 &
mute=$!
waited=0
while [ ! -e "$work/ctrl/radio0" ] && [ "$waited" -lt 50 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
# Both, or nothing is planned and the adoption code is never reached at all:
# `owned.json` still saying the backend is running makes the plan empty, and
# the first version of this check passed with the reachability guard removed --
# a control that could not fail.
rm -f "$work/run/supplicant/radio0.pid" "$work/run/owned.json"

start_daemon d3
sleep 2
check "a supplicant that answers nothing is not adopted" \
	"$([ -s "$work/run/supplicant/radio0.pid" ] && echo adopted || echo declined)" "declined"
check "and netcfgd says the radio is not usable rather than claiming it" \
	"$(grep -ci 'adopted' "$work/d3.log" 2>/dev/null | head -1)" "0"
kill -CONT "$adopted" 2>/dev/null || true
kill "$mute" 2>/dev/null || true

echo
if [ "$failures" -eq 0 ]; then
	echo "orphan.sh: all checks passed"
else
	echo "orphan.sh: $failures failed"
	exit 1
fi
