#!/bin/sh
# Bringing back a supplicant that died under an activated radio.
#
# WHY THIS FILE EXISTS
#   The symptom that started this was a GUI saying "cannot reach supplicant for
#   wlp0s20f3" with buttons that did nothing, while `ncfg wifi radios` on the
#   same machine answered "netcfgd's". Those two facts together are the whole
#   report: netcfgd believes it owns the radio, and there is no control socket
#   to reach. Every client then fails in the same way, because every client
#   goes through that socket.
#
#   `displace.sh` covers netcfgd taking a radio that was never its own.
#   Nothing covered a radio that *was* its own and lost its supplicant, which
#   is the shape a crash leaves behind, and the shape a machine is in after a
#   reboot that did not restart everything.
#
# WHAT MUST HAPPEN, AND WHY IT IS NOT OPTIONAL
#   The daemon reconciles by default (0132): apart from a config-to-apply
#   cycle it applies settings, and re-applies a setting that has deviated. A
#   supplicant that is gone from a radio netcfgd owns is a deviation, so
#   nothing needs to ask netcfgd to fix it -- no apply is run below on purpose.
#   A daemon that only fixes this when told is a daemon that looks broken
#   until somebody who knows to run `ncfg apply` comes along.
#
# THE STALE PID FILE IS THE POINT
#   netcfgd's handle on its own supplicant is the pid file it told it to
#   write, and a pid file outlives the process it names. So the failure this
#   guards against is not "netcfgd does nothing" but "netcfgd reads a pid file,
#   concludes a supplicant is running, and does nothing" -- which from outside
#   is indistinguishable, and which is why the check below reads the pid rather
#   than the file's existence.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "revive.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "revive.sh: skipping: $1"
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

"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		cat "$work/daemon.log" >&2
		echo "revive.sh: the daemon never started" >&2
		exit 1
	fi
	sleep 0.1
done

# ---------------------------------------------------------------------------
# 1. The radio is netcfgd's and has a supplicant. Baseline, and it has to hold
#    or nothing below means anything -- a revival test that starts from no
#    supplicant proves only that the first start works.
first=$(await_pid_other_than '')
check "netcfgd starts a supplicant on the radio it owns" \
	"$([ -n "$first" ] && echo yes || echo no)" "yes"
[ -n "$first" ] || { echo "revive.sh: no supplicant to kill"; cat "$work/daemon.log" >&2; exit 1; }
contains "and the radio reports as netcfgd's" "$("$ncfg" wifi radios 2>&1)" "netcfgd's"
contains "and scanning works through it" "$("$ncfg" wifi scan radio0 2>&1 || true)" "HomeFiber"

# ---------------------------------------------------------------------------
# 2. The supplicant dies, the way it dies on a real machine: the process goes
#    and the pid file it wrote stays behind naming it.
kill -9 "$first" 2>/dev/null || true
waited=0
while [ -e "/proc/$first" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && break
	sleep 0.1
done
check "the supplicant is gone" "$([ -e "/proc/$first" ] && echo alive || echo gone)" "gone"

# This is the state the report described: netcfgd's radio, no socket to reach.
# A daemon that stopped here is one whose every client says "cannot reach
# supplicant" for ever.
rm -f "$work/ctrl/radio0"

# ---------------------------------------------------------------------------
# 3. netcfgd fixes it without being asked.
second=$(await_pid_other_than "$first")
check "netcfgd starts another supplicant on its own" \
	"$([ -n "$second" ] && echo yes || echo no)" "yes"
differs "and it is a new process, not the pid file's ghost" "$second" "$first"
check "and the pid file names the live one" \
	"$(cat "$work/run/supplicant/radio0.pid" 2>/dev/null || echo '')" "$second"
check "and it is netcfgd's, by the pid file it was told to write" \
	"$(tr '\0' ' ' < "/proc/$second/cmdline" 2>/dev/null | grep -c "$work/run/supplicant/radio0.pid" || true)" "1"
contains "and the radio is netcfgd's again" "$("$ncfg" wifi radios 2>&1)" "netcfgd's"
contains "and scanning works again" "$("$ncfg" wifi scan radio0 2>&1 || true)" "HomeFiber"

echo
if [ "$failures" -eq 0 ]; then
	echo "revive.sh: all checks passed"
else
	echo "revive.sh: $failures failed"
	exit 1
fi
