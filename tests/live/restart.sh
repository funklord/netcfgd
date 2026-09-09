#!/bin/sh
# Stopping netcfgd, killing it, and starting it again.
#
#     sh tests/live/restart.sh        # needs its own network namespace
#
# WHY THIS EXISTS
#   The audit of shutdown and restart. netcfgd has **no signal handler and no
#   `ExecStop`**, which is deliberate -- 0134's whole argument is that stopping
#   the daemon must not take the network down -- but "deliberate" is a claim,
#   and nothing checked it. Four things are asserted here, and all four were
#   measured before they were written:
#
#     * `SIGTERM` to exit is 20ms, so `TimeoutStopSec` never matters;
#     * the address and the route are still there afterwards;
#     * a restart over the leftovers is clean, and the machine stays
#       configured;
#     * `SIGKILL` mid-apply releases the apply lock, because it is an `flock`
#       held by the open file description and the kernel drops it when the
#       process dies (0184 chose it for exactly this).
#
# WHAT IT DELIBERATELY DOES NOT COVER
#   The hook child that outlives a killed daemon. Measured -- a `pre_up`
#   sleeping when the daemon is killed keeps running -- and that is the same
#   `KillMode=process` bargain the supplicant and the DHCP client are held by,
#   which `killmode.sh` owns. What a hook should do about it is an operator's
#   question, not a property of this daemon.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "restart.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "restart.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
	skip "this makes an interface and must not do it on the machine's own network; run it under \`unshare -rn\`, as the Makefile does"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-restart.XXXXXX")
daemon=
cleanup() {
	if [ -n "$daemon" ]; then
		kill "$daemon" 2>/dev/null || true
		wait "$daemon" 2>/dev/null || true
	fi
	# The hook's own child, by pid rather than by pattern: a `pkill -f` here
	# matched this script's own command line while it was being written, and
	# killed the run.
	if [ -n "${hook_child:-}" ]; then
		kill "$hook_child" 2>/dev/null || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_RESOLV_CONF="$work/resolv.conf"

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

ip link add st0 type dummy 2>/dev/null || skip "cannot make a dummy interface"

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface st0 {
	config = "10.17.0.1/24"
	routes = ["10.60.0.0/16 via 10.17.0.254"]
}
CONF

start_daemon() {
	"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
	daemon=$!
	waited=0
	while [ ! -S "$work/run/netcfgd.sock" ] && [ "$waited" -lt 60 ]; do
		waited=$((waited + 1))
		sleep 0.1
	done
	[ -S "$work/run/netcfgd.sock" ] || skip "the daemon never bound its socket"
	sleep 2
}

configured() { ip -4 -br addr show st0 | grep -c '10\.17\.0\.1' || true; }
routed() { ip -4 route show dev st0 | grep -c '10\.60\.0\.0/16' || true; }

start_daemon
check "the daemon configures the interface" "$(configured)" "1"
check "and installs its route" "$(routed)" "1"

# ------------------------------------------------------------- a clean stop

began=$(date +%s%N)
kill -TERM "$daemon"
wait "$daemon" 2>/dev/null || true
took=$(( ($(date +%s%N) - began) / 1000000 ))
daemon=

# **Promptness is a property, not a detail.** With no handler the default
# disposition ends the process, so `TimeoutStopSec` -- 90 seconds here -- never
# comes into it. A daemon that started blocking on the way out would push
# every reboot and every upgrade by up to that long, silently.
check "SIGTERM ends it in well under a second" \
	"$([ "$took" -lt 1000 ] && echo prompt || echo "slow: ${took}ms")" "prompt"

# 0134, asserted rather than asserted about: stopping the daemon must not take
# the network with it.
check "and the address is still there afterwards" "$(configured)" "1"
check "and so is the route" "$(routed)" "1"

# ------------------------------------------------- a restart over leftovers

# Everything the last run left is still in the run directory -- the socket, the
# two lock files, the recorded state. A restart has to walk over all of it.
check "the socket file is left behind, as it is on a real stop" \
	"$([ -e "$work/run/netcfgd.sock" ] && echo present || echo absent)" "present"

start_daemon
check "it starts again over its own leftovers" \
	"$(kill -0 "$daemon" 2>/dev/null && echo running || echo dead)" "running"
check "and the machine is still configured" "$(configured)" "1"

# --------------------------------------------------- killed, not asked

# `SIGKILL` while an apply is in flight, which is the case a lock file cannot
# survive: nothing runs to clean up. `flock` is held by the open file
# description, so the kernel releases it when the process dies -- which is why
# 0184 chose it over a file whose presence means "locked".
kill -KILL "$daemon"
wait "$daemon" 2>/dev/null || true
daemon=
check "after SIGKILL the apply lock is not left held" \
	"$(flock -n "$work/run/apply.lock" -c true 2>/dev/null && echo free || echo held)" "free"

start_daemon
check "and the daemon starts after being killed outright" \
	"$(kill -0 "$daemon" 2>/dev/null && echo running || echo dead)" "running"
check "with the configuration still in place" "$(configured)" "1"

if [ "$failures" -eq 0 ]; then
	echo "restart.sh: all checks passed"
else
	echo "restart.sh: $failures check(s) failed"
	tail -5 "$work/daemon.log" >&2
	exit 1
fi
