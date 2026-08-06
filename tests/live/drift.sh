#!/bin/sh
# The `drift` hook, against a real kernel and a running daemon.
#
# Every other hook phase is a plan action, so `ncfg apply` exercises it and
# hooks.sh can drive the whole thing with one command. This one is not: drift
# under `on_drift = "report"` produces no apply at all -- that is what `report`
# means -- so a planned action would never run, and the one policy whose entire
# purpose is "tell me, do not touch it" would be the one where nothing told
# anybody. It fires from the daemon at detection instead, which means **this
# test needs a netcfgd running**, and that is the whole reason it is a separate
# script.
#
# Three things are checked, and the second is the one worth having:
#
#   1. it fires when somebody moves the machine away from the document;
#   2. it fires *once*, not on every netlink event while the drift persists.
#      Under `report` the drift is still there a second later and a minute
#      later, so a hook that fired on presence rather than on appearance would
#      run somebody else's script forever -- 0079's restart storm in a
#      different costume;
#   3. under `reconcile` it still fires, and sees the machine as it drifted
#      rather than as netcfgd has just put it back.
#
# Runs under `unshare -rn`: it creates a dummy interface and deletes an address
# from it behind netcfgd's back.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "drift.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "drift.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-drift.XXXXXX")
daemon=
cleanup() {
	if [ -n "$daemon" ]; then
		kill "$daemon" 2>/dev/null || true
		wait "$daemon" 2>/dev/null || true
	fi
	# Retry: a signalled daemon writes on its way out, so a single `rm -rf`
	# races the process the lines above have just asked to stop. A trap that
	# exits non-zero fails the whole run after every check has passed, which is
	# how this surfaced -- three times, in three different scripts.
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
	if [ -d "$work" ]; then
		echo "note: $work outlived five seconds of trying to remove it" >&2
	fi
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"

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

log=$work/transcript
: > "$log"

# One line per run, carrying what the daemon told the script. `NCFG_REASON` is
# what drifted and `NCFG_ACTION` is what netcfgd is going to do about it -- the
# second being the only thing that differs between the two policies, and the
# reason a script can be written once and behave correctly under both.
write_config() {
	cat > "$work/etc/netcfgd.conf" <<CONF
interface drifty0 {
	kind     = "dummy"
	config   = "10.9.0.1/24"
	on_drift = "$1"
	on drift {
	echo "drift iface=\$NCFG_IFACE action=\$NCFG_ACTION reason=\$NCFG_REASON" >> $log
	}
}
CONF
}

runs() {
	grep -c '^drift ' "$log" 2>/dev/null || true
}

start_daemon() {
	"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
	daemon=$!
	i=0
	while [ ! -e "$work/run/netcfgd.sock" ] && [ "$i" -lt 50 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -e "$work/run/netcfgd.sock" ]; then
		echo "drift.sh: the daemon never bound its socket" >&2
		cat "$work/daemon.log" >&2
		exit 1
	fi
	# The socket appearing does not mean the first apply has finished -- the
	# daemon binds before it converges (switch.sh's note). Wait for the thing
	# this test is about to take away.
	i=0
	while [ "$i" -lt 50 ]; do
		if ip -br addr show drifty0 2>/dev/null | grep -q 10.9.0.1; then
			break
		fi
		i=$((i + 1))
		sleep 0.1
	done
}

# ----------------------------------------------------------------- report

write_config report
start_daemon
check "the interface converged before anything was disturbed" \
	"$(ip -br addr show drifty0 2>/dev/null | grep -c 10.9.0.1 || true)" 1
check "and nothing has fired the drift hook yet" "$(runs)" 0

# Behind netcfgd's back, which is what drift is.
ip addr del 10.9.0.1/24 dev drifty0
sleep 1

check "a drift the operator caused fires the hook once" "$(runs)" 1
check "and the script is told which interface" \
	"$(grep -c 'iface=drifty0' "$log" || true)" 1
check "and what netcfgd is going to do about it" \
	"$(grep -c 'action=reported only' "$log" || true)" 1
check "and what drifted, in the daemon's own words" \
	"$(grep -c 'reason=addr.add: ' "$log" || true)" 1

# The check this script exists for. Under `report` the address stays gone, so
# the drift is still there -- and every netlink event re-runs the detection.
# Something has to make each of these *not* a hook run.
for _ in 1 2 3; do
	ip link add drift-noise type dummy
	ip link del drift-noise
done
sleep 1
check "and does not fire again while the same drift persists" "$(runs)" 1

kill "$daemon"
wait "$daemon" 2>/dev/null || true
daemon=

# --------------------------------------------------------------- reconcile

: > "$log"
rm -rf "$work/run"
mkdir -p "$work/run"
ip link del drifty0 2>/dev/null || true

write_config reconcile
start_daemon
check "the interface converged under reconcile too" \
	"$(ip -br addr show drifty0 2>/dev/null | grep -c 10.9.0.1 || true)" 1
check "and nothing has fired the drift hook yet" "$(runs)" 0

ip addr del 10.9.0.1/24 dev drifty0
sleep 1

check "reconciling still tells the script" "$(runs)" 1
check "and says so, rather than saying what report says" \
	"$(grep -c 'action=reconciling' "$log" || true)" 1
check "and netcfgd put the address back" \
	"$(ip -br addr show drifty0 2>/dev/null | grep -c 10.9.0.1 || true)" 1

if [ "$failures" -eq 0 ]; then
	echo "drift.sh: all checks passed"
else
	echo "drift.sh: $failures check(s) failed"
	exit 1
fi
