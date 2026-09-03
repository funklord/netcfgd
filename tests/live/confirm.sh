#!/bin/sh
# Commit-confirm against a real kernel.
#
# This is the mechanism an operator bets their remote access on, and until now
# nothing exercised it end to end. The three cases below are the three ways it
# is used: confirmed, reverted by hand, and -- the one that matters -- left
# alone by somebody who has just lost the machine.
#
# The first apply is covered deliberately. A window reverts to the last-good
# configuration and there was none until netcfgd had applied once, so
# `--confirm-within` used to be refused exactly when it was most wanted. An
# empty last-good is written at startup now, and "revert to empty" is the exact
# undo of a first apply.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "confirm.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "confirm.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-confirm.XXXXXX")
daemon=
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
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

cat > "$work/etc/netcfgd.conf" <<'CONF'
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config = "10.9.9.1/24"
}
CONF

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
ncfg="$repo/target/debug/ncfg"

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

present() { ip -br addr show probe0 >/dev/null 2>&1 && echo yes || echo no; }

# Wait for an outcome rather than sleeping a fixed time, except where the thing
# being waited for is a timer.
await() {
	waited=0
	while [ "$(present)" != "$1" ]; do
		waited=$((waited + 1))
		[ "$waited" -gt 60 ] && return 1
		sleep 0.1
	done
	return 0
}

start_daemon() {
	rm -rf "$work/run"
	mkdir -p "$work/run"
	# shellcheck disable=SC2086
	"$repo/target/debug/netcfgd" $1 > "$work/daemon.log" 2>&1 &
	daemon=$!
	waited=0
	while [ ! -e "$work/run/netcfgd.sock" ]; do
		waited=$((waited + 1))
		if [ "$waited" -gt 60 ]; then
			if grep -q 'Operation not permitted' "$work/daemon.log" 2>/dev/null; then
				skip "no CAP_NET_ADMIN (run under unshare -rn)"
			fi
			cat "$work/daemon.log" >&2
			echo "confirm.sh: the daemon never started" >&2
			exit 1
		fi
		sleep 0.1
	done
}

stop_daemon() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	wait "$daemon" 2>/dev/null || true
	daemon=
	ip link del probe0 2>/dev/null || true
}

# A crash, and a restart that finds what the crash left behind.
#
# Separate from `start_daemon` because that one clears `/run` first, which is
# right for an independent case and wrong here: the window and the last-good
# document are exactly what the restarted daemon has to find. And `kill -9`
# rather than a term, because the point is a daemon that got no chance to
# tidy up -- one that exits cleanly could have resolved the window on the way
# out and the test would prove nothing about the startup path.
crash_daemon() {
	[ -n "$daemon" ] && kill -9 "$daemon" 2>/dev/null
	wait "$daemon" 2>/dev/null || true
	daemon=
	rm -f "$work/run/netcfgd.sock"
}

restart_daemon() {
	# shellcheck disable=SC2086
	"$repo/target/debug/netcfgd" $1 > "$work/restart.log" 2>&1 &
	daemon=$!
	waited=0
	while [ ! -e "$work/run/netcfgd.sock" ]; do
		waited=$((waited + 1))
		if [ "$waited" -gt 60 ]; then
			cat "$work/restart.log" >&2
			echo "confirm.sh: the restarted daemon never started" >&2
			exit 1
		fi
		sleep 0.1
	done
}

# 1. The gap this file was written for: a protected *first* apply. The daemon
#    observes and changes nothing, so the operator's own first apply is the one
#    that carries the window.
start_daemon --no-apply-on-start
check "nothing is configured before the first apply" "$(present)" "no"

if ! "$ncfg" apply --confirm-within 30 > "$work/apply.log" 2>&1; then
	echo "FAIL a first apply could not open a window"
	cat "$work/apply.log"
	failures=$((failures + 1))
fi
await yes || true
check "the first apply can carry a confirm window" "$(present)" "yes"

# 2. Reverting by hand undoes it. "Revert to empty" is the exact undo of a
#    first apply: everything netcfgd installed goes, and nothing else is
#    touched.
"$ncfg" revert >/dev/null 2>&1
await no || true
check "reverting the first apply removes what it created" "$(present)" "no"
stop_daemon

# 3. The case that matters: nobody confirms, because whoever applied has just
#    lost the machine. Nothing below runs a command after the apply.
start_daemon --no-apply-on-start
"$ncfg" apply --confirm-within 2 >/dev/null 2>&1
await yes || true
check "the change is live while the window is open" "$(present)" "yes"

sleep 4
check "an unconfirmed window reverts on its own" "$(present)" "no"
stop_daemon

# 4. Confirming keeps it, which is the ordinary path and the one that would be
#    missed if only the reverts were tested.
start_daemon --no-apply-on-start
"$ncfg" apply --confirm-within 2 >/dev/null 2>&1
await yes || true
"$ncfg" confirm >/dev/null 2>&1
sleep 4
check "a confirmed change survives the window closing" "$(present)" "yes"
stop_daemon

# 5. And the ordinary reboot is not collateral damage. A daemon that applies at
#    startup records the real configuration as last-good, so an unconfirmed
#    window reverts to *that* rather than to the empty document written a
#    moment earlier.
start_daemon ""
await yes || true
"$ncfg" apply --confirm-within 2 >/dev/null 2>&1
sleep 4
check "a normally started daemon reverts to its config, not to nothing" \
	"$(present)" "yes"
stop_daemon

# 6. The recovery path for the recovery path: a daemon that died inside the
#    window.
#
#    This is the case commit-confirm exists for, at its worst. The operator
#    applied something, the machine went away before they could confirm, and
#    what comes back has to undo it -- with no help from the process that
#    applied it, which is gone.
#
#    `resolve_on_startup` reverts on finding a window at all, without looking
#    at the deadline, and the reasoning is worth restating because the
#    alternative sounds reasonable: honouring the remaining time assumes the
#    operator is still there and can still reach a socket that has been gone
#    for however long the daemon was down, which is exactly the assumption
#    commit-confirm exists because you cannot make.
#
#    The window here is deliberately long. A short one would expire while the
#    daemon was dead and the check could not tell "reverted because the window
#    was found" from "reverted because it ran out".
start_daemon --no-apply-on-start
"$ncfg" apply --confirm-within 600 >/dev/null 2>&1
await yes || true
check "the change is live, inside a window that will not expire on its own" \
	"$(present)" "yes"

crash_daemon
check "and it survives the daemon being killed" "$(present)" "yes"

restart_daemon --no-apply-on-start
check "the restarted daemon reverts what was never confirmed" "$(present)" "no"
check "and says why" \
	"$(grep -ci 'confirm window was open' "$work/restart.log")" "1"

# And it stays reverted. A daemon that reverted and then reconciled straight
# back to the rejected configuration would satisfy the check above and undo
# itself a tick later, which is worse than not reverting at all -- the
# operator watches it work and then watches it fail.
sleep 6
check "and does not put it back on the next reconcile" "$(present)" "no"
stop_daemon

echo
if [ "$failures" -eq 0 ]; then
	echo "confirm.sh: all checks passed"
else
	echo "confirm.sh: $failures failed"
	exit 1
fi
