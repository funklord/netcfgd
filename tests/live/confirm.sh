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

# 7. A setting the last-good document does not mention.
#
#    The revert restores the last-good document and re-plans, which can only
#    take back what that document *disagrees* with. An MTU it does not state
#    agrees with whatever the machine currently has -- so before the declared
#    inverses were replayed, a window that changed the MTU and closed
#    unconfirmed left the new MTU in place for ever, with the address and the
#    route correctly restored around it. The operator sees a revert that
#    worked and a machine that is not what they went back to.
#
#    `on_drift = "report"` so the watcher cannot apply the change before the
#    windowed apply does. Without it the reconcile loop wins the race, the
#    window covers nothing, and this passes for the wrong reason -- which is
#    the state the first version of this case was written in.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	on_drift = "report"
}
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config = "10.9.9.1/24"
}
CONF
start_daemon ""
await yes || true
mtu_of() { ip link show probe0 2>/dev/null | sed -n 's/.*mtu \([0-9]*\).*/\1/p'; }
check "the device starts at the kernel default" "$(mtu_of)" "1500"

cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	on_drift = "report"
}
device probe0 {
	kind   = "dummy"
	mtu    = 1400
}
interface probe0 {
	config = "10.9.9.1/24"
}
CONF
sleep 1
"$ncfg" apply --confirm-within 2 >/dev/null 2>&1
check "the windowed apply set the MTU" "$(mtu_of)" "1400"

# Longer than the window, and longer than a tick, so the revert has run.
sleep 7
check "an unconfirmed MTU is put back by the declared inverse" "$(mtu_of)" "1500"
check "and the address the document does state is still there" "$(present)" "yes"
stop_daemon

# 8. `global { confirm = N }`: the machine's own answer, on a change the
#    daemon applies for itself.
#
#    The key compiled, was carried in the document, was pinned in the witness
#    and was honoured by the planner -- which emitted `commit.arm`. That op is
#    a marker the executor deliberately no-ops, because the window belongs to
#    the daemon, so the action was recorded Done, counted in "applied N
#    actions", and no window was ever written. An operator who wrote the key
#    and watched an apply succeed had the safety net they would have had
#    without it (0094 fixed the planner; the daemon still armed nothing).
#
#    Startup is excluded deliberately and is checked here rather than assumed.
#    `establish_first_last_good` writes an empty document as the last-good
#    before the first apply, so a window armed at boot and left unconfirmed
#    would revert to *nothing* -- every address, route and backend netcfgd had
#    just brought up, taken down N seconds after start with nobody present.
address_of() { ip -4 -br addr show probe0 2>/dev/null | tr -s ' ' | cut -d' ' -f3; }
window_open() { [ -e "$work/run/confirm.json" ] && echo yes || echo no; }

cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	confirm = 3
}
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config = "10.9.9.1/24"
}
CONF
start_daemon ""
await yes || true
check "the startup apply does not arm a window" "$(window_open)" "no"
check "and it applied the configuration" "$(address_of)" "10.9.9.1/24"

cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	confirm = 3
}
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config = "10.9.9.2/24"
}
CONF
sleep 2
check "a change the daemon applies for itself arms the document's window" \
	"$(window_open)" "yes"
check "and the change is live inside it" "$(address_of)" "10.9.9.2/24"

# Longer than the window and than a tick, so the expiry has been served.
sleep 7
check "an unconfirmed one reverts without anybody asking" \
	"$(address_of)" "10.9.9.1/24"
check "and the window is closed" "$(window_open)" "no"
stop_daemon

# 9. The control, and the opt-in half: a machine that never wrote the key gets
#    nothing. Same change, same timings -- only the key differs, so a pass here
#    cannot come from the change failing to apply.
cat > "$work/etc/netcfgd.conf" <<'CONF'
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config = "10.9.9.1/24"
}
CONF
start_daemon ""
await yes || true
cat > "$work/etc/netcfgd.conf" <<'CONF'
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config = "10.9.9.2/24"
}
CONF
sleep 2
check "without the key the same change arms nothing" "$(window_open)" "no"
sleep 7
check "and it stays applied" "$(address_of)" "10.9.9.2/24"
stop_daemon

# 10. A pass that corrects only drift must not arm, whatever the document says.
#
#     Arming there would revert netcfgd's own correction when nobody confirmed,
#     and the drift would be found again on the next pass. Nobody is waiting to
#     confirm a correction they did not ask for.
#
#     "Only drift" is the claim, and it is narrower than "a drift correction
#     never arms" -- which is what this comment said first. One plan covers the
#     config delta and the drift delta together, so a pass caused by a real
#     edit arms over whatever else that pass corrected. That does not
#     oscillate, because the following pass re-corrects with no document change
#     and therefore no window; but it is not what the looser sentence would
#     lead anybody to expect, and this case does not test it.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	confirm = 3
}
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config = "10.9.9.1/24"
}
CONF
start_daemon ""
await yes || true
ip addr del 10.9.9.1/24 dev probe0 2>/dev/null || true
sleep 8
check "a drift correction arms no window" "$(window_open)" "no"
check "and it put the address back" "$(address_of)" "10.9.9.1/24"
sleep 6
check "and left it there rather than oscillating" "$(address_of)" "10.9.9.1/24"
stop_daemon

# 11. `--confirm-within 0` on a machine that sets the key.
#
#     0094 makes zero the operator declining a window, and the only way to
#     decline one where the config sets a default -- so the planner suppresses
#     `commit.arm` for it. The daemon armed from the request's number without
#     looking at it, so zero armed a window that expired immediately: measured,
#     `ncfg apply --confirm-within 0` printed "confirm window open for 0s" and
#     four seconds later the interface had no address at all. The flag
#     documented as the safe way to skip the safety net was the most
#     destructive thing in the command.
#
#     Checked here rather than only in a unit test because the fault needed
#     three things to line up -- a request carrying zero, a daemon arming from
#     it, and a timer firing at once -- and only a real daemon has all three.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	confirm = 60
}
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config = "10.9.9.1/24"
}
CONF
start_daemon "--no-apply-on-start"
"$ncfg" apply --confirm-within 0 >/dev/null 2>&1
check "declining the window still applies" "$(address_of)" "10.9.9.1/24"
check "and arms nothing" "$(window_open)" "no"
sleep 4
check "and nothing takes it away a moment later" "$(address_of)" "10.9.9.1/24"
stop_daemon

# 12. A timer resolves the window it was spawned for, and no other.
#
#     `ConfirmExpired` carries no identity. A window confirmed before its
#     timer fires leaves that timer running, and it used to revert whichever
#     window was open when it landed -- so the operator's *next* change was
#     undone seconds after being applied, under a log line saying the window
#     closed unconfirmed. It needed two windows inside one window's length,
#     which was unusual when only `--confirm-within` armed them and is the
#     ordinary edit-confirm-edit loop now that a config change does.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	confirm = 6
}
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config = "10.9.9.1/24"
}
CONF
start_daemon ""
await yes || true
sed -i 's/10\.9\.9\.1/10.9.9.2/' "$work/etc/netcfgd.conf"
sleep 2
check "the first window is open" "$(window_open)" "yes"
"$ncfg" confirm >/dev/null 2>&1
sed -i 's/10\.9\.9\.2/10.9.9.3/' "$work/etc/netcfgd.conf"
sleep 2
check "and a second change arms a second" "$(window_open)" "yes"
# The first window's timer fires about here. It must find nothing to do.
sleep 3
check "the first window's timer does not revert the second" \
	"$(address_of)" "10.9.9.3/24"
stop_daemon

# 13. An apply served inside an open window leaves the window's record alone.
#
#     The no-window arm of `apply_request` clears the recorded inverses and
#     overwrites the last-good. Run while a window was outstanding, that
#     replaced the fall-back with the very configuration the window exists to
#     undo -- so the expiry found nothing to take back, re-planned to what was
#     already in effect, and reported a revert that reverted nothing.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	confirm = 8
}
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config = "10.9.9.1/24"
}
CONF
start_daemon ""
await yes || true
sed -i 's/10\.9\.9\.1/10.9.9.2/' "$work/etc/netcfgd.conf"
sleep 2
check "the window is open over the change" "$(window_open)" "yes"
"$ncfg" apply --confirm-within 0 >/dev/null 2>&1
sleep 9
check "an apply inside the window does not eat the way back" \
	"$(address_of)" "10.9.9.1/24"
stop_daemon

# 14. A written file is not a changed configuration.
#
#     `Command::ConfigChanged` fires for any inotify event, so an editor
#     writing the same bytes sets it -- and on a pass that is also correcting
#     drift, that armed a window over the drift correction, which is the thing
#     the design says never happens. On expiry it undoes netcfgd's own repair,
#     the drift returns next pass, and the machine oscillates.
#
#     The drift here is a sysctl because the kernel announces no event for it,
#     so it is still outstanding when the rewrite wakes the loop. With an
#     address the netlink event arrives first and the two land in separate
#     passes, which is why an earlier version of this case passed for the
#     wrong reason.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	confirm = 5
}
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config      = "10.9.9.1/24"
	forwarding  = true
}
CONF
start_daemon ""
await yes || true
sleep 1
check "the sysctl is set" \
	"$(cat /proc/sys/net/ipv4/conf/probe0/forwarding 2>/dev/null)" "1"
echo 0 > /proc/sys/net/ipv4/conf/probe0/forwarding 2>/dev/null || true
touch "$work/etc/netcfgd.conf"
sleep 3
check "an identical rewrite over drift arms nothing" "$(window_open)" "no"
check "and the drift was still corrected" \
	"$(cat /proc/sys/net/ipv4/conf/probe0/forwarding 2>/dev/null)" "1"
stop_daemon

# 15. A window is not armed against the empty placeholder.
#
#     `establish_first_last_good` writes an empty document so `--confirm-within`
#     works from the first apply, where "revert to nothing" really is the undo
#     of a first apply -- somebody asked and is watching. `converge` replaces it
#     only when the startup apply had no failure at all, so one failing action
#     leaves it in place indefinitely. Arming against it makes the revert
#     remove *everything* netcfgd installed rather than the change.
#
#     Measured with the guard removed: the window armed and the interface lost
#     its address entirely, from an operator editing one field.
ip link add probe1 type dummy 2>/dev/null || true
ip link set probe1 up 2>/dev/null || true
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	confirm = 5
}
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config = "10.9.9.1/24"
}
device probe1 {
	kind   = "dummy"
}
interface probe1 {
	config = "10.7.0.1/24"
	routes = "192.168.55.0/24 via 10.99.99.99"
}
CONF
start_daemon ""
await yes || true
sleep 1
check "a failed startup apply leaves the placeholder in place" \
	"$(grep -c '"interfaces": \[\]' "$work/run/last-good.json" 2>/dev/null)" "1"
sed -i 's/10\.9\.9\.1/10.9.9.4/' "$work/etc/netcfgd.conf"
sleep 3
check "and no window is armed against it" "$(window_open)" "no"
check "and it says why" \
	"$(grep -ac 'the last-good configuration is empty' "$work/daemon.log")" "1"
sleep 6
# The address is still the one from before the edit, and that is the assertion:
# the edit itself cannot apply, because a failing action stops the rest of the
# plan and the failing route above is deliberately in this fixture. What the
# guard prevents is the address being *removed* -- with it taken out, this line
# reads empty rather than either address.
#
# `present` was the first thing asserted here and it only asks whether the link
# exists, which stays true while the address goes away: it would have passed
# against the very failure the case is named for.
check "so nothing tears the machine down" "$(address_of)" "10.9.9.1/24"
stop_daemon
ip link del probe1 2>/dev/null || true

# 16. A revert blacklists what it reverted, not what happens to be on disk.
#
#     `state.rejected` stops a reload putting the configuration that just broke
#     the machine straight back. It was taken from `state.desired` at revert
#     time -- and an operator editing twice inside one window leaves `desired`
#     holding the *second* edit, which was deferred, never applied and never at
#     fault. Measured before the fix: the window reverted the first edit and
#     blacklisted the second, so `ncfg reload` answered "this configuration was
#     reverted away from and has not changed since" about a configuration that
#     had never been tried, and the operator's newest work could not be loaded
#     until they edited the file again.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	confirm = 8
}
device probe0 {
	kind   = "dummy"
}
interface probe0 {
	config = "10.9.9.1/24"
}
CONF
start_daemon ""
await yes || true
sed -i 's/10\.9\.9\.1/10.9.9.2/' "$work/etc/netcfgd.conf"
sleep 2
check "the first edit is live in a window" "$(address_of)" "10.9.9.2/24"
# A second edit while the window is open: deferred, never applied.
sed -i 's/10\.9\.9\.2/10.9.9.3/' "$work/etc/netcfgd.conf"
sleep 2
check "the second edit is held, not applied" "$(address_of)" "10.9.9.2/24"
sleep 9
check "the window reverts the edit it covered" "$(address_of)" "10.9.9.1/24"
check "and the edit it never applied is still loadable" \
	"$("$ncfg" reload 2>&1 | head -1)" "reloaded; the configuration compiles"
sleep 3
check "so the operator's newest work is not lost" "$(address_of)" "10.9.9.3/24"
stop_daemon

echo
if [ "$failures" -eq 0 ]; then
	echo "confirm.sh: all checks passed"
else
	echo "confirm.sh: $failures failed"
	exit 1
fi
