#!/bin/sh
# An access point's station list, converged over the control socket.
#
#     unshare -rn sh tests/live/acl.sh
#
# Decision 0041. hostapd reads `deny_mac_file` once, at startup, so up to that
# decision an edited `access_control` block did nothing at all until somebody
# restarted the access point -- and restarting deauthenticates every client on
# the radio, which for a feature whose purpose is a smooth handoff is worse than
# the gap it closes.
#
# What this checks is the whole path and not the parser: netcfgd reads hostapd's
# live lists, plans the difference, sends `ADD_MAC` and `DEL_MAC`, and then plans
# nothing on the next run. `ap.sh` drives a real hostapd and proves netcfgd
# writes a file it accepts; it cannot go further, because converging a list
# needs a hostapd that will hold one, and one with no radio exits before it
# listens. So the radio is faked and the protocol is not -- fake_hostapd.py
# implements the lists the way `hostapd/ctrl_iface.c` implements them, including
# the two things that decided this design:
#
#   - `DENY_ACL SHOW` prints nothing at all for an empty list
#   - `ADD_MAC` and `DEL_MAC` are idempotent, so a converger that never
#     converged would look exactly like one that did
#
# The second is why the last check re-plans instead of only asserting that the
# commands went out.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "acl.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "acl.sh: skipping: $1"
	exit 0
}

command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d /tmp/ncfg-acl.XXXXXX)
cleanup() {
	[ -n "${fake:-}" ] && kill "$fake" 2>/dev/null
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
mkdir -p "$work/etc/secrets" "$work/run/hostapd"

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

passphrase=correct-horse-battery
printf '%s' "$passphrase" > "$work/etc/secrets/guest"
chmod 600 "$work/etc/secrets/guest"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
ncfg="$repo/target/debug/ncfg"

write_config() {
	cat > "$work/etc/netcfgd.conf" <<CONF
interface ap0 {
	kind   = "dummy"
	config = "null"
}

access_point "guest" {
	device  = "ap0"
	channel = 11
	wifi    { psk = "@secret:guest"; proto = "wpa2" }
$1
}
CONF
}

# What a previous apply left behind: netcfgd started hostapd on ap0, and the
# station list it generated records which policy it was started with. Both are
# needed and for different reasons -- without the first nothing believes there
# is an access point to ask, and without the second netcfgd does not know which
# of hostapd's two lists this one consults and refuses to converge either.
seed_run_state() {
	cat > "$work/run/owned.json" <<'STATE'
{
	"created_links": ["ap0"],
	"backends": [{"kind": "access_point", "interface": "ap0", "running": true}]
}
STATE
	printf '# netcfgd policy: %s\n' "$1" > "$work/run/hostapd/ap0.acl"
}

start_fake() {
	[ -n "${fake:-}" ] && kill "$fake" 2>/dev/null
	rm -f "$work/run/hostapd/ap0"
	# Remove the log rather than letting the redirect below truncate it, and
	# this is not tidiness either. The redirect is opened by the *child*, after
	# the fork, while the readiness loop below runs in the parent -- so the
	# first `grep` can win that race and match the **previous** fake's `ready`.
	# `start_fake` then returns before the new one has run a line of code.
	#
	# That race was harmless until the pid file existed: nothing downstream
	# depended on the new process having done any startup work, and `warm_fake`
	# absorbed the rest. With 0110 it stopped being harmless -- the pid file
	# still named the fake that had just been killed, so netcfgd correctly
	# observed a dead access point and every check about a live one failed.
	# Three in eight, and it moved from check to check depending on which
	# section lost the race.
	#
	# Removing it closes the window rather than narrowing it: the file does not
	# exist until the child opens it, `grep` on a missing file simply fails, and
	# the loop keeps waiting. A wait that cannot match stale output is the only
	# kind worth having.
	rm -f "$work/fake.log"
	# `--pidfile` is what netcfgd's `-P` produces against a real hostapd, and
	# every section needs it now rather than only the one that tests it: since
	# 0110 the liveness pass reads that file on every observation, and a
	# section whose fake wrote none would be asking netcfgd a question with no
	# handle -- answered "cannot tell", which passes for the wrong reason.
	python3 "$repo/tests/live/fake_hostapd.py" "$work/run/hostapd" ap0 \
		--pidfile "$work/run/hostapd/ap0.pid" "$@" \
		> "$work/fake.log" 2>&1 &
	fake=$!
	waited=0
	while ! grep -q ready "$work/fake.log" 2>/dev/null; do
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && skip "the fake hostapd never started"
		sleep 0.1
	done
}

# Wait until netcfgd has actually had an answer out of the fake.
#
# The socket existing is not the same as the process answering on it, and
# netcfgd reads a running access point's ACL under a one-second deadline that
# is there on purpose -- a wedged hostapd must not stall the reconcile loop. On
# a loaded machine a Python fake's *first* reply can cost more than that, and
# netcfgd then correctly treats the list as unreadable and converges nothing,
# which reads as checks failing for no reason. The deadline is not the thing to
# change.
#
# This replaces a single round trip nobody read, at the end of `start_fake`.
# Two things were wrong with it. It was **blind** -- a warm-up that itself
# timed out looked exactly like one that worked -- and it ran *before*
# `seed_run_state`, so on the first call netcfgd did not yet believe an access
# point was running, never read an ACL, and never touched the fake at all. It
# missed the one moment it existed for: the interpreter's first reply.
#
# 0085's warning is the signal, and it is a positive one: netcfgd says a
# running backend "did not answer its control socket" exactly when this read
# fails. Waiting for that to stop being true is waiting for a real answer to
# have arrived within the real deadline.
# Wait for a command to reach the fake's log before asserting it did.
#
# `ncfg apply` returns when netcfgd has *sent* a command, not when the process
# on the other end has logged it, and under load those are far enough apart to
# matter: with the cores saturated these checks failed three runs in four,
# reading a log the fake had not got to yet. Bounded, so a command that never
# arrives still fails its own check with its own message.
#
# Only for the assertions that a command *did* arrive. The ones asserting a
# command did not must not wait -- there would be nothing to wait for, and five
# seconds of it on every run.
wait_for_log() {
	waited=0
	while [ "$(grep -c "$1" "$work/fake.log" 2>/dev/null || true)" = "0" ]; do
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && return 1
		sleep 0.1
	done
	return 0
}

warm_fake() {
	# Nothing to warm through yet: the sections build up a configuration and the
	# first of them seeds the run state before writing one. A plan with no
	# configuration says exactly that and reads no ACL, so there is no round
	# trip to wait for -- the caller warms again after `write_config`, and this
	# is called in both places precisely so no section is left cold.
	if "$ncfg" plan 2>&1 | grep -q 'no configuration found'; then
		return 0
	fi
	waited=0
	while "$ncfg" plan 2>&1 | grep -q 'did not answer its control socket'; do
		waited=$((waited + 1))
		if [ "$waited" -gt 50 ]; then
			echo "FAIL the fake hostapd answered netcfgd inside its deadline"
			echo "       five seconds of plans and it is still reported as not"
			echo "       answering, so every check below would converge nothing"
			echo "       and say so for a reason that is not netcfgd's"
			failures=$((failures + 1))
			return 1
		fi
		sleep 0.1
	done
	return 0
}

# --------------------------------------------------- an edited list converges

# hostapd holds what it read at startup. The document now says something else.
start_fake --deny 00:11:22:33:44:55
seed_run_state deny
warm_fake || true
write_config '	access_control { deny = ["aa:bb:cc:dd:ee:ff"] }'
warm_fake || true

"$ncfg" plan > "$work/plan.txt" 2>&1 || true
check "the plan names the station being denied" \
	"$(grep -c 'access_control.add' "$work/plan.txt" || true)" "1"
check "and the one that is no longer" \
	"$(grep -c 'access_control.del' "$work/plan.txt" || true)" "1"
# The whole point of 0041. A plan that restarted hostapd would take every
# station on the radio off it to change one line of a list.
check "and does not restart the access point to do it" \
	"$(grep -c 'backend\.' "$work/plan.txt" || true)" "0"

"$ncfg" apply > "$work/apply.txt" 2>&1 || true

wait_for_log 'cmd: DENY_ACL ADD_MAC aa:bb:cc:dd:ee:ff' || true
check "the addition went out over the wire" \
	"$(grep -c 'cmd: DENY_ACL ADD_MAC aa:bb:cc:dd:ee:ff' "$work/fake.log" || true)" "1"
wait_for_log 'cmd: DENY_ACL DEL_MAC 00:11:22:33:44:55' || true
check "so did the removal" \
	"$(grep -c 'cmd: DENY_ACL DEL_MAC 00:11:22:33:44:55' "$work/fake.log" || true)" "1"
# TERMINATE is how netcfgd stops an access point (decision 0026). Seeing one
# here would mean the list was changed by restarting after all.
check "and hostapd was never told to stop" \
	"$(grep -c 'cmd: TERMINATE' "$work/fake.log" || true)" "0"

# hostapd now holds the document's list, so there is nothing left to do. This is
# the check that `ADD_MAC` being idempotent cannot fake: a converger that sent
# the right commands to the wrong list, or read the reply wrong, would plan the
# same two actions again here and forever.
"$ncfg" plan > "$work/replan.txt" 2>&1 || true
check "and the next plan has nothing left to converge" \
	"$(grep -cE 'access_control\.(add|del)' "$work/replan.txt" || true)" "0"

# ------------------------------- the list the policy does not name is not inert

# `hostapd_check_acl` consults the accept list *first* and the deny list second,
# whatever `macaddr_acl` says -- that value decides only what happens to an
# address in neither. So a station left on the accept list is accepted despite
# the deny list naming it, and a deny list that looks applied and is not is
# worse than no deny list at all.
start_fake --deny aa:bb:cc:dd:ee:ff --accept aa:bb:cc:dd:ee:ff
seed_run_state deny
warm_fake || true
"$ncfg" apply > "$work/apply2.txt" 2>&1 || true
wait_for_log 'cmd: ACCEPT_ACL DEL_MAC aa:bb:cc:dd:ee:ff' || true
check "the entry overriding the deny list is removed" \
	"$(grep -c 'cmd: ACCEPT_ACL DEL_MAC aa:bb:cc:dd:ee:ff' "$work/fake.log" || true)" "1"
check "and the deny list itself is left alone" \
	"$(grep -c 'cmd: DENY_ACL DEL_MAC aa:bb:cc:dd:ee:ff' "$work/fake.log" || true)" "0"

# ------------------------------------------------ a policy change is different

# `macaddr_acl` is read once, at startup, and is not reported back by anything
# on the control socket. Converging the lists without it would enforce the new
# list under the old default: a document changed from `deny` to `allow` would
# leave every unlisted station accepted, and netcfgd would report it applied.
start_fake --deny 00:11:22:33:44:55
seed_run_state deny
warm_fake || true
write_config '	access_control { allow = ["aa:bb:cc:dd:ee:ff"] }'
warm_fake || true

"$ncfg" plan > "$work/flip.txt" 2>&1 || true
check "a changed policy restarts the access point" \
	"$(grep -c 'backend.stop' "$work/flip.txt" || true)" "1"
# The op names, not the reason -- which reads `access_point.access_control.policy`
# and would match a bare `access_control.` in every one of these lines.
check "rather than converging the lists under a policy hostapd was not told" \
	"$(grep -cE 'access_control\.(add|del)' "$work/flip.txt" || true)" "0"
check "and says what the restart costs" \
	"$(grep -c 'deauthenticated' "$work/flip.txt" || true)" "1"

# ------------------------------------------------------ and with no record

# An access point started by a netcfgd from before the record existed: the
# station list is there and says only which addresses are on it. Under `deny` an
# emptied accept list is nothing; under `allow` it is a network nobody can join.
# There is no way to tell which, so nothing is converged.
#
# A *missing* file is a different answer and not this one -- `write_acl` removes
# it when the document carries no `access_control` block, so its absence says
# hostapd was started without one, which is a policy change and restarts.
start_fake --accept 00:11:22:33:44:55
printf '00:11:22:33:44:55\n' > "$work/run/hostapd/ap0.acl"
write_config '	access_control { deny = ["aa:bb:cc:dd:ee:ff"] }'
warm_fake || true

"$ncfg" plan > "$work/norecord.txt" 2>&1 || true
check "an unrecorded policy converges nothing" \
	"$(grep -cE 'access_control\.(add|del)' "$work/norecord.txt" || true)" "0"
check "and does not restart on the strength of a guess either" \
	"$(grep -c 'backend\.' "$work/norecord.txt" || true)" "0"
check "and says so rather than reporting the list as applied" \
	"$(grep -c 'no record' "$work/norecord.txt" || true)" "1"

# ------------------------------------------------ a wedged hostapd is not fatal

# Reading the lists put a control-socket round trip in the reconcile loop, which
# runs on every netlink event. A hostapd that is alive with its socket bound and
# not answering -- wedged rather than dead, so nothing fails fast -- would hold
# that loop for the client's whole reply timeout, twice per access point, every
# time. Measured at 10.2 seconds before `acl::read` got a deadline of its own,
# and 1.0 after.
#
# Four seconds is the threshold rather than two: this is wall clock on whatever
# machine is running the suite, and a gate that goes red under load teaches
# people to re-run the suite. It is still nowhere near ten.
# The fake's own `--wedged` rather than a second socket written inline here,
# which is what this was. Two reasons, and the first is not tidiness: since
# 0110 a wedged access point needs a pid file naming *itself*, and an inline
# socket inherits whatever the last `start_fake` left -- which names a process
# that has been killed, so every check below would be about a hostapd netcfgd
# believes has died rather than one that will not answer. The second is that
# the flag already existed and nothing used it.
start_fake --wedged
seed_run_state deny

before=$(date +%s)
"$ncfg" plan > "$work/wedgedplan.txt" 2>&1 || true
elapsed=$(( $(date +%s) - before ))
check "a hostapd that never answers does not stall the reconcile loop" \
	"$([ "$elapsed" -lt 4 ] && echo quick || echo "slow: ${elapsed}s")" "quick"
# And what it does instead is nothing, rather than converging against a list it
# could not read.
check "and nothing is converged against a list that could not be read" \
	"$(grep -cE 'access_control\.(add|del)' "$work/wedgedplan.txt" || true)" "0"

# The same wedged hostapd, asked to stop. Decision 0109.
#
# `stop` connects before it sends `TERMINATE`, and the connect opens with a
# `PING` -- so a daemon that has bound its socket and gone silent fails at the
# connect, and until 0109 every connect failure was read as "nothing is
# running". The stop then reported success without a byte having been sent: the
# access point stayed on the air, and the run state came back with no backend in
# it, so no later run would ever try again.
#
# Two states, and the whole check is that netcfgd tells them apart. Nothing is
# killed and restarted here -- reusing the wedged process is the point, because
# it is the only one that produces the state.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface ap0 {
	kind   = "dummy"
	config = "192.168.9.1/24"
}
CONF
wedgedstop=0
stopstart=$(date +%s)
"$ncfg" apply > "$work/wedgedstop.txt" 2>&1 || wedgedstop=$?
stopelapsed=$(( $(date +%s) - stopstart ))
check "a stop that could not be delivered is not reported as a stop" \
	"$([ "$wedgedstop" -ne 0 ] && echo failed || echo "reported success")" "failed"
check "and says which of the two states it found" \
	"$(grep -c 'did not answer its control socket' "$work/wedgedstop.txt" || true)" "1"
# The half that matters more. A failure the operator reads is recoverable; a
# forgotten access point is not, because nothing is left to plan against.
check "and the access point is still recorded, so a re-run can try again" \
	"$(grep -c '"kind": "access_point"' "$work/run/owned.json" || true)" "1"
# And it failed *quickly*, which is a separate property and the one that costs
# the machine something. `stop` runs inside the reconcile loop, so waiting on a
# daemon that will not answer is the whole machine waiting: measured on the
# laptop feature that has no operator in it, pulling the cable with a wedged
# access point recorded took **12.2 seconds** to switch to wifi against 106ms
# with nothing wedged. The read got a deadline in 0085 for exactly this and the
# stop kept the client's ten-second default.
#
# Four seconds for the same reason the check above uses four: this is wall clock
# on whatever machine is running the suite, and it is still nowhere near ten.
check "and failed quickly, rather than holding the reconcile loop" \
	"$([ "$stopelapsed" -lt 4 ] && echo quick || echo "slow: ${stopelapsed}s")" "quick"

# ------------------------------------ a stopped access point keeps no secret

# The generated configuration holds the passphrase in the clear, because hostapd
# has no indirection for one. An access point that is stopped has nothing left
# to authenticate, so it must not stay in /run -- tmpfs would clear it at the
# next reboot, but a passphrase beside a stopped daemon is one nobody is
# watching.
#
# Checked here rather than in ap.sh because ap.sh's hostapd never starts -- a
# dummy has no radio -- so nothing is ever stopped there and the check could not
# fire. This suite has a fake that answers TERMINATE, which is what a stop
# needs.
start_fake --deny aa:bb:cc:dd:ee:ff
seed_run_state deny
printf '# a previous start left this\nwpa_passphrase=correct-horse-battery\n' \
	> "$work/run/hostapd/ap0.conf"
chmod 600 "$work/run/hostapd/ap0.conf"
write_config ""
# The fake here is three lines old and the stop below is the first thing that
# talks to it. Since 0109 an unanswered stop is a failure rather than a silent
# success, so a cold interpreter that misses the deadline fails this section
# loudly -- which is the right behaviour and still not what is being tested.
warm_fake || true
# The document no longer names an access point on ap0, so the plan stops it.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface ap0 {
	kind   = "dummy"
	config = "192.168.9.1/24"
}
CONF
"$ncfg" apply > "$work/stopped.txt" 2>&1 || true

# Wait for the fake to have written it. `ncfg apply` returns when netcfgd has
# sent TERMINATE, not when the process on the other end has logged it, and under
# load those are far enough apart to matter: this check failed three runs in
# four with the machine's cores saturated, reading a log the fake had not got to
# yet. Bounded, so a TERMINATE that never arrives still fails.
wait_for_log 'cmd: TERMINATE' || true
check "stopping the access point asked hostapd to terminate" \
	"$(grep -c 'cmd: TERMINATE' "$work/fake.log" || true)" "1"
# By content, not by path: what matters is the secret rather than the filename.
check "and left no passphrase anywhere under /run" \
	"$(grep -rl 'correct-horse-battery' "$work/run" 2>/dev/null | wc -l)" "0"

# ------------------------------------- the rest of the configuration, at last

# hostapd reads its configuration once, at startup, and reports almost none of
# it back: `GET_CONFIG` gives the SSID and the ciphers and says nothing about
# the channel. So the only account of what it is running is netcfgd's own --
# the file it generated -- and until this existed an edited SSID left the radio
# announcing the old one with an empty plan to explain it. project.md carried
# that gap in as many words since 0041.
#
# The file is written here rather than by an apply, because an apply cannot get
# that far: a dummy has no radio and hostapd exits before it daemonizes.
start_fake --deny 00:11:22:33:44:55
seed_run_state deny
warm_fake || true
write_config '	access_control { deny = ["00:11:22:33:44:55"] }'
warm_fake || true
cat > "$work/run/hostapd/ap0.conf" <<'STARTED'
# hostapd configuration for the `guest` access point.
interface=ap0
ssid2=6f6c64
hw_mode=g
channel=11
STARTED

"$ncfg" plan > "$work/identity.txt" 2>&1 || true
check "an edited ssid restarts the access point" \
	"$(grep -c 'backend.stop' "$work/identity.txt" || true)" "1"
check "and comes back up in the same plan" \
	"$(grep -c 'backend.start' "$work/identity.txt" || true)" "1"
# Twice on the actions and once in the warning, which is the point: the reason
# travels with both halves of the restart so a plan read from the middle still
# says why.
check "naming the field that moved, on both halves and in the warning" \
	"$(grep -c 'access_point.ssid' "$work/identity.txt" || true)" "3"
check "and saying what the restart costs" \
	"$(grep -c 'deauthenticated' "$work/identity.txt" || true)" "1"
# The station lists are left alone while a restart is planned: the access point
# comes back with the whole file rebuilt, so converging a list on the hostapd
# that is about to be replaced is work that fails or is undone.
check "rather than converging a list on a daemon that is about to go" \
	"$(grep -cE 'access_control\.(add|del)' "$work/identity.txt" || true)" "0"

# And an edited passphrase, which is the half the identity comparison cannot
# make: the secret is in neither the document nor the observation, so what the
# observer publishes is a boolean it computed where both halves were already in
# hand (decision 0052).
sed -i 's/^ssid2=6f6c64$/ssid2=6775657374/' "$work/run/hostapd/ap0.conf"
printf 'wpa_passphrase=%s\n' 'what-it-was-started-with' >> "$work/run/hostapd/ap0.conf"
"$ncfg" plan > "$work/secret.txt" 2>&1 || true
check "an edited passphrase restarts the access point" \
	"$(grep -c 'access_point.wifi.psk' "$work/secret.txt" || true)" "3"
# Neither value may appear in a plan an operator pastes into a bug report. The
# document's is the one in the secrets directory; the daemon's is the line just
# written above.
check "without printing what the store holds" \
	"$(grep -c "$passphrase" "$work/secret.txt" || true)" "0"
check "or what the access point was started with" \
	"$(grep -c 'what-it-was-started-with' "$work/secret.txt" || true)" "0"
# And nowhere in the observation either, which goes over the socket and into
# /run -- constraint 5 is about all three.
"$ncfg" status --json > "$work/status.json" 2>&1 || true
check "nor anywhere in the observation" \
	"$(grep -c "$passphrase\|what-it-was-started-with" "$work/status.json" || true)" "0"
check "which says the answer instead" \
	"$(grep -c 'secret_matches' "$work/status.json" || true)" "1"

# And the same file, matching the document, plans nothing. Without this the
# check above passes for a netcfgd that restarts on every reconcile.
sed -i '/^wpa_passphrase=/d' "$work/run/hostapd/ap0.conf"
printf 'wpa_passphrase=%s\n' "$passphrase" >> "$work/run/hostapd/ap0.conf"
"$ncfg" plan > "$work/identity2.txt" 2>&1 || true
check "an access point already running what the document says is left alone" \
	"$(grep -cE 'backend\.(stop|start)' "$work/identity2.txt" || true)" "0"

# ------------------------------------------------------- dead, not wedged

# The state 0110 is about, and until it there was no way for netcfgd to be in
# any other one: an access point's `running` came from the record and nothing
# ever set it false. A hostapd that crashed an hour ago stayed `running: true`
# for as long as netcfgd was up, so the planner had nothing to do and 0079's
# restart -- which every other backend gets -- could not fire for it.
#
# `SIGKILL` rather than `SIGTERM` because the point is what a crash leaves
# behind. The socket is a file and outlives the process that bound it (0080),
# and so does the pid file, so every artefact netcfgd could look at says the
# access point is there. The only thing that says otherwise is the pid.
start_fake --deny aa:bb:cc:dd:ee:ff
seed_run_state deny
write_config '	access_control { deny = ["aa:bb:cc:dd:ee:ff"] }'
warm_fake || true

# The counter-proof, and it goes first: a check that a dead access point is
# restarted proves nothing unless a live one is left alone. Without this the
# section passes for a netcfgd that starts hostapd on every reconcile.
"$ncfg" plan > "$work/alive.txt" 2>&1 || true
check "an access point whose process is there is not started again" \
	"$(grep -cE 'backend\.start' "$work/alive.txt" || true)" "0"

kill -9 "$fake" 2>/dev/null || true
wait "$fake" 2>/dev/null || true
fake=
check "a killed hostapd leaves the socket it bound behind" \
	"$([ -S "$work/run/hostapd/ap0" ] && echo present || echo gone)" "present"
check "and the pid file it was told to write" \
	"$([ -f "$work/run/hostapd/ap0.pid" ] && echo present || echo gone)" "present"

"$ncfg" status --json > "$work/dead.json" 2>&1 || true
check "and is observed as not running, on the strength of the pid alone" \
	"$(grep -c '"running": *false' "$work/dead.json" || true)" "1"
"$ncfg" plan > "$work/dead.txt" 2>&1 || true
check "so the plan starts one" \
	"$(grep -cE 'backend\.start ap0' "$work/dead.txt" || true)" "1"

# ------------------------------------------------- alive, and not answering

# The state 0085 is about, and the reason it needed a flag on the fake rather
# than a second one: the process is there, the pid file is right, the socket
# takes a datagram, and no reply ever comes. A dead hostapd is a different
# thing and netcfgd notices that one separately, in the section above -- which
# is the pair this one has to be read against, because until 0110 the two
# states were indistinguishable to everything downstream.
start_fake --wedged
seed_run_state deny
write_config '	access_control { deny = ["aa:bb:cc:dd:ee:ff"] }'

"$ncfg" status --json > "$work/wedged.json" 2>&1 || true
check "a daemon that does not answer is observed as not answering" \
	"$(grep -c '"answering": *false' "$work/wedged.json" || true)" "1"
# The half that would otherwise be a guess. `access_control` absent is what
# says netcfgd did not read a list -- converging against a list it could not
# read is the thing read_access_control refuses to do.
check "and its list is absent rather than empty" \
	"$(grep -c '"access_control"' "$work/wedged.json" || true)" "0"

"$ncfg" plan > "$work/wedged.txt" 2>&1 || true
check "the operator is told, in a sentence naming the interface" \
	"$(grep -c 'ap0 is running and did not answer' "$work/wedged.txt" || true)" "1"
# Not a restart, and this is the check that keeps it that way. netcfgd cannot
# tell a wedged daemon from a slow one -- the deadline above is a second, and
# this same script records having seen a healthy fake miss it under load. A
# netcfgd that restarted on that reading would take down working access points
# on busy machines.
check "and nothing is stopped or started on the strength of it" \
	"$(grep -cE 'backend\.(stop|start)' "$work/wedged.txt" || true)" "0"

echo
if [ "$failures" -eq 0 ]; then
	echo "acl.sh: all checks passed"
else
	echo "acl.sh: $failures check(s) failed"
	exit 1
fi
