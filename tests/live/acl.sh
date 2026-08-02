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
	rm -rf "$work"
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
	python3 "$repo/tests/live/fake_hostapd.py" "$work/run/hostapd" ap0 "$@" \
		> "$work/fake.log" 2>&1 &
	fake=$!
	waited=0
	while ! grep -q ready "$work/fake.log" 2>/dev/null; do
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && skip "the fake hostapd never started"
		sleep 0.1
	done
	# A round trip nobody reads, before anything is measured. The socket
	# existing is not the same as the process answering on it, and netcfgd
	# reads a running access point's ACL under a one-second deadline that is
	# there on purpose -- a wedged hostapd must not stall the reconcile loop.
	# On a loaded machine a Python fake's *first* reply can cost more than
	# that, and netcfgd then correctly treats the list as unreadable and
	# converges nothing, which reads as two checks failing for no reason.
	# Seen once, during a `make live` sharing the machine with a container
	# build; the deadline is not the thing to change.
	"$ncfg" plan > /dev/null 2>&1 || true
}

# --------------------------------------------------- an edited list converges

# hostapd holds what it read at startup. The document now says something else.
start_fake --deny 00:11:22:33:44:55
seed_run_state deny
write_config '	access_control { deny = ["aa:bb:cc:dd:ee:ff"] }'

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

check "the addition went out over the wire" \
	"$(grep -c 'cmd: DENY_ACL ADD_MAC aa:bb:cc:dd:ee:ff' "$work/fake.log" || true)" "1"
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
"$ncfg" apply > "$work/apply2.txt" 2>&1 || true
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
write_config '	access_control { allow = ["aa:bb:cc:dd:ee:ff"] }'

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
kill "$fake" 2>/dev/null
fake=
rm -f "$work/run/hostapd/ap0"
python3 -c '
import os, socket, sys, time
d, iface = sys.argv[1], sys.argv[2]
p = os.path.join(d, iface)
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(p)
print("ready", flush=True)
time.sleep(600)
' "$work/run/hostapd" ap0 > "$work/wedged.log" 2>&1 &
wedged=$!
waited=0
while ! grep -q ready "$work/wedged.log" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && break
	sleep 0.1
done
seed_run_state deny

before=$(date +%s)
"$ncfg" plan > "$work/wedgedplan.txt" 2>&1 || true
elapsed=$(( $(date +%s) - before ))
kill "$wedged" 2>/dev/null
check "a hostapd that never answers does not stall the reconcile loop" \
	"$([ "$elapsed" -lt 4 ] && echo quick || echo "slow: ${elapsed}s")" "quick"
# And what it does instead is nothing, rather than converging against a list it
# could not read.
check "and nothing is converged against a list that could not be read" \
	"$(grep -cE 'access_control\.(add|del)' "$work/wedgedplan.txt" || true)" "0"

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
# The document no longer names an access point on ap0, so the plan stops it.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface ap0 {
	kind   = "dummy"
	config = "192.168.9.1/24"
}
CONF
"$ncfg" apply > "$work/stopped.txt" 2>&1 || true

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
write_config '	access_control { deny = ["00:11:22:33:44:55"] }'
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

echo
if [ "$failures" -eq 0 ]; then
	echo "acl.sh: all checks passed"
else
	echo "acl.sh: $failures check(s) failed"
	exit 1
fi
