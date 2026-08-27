#!/bin/sh
# A supplicant that has bound its socket and stopped answering.
#
# 0080 made a *dead* supplicant visible: it writes a pid file, and a pid file
# naming nothing is a daemon that has gone. A wedged one has a live pid and a
# socket on disk, and from every other angle netcfgd has it looks exactly like a
# supplicant that is working and has not associated yet -- so the plan said
# everything was fine while the radio joined nothing.
#
# Two things are checked and the second is the reason the first has a deadline:
# what netcfgd says, and how long it takes to say it. The round trip runs in the
# reconcile loop, so a supplicant eating the full ten-second reply timeout would
# hold that loop on every netlink event.
#
# The supplicant is faked, for the reason `fake_supplicant.py` exists: what is
# real here is the socket and the protocol, and a radio is the one thing this
# project cannot pretend to have. `dot1x.sh` drives a real wpa_supplicant.
#
# Runs under `unshare -rn`.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "wedged.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "wedged.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-wedged.XXXXXX")
fake=
cleanup() {
	if [ -n "$fake" ]; then
		kill "$fake" 2>/dev/null || true
		wait "$fake" 2>/dev/null || true
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
mkdir -p "$work/etc" "$work/run" "$work/ctrl"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
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

ip link add wlan0 type dummy 2>/dev/null || skip "cannot make a dummy interface"

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface wlan0 {
	config = "null"
}
CONF

# netcfgd asks this only of a supplicant its own record says is running -- a
# control socket outlives the process that bound it, so the file alone would
# describe one that exited an hour ago. No pid file is written, which is the
# "cannot tell" case the liveness pass leaves alone.
cat > "$work/run/owned.json" <<'STATE'
{
	"created_links": [],
	"backends": [{"kind": "supplicant", "interface": "wlan0", "running": true}]
}
STATE

wedged_warnings() {
	grep -c 'did not answer its control socket' "$1" || true
}

# ------------------------------------------------- one that answers says nothing

python3 "$repo/tests/live/fake_supplicant.py" "$work/ctrl" wlan0 > "$work/fake.log" 2>&1 &
fake=$!
waited=0
while ! grep -q ready "$work/fake.log" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && skip "the fake supplicant never started"
	sleep 0.1
done

"$ncfg" plan > "$work/answers.txt" 2>&1 || true
check "a supplicant that answers is not called wedged" \
	"$(wedged_warnings "$work/answers.txt")" 0
# The negative above is only worth something if the round trip happened at all.
# A PING in the fake's log is what says netcfgd asked; without it this check
# would pass just as well against an observation that never opened the socket.
check "and netcfgd did ask it" \
	"$([ "$(grep -c '^PING' "$work/fake.log" || true)" -ge 1 ] && echo yes || echo no)" "yes"

# --------------------------------------------------- one that does not is named

kill "$fake" 2>/dev/null || true
wait "$fake" 2>/dev/null || true
rm -f "$work/ctrl/wlan0"
# Binds the socket and answers nothing: alive, reachable, and mute. A supplicant
# that had *died* would fail fast on a missing socket, which is a different
# report and 0080's.
python3 -c '
import os, socket, sys, time
d, iface = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(os.path.join(d, iface))
print("ready", flush=True)
time.sleep(600)
' "$work/ctrl" wlan0 > "$work/mute.log" 2>&1 &
fake=$!
waited=0
while ! grep -q ready "$work/mute.log" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && skip "the mute socket never bound"
	sleep 0.1
done

before=$(date +%s)
"$ncfg" plan > "$work/wedged.txt" 2>&1 || true
elapsed=$(( $(date +%s) - before ))

check "a supplicant that never answers is reported" \
	"$(wedged_warnings "$work/wedged.txt")" 1
# By its own noun. On a machine running both an access point and a supplicant,
# "the backend on wlan0" is the least useful true thing available.
check "and called a supplicant" \
	"$(grep -c 'the supplicant on wlan0' "$work/wedged.txt" || true)" 1
# **It is a warning AND a refusal now (0141), and this asserted the opposite.**
#
# The old rule was "a warning, not a refusal: netcfgd cannot tell a wedged
# supplicant from a busy one, so acting on this would take working radios off
# the air". That reasoning is why netcfgd still does not restart it on its own
# -- it is not why declining should be invisible to a script. The copyright
# holder's rule is that the default is a loud failure with restart as an
# option, so the refusal is the loud half and it names the option.
check "and netcfgd declines to restart it, in the type built for declining" \
	"$(grep -c '^refused: backend.restart' "$work/wedged.txt" || true)" 1
check "and names the flag that consents" \
	"$(grep -c -- '--restart-wedged' "$work/wedged.txt" || true)" 1

# **And the flag is not decorative.** Asked for by interface, netcfgd stops and
# starts the backend rather than describing it. Without this the option could
# be accepted and ignored, which passes a test while doing nothing.
"$ncfg" plan --restart-wedged wlan0 > "$work/consented.txt" 2>&1 || true
check "with consent it plans a restart instead" \
	"$(grep -c 'backend.answering' "$work/consented.txt" || true)" 2
check "and refuses nothing" \
	"$(grep -c '^refused: backend.restart' "$work/consented.txt" || true)" 0

# Four seconds rather than two: this is wall clock on whatever machine runs the
# suite, and a gate that goes red under load teaches people to re-run it. Still
# nowhere near the ten a wedged one was measured at.
check "and does not stall the reconcile loop" \
	"$([ "$elapsed" -lt 4 ] && echo quick || echo "slow: ${elapsed}s")" "quick"

# ------------------------------------------- a stopped one is not called wedged

kill "$fake" 2>/dev/null || true
wait "$fake" 2>/dev/null || true
rm -f "$work/ctrl/wlan0"
# The answering fake again, so "was it asked?" has an answer. With the mute
# socket this section would prove nothing: a supplicant that is never asked and
# one that is asked and says nothing produce the same silent plan.
python3 "$repo/tests/live/fake_supplicant.py" "$work/ctrl" wlan0 > "$work/second.log" 2>&1 &
fake=$!
waited=0
while ! grep -q ready "$work/second.log" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && skip "the fake supplicant never restarted"
	sleep 0.1
done

cat > "$work/run/owned.json" <<'STATE'
{
	"created_links": [],
	"backends": [{"kind": "supplicant", "interface": "wlan0", "running": false}]
}
STATE
"$ncfg" plan > "$work/stopped.txt" 2>&1 || true
check "a supplicant netcfgd's record calls stopped is not named" \
	"$(wedged_warnings "$work/stopped.txt")" 0
# And not asked, which is the half the plan cannot show: the planner skips a
# stopped backend whatever the observation put in the field, so removing the
# observation's own guard changes no output and costs a round trip per pass to
# a process netcfgd believes is gone. A control socket outlives the process
# that bound it, so that round trip could even succeed.
check "and not asked at all" \
	"$(grep -c '^PING' "$work/second.log" || true)" 0

if [ "$failures" -eq 0 ]; then
	echo "wedged.sh: all checks passed"
else
	echo "wedged.sh: $failures check(s) failed"
	exit 1
fi
