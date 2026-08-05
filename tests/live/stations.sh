#!/bin/sh
# Who is on the access point, end to end.
#
#     unshare -rn sh tests/live/stations.sh
#
# ap.sh drives a real hostapd and proves netcfgd writes a file it accepts. It
# cannot go further: a hostapd with no radio has no clients, so everything
# downstream of "who is connected" needs a station that cannot exist here.
#
# So the radio is faked and the protocol is not -- fake_hostapd.py speaks the
# real wpa_ctrl wire format with replies copied from hostapd's own source. What
# this checks is the half ap.sh cannot reach: the walk over STA-FIRST/STA-NEXT,
# the parse, the tier, and what an operator actually sees.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "stations.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "stations.sh: skipping: $1"
	exit 0
}

command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

work=$(mktemp -d /tmp/ncfg-stations.XXXXXX)
cleanup() {
	[ -n "${fake:-}" ] && kill "$fake" 2>/dev/null
	[ -n "${daemon:-}" ] && kill "$daemon" 2>/dev/null
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
mkdir -p "$work/etc/secrets" "$work/run"

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

printf '%s' correct-horse-battery > "$work/etc/secrets/guest"
chmod 600 "$work/etc/secrets/guest"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
ncfg="$repo/target/debug/ncfg"

# The fake sits where netcfgd looks for a hostapd control socket, which is
# under netcfgd's own run directory rather than /run/hostapd (decision 0026).
mkdir -p "$work/run/hostapd"
python3 "$repo/tests/live/fake_hostapd.py" "$work/run/hostapd" ap0 > "$work/fake.log" 2>&1 &
fake=$!
waited=0
while ! grep -q ready "$work/fake.log" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && skip "the fake hostapd never started"
	sleep 0.1
done

write_config() {
	cat > "$work/etc/netcfgd.conf" <<CONF
interface ap0 {
	kind   = "dummy"
	config = "192.168.9.1/24"
}

access_point "guest" {
	device  = "ap0"
	channel = 11
	wifi    { psk = "@secret:guest"; proto = "wpa2" }
$1
}
CONF
}

write_config ""

"$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 50 ]; then
		cat "$work/daemon.log" >&2
		skip "the daemon never started"
	fi
	sleep 0.1
done

# ------------------------------------------------------------- the station list

"$ncfg" wifi clients ap0 --json > "$work/clients.json" 2>"$work/clients.err" || true
# `--json` prints the report itself rather than the response envelope, the same
# as `wifi scan` does, so the fields to assert on are the report's own.
check "the report names the access point and the radio it runs on" \
	"$(python3 -c '
import json,sys
report = json.load(open(sys.argv[1]))
print(report["access_point"], report["interface"])' "$work/clients.json" 2>/dev/null \
		|| echo "unreadable")" "guest ap0"

count=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["stations"]))' \
	"$work/clients.json" 2>/dev/null || echo 0)
# Three, which is the whole walk: STA-FIRST, two STA-NEXT that answer, and the
# empty reply that ends it. A parser that stopped at the first station would
# say 1 and a walk that never terminated would not return at all.
check "every station on the walk is listed" "$count" "3"

# Sorted by address, so the output does not reorder itself between runs.
check "sorted by address" \
	"$(python3 -c 'import json,sys; print(" ".join(s["address"] for s in json.load(open(sys.argv[1]))["stations"]))' \
		"$work/clients.json")" \
	"00:11:22:33:44:55 66:77:88:99:aa:bb aa:bb:cc:dd:ee:ff"

# The station the driver would not answer about is present, with its statistics
# absent rather than zero. Dropping it would be the worst way for this feature
# to be wrong: the question is who is connected.
check "a station with no driver statistics is still listed" \
	"$(python3 -c '
import json,sys
station = [s for s in json.load(open(sys.argv[1]))["stations"]
           if s["address"] == "aa:bb:cc:dd:ee:ff"][0]
print("signal" in station, "rx_bytes" in station)' "$work/clients.json")" \
	"False False"

check "and one that was read carries its signal" \
	"$(python3 -c '
import json,sys
station = [s for s in json.load(open(sys.argv[1]))["stations"]
           if s["address"] == "00:11:22:33:44:55"][0]
print(station["signal"], station["connected_seconds"])' "$work/clients.json")" \
	"-52 3600"

# Associated without having finished authenticating is a real state, not a
# parse failure, and it is shown differently.
check "an unauthorized station says so" \
	"$(python3 -c '
import json,sys
station = [s for s in json.load(open(sys.argv[1]))["stations"]
           if s["address"] == "66:77:88:99:aa:bb"][0]
print(station["authorized"])' "$work/clients.json")" "False"

# The walk really happened over the wire, rather than the daemon inventing it.
check "the walk was STA-FIRST then STA-NEXT" \
	"$(grep -c 'cmd: STA-FIRST' "$work/fake.log" || true)" "1"
check "and asked for the next one from each address" \
	"$(grep -c 'cmd: STA-NEXT ' "$work/fake.log" || true)" "3"

# --------------------------------------------------- the two halves as one view

# A station on the deny list that is nonetheless connected is the gap decision
# 0039 named: hostapd read the list once at startup and was never told it
# changed. That is exactly what an operator has to be able to see.
write_config '	access_control { deny = ["00:11:22:33:44:55"] }'
"$ncfg" reload > /dev/null 2>&1 || true
waited=0
while ! "$ncfg" wifi clients ap0 --json 2>/dev/null | grep -q '"listed": true'; do
	waited=$((waited + 1))
	[ "$waited" -gt 30 ] && break
	sleep 0.1
done
"$ncfg" wifi clients ap0 --json > "$work/denied.json" 2>&1 || true

check "the policy travels with the list" \
	"$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("access_control"))' \
		"$work/denied.json")" "deny"
check "a denied station that is still connected is marked" \
	"$(python3 -c '
import json,sys
station = [s for s in json.load(open(sys.argv[1]))["stations"]
           if s["address"] == "00:11:22:33:44:55"][0]
print(station["listed"])' "$work/denied.json")" "True"
check "and the ones the list does not name are not" \
	"$(python3 -c '
import json,sys
print(sum(1 for s in json.load(open(sys.argv[1]))["stations"] if s["listed"]))' \
		"$work/denied.json")" "1"

# The text output, which is what a person sees. The arrow is the whole point:
# it says the ACL is not in force, rather than showing a deny list and letting
# somebody believe it.
"$ncfg" wifi clients ap0 > "$work/denied.txt" 2>&1 || true
check "the text output names the contradiction" \
	"$(grep -c 'on the deny list and still connected' "$work/denied.txt" || true)" "1"
# What the arrow means changed with decision 0041: netcfgd now converges the
# list over the control socket, so this is a state that lasts until the next
# reconcile rather than one somebody has to restart an access point to clear.
# Saying the old thing would send an operator to deauthenticate every client on
# the radio for something about to fix itself.
check "and says what to do about it" \
	"$(grep -c 'ncfg apply. does it now' "$work/denied.txt" || true)" "1"
check "the station with no statistics shows dashes rather than zeroes" \
	"$(grep -c 'aa:bb:cc:dd:ee:ff .*--' "$work/denied.txt" || true)" "1"

# ------------------------------------------------------------------ the refusals

# An interface with no access point is not a broken hostapd, and saying "no
# control socket" would send somebody looking for one.
"$ncfg" wifi clients lo > "$work/nointerface.txt" 2>&1 || true
check "an interface with no access point says so" \
	"$(grep -c 'runs no access point' "$work/nointerface.txt" || true)" "1"

echo
if [ "$failures" -eq 0 ]; then
	echo "stations.sh: all checks passed"
else
	echo "stations.sh: $failures check(s) failed"
	exit 1
fi
