#!/bin/sh
# What netcfgd says when the supplicant cannot join.
#
# The audit that produced this found the daemon attached to the supplicant's
# event socket and reading exactly one event out of it: `CONNECTED`, for the
# roam watcher roam.sh drives. Everything else was dropped, which is every
# event that says a link is failing rather than working.
#
# The failure that cost is on this machine's record. `EMP-XYLEM` was configured
# with `ca_cert ""` -- a filename, and the empty one -- so PEAP failed inside
# OpenSSL before an inner method was ever proposed, and the supplicant said so
# forty-five times:
#
#     CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="EMP-XYLEM" auth_failures=45 \
#         duration=60 reason=CONN_FAILED
#
# Every one of those arrived on a socket netcfgd was holding open, and netcfgd's
# log for the morning says nothing about any of them. The operator was told the
# interface had no carrier: true, and useless.
#
# So this drives both halves of the fix. The log half, where the event has to
# become a line somebody can read; and the status half, where `LIST_NETWORKS`
# already carried the flags and nothing had ever read past `[CURRENT]`.
#
# The event texts below are copied out of that journal rather than invented --
# the format is the supplicant's own and a test written from the documentation
# would be testing the documentation. Decision 0192.
#
# Runs under `unshare -rn`: it creates a dummy interface.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "wifi_trouble.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "wifi_trouble.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-wifi-trouble.XXXXXX")
daemon=
fake=
cleanup() {
	for pid in $daemon $fake; do
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run" "$work/ctrl" "$work/runroot"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_WPA_CTRL_DIR="$work/ctrl"
export NCFG_RUN_ROOT="$work/runroot"

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
}
CONF

python3 "$repo/tests/live/fake_supplicant.py" "$work/ctrl" wlan0 > "$work/fake.log" 2>&1 &
fake=$!
waited=0
while ! grep -q ready "$work/fake.log" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && skip "the fake supplicant never started"
	sleep 0.1
done

"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ] && [ "$waited" -lt 50 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
[ -e "$work/run/netcfgd.sock" ] || { cat "$work/daemon.log" >&2; exit 1; }

# Events reach only a connection that asked, so there is nothing to assert
# until the watcher has attached.
waited=0
while ! grep -q '^ATTACH' "$work/fake.log" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 60 ] && break
	sleep 0.1
done
check "netcfgd attached to the event socket" \
	"$(grep -c '^ATTACH' "$work/fake.log" || true)" 1

send() {
	python3 - "$work/ctrl/wlan0" "$1" <<'PY'
import socket, sys, os, tempfile
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
staging = tempfile.mkdtemp()
local = os.path.join(staging, "c")
try:
	sock.bind(local)
	sock.sendto(sys.argv[2].encode(), sys.argv[1])
finally:
	sock.close()
	os.unlink(local)
	os.rmdir(staging)
PY
}

# ------------------------------------------------- the control, asserted first
#
# From both sides, because a test that only looks after the event cannot tell a
# line the event produced from a line that was always going to be there.
check "nothing is said about a network before anything goes wrong" \
	"$(grep -c 'not trying' "$work/daemon.log" || true)" 0
check "and the status names nothing it is not trying" \
	"$("$repo/target/debug/ncfg" wifi status wlan0 2>&1 |
		grep -c 'not being tried' || true)" 0

# ------------------------------------------------------------------ the events

send 'TROUBLE CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="Guest Wifi" auth_failures=45 duration=60 reason=CONN_FAILED'
sleep 1

check "a temporary disable becomes a line in netcfgd's own log" \
	"$(grep -c 'not trying `Guest Wifi`' "$work/daemon.log" || true)" 1
# The count and the reason, which are the whole content: a name alone says the
# network is not working, which the operator knew before they asked.
check "and it carries the failure count" \
	"$(grep -c '45 failed attempts' "$work/daemon.log" || true)" 1
check "and the supplicant's own reason" \
	"$(grep -c 'CONN_FAILED' "$work/daemon.log" || true)" 1
# The name has a space in it on purpose. A whitespace-split reader reports the
# network as `"Guest` and loses everything after it -- including the count --
# and a router that ships with a two-word name is not exotic.
check "and the name was not truncated at the space" \
	"$(grep -c '"Guest' "$work/daemon.log" || true)" 0

send 'TROUBLE CTRL-EVENT-SSID-REENABLED id=0 ssid="Guest Wifi"'
sleep 1
check "and the recovery is said too, not only the failure" \
	"$(grep -c 'trying `Guest Wifi` again' "$work/daemon.log" || true)" 1

# Who ended a disconnect is its whole content. This machine leaving is ordinary
# and there are dozens a day; the access point dropping the station is the one
# worth a line at the default level.
send 'TROUBLE CTRL-EVENT-DISCONNECTED bssid=a0:a4:7f:23:9a:cf reason=3 locally_generated=1'
sleep 1
check "netcfgd leaving an access point is not news" \
	"$(grep -c 'dropped by' "$work/daemon.log" || true)" 0

send 'TROUBLE CTRL-EVENT-DISCONNECTED bssid=a0:a4:7f:23:9a:cf reason=15 locally_generated=0'
sleep 1
check "the access point dropping the station is" \
	"$(grep -c 'dropped by a0:a4:7f:23:9a:cf (reason 15)' "$work/daemon.log" || true)" 1

send 'TROUBLE CTRL-EVENT-AUTH-REJECT f0:9f:c2:7e:bd:7d auth_type=3 auth_transaction=2 status_code=1'
sleep 1
check "a refusal at the 802.11 layer is its own line" \
	"$(grep -c 'refused this station, status 1' "$work/daemon.log" || true)" 1

# And the traffic that is most of the stream by volume stays out of the log.
send 'TROUBLE CTRL-EVENT-DSCP-POLICY clear_all'
sleep 1
check "and everything else is still dropped" \
	"$(grep -c 'DSCP' "$work/daemon.log" || true)" 0

# ------------------------------------------------------------------ the status

send 'DISABLE [TEMP-DISABLED] Guest Wifi'
sleep 1
status=$("$repo/target/debug/ncfg" wifi status wlan0 2>&1 || true)

check "the status names what the supplicant is not trying" \
	"$(printf '%s\n' "$status" | grep -c 'not being tried' || true)" 1
check "with the supplicant's own flag, not a translation of it" \
	"$(printf '%s\n' "$status" | grep -c '\[TEMP-DISABLED\]' || true)" 1
# Said once, where somebody is reading, rather than on each of the log lines
# that got them here: a temporary disable is not a network out of range.
check "and says what a temporary disable actually means" \
	"$(printf '%s\n' "$status" | grep -c 'not a network out of range' || true)" 1

if [ "$failures" -eq 0 ]; then
	echo "wifi_trouble.sh: all checks passed"
else
	echo "wifi_trouble.sh: $failures check(s) failed"
	exit 1
fi
