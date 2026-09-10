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
# The radio's kill switch is read from here. Staged empty to begin with, so the
# observation finds a phy with a clear switch, and rewritten below.
mkdir -p "$work/sys/class/net/wlan0/phy80211" "$work/sys/class/rfkill/rfkill0"
printf 'phy0\n' > "$work/sys/class/net/wlan0/phy80211/name"
printf 'phy0\n' > "$work/sys/class/rfkill/rfkill0/name"
printf '0\n' > "$work/sys/class/rfkill/rfkill0/soft"
printf '0\n' > "$work/sys/class/rfkill/rfkill0/hard"
export NCFG_SYS_ROOT="$work/sys"

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
device wlan0 {
	wifi {
	}
}
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

# Two reply sockets planted before the daemon starts, so its startup sweep has
# something to find and something to leave. netcfgd installs no SIGTERM handler,
# so `Drop` never runs and every restart leaves two of these behind for ever --
# measured on the reporting machine as 18 entries growing to 20 across one
# ordinary `systemctl restart`. The unit test covers the rule; this covers the
# wiring, which is the half a unit test cannot see.
python3 - "$work/ctrl" <<'PLANT'
import socket, sys, os
for name in ("netcfgd-0-9", "netcfgd-1-9"):
	sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
	sock.bind(os.path.join(sys.argv[1], name))
PLANT

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

# Pid 0 never appears in /proc, so that socket's owner is gone. Pid 1 is alive on
# any machine this runs on, and its socket is not the reaper's to take -- which is
# the assertion that matters, a sweep that removes everything being far worse than
# one that removes nothing.
check "a reply socket from a dead process is swept at startup" \
	"$([ -e "$work/ctrl/netcfgd-0-9" ] && echo present || echo gone)" gone
check "and one from a living process is left where it is" \
	"$([ -e "$work/ctrl/netcfgd-1-9" ] && echo present || echo gone)" present
check "and the interface socket is not confused with either" \
	"$([ -S "$work/ctrl/wlan0" ] && echo present || echo gone)" present

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

# --------------------------------------------------------------- the scan half
#
# `SCAN` queues a scan and `SCAN_RESULTS` reads the cache the last one filled,
# so a client that sends one and reads the other answers with the scan *before*
# the one it asked for. Measured on the reporting machine before this was
# fixed: `ncfg wifi scan` returned in 7ms -- four orders of magnitude short of
# a real scan -- and three consecutive calls gave 15, then 20, then 20 access
# points, the first list being five networks out of date.
#
# The fake has no radio, so what is checked here is not the timing but the
# protocol: that netcfgd waits to be told the scan finished, and that it says
# so when it was not told.

scan=$("$repo/target/debug/ncfg" wifi scan wlan0 2>&1 || true)
check "an ordinary scan does not call its results stale" \
	"$(printf '%s\n' "$scan" | grep -c "previous scan" || true)" 0
# The control from the other side: the scan really did return something, so
# the check above is not passing on an empty answer.
check "and it returned what the fake radio can see" \
	"$(printf '%s\n' "$scan" | grep -c 'HomeFiber' || true)" 1

# -16 is EBUSY, which is what a radio doing something else answers, and one of
# the two this machine's journal actually shows.
send 'FAIL_NEXT_SCAN -16'
sleep 1
scan=$("$repo/target/debug/ncfg" wifi scan wlan0 2>&1 || true)
check "a scan the radio refused says the results are the previous ones" \
	"$(printf '%s\n' "$scan" | grep -c "previous scan" || true)" 1
check "and passes the driver's own return code through" \
	"$(printf '%s\n' "$scan" | grep -c 'ret=-16' || true)" 1
# Still a list, not an error: stale results are worth more than nothing, so
# long as they are labelled.
check "and still lists what the last scan found" \
	"$(printf '%s\n' "$scan" | grep -c 'HomeFiber' || true)" 1

# And the failure reaches the log through the event watcher, which 0192 built
# and which did not read this event.
check "the failed scan is in netcfgd's own log too" \
	"$(grep -c 'could not scan (ret=-16)' "$work/daemon.log" || true)" 1

# The mode is one scan deep, so the next one is fresh again -- the assertion
# that netcfgd is reading the event rather than latching on a first failure.
scan=$("$repo/target/debug/ncfg" wifi scan wlan0 2>&1 || true)
check "and the scan after it is fresh again" \
	"$(printf '%s\n' "$scan" | grep -c "previous scan" || true)" 0

# **A scan lets go of the event stream when it is done.** Attaching registers
# this connection inside wpa_supplicant, and removing the socket underneath it
# unregisters nothing -- the supplicant finds out on the next event it fails to
# deliver, logging "Detach monitor that cannot receive messages". Harmless
# once, and a scan now attaches every time, so those accumulate: the reporting
# machine's journal carries them at serials 482 and 516 of one daemon's life.
#
# The fake records every command it is sent, so the count is readable directly.
# One ATTACH belongs to the roam watcher and is held for the daemon's life;
# the scans are the rest, and each must be paired.
scans=$(grep -c '^SCAN$' "$work/fake.log" || true)
attaches=$(grep -c '^ATTACH$' "$work/fake.log" || true)
detaches=$(grep -c '^DETACH$' "$work/fake.log" || true)
check "every scan's ATTACH is matched by a DETACH" \
	"$((attaches - detaches))" 1

# -------------------------------------------------------- the switch, and it
#
# **A blocked radio looks exactly like a network that will not associate.** The
# planner has said so since 0062 and warns about it -- but a plan is not what
# anybody reaches for when the wifi is simply not working. `ncfg wifi status`
# and `ncfg wifi scan` are, and neither of them looked at the switch: status
# reported SCANNING and the scan reported no access points in range, which is
# the same output a laptop gives in a field.
#
# Staged through NCFG_SYS_ROOT rather than by blocking the real radio, which
# would take the network off the machine running the test.
sysroot=$work/sys
mkdir -p "$sysroot/class/net/wlan0/phy80211" "$sysroot/class/rfkill/rfkill0"
printf 'phy0\n' > "$sysroot/class/net/wlan0/phy80211/name"
printf 'phy0\n' > "$sysroot/class/rfkill/rfkill0/name"
printf '0\n' > "$sysroot/class/rfkill/rfkill0/soft"
printf '0\n' > "$sysroot/class/rfkill/rfkill0/hard"

# The control first: with the switch clear, nothing is said about it. Without
# this the checks below pass on a daemon that prints the line unconditionally.
check "an unblocked radio says nothing about a switch" \
	"$("$repo/target/debug/ncfg" wifi status wlan0 2>&1 | grep -c 'switched off' || true)" 0

# Soft: the one a command can clear, and the message has to say which command.
printf '1\n' > "$sysroot/class/rfkill/rfkill0/soft"
"$repo/target/debug/ncfg" reload >/dev/null 2>&1 || true
# **Seven seconds, because the switch is read by the reconcile loop.** A
# `/sys` file changing produces no netlink event and no rfkill record here --
# the real thing would emit one, and this fake cannot -- so what picks it up is
# the loop's five-second backstop. Two seconds passed the soft case by luck of
# where in that cycle it landed, and failed the hard one.
sleep 7
status=$("$repo/target/debug/ncfg" wifi status wlan0 2>&1 || true)
check "a soft-blocked radio says so in status" \
	"$(printf '%s\n' "$status" | grep -c 'switched off at phy0' || true)" 1
check "and names the command that clears it" \
	"$(printf '%s\n' "$status" | grep -c 'rfkill unblock wifi' || true)" 1

scan=$("$repo/target/debug/ncfg" wifi scan wlan0 2>&1 || true)
check "and a scan says it too, rather than 'no access points'" \
	"$(printf '%s\n' "$scan" | grep -c 'switched off at phy0' || true)" 1

# Hard: telling somebody to run a command that cannot work wastes their evening.
printf '0\n' > "$sysroot/class/rfkill/rfkill0/soft"
printf '1\n' > "$sysroot/class/rfkill/rfkill0/hard"
"$repo/target/debug/ncfg" reload >/dev/null 2>&1 || true
# **Seven seconds, because the switch is read by the reconcile loop.** A
# `/sys` file changing produces no netlink event and no rfkill record here --
# the real thing would emit one, and this fake cannot -- so what picks it up is
# the loop's five-second backstop. Two seconds passed the soft case by luck of
# where in that cycle it landed, and failed the hard one.
sleep 7
status=$("$repo/target/debug/ncfg" wifi status wlan0 2>&1 || true)
check "a hard-blocked radio is not offered a software remedy" \
	"$(printf '%s\n' "$status" | grep -c 'rfkill unblock wifi' || true)" 0
check "and is told it is the button on the machine" \
	"$(printf '%s\n' "$status" | grep -c 'button' || true)" 1

# Back to clear, so the checks after this see an ordinary radio.
printf '0\n' > "$sysroot/class/rfkill/rfkill0/hard"
"$repo/target/debug/ncfg" reload >/dev/null 2>&1 || true
sleep 2

# ------------------------------------------------------------- joining, or not
#
# `SELECT_NETWORK` answering OK means the supplicant took the command.
# Association, the key exchange and any EAP handshake happen after it, and
# every way they fail is an event. netcfgd used to return success on the
# acknowledgement, and `ncfg wifi connect` printed "joining; `ncfg wifi status`
# says whether it worked" -- the program admitting it did not know the answer
# to what it had just been asked. On the network that started this work, that
# answer was forty-five consecutive authentication failures.

# The network has to exist in the document: `wifi connect` joins what the
# configuration already describes, which is the boundary 0124 draws.
mkdir -p "$work/etc/conf.d" "$work/etc/secrets"
printf 'hunter2hunter2' > "$work/etc/secrets/home"
chmod 600 "$work/etc/secrets/home"
cat > "$work/etc/conf.d/net.conf" <<'CONF'
network "HomeFiber" {
	wifi {
		psk = "@secret:home"
	}
}
CONF
"$repo/target/debug/ncfg" reload >/dev/null 2>&1 || true
sleep 1

join=$("$repo/target/debug/ncfg" wifi connect HomeFiber 2>&1 || true)
check "a join that works says so, in the past tense" \
	"$(printf '%s\n' "$join" | grep -c 'joined' || true)" 1
check "and does not say it is still trying" \
	"$(printf '%s\n' "$join" | grep -c 'joining' || true)" 0

# The failure that started all of this: the supplicant gives up, and says why.
send 'FAIL_NEXT_JOIN CONN_FAILED'
sleep 1
join=$("$repo/target/debug/ncfg" wifi connect HomeFiber 2>&1 || true)
check "a join that fails is reported as a failure" \
	"$(printf '%s\n' "$join" | grep -c 'did not join' || true)" 1
check "and carries the supplicant's own reason" \
	"$(printf '%s\n' "$join" | grep -c 'CONN_FAILED' || true)" 1
# Nothing is invented: the count comes from the event, not from netcfgd.
check "and the count of attempts the supplicant reported" \
	"$(printf '%s\n' "$join" | grep -c '1 failed attempt' || true)" 1

# ------------------------------------------- and it does not stall the daemon
#
# Making the scan wait is only correct if the waiting happens somewhere the
# rest of netcfgd is not. 0111 is the record of what a blocking wait costs
# here: a wedged PING on an unrelated interface held the reconcile loop for
# 12.2 seconds, and the fix was to stop waiting rather than to wait better.
# So a scan is answered on its own thread, and this is the check that says so.
#
# The fake takes the next SCAN and never announces a result, so the scan below
# lasts its full ten seconds. While it is out, an unrelated request has to come
# back promptly -- promptly meaning "not queued behind ten seconds", which is
# what a two-second bound tests without being flaky on a loaded machine.
send 'SILENT_NEXT_SCAN'
sleep 1
"$repo/target/debug/ncfg" wifi scan wlan0 > "$work/slow_scan" 2>&1 &
slow=$!
sleep 1

started=$(date +%s)
"$repo/target/debug/ncfg" wifi status wlan0 > /dev/null 2>&1 || true
waited=$(( $(date +%s) - started ))
check "another request is answered while a scan is still waiting" \
	"$([ "$waited" -lt 2 ] && echo prompt || echo "blocked for ${waited}s")" prompt

# And the scan itself finishes, saying what happened rather than hanging for
# ever or returning an unlabelled list.
wait "$slow" 2>/dev/null || true
check "and the silent scan gives up and says the results are stale" \
	"$(grep -c 'previous scan' "$work/slow_scan" || true)" 1
check "and says it was the deadline rather than a refusal" \
	"$(grep -c 'did not finish within 10s' "$work/slow_scan" || true)" 1

if [ "$failures" -eq 0 ]; then
	echo "wifi_trouble.sh: all checks passed"
else
	echo "wifi_trouble.sh: $failures check(s) failed"
	exit 1
fi
