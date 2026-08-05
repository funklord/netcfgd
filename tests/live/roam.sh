#!/bin/sh
# The `roam` hook: a station moving to a different access point runs a script.
#
# Needs a running netcfgd, like drift.sh and for the same kind of reason: this
# is not a plan action. A roam is `wpa_supplicant`'s decision -- it picks the
# loudest access point on the network it is already on -- and netcfgd hears
# about it afterwards, on the supplicant's event socket. Nothing is planned and
# nothing is applied, so `ncfg apply` cannot exercise it.
#
# The supplicant is faked, for the reason `fake_supplicant.py` exists: the one
# thing this repository cannot produce on demand is a radio, and a roam needs
# two access points to move between. What is *not* faked is the protocol -- the
# event is `wpa_supplicant`'s own format string, read out of the binary -- nor
# the requirement to send `ATTACH`, which the fake honours by sending events
# only to connections that asked. A netcfgd that forgot to attach sees nothing
# here, exactly as it would against the real thing.
#
# Runs under `unshare -rn`: it creates a dummy interface.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "roam.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "roam.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

work=$(mktemp -d /tmp/ncfg-roam.XXXXXX)
daemon=
fake=
cleanup() {
	for pid in $daemon $fake; do
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
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

# `wlan0` is a dummy: netcfgd only needs the interface to exist for the hook to
# be attached to it, and the association is the supplicant's business.
ip link add wlan0 type dummy 2>/dev/null || skip "cannot make a dummy interface"

cat > "$work/etc/netcfgd.conf" <<CONF
interface wlan0 {
	on roam {
	echo "roam iface=\$NCFG_IFACE bssid=\$NCFG_BSSID reason=\$NCFG_REASON" >> $log
	}
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

# The watcher has to have found the socket and attached before an event can
# reach it. It scans the directory each pass, so this is a bounded wait on a
# line in the fake's own log rather than a guess.
waited=0
while ! grep -q '^ATTACH' "$work/fake.log" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 60 ] && break
	sleep 0.1
done
# Exactly one, and that is the assertion rather than "at least one": a watcher
# whose ATTACH is refused reconnects on every pass, and this counted 1 while
# that was happening simply because it looked early enough. The fake answered
# FAIL to ATTACH until this test existed, which is how that was found.
check "netcfgd attaches to the supplicant's event socket, once" \
	"$(grep -c '^ATTACH' "$work/fake.log" || true)" 1

runs() {
	grep -c '^roam ' "$log" 2>/dev/null || true
}

# Send one event to the fake supplicant, having first established that there is
# a fake supplicant to send it to.
#
# The bare sends this replaces raised FileNotFoundError when the socket was not
# there and took the whole run with it -- a traceback naming "<stdin>" line 5,
# which says nothing about which of the two preconditions failed. That happened
# once inside a full `make live` in a container and has not reproduced in twelve
# runs here, so what is fixed is the report and not the cause: the next
# occurrence says whether the socket went away or the fake did.
send_event() {
	if ! kill -0 "$fake" 2>/dev/null; then
		echo "FAIL the fake supplicant was alive to be sent: $1"
		echo "       pid $fake is gone; it last said:"
		tail -3 "$work/fake.log" 2>/dev/null | sed 's/^/       /' || true
		failures=$((failures + 1))
		return 1
	fi
	if [ ! -S "$work/ctrl/wlan0" ]; then
		echo "FAIL the control socket was there to be sent: $1"
		echo "       $work/ctrl/wlan0 is missing, so nothing could be delivered"
		ls -la "$work/ctrl" 2>/dev/null | sed 's/^/       /' || true
		failures=$((failures + 1))
		return 1
	fi
	python3 - "$work/ctrl/wlan0" "$1" <<'PY'
import socket, sys, os, tempfile
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
local = os.path.join(tempfile.mkdtemp(), "c")
sock.bind(local)
sock.sendto(sys.argv[2].encode(), sys.argv[1])
PY
}

# Ask the fake to emit a CONNECTED. The first one is an association, not a
# roam: there is nothing to have moved from, and firing here would run the hook
# on every boot.
send_event "ROAM aa:bb:cc:dd:ee:ff"
sleep 1
check "the first association is not a roam" "$(runs)" 0

# And now it moves.
send_event "ROAM 11:22:33:44:55:66"
sleep 1

check "moving to another access point runs the hook" "$(runs)" 1
check "and the script is told which interface" \
	"$(grep -c 'iface=wlan0' "$log" || true)" 1
check "and which access point it is on now" \
	"$(grep -c 'bssid=11:22:33:44:55:66' "$log" || true)" 1

# Not de-duplicated the way `drift` is: a roam is a thing that happened, not a
# condition that persists, and a station that moved back moved twice.
send_event "ROAM aa:bb:cc:dd:ee:ff"
sleep 1
check "moving back is a second roam and not a repeat" "$(runs)" 2

# The same access point again is not a move at all.
send_event "ROAM aa:bb:cc:dd:ee:ff"
sleep 1
check "re-associating with the same one is not a roam" "$(runs)" 2

# And the connection was held the whole time rather than remade for each event.
check "and it stayed attached throughout" \
	"$(grep -c '^ATTACH' "$work/fake.log" || true)" 1

# ------------------------------- not everything in the directory is a radio

# A datagram client has to bind an address of its own to be replied to, and it
# binds it here, beside the sockets it talks to. So the control directory holds
# entries that are not interfaces -- netcfgd's own in-flight connections -- and
# the watcher above took every entry as one. Decision 0112.
#
# Two things went wrong and this checks the one that is visible. Connecting to a
# reply socket waits out the whole timeout, because the far end is a live
# process that is not a server: three `PING`s in twenty-five seconds, once per
# timeout, for as long as the entry exists. The other is worse and racy -- the
# `PING` lands in that client's reply queue, where it is not an event, so the
# client can hand it back as the answer to a command it really sent.
#
# Named exactly as `Client::connect` names one, because a filter that does not
# match the real thing is no filter. A pid that is not running is deliberate:
# what makes this socket answer nothing is that nobody is serving it, and that
# is true of a live client too.
cat > "$work/stray.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(sys.argv[1])
print("bound", flush=True)
while True:
	data, _ = s.recvfrom(4096)
	print("received: " + data.decode("utf-8", "replace").strip(), flush=True)
PY
python3 "$work/stray.py" "$work/ctrl/netcfgd-999999-0" > "$work/stray.log" 2>&1 &
stray=$!
waited=0
while ! grep -q bound "$work/stray.log" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && break
	sleep 0.1
done
# The watcher rescans on every pass and sends its `PING` immediately -- it is
# the *reply* it waits for -- so a second is enough to catch it. Measured with
# the filter removed: the first `PING` arrives before this returns.
sleep 2
check "a reply socket in the control directory is not taken for a radio" \
	"$(grep -c '^received:' "$work/stray.log" || true)" 0
kill "$stray" 2>/dev/null || true

if [ "$failures" -eq 0 ]; then
	echo "roam.sh: all checks passed"
else
	echo "roam.sh: $failures check(s) failed"
	exit 1
fi
