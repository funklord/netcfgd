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
	rm -rf "$work"
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

# Ask the fake to emit a CONNECTED. The first one is an association, not a
# roam: there is nothing to have moved from, and firing here would run the hook
# on every boot.
python3 - "$work/ctrl/wlan0" "ROAM aa:bb:cc:dd:ee:ff" <<'PY'
import socket, sys, os, tempfile
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
local = os.path.join(tempfile.mkdtemp(), "c")
sock.bind(local)
sock.sendto(sys.argv[2].encode(), sys.argv[1])
PY
sleep 1
check "the first association is not a roam" "$(runs)" 0

# And now it moves.
python3 - "$work/ctrl/wlan0" "ROAM 11:22:33:44:55:66" <<'PY'
import socket, sys, os, tempfile
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
local = os.path.join(tempfile.mkdtemp(), "c")
sock.bind(local)
sock.sendto(sys.argv[2].encode(), sys.argv[1])
PY
sleep 1

check "moving to another access point runs the hook" "$(runs)" 1
check "and the script is told which interface" \
	"$(grep -c 'iface=wlan0' "$log" || true)" 1
check "and which access point it is on now" \
	"$(grep -c 'bssid=11:22:33:44:55:66' "$log" || true)" 1

# Not de-duplicated the way `drift` is: a roam is a thing that happened, not a
# condition that persists, and a station that moved back moved twice.
python3 - "$work/ctrl/wlan0" "ROAM aa:bb:cc:dd:ee:ff" <<'PY'
import socket, sys, os, tempfile
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
local = os.path.join(tempfile.mkdtemp(), "c")
sock.bind(local)
sock.sendto(sys.argv[2].encode(), sys.argv[1])
PY
sleep 1
check "moving back is a second roam and not a repeat" "$(runs)" 2

# The same access point again is not a move at all.
python3 - "$work/ctrl/wlan0" "ROAM aa:bb:cc:dd:ee:ff" <<'PY'
import socket, sys, os, tempfile
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
local = os.path.join(tempfile.mkdtemp(), "c")
sock.bind(local)
sock.sendto(sys.argv[2].encode(), sys.argv[1])
PY
sleep 1
check "re-associating with the same one is not a roam" "$(runs)" 2

# And the connection was held the whole time rather than remade for each event.
check "and it stayed attached throughout" \
	"$(grep -c '^ATTACH' "$work/fake.log" || true)" 1

if [ "$failures" -eq 0 ]; then
	echo "roam.sh: all checks passed"
else
	echo "roam.sh: $failures check(s) failed"
	exit 1
fi
