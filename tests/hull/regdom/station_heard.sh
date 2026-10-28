#!/bin/sh
# netcfgd's station for the regdom rig: does a running daemon say who set the
# wireless regulatory domain (decision 0296)?
#
# The kernel's half of this rig measured that a station in the world domain
# adopts its access point's country on joining, and reverts when it leaves.
# Those two look exactly like a country set by hand unless something heard
# the REG_CHANGE that made them, and only a process subscribed at the time
# can. So this runs the daemon built on the host, makes the domain move three
# ways, and asks `ncfg status` -- which observes for itself and takes the
# setter from the daemon -- each time:
#
#   before anything moves  00, nobody named: set before the daemon started
#   joins de13             DE, access_point
#   leaves it              00, kernel
#   iw reg set SE          SE, user
#
# The first is the control. A daemon that named a setter for a change it did
# not hear would be inventing one, and it is the case a guess would get wrong.
#
# Always exits 0 and reports through /verdict/station_heard; see ap.sh.
#
# HOW IT STOPS: every wait is bounded (the access point at 120 s, each change
# at 15 s), the steps are a fixed list, the relay has a lifetime of its own,
# and the daemon is killed before the verdict is written.
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/station_heard
: > "$out"
say() { echo "$*" >> "$out"; echo "station_heard: $*"; }
row() { line=$(printf '%-46s %s' "$1" "$2"); say "  $line"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/heard
mkdir -p "$work/etc" "$work/run"

build=/repo/c
for program in netcfgd ncfg; do
	if [ ! -x "$build/$program" ]; then
		say "VERDICT bad: $build/$program is not built on the host"
		exit 0
	fi
done
if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so there is no segment to relay over"
	exit 0
fi
ip link set eth1 up
ip addr add 10.98.0.2/24 dev eth1

waited=0
until grep -q '^UP' /verdict/ap_heard 2>/dev/null; do
	if grep -q '^VERDICT bad' /verdict/ap_heard 2>/dev/null; then
		say "VERDICT bad: the access point's machine failed, so nothing here is a reading"
		exit 0
	fi
	waited=$((waited + 1))
	[ "$waited" -gt 120 ] && { say "VERDICT bad: the access point never came up"; exit 0; }
	sleep 1
done

modprobe cfg80211 && modprobe mac80211_hwsim radios=1
tenths=0
while [ ! -e /sys/class/net/wlan0 ] && [ "$tenths" -lt 50 ]; do
	sleep 0.1
	tenths=$((tenths + 1))
done
python3 /payload/relay.py --peer 10.98.0.1 --radios 0 --stats "$work/relay.stats" \
	--lifetime 300 > "$work/relay.log" 2>&1 &
relay=$!
ip link set wlan0 up

# An empty configuration: netcfgd manages nothing here, and the observation
# is all this asks of it.
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
"$build/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ] && [ "$waited" -lt 100 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
if [ ! -e "$work/run/netcfgd.sock" ]; then
	say "VERDICT bad: the daemon never started"
	sed 's/^/  daemon: /' "$work/daemon.log" >> "$out"
	kill "$relay" 2>/dev/null
	exit 0
fi

# "<domain> <setter>" from the daemon, `-` for a member it left out.
heard() {
	"$build/ncfg" status --json > "$work/status.json" 2> "$work/status.err" || {
		echo "error $(head -1 "$work/status.err")"
		return
	}
	domain=$(sed -n 's/^  "regdom": "\(..\)",*$/\1/p' "$work/status.json")
	setter=$(sed -n 's/^  "regdom_set_by": "\([a-z_]*\)",*$/\1/p' "$work/status.json")
	echo "${domain:--} ${setter:--}"
}

# Wait for the daemon to say $1, bounded at fifteen seconds: the daemon
# re-observes on the notification's wake, but a client asks between passes.
expect() {
	tenths=0
	while [ "$tenths" -lt 150 ]; do
		now=$(heard)
		[ "$now" = "$1" ] && { echo "$now after $((tenths / 10)).$((tenths % 10))s"; return 0; }
		sleep 0.1
		tenths=$((tenths + 1))
	done
	echo "$now, not $1, after 15s"
	return 1
}

failed=0
step() {
	if result=$(expect "$2"); then
		row "$1" "$result"
	else
		row "$1" "$result"
		failed=$((failed + 1))
	fi
}

say "kernel $(uname -r)"
step "CONTROL, before anything moves" "00 -"

# The scan first, as the kernel half found: in the world domain channel 13 is
# listen-only until a beacon is heard on it.
tries=0
until iw dev wlan0 scan 2>/dev/null | grep -q 'SSID: de13'; do
	tries=$((tries + 1))
	[ "$tries" -gt 8 ] && break
	sleep 0.5
done
iw dev wlan0 connect de13 2>/dev/null
step "joins de13" "DE access_point"
say "  ncfg status says: $("$build/ncfg" status 2>/dev/null | grep '^wireless regulatory domain')"

iw dev wlan0 disconnect 2>/dev/null
step "leaves de13" "00 kernel"

iw reg set SE
step "iw reg set SE" "SE user"

kill "$daemon" 2>/dev/null
wait "$daemon" 2>/dev/null
kill "$relay" 2>/dev/null
wait "$relay" 2>/dev/null
grep 'regulatory' "$work/daemon.log" | sed 's/^/  daemon: /' >> "$out"
if [ "$failed" -ne 0 ]; then
	sed 's/^/  daemon: /' "$work/daemon.log" | tail -20 >> "$out"
	say "VERDICT bad: $failed of 4 readings were not what the daemon should say"
else
	say "VERDICT ok"
fi
exit 0
