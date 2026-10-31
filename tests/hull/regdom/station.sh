#!/bin/sh
# The station's machine for the two-kernel half of the regdom rig (project.md
# 10.585): an access point on channel 13 in another kernel, reached through
# `relay.py`, and this kernel's domain set to one that forbids channel 13 or
# allows it only passively. What it measures is the case one kernel could not
# hold: can a station in the wrong domain find, and join, the access point
# that would tell it where it is?
#
# The control comes first and is the same access point with this kernel in
# DE. If that does not join, the relay or the medium is at fault and nothing
# after it is a reading, so it is the one thing this payload asserts.
#
# Always exits 0 and reports through /verdict/station; see ap.sh.
#
# HOW IT STOPS: every wait is bounded (the access point's start by hull's `ready` at 2m,
# each scan and association at about ten), the cases are a fixed list, and
# the relay has a lifetime of its own.
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/station
: > "$out"
say() { echo "$*" >> "$out"; echo "station: $*"; }
row() { line=$(printf '%-46s %s' "$1" "$2"); say "  $line"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/station
mkdir -p "$work"

if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so there is no segment to relay over"
	exit 0
fi
ip link set eth1 up
ip addr add 10.98.0.2/24 dev eth1

# **Started only once the access point is up**: `(after ap)` in wire.conf,
# whose `(ready ...)` is the `UP` line in /verdict/ap -- hull's start order,
# in place of a loop here polling for it. An access point that fails or never
# comes up stops the run there, its verdict saying why.

country() {
	iw reg get 2>/dev/null | awk '/^global/ { g = 1; next }
		g && /^country/ { sub(":", "", $2); print $2; exit }'
}

observe() {
	limit=$1 from=$2 tenths=0
	while [ "$tenths" -lt $((limit * 10)) ]; do
		now=$(country)
		if [ "$now" != "$from" ]; then
			echo "$now after $((tenths / 10)).$((tenths % 10))s"
			return
		fi
		sleep 0.1
		tenths=$((tenths + 1))
	done
	echo "$(country), unchanged over ${limit}s"
}

# One channel's flag: ok, noIR, off or absent. `iw` prints "(disabled)".
ch13() {
	iw phy "$(cat /sys/class/net/wlan0/phy80211/name)" channels 2>/dev/null | awk '
		$1 == "*" { inside = ($2 == 2472); if (inside) seen = 1 }
		inside && tolower($0) ~ /disabled/ { off = 1 }
		inside && /No IR/ { noir = 1 }
		END { if (!seen) print "absent"; else if (off) print "off";
		      else if (noir) print "noIR"; else print "ok" }'
}

relay=
fresh() {
	[ -n "$relay" ] && { kill "$relay" 2>/dev/null; wait "$relay" 2>/dev/null; }
	modprobe -r mac80211_hwsim 2>/dev/null
	modprobe -r mac80211 2>/dev/null
	modprobe -r cfg80211 2>/dev/null
	modprobe cfg80211 && modprobe mac80211_hwsim radios=1
	tenths=0
	while { [ ! -e /sys/class/net/wlan0 ] || [ -z "$(country)" ]; } && [ "$tenths" -lt 50 ]; do
		sleep 0.1
		tenths=$((tenths + 1))
	done
	# A registration belongs to the module instance, so a reload needs a new
	# relay; and the stats are per case, so a reading is never last case's.
	rm -f "$work/relay.stats"
	python3 /payload/relay.py --peer 10.98.0.1 --radios 0 --stats "$work/relay.stats" \
		--lifetime 200 >> "$work/relay.log" 2>&1 &
	relay=$!
	ip link set wlan0 up
	sleep 1
}

heard() {
	tries=0
	while [ "$tries" -lt 8 ]; do
		said=$(iw dev wlan0 scan 2>/dev/null | awk '
			/^BSS / { ssid = ""; code = "" }
			/^\tSSID: / { ssid = $2 }
			/^\tCountry: / { code = $2 }
			ssid == "de13" && code != "" { print code; exit }')
		[ -n "$said" ] && { echo "$said"; return 0; }
		tries=$((tries + 1))
		sleep 0.5
	done
	return 1
}

connect() {
	iw dev wlan0 connect de13 2>/dev/null
	waited=0
	while ! iw dev wlan0 link 2>/dev/null | grep -q '^Connected'; do
		waited=$((waited + 1))
		[ "$waited" -gt 100 ] && return 1
		sleep 0.1
	done
	return 0
}

stat_of() { awk -v k="$1" '$1 == k { print $2 }' "$work/relay.stats" 2>/dev/null; }

# One case: this kernel's domain set by hand to $2 ("-" for none at all), then
# what the station can do about an access point on channel 13.
case_run() {
	label=$1 domain=$2
	fresh
	if [ "$domain" != - ]; then
		iw reg set "$domain"
		observe 5 00 >/dev/null
	fi
	start=$(country)
	row "$label: domain $start, channel 13" "$(ch13)"
	code=$(heard) || code=
	row "  hears de13 advertising" "${code:-nothing}"
	row "  channel 13 after the scan" "$(ch13)"
	if connect; then
		joined=yes
		row "  joins de13; the domain" "$(observe 10 "$start")"
		row "  channel 13 now" "$(ch13)"
	else
		joined=no
		row "  joins de13" "no; the domain stays $(country)"
	fi
	sleep 1
	row "  relay: frames out / in / refused" \
	    "$(stat_of sent) / $(stat_of received) / $(stat_of refused)"
}

say "kernel $(uname -r); the access point's machine says: $(grep '^domain' /verdict/ap)"

case_run "CONTROL, DE set by hand" DE
control=$joined
transmitters=$(awk '$1 == "transmitters" { $1 = ""; print }' "$work/relay.stats" 2>/dev/null)
unexpected=$(stat_of unexpected)
row "  transmitters the relay saw" "${transmitters:- none}"
case_run "W1, nothing set (the world domain)" -
case_run "W2, US set by hand" US

if [ "$control" != yes ]; then
	say "VERDICT bad: the control did not join, so the relay or the medium is at fault"
elif [ "${unexpected:--}" != - ]; then
	say "VERDICT bad: the relay saw transmitters it does not deliver to: $unexpected"
else
	say "VERDICT ok"
fi
exit 0
