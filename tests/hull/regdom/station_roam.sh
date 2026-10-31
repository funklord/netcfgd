#!/bin/sh
# The station's machine for the roam half of the regdom rig (project.md
# 10.585). The question: does a roam -- moving between access points of one
# network without disconnecting -- keep the country, and does it take up a
# different one when the next access point advertises it? A disconnect
# returns a machine with no country set to the world domain (E16); a roam is
# the move that is not supposed to.
#
# Each case starts from a fresh kernel with no country set, joins the first
# access point (pinned by BSSID), scans while connected, and roams to the
# second with `wpa_cli roam`, sampling the domain every 50 ms meanwhile so a
# moment spent in the world domain shows even if it does not last. The last
# case makes the cross-border move by disconnecting instead, for contrast.
#
# What has to hold for anything to be a reading: the scan while connected
# lists the second access point, and the roam changes the BSSID. Both are
# checked per case and a case that fails either says "not measured".
#
# Always exits 0 and reports through /verdict/station_roam, as station.sh
# does.
#
# HOW IT STOPS: waits are bounded -- the access points by hull's `ready` at 5m, each join at
# fifteen seconds, each roam at fifteen, the sampler at 200 readings -- over
# three cases; every relay, supplicant and sampler is stopped by the next.
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/station_roam
: > "$out"
say() { echo "$*" >> "$out"; echo "station_roam: $*"; }
row() { line=$(printf '%-44s %s' "$1" "$2"); say "  $line"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/station_roam
mkdir -p "$work"

if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so there is no segment to relay over"
	exit 0
fi
ip link set eth1 up
ip addr add 10.94.0.2/24 dev eth1

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
	echo "$(country), unchanged"
}

relay=
supplicant=
sampler=
stop_case() {
	for p in $sampler $supplicant $relay; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
	sampler=
	supplicant=
	relay=
}
fresh() {
	stop_case
	modprobe -r mac80211_hwsim 2>/dev/null
	modprobe -r mac80211 2>/dev/null
	modprobe -r cfg80211 2>/dev/null
	modprobe cfg80211 && modprobe mac80211_hwsim radios=1
	tenths=0
	while { [ ! -e /sys/class/net/wlan0 ] || [ -z "$(country)" ]; } && [ "$tenths" -lt 50 ]; do
		sleep 0.1
		tenths=$((tenths + 1))
	done
	rm -f "$work/relay.stats"
	python3 /payload/relay.py --peer 10.94.0.1 --radios 0 \
		--stats "$work/relay.stats" --lifetime 150 >> "$work/relay.log" 2>&1 &
	relay=$!
	ip link set wlan0 up
	sleep 1
}

# **Started only once the access point is up**: `(after ap-roam)` in wire_roam.conf,
# whose `(ready ...)` is the `UP` line in /verdict/ap_roam -- hull's start order,
# in place of a loop here polling for it. An access point that fails or never
# comes up stops the run there, its verdict saying why.

wpa() { wpa_cli -p "$work/wpa" -i wlan0 "$@" 2>/dev/null; }
state_of() { wpa status | awk -F= -v k="$1" '$1 == k { print $2 }'; }

# hwsim's address for the access points' machine's radio $1.
ap() { printf '02:00:00:00:%02x:00' "$1"; }

join() {
	ssid=$1 bssid=$2
	mkdir -p "$work/wpa"
	cat > "$work/wpa.conf" <<CONF
ctrl_interface=$work/wpa
network={
	ssid="$ssid"
	key_mgmt=NONE
	bssid=$bssid
}
CONF
	wpa_supplicant -i wlan0 -D nl80211 -c "$work/wpa.conf" >> "$work/wpa.log" 2>&1 &
	supplicant=$!
	waited=0
	until [ "$(state_of wpa_state)" = COMPLETED ] && [ "$(state_of bssid)" = "$bssid" ]; do
		waited=$((waited + 1))
		[ "$waited" -gt 150 ] && return 1
		sleep 0.1
	done
	return 0
}

# The domain every 50 ms into $work/samples, for at most 200 readings.
sample() {
	: > "$work/samples"
	(
		count=0
		while [ "$count" -lt 200 ]; do
			country >> "$work/samples"
			count=$((count + 1))
			sleep 0.05
		done
	) &
	sampler=$!
	# **Readings before the move, or the start of the sequence is a guess.**
	# The first run roamed before the sampler had read anything and reported a
	# cross-border roam as "US", with nothing before it.
	tries=0
	while [ "$(grep -c . "$work/samples")" -lt 2 ] && [ "$tries" -lt 50 ]; do
		tries=$((tries + 1))
		sleep 0.05
	done
}
# What the samples went through, repeats collapsed: "DE", or "DE 00 US".
sequence() {
	awk 'NF && $1 != last { printf "%s%s", (n++ ? " " : ""), $1; last = $1 } END { print "" }' \
		"$work/samples"
}

measured=0
# One roam: network $1, from radio $2 to radio $3.
roam_case() {
	label=$1 ssid=$2 from=$(ap "$3") to=$(ap "$4")
	fresh
	say "$label:"
	if ! join "$ssid" "$from"; then
		row "joins the first access point" "no; not measured"
		return
	fi
	row "joins $from; the domain" "$(observe 10 00)"
	first=$(country)
	# The pin goes, or the supplicant holds to the first BSSID whatever it is
	# told; then a scan from the channel it is on.
	wpa set_network 0 bssid any >/dev/null
	wpa scan >/dev/null
	sleep 4
	if ! wpa scan_results | grep -qi "^$to"; then
		row "a scan while connected lists $to" "no; not measured"
		return
	fi
	row "a scan while connected lists $to" "yes; the domain is $(country)"
	sample
	wpa roam "$to" >/dev/null
	waited=0
	until [ "$(state_of wpa_state)" = COMPLETED ] && [ "$(state_of bssid)" = "$to" ]; do
		waited=$((waited + 1))
		[ "$waited" -gt 150 ] && break
		sleep 0.1
	done
	if [ "$(state_of bssid)" != "$to" ]; then
		row "roams to $to" "no, still on $(state_of bssid); not measured"
		return
	fi
	sleep 3
	kill "$sampler" 2>/dev/null
	wait "$sampler" 2>/dev/null
	sampler=
	went=$(sequence)
	case $went in
	"$first"|"$first "*) ;;
	*) row "roams to $to; the domain went" "$went: the sampler missed the start, not measured"
	   return ;;
	esac
	row "roams to $to; the domain went" "$went"
	row "  and is, 10s on" "$(observe 10 "$(country)")"
	measured=$((measured + 1))
}

say "the access points' machine: $(grep '^domain' /verdict/ap_roam | head -1)"
roam_case "within a country: same, DE to DE" same 1 2
roam_case "across a border: cross, DE to US" cross 3 4

# The same move by disconnecting and joining again, which E16 says passes
# through the world domain; here it is sampled the same way.
fresh
say "across a border by disconnecting: cross, DE then US:"
if join cross "$(ap 3)"; then
	row "joins $(ap 3); the domain" "$(observe 10 00)"
	sample
	wpa disconnect >/dev/null
	sleep 2
	wpa set_network 0 bssid "$(ap 4)" >/dev/null
	wpa reconnect >/dev/null
	waited=0
	until [ "$(state_of wpa_state)" = COMPLETED ] && [ "$(state_of bssid)" = "$(ap 4)" ]; do
		waited=$((waited + 1))
		[ "$waited" -gt 150 ] && break
		sleep 0.1
	done
	sleep 3
	kill "$sampler" 2>/dev/null
	wait "$sampler" 2>/dev/null
	sampler=
	row "rejoins $(ap 4); the domain went" "$(sequence)"
else
	row "joins the first access point" "no; not measured"
fi
stop_case

if [ "$measured" -ne 2 ]; then
	say "VERDICT bad: $measured of 2 roams measured, so the rig did not roam"
	tail -8 "$work/wpa.log" | sed 's/^/  wpa_supplicant: /' >> "$out"
else
	say "VERDICT ok"
fi
exit 0
