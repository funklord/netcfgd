#!/bin/sh
# The access points' machine for the roam half of the regdom rig (project.md
# 10.585). Four open access points, all on 2.4 GHz channel 1 so a station can
# scan for the next one without leaving the channel it is on -- which the RNR
# half found this rig cannot do across bands. Two networks:
#
#   same    wlan1 and wlan2, both advertising DE
#   cross   wlan3 advertising DE and wlan4 advertising US: one network
#           spanning a border, where a roam could carry the wrong country
#
# Each country is put in the beacon as raw bytes through `vendor_elements`,
# with `country_code` unset, as the one-kernel half does: that is what lets one
# kernel advertise two countries, and it leaves this machine's own domain
# alone.
#
# Always exits 0 and reports through /verdict/ap_roam, as ap.sh does.
#
# HOW IT STOPS: the access points get 60 seconds to come up, then it waits for
# the station's verdict, bounded at 900 seconds, and stops what it started.
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/ap_roam
: > "$out"
say() { echo "$*" >> "$out"; echo "ap_roam: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/ap_roam
mkdir -p "$work"

if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so there is no segment to relay over"
	exit 0
fi
ip link set eth1 up
ip addr add 10.94.0.1/24 dev eth1

# Five radios, the access points on 1 to 4; the station's machine uses 0.
modprobe mac80211_hwsim radios=5
say "domain: $(iw reg get | awk '/^global/{g=1;next} g&&/^country/{print $2;exit}')"

python3 /payload/relay.py --peer 10.94.0.2 --radios 1,2,3,4 --stats "$work/relay.stats" \
	--lifetime 1200 > "$work/relay.log" 2>&1 &
pids=$!

# The Country element for a two-letter code: id 7, length 6, the code, a
# space (any environment), and one triplet, channels 1 to 13 at 20 dBm.
country_element() {
	printf '0706%02x%02x20010d14' "'$(printf %.1s "$1")" "'$(printf %s "$1" | cut -c2)"
}

start() {
	iface=$1 ssid=$2 code=$3
	cat > "$work/$iface.conf" <<CONF
interface=$iface
driver=nl80211
ctrl_interface=$work/hostapd-$iface
ssid=$ssid
hw_mode=g
channel=1
vendor_elements=$(country_element "$code")
CONF
	hostapd "$work/$iface.conf" > "$work/$iface.log" 2>&1 &
	pids="$pids $!"
}
start wlan1 same DE
start wlan2 same DE
start wlan3 cross DE
start wlan4 cross US

waited=0
up=0
while [ "$waited" -lt 60 ]; do
	up=0
	for iface in wlan1 wlan2 wlan3 wlan4; do
		grep -q 'AP-ENABLED' "$work/$iface.log" 2>/dev/null && up=$((up + 1))
	done
	[ "$up" -eq 4 ] && break
	waited=$((waited + 1))
	sleep 1
done
if [ "$up" -ne 4 ]; then
	say "VERDICT bad: $up of 4 access points came up in 60s"
	for iface in wlan1 wlan2 wlan3 wlan4; do
		tail -3 "$work/$iface.log" | sed "s/^/  $iface: /" >> "$out"
	done
	kill $pids 2>/dev/null
	exit 0
fi
say "domain still: $(iw reg get | awk '/^global/{g=1;next} g&&/^country/{print $2;exit}')"
say "UP: same (DE, DE) and cross (DE, US) on channel 1, after ${waited}s"

waited=0
until grep -q '^VERDICT' /verdict/station_roam 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 900 ] && { say "the station never reported; stopping after 900s"; break; }
	sleep 1
done
kill $pids 2>/dev/null
wait $pids 2>/dev/null
sed 's/^/  relay: /' "$work/relay.stats" >> "$out" 2>/dev/null
say "VERDICT ok"
exit 0
