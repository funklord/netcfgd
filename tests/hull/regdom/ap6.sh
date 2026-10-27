#!/bin/sh
# The access points' machine for the 6 GHz half of the regdom rig (project.md
# 10.585): CA in its own kernel, and two 6 GHz access points -- channel 5
# (5975 MHz), inside the band Europe opened, and channel 101 (6455 MHz), above
# it. 6 GHz admits no open network, so both are WPA3 (SAE, hash-to-element,
# protected management frames), which is what hostapd requires there.
#
# **CA and not US, because US cannot run one.** This regulatory database marks
# US 5925-7125 MHz PASSIVE-SCAN, so every 6 GHz channel is NO-IR there and
# hostapd refuses: "Frequency 5975 (primary) not allowed for AP mode". CA, BR
# and SA allow the whole band without it, measured 2026-10-27.
#
# Always exits 0 and reports through /verdict/ap6, as ap.sh does.
#
# HOW IT STOPS: the access points get 60 seconds to come up, then it waits for
# the station's verdict, bounded at 900 seconds, and stops what it started.
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/ap6
: > "$out"
say() { echo "$*" >> "$out"; echo "ap6: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/ap6
mkdir -p "$work"

if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so there is no segment to relay over"
	exit 0
fi
ip link set eth1 up
ip addr add 10.96.0.1/24 dev eth1

# Three radios, the access points on 1 and 2: the station's machine uses its
# radio 0, and the two would otherwise share an address.
modprobe mac80211_hwsim radios=3
iw reg set CA
waited=0
until iw reg get | grep -q '^country CA'; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && break
	sleep 0.1
done
say "domain: $(iw reg get | awk '/^global/{g=1;next} g&&/^country/{print $2;exit}')"

python3 /payload/relay.py --peer 10.96.0.2 --radios 1,2 --stats "$work/relay.stats" \
	--lifetime 1200 > "$work/relay.log" 2>&1 &
pids=$!

start() {
	iface=$1 ssid=$2 channel=$3
	cat > "$work/$ssid.conf" <<CONF
interface=$iface
driver=nl80211
ctrl_interface=$work/hostapd-$ssid
ssid=$ssid
hw_mode=a
op_class=131
channel=$channel
ieee80211ax=1
he_oper_chwidth=0
country_code=CA
ieee80211d=1
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=1
sae_password=regdom-rig
CONF
	hostapd "$work/$ssid.conf" > "$work/$ssid.log" 2>&1 &
	pids="$pids $!"
}
start wlan1 ca5 5
start wlan2 ca101 101

waited=0
up=0
while [ "$waited" -lt 60 ]; do
	up=0
	for ssid in ca5 ca101; do
		grep -q 'AP-ENABLED' "$work/$ssid.log" 2>/dev/null && up=$((up + 1))
	done
	[ "$up" -eq 2 ] && break
	waited=$((waited + 1))
	sleep 1
done
for ssid in ca5 ca101; do
	if grep -q 'AP-ENABLED' "$work/$ssid.log"; then
		say "  $ssid enabled"
	else
		say "  $ssid never enabled:"
		tail -6 "$work/$ssid.log" | sed 's/^/    hostapd: /' >> "$out"
	fi
done
if [ "$up" -ne 2 ]; then
	say "VERDICT bad: $up of 2 access points came up in 60s"
	kill $pids 2>/dev/null
	exit 0
fi
say "UP: ca5 and ca101, advertising CA, after ${waited}s"

waited=0
until grep -q '^VERDICT' /verdict/station6 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 900 ] && { say "the station never reported; stopping after 900s"; break; }
	sleep 1
done
kill $pids 2>/dev/null
wait $pids 2>/dev/null
sed 's/^/  relay: /' "$work/relay.stats" >> "$out" 2>/dev/null
say "VERDICT ok"
exit 0
