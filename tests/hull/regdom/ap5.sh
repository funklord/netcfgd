#!/bin/sh
# The access points' machine for the 5 GHz half of the regdom rig (project.md
# 10.585): US in its own kernel, and four access points on channels that
# behave differently -- 36, which nearly every domain allows; 52, which
# needs radar detection (DFS) and a minute of listening before hostapd may
# transmit; 100, another radar channel, which CN has no band for; and 149,
# which JP has no band for. (The first version expected 149 to be restricted
# in Europe; this regulatory database allows it there, measured 2026-10-27.)
#
# Always exits 0 and reports through /verdict/ap5, as ap.sh does.
#
# HOW IT STOPS: the access points get 180 seconds to come up (52's channel
# availability check is 60 of them), then it waits for the station's verdict,
# bounded at 900 seconds, and stops everything it started.
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/ap5
: > "$out"
say() { echo "$*" >> "$out"; echo "ap5: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/ap5
mkdir -p "$work"

if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so there is no segment to relay over"
	exit 0
fi
ip link set eth1 up
ip addr add 10.97.0.1/24 dev eth1

# Five radios, the access points on 1 to 4: the station's machine uses its
# radio 0, and the two would otherwise share an address.
modprobe mac80211_hwsim radios=5
iw reg set US
waited=0
until iw reg get | grep -q '^country US'; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && break
	sleep 0.1
done
say "domain: $(iw reg get | awk '/^global/{g=1;next} g&&/^country/{print $2;exit}')"

python3 /payload/relay.py --peer 10.97.0.2 --radios 1,2,3,4 --stats "$work/relay.stats" \
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
channel=$channel
country_code=US
ieee80211d=1
ieee80211h=1
CONF
	hostapd "$work/$ssid.conf" > "$work/$ssid.log" 2>&1 &
	pids="$pids $!"
}
start wlan1 us36 36
start wlan2 us52 52
start wlan3 us100 100
start wlan4 us149 149

waited=0
up=0
while [ "$waited" -lt 180 ]; do
	up=0
	for ssid in us36 us52 us100 us149; do
		grep -q 'AP-ENABLED' "$work/$ssid.log" 2>/dev/null && up=$((up + 1))
	done
	[ "$up" -eq 4 ] && break
	waited=$((waited + 1))
	sleep 1
done
# **Its own interface's line, not any.** Every hostapd hears the radar events
# of every radio on the machine, so the first version credited a radar check to
# all three access points, two of them on channels that need none.
for pair in us36:wlan1 us52:wlan2 us100:wlan3 us149:wlan4; do
	ssid=${pair%:*} iface=${pair#*:}
	if grep -q 'AP-ENABLED' "$work/$ssid.log"; then
		cac=$(grep -c "^$iface: DFS-CAC-COMPLETED" "$work/$ssid.log")
		say "  $ssid enabled$( [ "$cac" -gt 0 ] && echo ', after a radar check')"
	else
		say "  $ssid never enabled:"
		tail -4 "$work/$ssid.log" | sed 's/^/    hostapd: /' >> "$out"
	fi
done
if [ "$up" -ne 4 ]; then
	say "VERDICT bad: $up of 4 access points came up in 180s"
	kill $pids 2>/dev/null
	exit 0
fi
say "UP: us36, us52, us100 and us149, advertising US, after ${waited}s"

waited=0
until grep -q '^VERDICT' /verdict/station5 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 900 ] && { say "the station never reported; stopping after 900s"; break; }
	sleep 1
done
kill $pids 2>/dev/null
wait $pids 2>/dev/null
sed 's/^/  relay: /' "$work/relay.stats" >> "$out" 2>/dev/null
say "VERDICT ok"
exit 0
