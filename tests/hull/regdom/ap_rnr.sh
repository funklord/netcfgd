#!/bin/sh
# The access points' machine for the RNR half of the regdom rig (project.md
# 10.585). How a real machine usually finds a 6 GHz network: a 2.4 or 5 GHz
# access point names its co-located 6 GHz neighbour in a Reduced Neighbour
# Report element in its beacons. Here: CA in its own kernel, one hostapd
# process running two BSSes both called `home` -- 5 GHz channel 36 with
# `rnr=1`, and 6 GHz at 5975 MHz -- both WPA3, since 6 GHz admits nothing
# else. The 5 GHz one is plain 802.11a and the 6 GHz one 802.11ax, so a
# supplicant estimating throughput prefers 6 GHz whenever it can see it.
#
# **One process, because hostapd builds the report only from BSSes it runs
# itself.** Two processes would beacon a report naming nobody.
#
# Always exits 0 and reports through /verdict/ap_rnr, as ap.sh does.
#
# HOW IT STOPS: the access points get 60 seconds to come up, then it waits for
# the station's verdict, bounded at 900 seconds, and stops what it started.
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/ap_rnr
: > "$out"
say() { echo "$*" >> "$out"; echo "ap_rnr: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/ap_rnr
mkdir -p "$work"

if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so there is no segment to relay over"
	exit 0
fi
ip link set eth1 up
ip addr add 10.95.0.1/24 dev eth1

# Three radios, the access points on 1 and 2; the station's machine uses 0.
modprobe mac80211_hwsim radios=3
iw reg set CA
waited=0
until iw reg get | grep -q '^country CA'; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && break
	sleep 0.1
done
say "domain: $(iw reg get | awk '/^global/{g=1;next} g&&/^country/{print $2;exit}')"

python3 /payload/relay.py --peer 10.95.0.2 --radios 1,2 --stats "$work/relay.stats" \
	--lifetime 1200 > "$work/relay.log" 2>&1 &
pids=$!

common="driver=nl80211
ssid=home
country_code=CA
ieee80211d=1
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=1
sae_password=regdom-rig"
cat > "$work/home5.conf" <<CONF
interface=wlan1
ctrl_interface=$work/hostapd
$common
hw_mode=a
channel=36
rnr=1
CONF
cat > "$work/home6.conf" <<CONF
interface=wlan2
ctrl_interface=$work/hostapd
$common
hw_mode=a
op_class=131
channel=5
ieee80211ax=1
he_oper_chwidth=0
CONF
hostapd "$work/home5.conf" "$work/home6.conf" > "$work/hostapd.log" 2>&1 &
pids="$pids $!"

waited=0
until [ "$(grep -c 'AP-ENABLED' "$work/hostapd.log" 2>/dev/null)" -ge 2 ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		say "VERDICT bad: both BSSes did not come up in 60s"
		grep -iE 'enabled|disabled|unable|not allowed|invalid' "$work/hostapd.log" |
			tail -8 | sed 's/^/  hostapd: /' >> "$out"
		kill $pids 2>/dev/null
		exit 0
	fi
	sleep 1
done
# **The report is rebuilt once both are up.** The first runs' 5 GHz beacon
# carried no element 201 at all: both BSSes start together, and the 5 GHz
# beacon is built before its 6 GHz neighbour exists. `update_beacon` asks for it
# again, and the station checks the element is there before anything counts.
sleep 1
hostapd_cli -p "$work/hostapd" -i wlan1 update_beacon > "$work/update.log" 2>&1
say "asked hostapd to rebuild the 5 GHz beacon: $(tr '\n' ' ' < "$work/update.log")"
say "UP: home on 5180 MHz (with rnr=1) and on 5975 MHz, advertising CA, after ${waited}s"

waited=0
until grep -q '^VERDICT' /verdict/station_rnr 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 900 ] && { say "the station never reported; stopping after 900s"; break; }
	sleep 1
done
kill $pids 2>/dev/null
wait $pids 2>/dev/null
sed 's/^/  relay: /' "$work/relay.stats" >> "$out" 2>/dev/null
say "VERDICT ok"
exit 0
