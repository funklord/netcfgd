#!/bin/sh
# The access point's machine for the two-kernel half of the regdom rig
# (project.md 10.585): DE in its own kernel, so channel 13 is allowed here
# whatever the station's domain is, and hostapd configured as a real access
# point would be -- `country_code` and all, which the one-kernel half could
# not use because it sets the domain for every radio in the kernel.
#
# Always exits 0 and reports through /verdict/ap, as the delegation rig's
# payloads do: a machine whose command fails stops the run, and the station
# would then be reported for a fault that was this machine's.
#
# HOW IT STOPS: it waits for the station's verdict, bounded at 400 seconds,
# then stops hostapd and the relay. The vm goes with it in any case.
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/ap
: > "$out"
say() { echo "$*" >> "$out"; echo "ap: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/ap
mkdir -p "$work"

if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so there is no segment to relay over"
	exit 0
fi
ip link set eth1 up
ip addr add 10.98.0.1/24 dev eth1

# Two radios, the access point on the second: the station's machine uses its
# first, and both machines would otherwise give their radio the same address.
modprobe mac80211_hwsim radios=2
iw reg set DE
waited=0
until iw reg get | grep -q '^country DE'; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && break
	sleep 0.1
done
say "domain: $(iw reg get | awk '/^global/{g=1;next} g&&/^country/{print $2;exit}')"

python3 /payload/relay.py --peer 10.98.0.2 --radios 1 --stats "$work/relay.stats" \
	--lifetime 500 > "$work/relay.log" 2>&1 &
relay=$!

cat > "$work/de13.conf" <<CONF
interface=wlan1
driver=nl80211
ctrl_interface=$work/hostapd
ssid=de13
hw_mode=g
channel=13
country_code=DE
ieee80211d=1
CONF
hostapd "$work/de13.conf" > "$work/hostapd.log" 2>&1 &
hostapd=$!
waited=0
until grep -q 'AP-ENABLED' "$work/hostapd.log" 2>/dev/null; do
	waited=$((waited + 1))
	if [ "$waited" -gt 100 ]; then
		say "VERDICT bad: hostapd never enabled the access point on channel 13"
		sed 's/^/  hostapd: /' "$work/hostapd.log" | tail -5 >> "$out"
		kill "$hostapd" "$relay" 2>/dev/null
		exit 0
	fi
	sleep 0.1
done
say "UP: access point de13 on channel 13, advertising DE"

waited=0
until grep -q '^VERDICT' /verdict/station 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 400 ] && { say "the station never reported; stopping after 400s"; break; }
	sleep 1
done
kill "$hostapd" "$relay" 2>/dev/null
wait "$hostapd" "$relay" 2>/dev/null
sed 's/^/  relay: /' "$work/relay.stats" >> "$out" 2>/dev/null
sed 's/^/  relay log: /' "$work/relay.log" >> "$out" 2>/dev/null
say "VERDICT ok"
exit 0
