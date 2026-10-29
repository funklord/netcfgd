#!/bin/sh
# Advisory steering (project.md 10.595 item 2): a weak station is asked to
# move, is not disconnected, and goes because where it is asked to go is
# better.
#
# netcfgd runs one access point on 2.4 GHz channel 1 with `steering { signal =
# -45 }` and a declared neighbour: a plain hostapd on channel 6 with 802.11n,
# standing in for an access point on another machine. A station joins
# netcfgd's, and both it and that access point drop their transmit power to
# 0 dBm, so each hears the other at -50 dBm -- hwsim's floor, since it
# reports power minus 50 and `iw` takes no negative power, which is why the
# threshold here is -45 rather than a real-world -75.
#
# **Why the neighbour runs 802.11n.** wpa_supplicant 2.10 chooses among the
# candidates by estimated throughput. Two 802.11g access points at -50 and
# -30 dBm both estimate 54 Mbit/s, so it stayed where it was, which was the
# first run of this rig; a real weak station estimates less and moves. HT20
# beats 54 Mbit/s, so here the request has somewhere better to point.
#
# Asserted:
#   - the control: a plan before the station has settled steers nobody, and
#     for the minute after, with the better access point in its scan
#     results, the station stays where it is -- so a move is the steer's;
#   - the plan after the minute carries one steer, which the record marks
#     advisory (`0`), not imminent;
#   - the station is then on the neighbour;
#   - and a plan after that steers nobody, the station having gone.
#
# Always exits 0 and reports through /verdict/weak, as the regdom rig's
# payloads do.
#
# HOW IT STOPS: every wait is bounded (the radios at 5 s, the access points at
# 20 s, the association at 10 s, the settling at 65 s, the move at 30 s), the
# steps are a fixed list, and the vm takes hostapd and wpa_supplicant with it.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/weak
: > "$out"
say() { echo "$*" >> "$out"; echo "weak: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/weak
mkdir -p "$work/etc/secrets" "$work/run" "$work/sta"

build=/repo/c
for program in netcfgd ncfg; do
	if [ ! -x "$build/$program" ]; then
		say "VERDICT bad: $build/$program is not built on the host"
		exit 0
	fi
done

modprobe mac80211_hwsim radios=3
n=0
while [ ! -e /sys/class/net/wlan2 ] && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
[ -e /sys/class/net/wlan2 ] || { say "VERDICT bad: hwsim gave no third radio"; exit 0; }

b0=$(cat /sys/class/net/wlan0/address)
b1=$(cat /sys/class/net/wlan1/address)
cat > "$work/near.conf" <<CONF
interface=wlan1
driver=nl80211
ctrl_interface=$work/near
ssid=weak
hw_mode=g
channel=6
ieee80211n=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=correcthorse
CONF
hostapd -B -P "$work/near.pid" -f "$work/near.log" "$work/near.conf" >/dev/null 2>&1

printf 'correcthorse' > "$work/etc/secrets/weak"
chmod 600 "$work/etc/secrets/weak"
cat > "$work/etc/netcfgd.conf" <<CONF
interface wlan0 {
	config = "192.168.4.1/24"
}

access_point "far" {
	device = "wlan0"
	ssid = "7765616b"
	channel = 1
	neighbour_reports = true
	neighbour "$b1" { channel = 6 }
	steering { signal = -45 }
	wifi { psk = "@secret:weak" }
}
CONF
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
"$build/ncfg" apply > "$work/apply.log" 2>&1
say "ncfg apply rc=$?"
n=0
until [ -S "$work/run/hostapd/wlan0" ] && [ -S "$work/near/wlan1" ] || [ "$n" -gt 100 ]; do
	sleep 0.2
	n=$((n + 1))
done
# The declared neighbour, now there is a hostapd to hold it.
"$build/ncfg" apply > "$work/apply2.log" 2>&1
say "a second ncfg apply rc=$?: $(grep -c 'neighbour.add' "$work/apply2.log") neighbour.add line(s)"

cat > "$work/sta.conf" <<CONF
ctrl_interface=$work/sta
network={
	ssid="weak"
	psk="correcthorse"
	bssid=$b0
}
CONF
wpa_supplicant -B -i wlan2 -c "$work/sta.conf" -d -f "$work/sta.log" >/dev/null 2>&1
S() { wpa_cli -p "$work/sta" -i wlan2 "$@" 2>/dev/null; }
n=0
until S status | grep -q '^wpa_state=COMPLETED' || [ "$n" -gt 100 ]; do
	sleep 0.1
	n=$((n + 1))
done
say "joins: $(S status | grep -E '^bssid=')"

# Weak, both ways, and free to move -- and **not scanned again**. Without
# bgscan an associated wpa_supplicant reconsiders only on new scan results,
# and a scan here hands it the stronger HT neighbour: the first run of this
# payload asked for one, and the station roamed on its own inside the
# settling minute, which the control below caught. What it last heard is its
# scan from joining, both access points at -30 dBm.
iw dev wlan2 set txpower fixed 0
iw dev wlan0 set txpower fixed 0
S set_network 0 bssid any >/dev/null
sleep 4
say "the station last heard: $(S scan_results | tail -n +2 | awk '{print $1, $3}' | tr '\n' ' ')"
say "and hears its access point at: $(S signal_poll | grep '^RSSI=')"
"$build/ncfg" plan > "$work/plan-early.log" 2>&1
early=$(grep -cE '^ +[0-9]+ +station\.steer ' "$work/plan-early.log")
say "a plan before the station settled: $early steer(s)"

sleep 58
stayed=$(S status | grep -E '^bssid=')
say "a minute later, unasked, the station is on: $stayed"
"$build/ncfg" plan > "$work/plan.log" 2>&1
planned=$(grep -cE '^ +[0-9]+ +station\.steer ' "$work/plan.log")
say "the plan: $(grep -E '^ +[0-9]+ +station\.steer ' "$work/plan.log" | head -1)"
"$build/ncfg" apply > "$work/apply3.log" 2>&1
say "ncfg apply rc=$?"
n=0
until S status | grep -q "^bssid=$b1" && S status | grep -q '^wpa_state=COMPLETED' ||
    [ "$n" -gt 300 ]; do
	sleep 0.1
	n=$((n + 1))
done
after=$(S status | grep -E '^bssid=')
say "the station is then on: $after"
record=$(cat "$work/run/hostapd/wlan0.steered" 2>/dev/null)
say "  wlan0.steered: $record"
"$build/ncfg" plan > "$work/plan-after.log" 2>&1
again=$(grep -cE '^ +[0-9]+ +station\.steer ' "$work/plan-after.log")
say "a plan after: $again steer(s)"

# The request as the station received it: bit 0x4 of its mode is
# disassociation imminent.
mode=$(grep -o 'BSS Transition Management Request: dialog_token=[0-9]* request_mode=0x[0-9a-f]*' \
	"$work/sta.log" | tail -1 | sed 's/.*request_mode=//')
say "  the station was sent request_mode=${mode:-none}"
sta=$(cat /sys/class/net/wlan2/address)
failed=0
[ -n "$mode" ] && [ $(( mode & 4 )) -eq 0 ] || { say "  the station was told disassociation is imminent"; failed=1; }

[ "$early" -eq 0 ] || { say "  the control failed: a station that had just joined was steered"; failed=1; }
[ "$stayed" = "bssid=$b0" ] || { say "  the control failed: the station moved before it was asked"; failed=1; }
[ "$planned" -eq 1 ] || { say "  the plan after the minute did not carry one steer"; failed=1; }
[ "$after" = "bssid=$b1" ] || { say "  the station did not move to $b1"; failed=1; }
case "$record" in "$sta "*" 0") ;; *) say "  the record does not hold an advisory steer"; failed=1 ;; esac
[ "$again" -eq 0 ] || { say "  a plan after the move still steers"; failed=1; }
if [ "$failed" -ne 0 ]; then
	sed 's/^/  plan: /' "$work/plan.log" | head -8 >> "$out"
	sed 's/^/  apply3: /' "$work/apply3.log" | tail -6 >> "$out"
	grep -E 'WNM: (BSS Transition|Current BSS|Found|Transition to|No transition)' "$work/sta.log" |
		tail -8 | sed 's/^/  sta: /' >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
