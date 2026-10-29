#!/bin/sh
# Band steering between two access points netcfgd runs (project.md 10.595
# item 2).
#
# One SSID on two hwsim radios, 2.4 GHz channel 1 and 5 GHz channel 36, both
# with neighbour reports, and `steering { band = true }` on the 2.4 GHz one.
# A station on the third radio joins the 2.4 GHz access point, is left a
# minute to settle -- steering waits for that -- and an `ncfg apply` then
# plans a `station.steer` and sends it. What is asserted:
#
#   - the control: before the minute, a plan steers nobody;
#   - the plan after it carries one steer, to the 5 GHz BSSID, imminent;
#   - the station is then associated with the 5 GHz access point;
#   - the steer is in the record beside hostapd's socket;
#   - and a plan after that steers nobody, the station having gone.
#
# Always exits 0 and reports through /verdict/steer, as the regdom rig's
# payloads do.
#
# HOW IT STOPS: every wait is bounded (the radios at 5 s, the access points at
# 20 s, the association at 10 s, the settling at 65 s, the move at 20 s), the
# steps are a fixed list, and the vm takes hostapd and wpa_supplicant with it.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/steer
: > "$out"
say() { echo "$*" >> "$out"; echo "steer: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/steer
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

printf 'correcthorse' > "$work/etc/secrets/steer"
chmod 600 "$work/etc/secrets/steer"
cat > "$work/etc/netcfgd.conf" <<CONF
interface wlan0 {
	config = "192.168.4.1/24"
}

interface wlan1 {
	config = "192.168.5.1/24"
}

access_point "near" {
	device = "wlan0"
	ssid = "7374656572"
	channel = 1
	regdom = "US"
	neighbour_reports = true
	steering { band = true }
	wifi { psk = "@secret:steer" }
}

access_point "fast" {
	device = "wlan1"
	ssid = "7374656572"
	band = "5"
	channel = 36
	regdom = "US"
	neighbour_reports = true
	wifi { psk = "@secret:steer" }
}
CONF
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
"$build/ncfg" apply > "$work/apply.log" 2>&1
say "ncfg apply rc=$?"
n=0
until [ -S "$work/run/hostapd/wlan0" ] && [ -S "$work/run/hostapd/wlan1" ] ||
    [ "$n" -gt 100 ]; do
	sleep 0.2
	n=$((n + 1))
done
say "  run/hostapd: $(ls "$work/run/hostapd" 2>/dev/null | grep -v '\.' | tr '\n' ' ')"
# The neighbour lists, now there is a hostapd to hold them.
"$build/ncfg" apply > "$work/apply2.log" 2>&1
say "a second ncfg apply rc=$?"

b0=$(cat /sys/class/net/wlan0/address)
b1=$(cat /sys/class/net/wlan1/address)
cat > "$work/sta.conf" <<CONF
ctrl_interface=$work/sta
country=US
network={
	ssid="steer"
	psk="correcthorse"
	bssid=$b0
}
CONF
wpa_supplicant -B -i wlan2 -c "$work/sta.conf" -d -f "$work/sta.log" >/dev/null 2>&1
status() { wpa_cli -p "$work/sta" -i wlan2 status 2>/dev/null; }
n=0
until status | grep -q '^wpa_state=COMPLETED' || [ "$n" -gt 100 ]; do
	sleep 0.1
	n=$((n + 1))
done
say "joins: $(status | grep -E '^(bssid|freq)=' | tr '\n' ' ')"
# Free to move, and the 5 GHz one in its scan results.
wpa_cli -p "$work/sta" -i wlan2 set_network 0 bssid any >/dev/null
wpa_cli -p "$work/sta" -i wlan2 scan >/dev/null
sleep 3

"$build/ncfg" plan > "$work/plan-early.log" 2>&1
early=$(grep -cE '^ +[0-9]+ +station\.steer ' "$work/plan-early.log")
say "a plan before the station settled: $early steer(s)"

sleep 62
"$build/ncfg" plan > "$work/plan.log" 2>&1
planned=$(grep -cE '^ +[0-9]+ +station\.steer ' "$work/plan.log")
say "the plan after a minute: $(grep -E '^ +[0-9]+ +station\.steer ' "$work/plan.log" | head -1)"
"$build/ncfg" apply > "$work/apply3.log" 2>&1
say "ncfg apply rc=$?"
n=0
until status | grep -q "^bssid=$b1" && status | grep -q '^wpa_state=COMPLETED' ||
    [ "$n" -gt 200 ]; do
	sleep 0.1
	n=$((n + 1))
done
after=$(status | grep -E '^(bssid|freq)=' | tr '\n' ' ')
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
sta_mac=$(cat /sys/class/net/wlan2/address)
failed=0
[ -n "$mode" ] && [ $(( mode & 4 )) -eq 4 ] || { say "  the station was not told disassociation is imminent"; failed=1; }

[ "$early" -eq 0 ] || { say "  the control failed: a station that had just joined was steered"; failed=1; }
[ "$planned" -eq 1 ] || { say "  the plan after the minute did not carry one steer"; failed=1; }
case "$after" in *"bssid=$b1"*) ;; *) say "  the station did not move to $b1"; failed=1 ;; esac
case "$record" in "$sta_mac "*" 1") ;; *) say "  the steer is not in the record"; failed=1 ;; esac
[ "$again" -eq 0 ] || { say "  a plan after the move still steers"; failed=1; }
if [ "$failed" -ne 0 ]; then
	sed 's/^/  apply: /' "$work/apply.log" | tail -6 >> "$out"
	sed 's/^/  plan: /' "$work/plan.log" | head -12 >> "$out"
	sed 's/^/  apply3: /' "$work/apply3.log" | tail -8 >> "$out"
	grep -E 'WNM|BSS Transition' "$work/sta.log" | tail -6 | sed 's/^/  sta: /' >> "$out"
	grep -E 'BSS-TM|BSS_TM' "$work/run/hostapd/wlan0.log" 2>/dev/null | tail -4 | sed 's/^/  ap: /' >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
