#!/bin/sh
# 160 MHz on an access point netcfgd runs (project.md 10.599).
#
# One `access_point` on 5 GHz channel 100 with `width = 160`, in the US
# domain. Its block, 100 to 128, is all radar channels, so hostapd listens a
# minute before it may beacon; the plan has to say so -- here in channel 100's
# own warning, the 160 MHz one being for a channel such as 36 that has none,
# which `plan_access_point_test` covers. Asserted:
#
#   - the plan warns of the radar wait;
#   - the file says vht_oper_chwidth=2, centre 114 and [VHT160] -- measured,
#     without [VHT160] hostapd runs 80 MHz and says nothing;
#   - a station associates at 160 MHz as 802.11ac;
#   - and a second plan has nothing to do.
#
# Always exits 0 and reports through /verdict/width, as the regdom rig's
# payloads do.
#
# HOW IT STOPS: every wait is bounded (the radios at 5 s, the association,
# radar listening included, at 90 s), the steps are a fixed list, and the vm
# takes hostapd and wpa_supplicant with it.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/width
: > "$out"
say() { echo "$*" >> "$out"; echo "width: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/width
mkdir -p "$work/etc/secrets" "$work/run" "$work/sta"

build=/repo/c
for program in netcfgd ncfg; do
	if [ ! -x "$build/$program" ]; then
		say "VERDICT bad: $build/$program is not built on the host"
		exit 0
	fi
done

modprobe mac80211_hwsim radios=2
n=0
while [ ! -e /sys/class/net/wlan1 ] && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
[ -e /sys/class/net/wlan1 ] || { say "VERDICT bad: hwsim gave no second radio"; exit 0; }

printf 'correcthorse' > "$work/etc/secrets/wide"
chmod 600 "$work/etc/secrets/wide"
cat > "$work/etc/netcfgd.conf" <<CONF
interface wlan0 {
	config = "192.168.4.1/24"
}

access_point "wide" {
	device = "wlan0"
	ssid = "77696465"
	channel = 100
	width = 160
	regdom = "US"
	wifi { psk = "@secret:wide" }
}
CONF
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
"$build/ncfg" plan > "$work/plan-first.log" 2>&1
radar=$(grep -c 'runs at 160 MHz, which takes in channels shared with radar\|shared with radar' \
	"$work/plan-first.log")
say "the first plan warns of radar: $radar line(s)"
"$build/ncfg" apply > "$work/apply.log" 2>&1
say "ncfg apply rc=$?"
conf="$work/run/hostapd/wlan0.conf"
say "  wlan0: $(grep -E '^(ht_capab|ieee80211ac|vht_capab|vht_oper_chwidth|vht_oper_centr_freq_seg0_idx)=' "$conf" 2>/dev/null | tr '\n' ' ')"


cat > "$work/sta.conf" <<CONF
ctrl_interface=$work/sta
country=US
network={
	ssid="wide"
	psk="correcthorse"
}
CONF
wpa_supplicant -B -i wlan1 -c "$work/sta.conf" -f "$work/sta.log" >/dev/null 2>&1
S() { wpa_cli -p "$work/sta" -i wlan1 "$@" 2>/dev/null; }
# The station's own wait covers the radar listening: the access point says
# nothing until it is over, and the log netcfgd keeps for it does not carry
# hostapd's AP-ENABLED, which the first run of this payload waited on in vain.
n=0
until S status | grep -q '^wpa_state=COMPLETED' || [ "$n" -gt 900 ]; do
	sleep 0.1
	n=$((n + 1))
done
width=$(S signal_poll | sed -n 's/^WIDTH=//p')
generation=$(S status | sed -n 's/^wifi_generation=//p')
say "the station joins after $((n / 10)) s at ${width:-no width}, wifi_generation=${generation:-none}"
"$build/ncfg" plan > "$work/plan.log" 2>&1
again=$(grep -c '^nothing to do' "$work/plan.log")
say "a second plan: $(head -1 "$work/plan.log")"

failed=0
[ "$radar" -ge 1 ] || { say "  the plan did not warn of the radar wait"; failed=1; }
for line in 'vht_capab=\[VHT160\]' vht_oper_chwidth=2 vht_oper_centr_freq_seg0_idx=114 'ht_capab=\[HT40+\]' ieee80211ac=1; do
	grep -q "^$line\$" "$conf" || { say "  wlan0.conf was not written $line"; failed=1; }
done
[ "$width" = "160 MHz" ] || { say "  the station did not associate at 160 MHz"; failed=1; }
[ "$generation" = 5 ] || { say "  the station did not associate as 802.11ac"; failed=1; }
[ "$again" -ge 1 ] || { say "  the second plan was not empty"; failed=1; }
if [ "$failed" -ne 0 ]; then
	sed 's/^/  apply: /' "$work/apply.log" | tail -6 >> "$out"
	sed 's/^/  plan: /' "$work/plan.log" | head -6 >> "$out"
	grep -iE 'DFS|CAC|VHT|fail|error' "$work/run/hostapd/wlan0.log" | tail -6 | sed 's/^/  ap: /' >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
