#!/bin/sh
# Fast roaming between two access points netcfgd runs (project.md 10.587).
#
# Two `access_point` blocks offer one SSID on two hwsim radios with
# `fast_roaming = true`, as two machines would -- each derives its mobility
# domain and its keys alone, so they share nothing but the configuration --
# and a station on the third radio joins one and roams to the other. What is
# asserted is that the roam was a fast transition: the station's own log names
# the authentication algorithm of every exchange, 0 for open system and 2 for
# FT, so the first association is the control (it must be 0, which is what
# shows the instrument can tell) and the roam is the reading (it must be 2).
#
# Both also answer 802.11k neighbour report requests (10.595), and roam-b
# declares one neighbour that is not on this machine. The first apply starts
# hostapd; the second converges each one's neighbour list -- the sibling's
# own entry, and the declared one built from roam-b's -- and a third plan
# must have nothing to do. After the roam the station asks roam-b for a
# report and must be told about all three.
#
# The access points are netcfgd's -- `ncfg apply` renders and starts hostapd;
# the station is a bare wpa_supplicant, because what is under test is what the
# access points offer.
#
# Always exits 0 and reports through /verdict/roam, as the regdom rig's
# payloads do.
#
# HOW IT STOPS: every wait is bounded (the radios at 5 s, the access points at
# 20 s, each association at 10 s, the report at 2 s), the steps are a fixed list, and the vm takes
# hostapd and wpa_supplicant with it.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/roam
: > "$out"
say() { echo "$*" >> "$out"; echo "roam: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/roam
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

# One passphrase, one SSID (`roam`, 726f616d), two radios on two channels. An
# access point is started as its interface's prerequisite, so each radio has
# an `interface` block -- without one the plan is empty and only a warning
# says why, which the first run of this rig met.
printf 'correcthorse' > "$work/etc/secrets/roam"
chmod 600 "$work/etc/secrets/roam"
cat > "$work/etc/netcfgd.conf" <<CONF
interface wlan0 {
	config = "192.168.4.1/24"
}

interface wlan1 {
	config = "192.168.5.1/24"
}

access_point "roam-a" {
	device = "wlan0"
	ssid = "726f616d"
	channel = 1
	fast_roaming = true
	neighbour_reports = true
	wifi { psk = "@secret:roam" }
}

access_point "roam-b" {
	device = "wlan1"
	ssid = "726f616d"
	channel = 6
	fast_roaming = true
	neighbour_reports = true
	neighbour "02:00:00:00:09:00" { channel = 36 }
	wifi { psk = "@secret:roam" }
}
CONF
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
"$build/ncfg" apply > "$work/apply.log" 2>&1
say "ncfg apply rc=$?"

# What netcfgd rendered: one domain on both, derived from the SSID -- `01ff`
# is the first two octets of SHA-256 over `roam`, computed off this machine.
for device in wlan0 wlan1; do
	conf="$work/run/hostapd/$device.conf"
	say "  $device: $(grep -E '^(wpa_key_mgmt|mobility_domain|nas_identifier|ft_psk_generate_local|bss_transition)=' "$conf" 2>/dev/null | tr '\n' ' ')"
done
domains=$(cat "$work/run/hostapd/wlan0.conf" "$work/run/hostapd/wlan1.conf" 2>/dev/null |
	grep -c '^mobility_domain=01ff$')

n=0
until [ -S "$work/run/hostapd/wlan0" ] && [ -S "$work/run/hostapd/wlan1" ] ||
    [ "$n" -gt 100 ]; do
	sleep 0.2
	n=$((n + 1))
done
up=$(ls "$work/run/hostapd" 2>/dev/null | tr '\n' ' ')
say "  run/hostapd: $up"

# The lists, now that there is a hostapd to hold them: two entries on
# roam-a's (none declared, its sibling's) and two on roam-b's. Then nothing.
"$build/ncfg" apply > "$work/apply2.log" 2>&1
say "a second ncfg apply rc=$?: $(grep -c 'neighbour.add' "$work/apply2.log") neighbour.add line(s)"
"$build/ncfg" plan > "$work/plan.log" 2>&1
again=$(grep -c '^nothing to do' "$work/plan.log")
say "a third plan: $(head -1 "$work/plan.log")"

b0=$(cat /sys/class/net/wlan0/address)
b1=$(cat /sys/class/net/wlan1/address)
cat > "$work/sta.conf" <<CONF
ctrl_interface=$work/sta
network={
	ssid="roam"
	psk="correcthorse"
	key_mgmt=FT-PSK WPA-PSK
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
first=$(status | grep -E '^(bssid|key_mgmt)=' | tr '\n' ' ')
say "joins: $first"

wpa_cli -p "$work/sta" -i wlan2 set_network 0 bssid any >/dev/null
wpa_cli -p "$work/sta" -i wlan2 scan >/dev/null
sleep 3
start=$(date +%s%N)
wpa_cli -p "$work/sta" -i wlan2 roam "$b1" >/dev/null 2>&1
n=0
until status | grep -q "^bssid=$b1" && status | grep -q '^wpa_state=COMPLETED' ||
    [ "$n" -gt 200 ]; do
	sleep 0.05
	n=$((n + 1))
done
end=$(date +%s%N)
second=$(status | grep -E '^(bssid|key_mgmt)=' | tr '\n' ' ')
say "roams: $second after $(( (end - start) / 1000000 )) ms"

# The neighbour report, asked of the access point the station is now on.
wpa_cli -p "$work/sta" -i wlan2 neighbor_rep_request >/dev/null 2>&1
sleep 2
reported=$(grep 'RRM-NEIGHBOR-REP-RECEIVED' "$work/sta.log" | sed 's/.*bssid=//; s/ info=[^ ]*//' |
	sort -u | tr '\n' ' ')
say "  roam-b reports: $reported"

# The control and the reading, out of the station's own account.
joined_open=$(grep -c "SME: Authentication response: peer=$b0 auth_type=0 " "$work/sta.log")
roamed_ft=$(grep -c "SME: Authentication response: peer=$b1 auth_type=2 " "$work/sta.log")
say "  first association authenticated as open system: $joined_open"
say "  roam authenticated as fast transition: $roamed_ft"

failed=0
[ "$domains" -eq 2 ] || { say "  both access points were not rendered with domain 01ff"; failed=1; }
case "$first" in *"bssid=$b0"*"key_mgmt=FT-PSK"*) ;; *) say "  the first association was not FT-PSK to $b0"; failed=1 ;; esac
case "$second" in *"bssid=$b1"*"key_mgmt=FT-PSK"*) ;; *) say "  the station did not roam to $b1"; failed=1 ;; esac
[ "$joined_open" -ge 1 ] || { say "  the control failed: no open-system authentication to $b0"; failed=1; }
[ "$roamed_ft" -ge 1 ] || { say "  the roam to $b1 was not a fast transition"; failed=1; }
[ "$again" -ge 1 ] || { say "  the third plan was not empty"; failed=1; }
case "$reported" in *"$b0 op_class=81 chan=1 "*) ;; *) say "  roam-b did not report its sibling roam-a"; failed=1 ;; esac
case "$reported" in *"02:00:00:00:09:00 op_class=115 chan=36 "*) ;; *) say "  roam-b did not report the declared neighbour on channel 36"; failed=1 ;; esac
if [ "$failed" -ne 0 ]; then
	sed 's/^/  apply: /' "$work/apply.log" | tail -10 >> "$out"
	sed 's/^/  apply2: /' "$work/apply2.log" | tail -10 >> "$out"
	sed 's/^/  plan: /' "$work/plan.log" | head -8 >> "$out"
	grep -E 'SME: Authentication response|FT: ' "$work/sta.log" | tail -8 | sed 's/^/  sta: /' >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
