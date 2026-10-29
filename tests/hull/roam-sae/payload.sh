#!/bin/sh
# WPA3 fast roaming (FT-SAE) between two access points netcfgd runs, each on
# its own "machine" (project.md 10.587).
#
# Access point A is wlan0 in the root namespace, in bridge brA; access point B
# is wlan1 in namespace `b`, in bridge brB, run by a second netcfgd with a run
# directory of its own. The bridges are joined by a veth, which is the LAN:
# the only path the keys can take between them. Both blocks say `proto =
# "wpa3"`, `fast_roaming = true` and `roaming_key = "@secret:roam"`, and the
# two machines share nothing else -- each derives its mobility domain, names
# itself by its radio, and resolves the key from its own store.
#
# A bare wpa_supplicant on wlan2 joins A and roams to B. The station's own log
# names the authentication algorithm of each exchange: SAE is 3 and FT is 2.
# The first association is the control (SAE, which shows the instrument can
# tell) and the roam is the reading (FT). A second `ncfg plan` on each machine
# has nothing to do.
#
# Always exits 0 and reports through /verdict/roam-sae.
#
# HOW IT STOPS: every wait is bounded (the radios at 5 s, the access points at
# 20 s, the association at 15 s, the roam at 10 s), the steps are a fixed
# list, and the vm takes hostapd and wpa_supplicant with it.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/roam-sae
: > "$out"
say() { echo "$*" >> "$out"; echo "roam-sae: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/roam-sae
mkdir -p "$work/a/etc/secrets" "$work/a/run" "$work/b/etc/secrets" "$work/b/run" "$work/sta"
# The setup's complaints, for the failure report rather than the console.
exec 2>> "$work/setup.log"

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
ip netns add b
iw phy "$(cat /sys/class/net/wlan1/phy80211/name)" set netns name b
# The LAN between the two machines. Not `h` for a veth end: `ip link set h`
# reads it as `help` (the wds rig's lesson).
ip link add va type veth peer name vb netns b

# One configuration per machine, alike but for the radio and the bridge.
for side in a b; do
	if [ "$side" = a ]; then radio=wlan0 lan=va bridge=brA channel=1
	else radio=wlan1 lan=vb bridge=brB channel=6
	fi
	printf 'correcthorse' > "$work/$side/etc/secrets/ap"
	printf 'a roaming key both machines hold' > "$work/$side/etc/secrets/roam"
	chmod 600 "$work/$side/etc/secrets/ap" "$work/$side/etc/secrets/roam"
	cat > "$work/$side/etc/netcfgd.conf" <<CONF
device $bridge {
	bridge { members = ["$radio", "$lan"] }
}
interface $bridge { }
interface $radio { }
interface $lan { }
access_point "roam-$side" {
	device       = "$radio"
	ssid         = "726f616d"
	channel      = $channel
	fast_roaming = true
	roaming_key  = "@secret:roam"
	wifi {
		psk   = "@secret:ap"
		proto = "wpa3"
	}
}
CONF
done
ncfg_a() { NCFG_CONFIG_DIR="$work/a/etc" NCFG_RUN_DIR="$work/a/run" "$build/ncfg" "$@"; }
ncfg_b() {
	NCFG_CONFIG_DIR="$work/b/etc" NCFG_RUN_DIR="$work/b/run" ip netns exec b "$build/ncfg" "$@"
}
ncfg_a apply > "$work/a/apply.log" 2>&1
applied_a=$?
ncfg_b apply > "$work/b/apply.log" 2>&1
applied_b=$?
say "ncfg apply: a rc=$applied_a, b rc=$applied_b"

# What each rendered: the key management, and a name of its own.
for side in a b; do
	if [ "$side" = a ]; then radio=wlan0; else radio=wlan1; fi
	conf="$work/$side/run/hostapd/$radio.conf"
	say "  $side: $(grep -E '^(wpa_key_mgmt|mobility_domain|nas_identifier|bridge)=' "$conf" 2>/dev/null | tr '\n' ' ')"
done
names=$(cat "$work/a/run/hostapd/wlan0.conf" "$work/b/run/hostapd/wlan1.conf" 2>/dev/null |
	sed -n 's/^nas_identifier=//p' | sort -u | wc -l)

n=0
until [ -S "$work/a/run/hostapd/wlan0" ] && [ -S "$work/b/run/hostapd/wlan1" ] ||
    [ "$n" -gt 100 ]; do
	sleep 0.2
	n=$((n + 1))
done

cat > "$work/sta.conf" <<CONF
ctrl_interface=$work/sta
sae_pwe=2
network={
	ssid="roam"
	sae_password="correcthorse"
	key_mgmt=FT-SAE SAE
	ieee80211w=2
	bssid=$b0
}
CONF
wpa_supplicant -B -i wlan2 -c "$work/sta.conf" -d -f "$work/sta.log" >/dev/null 2>&1
status() { wpa_cli -p "$work/sta" -i wlan2 status 2>/dev/null; }
n=0
until status | grep -q '^wpa_state=COMPLETED' || [ "$n" -gt 150 ]; do
	sleep 0.1
	n=$((n + 1))
done
first=$(status | grep -E '^(bssid|key_mgmt)=' | tr '\n' ' ')
say "joins: $first"

wpa_cli -p "$work/sta" -i wlan2 set_network 0 bssid any >/dev/null
wpa_cli -p "$work/sta" -i wlan2 scan >/dev/null
sleep 3
wpa_cli -p "$work/sta" -i wlan2 roam "$b1" >/dev/null 2>&1
n=0
until status | grep -q "^bssid=$b1" && status | grep -q '^wpa_state=COMPLETED' ||
    [ "$n" -gt 100 ]; do
	sleep 0.1
	n=$((n + 1))
done
second=$(status | grep -E '^(bssid|key_mgmt)=' | tr '\n' ' ')
say "roams: $second"

joined_sae=$(grep -c "SME: Authentication response: peer=$b0 auth_type=3 " "$work/sta.log")
roamed_ft=$(grep -c "SME: Authentication response: peer=$b1 auth_type=2 " "$work/sta.log")
say "  first association authenticated as SAE: $joined_sae"
say "  roam authenticated as fast transition: $roamed_ft"

ncfg_a plan > "$work/a/plan.log" 2>&1
ncfg_b plan > "$work/b/plan.log" 2>&1
again=$(cat "$work/a/plan.log" "$work/b/plan.log" | grep -c '^nothing to do')
say "second plans: a $(head -1 "$work/a/plan.log"); b $(head -1 "$work/b/plan.log")"

failed=0
[ "$applied_a" -eq 0 ] && [ "$applied_b" -eq 0 ] || { say "  an apply failed"; failed=1; }
[ "$names" -eq 2 ] || { say "  the two access points were not given names of their own"; failed=1; }
case "$first" in *"bssid=$b0"*"key_mgmt=FT-SAE"*) ;; *) say "  the first association was not FT-SAE to $b0"; failed=1 ;; esac
case "$second" in *"bssid=$b1"*"key_mgmt=FT-SAE"*) ;; *) say "  the station did not roam to $b1"; failed=1 ;; esac
[ "$joined_sae" -ge 1 ] || { say "  the control failed: no SAE authentication to $b0"; failed=1; }
[ "$roamed_ft" -ge 1 ] || { say "  the roam to $b1 was not a fast transition"; failed=1; }
[ "$again" -ge 2 ] || { say "  a second plan was not empty"; failed=1; }
if [ "$failed" -ne 0 ]; then
	for side in a b; do
		sed "s/^/  apply $side: /" "$work/$side/apply.log" | tail -10 >> "$out"
		sed "s/^/  plan $side: /" "$work/$side/plan.log" | head -6 >> "$out"
	done
	grep -E 'SME: Authentication response|FT: ' "$work/sta.log" | tail -8 | sed 's/^/  sta: /' >> "$out"
	tail -8 "$work/setup.log" | sed 's/^/  setup: /' >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
