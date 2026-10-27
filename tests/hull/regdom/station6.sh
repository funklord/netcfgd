#!/bin/sh
# The station's machine for the 6 GHz half of the regdom rig (project.md
# 10.585). Two WPA3 access points in another kernel, in CA: ca5 at 5975 MHz
# and ca101 at 6455 MHz (CA because US cannot run one; see ap6.sh). For each domain this kernel is put in, and each
# access point, a fresh kernel: can the station hear it, join it through
# wpa_supplicant (6 GHz admits no open network, so `iw connect` cannot), and
# what does the domain become?
#
# The control is the CA domain, which allows both; if it cannot join them
# through the relay, nothing else is a reading. The channel table has two
# controls of its own, taken from published rules rather than from the
# database it reads: China opened no 6 GHz band, and Europe's stops at 6425
# MHz, so CN must read 5975 off and DE must read 6455 off.
#
# Always exits 0 and reports through /verdict/station6, as station.sh does.
#
# HOW IT STOPS: waits are bounded -- the access points at 300 s, each scan at
# eight tries, each association at fifteen seconds -- over a fixed list of
# ten cases; every relay and supplicant it starts is stopped by the next
# case, and the relays have lifetimes of their own.
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/station6
: > "$out"
say() { echo "$*" >> "$out"; echo "station6: $*"; }
row() { line=$(printf '%-40s %s' "$1" "$2"); say "  $line"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/station6
mkdir -p "$work"

if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so there is no segment to relay over"
	exit 0
fi
ip link set eth1 up
ip addr add 10.96.0.2/24 dev eth1

country() {
	iw reg get 2>/dev/null | awk '/^global/ { g = 1; next }
		g && /^country/ { sub(":", "", $2); print $2; exit }'
}

observe() {
	limit=$1 from=$2 tenths=0
	while [ "$tenths" -lt $((limit * 10)) ]; do
		now=$(country)
		if [ "$now" != "$from" ]; then
			echo "$now after $((tenths / 10)).$((tenths % 10))s"
			return
		fi
		sleep 0.1
		tenths=$((tenths + 1))
	done
	echo "$(country), unchanged"
}

# A channel's flags on the station's radio: off, absent, or ok with noIR and
# radar beside it. `iw` prints "(disabled)".
flag_of() {
	iw phy "$(cat /sys/class/net/wlan0/phy80211/name)" channels 2>/dev/null | awk -v mhz="$1" '
		$1 == "*" { inside = ($2 == mhz); if (inside) seen = 1 }
		inside && tolower($0) ~ /disabled/ { off = 1 }
		inside && /No IR/ { noir = 1 }
		inside && /Radar detection/ { radar = 1 }
		END {
			if (!seen) { print "absent"; exit }
			if (off) { print "off"; exit }
			f = "ok"
			if (noir) f = f "+noIR"
			if (radar) f = f "+radar"
			print f
		}'
}

relay=
supplicant=
stop_case() {
	for p in $supplicant $relay; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
	supplicant=
	relay=
}
fresh() {
	stop_case
	modprobe -r mac80211_hwsim 2>/dev/null
	modprobe -r mac80211 2>/dev/null
	modprobe -r cfg80211 2>/dev/null
	modprobe cfg80211 && modprobe mac80211_hwsim radios=1
	tenths=0
	while { [ ! -e /sys/class/net/wlan0 ] || [ -z "$(country)" ]; } && [ "$tenths" -lt 50 ]; do
		sleep 0.1
		tenths=$((tenths + 1))
	done
	if [ "$1" = relay ]; then
		rm -f "$work/relay.stats"
		python3 /payload/relay.py --peer 10.96.0.1 --radios 0 \
			--stats "$work/relay.stats" --lifetime 120 >> "$work/relay.log" 2>&1 &
		relay=$!
	fi
	ip link set wlan0 up
	sleep 1
}

set_domain() {
	[ "$1" = - ] && return
	iw reg set "$1"
	observe 5 00 >/dev/null
}

say "the station's 6 GHz channels under each domain:"
fresh
for domain in 00 US CA DE GB JP CN; do
	set_domain "$domain"
	row "$domain (global $(country))" \
	    "5975 $(flag_of 5975)  6135 $(flag_of 6135)  6455 $(flag_of 6455)  6615 $(flag_of 6615)  6875 $(flag_of 6875)"
done
table=ok
set_domain CN
case $(flag_of 5975) in off|absent) ;; *) table=bad ;; esac
set_domain DE
case $(flag_of 6455) in off|absent) ;; *) table=bad ;; esac

waited=0
until grep -q '^UP' /verdict/ap6 2>/dev/null; do
	if grep -q '^VERDICT bad' /verdict/ap6 2>/dev/null; then
		say "VERDICT bad: the access points' machine failed, so nothing here is a reading"
		sed 's/^/  ap6 said: /' /verdict/ap6 >> "$out"
		exit 0
	fi
	waited=$((waited + 1))
	[ "$waited" -gt 300 ] && { say "VERDICT bad: the access points never came up"; exit 0; }
	sleep 1
done

heard() {
	tries=0
	while [ "$tries" -lt 8 ]; do
		said=$(iw dev wlan0 scan 2>/dev/null | awk -v want="$1" '
			/^BSS / { ssid = ""; code = "" }
			/^\tSSID: / { ssid = $2 }
			/^\tCountry: / { code = $2 }
			ssid == want && code != "" { print code; exit }')
		[ -n "$said" ] && { echo "$said"; return 0; }
		tries=$((tries + 1))
		sleep 0.5
	done
	return 1
}

# Join through wpa_supplicant, as 6 GHz requires: SAE with hash-to-element and
# protected management frames, the same three the access point demands.
connect() {
	mkdir -p "$work/wpa"
	cat > "$work/wpa.conf" <<CONF
ctrl_interface=$work/wpa
sae_pwe=1
network={
	ssid="$1"
	key_mgmt=SAE
	sae_password="regdom-rig"
	ieee80211w=2
}
CONF
	wpa_supplicant -i wlan0 -D nl80211 -c "$work/wpa.conf" >> "$work/wpa.log" 2>&1 &
	supplicant=$!
	waited=0
	until wpa_cli -p "$work/wpa" -i wlan0 status 2>/dev/null | grep -q 'wpa_state=COMPLETED'; do
		waited=$((waited + 1))
		[ "$waited" -gt 150 ] && return 1
		sleep 0.1
	done
	return 0
}

controls=0
case_run() {
	domain=$1 ssid=$2 mhz=$3
	fresh relay
	set_domain "$domain"
	start=$(country)
	before=$(flag_of "$mhz")
	code=$(heard "$ssid") || code=
	after=$(flag_of "$mhz")
	if connect "$ssid"; then
		result="joins; $(observe 10 "$start")"
		[ "$domain" = CA ] && controls=$((controls + 1))
	else
		result="does not join; stays $(country)"
	fi
	row "$start, $ssid: $before, hears ${code:-nothing}, then $after" "$result"
}

say "each access point, from each domain (the AP's machine: $(grep '^domain' /verdict/ap6)):"
for domain in CA - US DE CN; do
	for pair in ca5:5975 ca101:6455; do
		case_run "$domain" "${pair%:*}" "${pair#*:}"
	done
done
stop_case

if [ "$table" != ok ]; then
	say "VERDICT bad: CN's 5975 or DE's 6455 read as usable, so the table cannot be read"
elif [ "$controls" -ne 2 ]; then
	say "VERDICT bad: the CA control joined $controls of 2, so the relay or medium is at fault"
	tail -8 "$work/wpa.log" | sed 's/^/  wpa_supplicant: /' >> "$out"
else
	say "VERDICT ok"
fi
exit 0
