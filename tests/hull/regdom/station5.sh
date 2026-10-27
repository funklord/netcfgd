#!/bin/sh
# The station's machine for the 5 GHz half of the regdom rig (project.md
# 10.585). Four access points in another kernel, in US: us36, us52 and us100
# (radar channels) and us149. For each domain this kernel is put in, and each access
# point, a fresh kernel: can the station hear it, join it, and what does the
# domain become? Fresh each time because joining one adopts a country, which
# would decide the next reading.
#
# The control is the US domain, which allows all four; if it cannot join
# them through the relay, nothing else is a reading.
#
# Always exits 0 and reports through /verdict/station5, as station.sh does.
#
# HOW IT STOPS: waits are bounded -- the access points at 300 s, each scan at
# eight tries, each association at ten seconds -- over a fixed list of
# sixteen cases, and every relay it starts has a lifetime of its own.
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/station5
: > "$out"
say() { echo "$*" >> "$out"; echo "station5: $*"; }
row() { line=$(printf '%-40s %s' "$1" "$2"); say "  $line"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/station5
mkdir -p "$work"

if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so there is no segment to relay over"
	exit 0
fi
ip link set eth1 up
ip addr add 10.97.0.2/24 dev eth1

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

# A channel's flags on the station's radio: off, or ok with any of noIR and
# radar beside it. `iw` prints "(disabled)", and "Radar detection" for DFS.
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
fresh() {
	[ -n "$relay" ] && { kill "$relay" 2>/dev/null; wait "$relay" 2>/dev/null; }
	relay=
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
		python3 /payload/relay.py --peer 10.97.0.1 --radios 0 \
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

# The table first, which needs no access point: the station's flags on five
# 5 GHz channels under each domain. The control is CN's channel 100: China has
# no band at 5470-5725 MHz, so a parser reading every channel as usable would
# show it -- the fault the 2.4 GHz table had. **The first control was DE's
# channel 165 and it was wrong, not the parser**: this regulatory database
# allows 5725-5875 MHz in DE and GB, while JP's 149 and CN's 100 read off.
say "the station's 5 GHz channels under each domain:"
fresh
for domain in 00 US DE GB JP CN; do
	set_domain "$domain"
	row "$domain (global $(country))" \
	    "36 $(flag_of 5180)  52 $(flag_of 5260)  100 $(flag_of 5500)  149 $(flag_of 5745)  165 $(flag_of 5825)"
done
set_domain CN
case $(flag_of 5500) in
off|absent) table=ok ;;
*) table=bad ;;
esac

waited=0
until grep -q '^UP' /verdict/ap5 2>/dev/null; do
	if grep -q '^VERDICT bad' /verdict/ap5 2>/dev/null; then
		say "VERDICT bad: the access points' machine failed, so nothing here is a reading"
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

connect() {
	iw dev wlan0 connect "$1" 2>/dev/null
	waited=0
	while ! iw dev wlan0 link 2>/dev/null | grep -q '^Connected'; do
		waited=$((waited + 1))
		[ "$waited" -gt 100 ] && return 1
		sleep 0.1
	done
	return 0
}

# One case: domain $1 ("-" for none), access point $2 on frequency $3.
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
		[ "$domain" = US ] && controls=$((controls + 1))
	else
		result="does not join; stays $(country)"
	fi
	row "$start, $ssid: $before, hears ${code:-nothing}, then $after" "$result"
}

say "each access point, from each domain (the AP's machine: $(grep '^domain' /verdict/ap5)):"
for domain in US - JP CN; do
	for pair in us36:5180 us52:5260 us100:5500 us149:5745; do
		case_run "$domain" "${pair%:*}" "${pair#*:}"
	done
done
[ -n "$relay" ] && { kill "$relay" 2>/dev/null; wait "$relay" 2>/dev/null; }

if [ "$table" != ok ]; then
	say "VERDICT bad: channel 100 read as usable under CN, so the table cannot be read"
elif [ "$controls" -ne 4 ]; then
	say "VERDICT bad: the US control joined $controls of 4, so the relay or medium is at fault"
else
	say "VERDICT ok"
fi
exit 0
