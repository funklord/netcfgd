#!/bin/sh
# The station's machine for the RNR half of the regdom rig (project.md
# 10.585). One network, `home`, on 5 GHz with a Reduced Neighbour Report
# naming its 6 GHz twin, in a CA kernel elsewhere. For each domain this kernel
# is put in, from a fresh kernel: what a plain scan sees, which band
# wpa_supplicant joins first and what the domain becomes, whether a scan while
# connected finds the 6 GHz BSS, whether the supplicant moves there by itself,
# and -- the question this half exists for -- whether the country survives the
# move. A world-domain machine has no 6 GHz; joining the 5 GHz BSS adopts CA,
# which opens it; if the move to 6 GHz counted as going idle, the domain would
# fall back to the world in the middle of it.
#
# The control is the CA domain: it must end on 6 GHz, and the 5 GHz beacon
# must carry the report (element 201), or nothing else here is a reading.
#
# Always exits 0 and reports through /verdict/station_rnr, as station.sh does.
#
# HOW IT STOPS: waits are bounded -- the access points by hull's `ready` at 5m, each scan at
# eight tries, each association at fifteen seconds, the wait for a move at
# twenty -- over five cases; every relay and supplicant is stopped by the next
# case, and the relays have lifetimes of their own.
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/station_rnr
: > "$out"
say() { echo "$*" >> "$out"; echo "station_rnr: $*"; }
row() { line=$(printf '%-44s %s' "$1" "$2"); say "  $line"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/station_rnr
mkdir -p "$work"

if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so there is no segment to relay over"
	exit 0
fi
ip link set eth1 up
ip addr add 10.95.0.2/24 dev eth1

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
	rm -f "$work/relay.stats"
	python3 /payload/relay.py --peer 10.95.0.1 --radios 0 \
		--stats "$work/relay.stats" --lifetime 150 >> "$work/relay.log" 2>&1 &
	relay=$!
	ip link set wlan0 up
	sleep 1
}

set_domain() {
	[ "$1" = - ] && return
	iw reg set "$1"
	observe 5 00 >/dev/null
}

# **Started only once the access point is up**: `(after ap-rnr)` in wire_rnr.conf,
# whose `(ready ...)` is the `UP` line in /verdict/ap_rnr -- hull's start order,
# in place of a loop here polling for it. An access point that fails or never
# comes up stops the run there, its verdict saying why.

# A plain scan, until the 5 GHz BSS is in it: whether its beacon carries
# element 201, and whether the 6 GHz BSS is listed beside it.
plain_scan() {
	tries=0
	while [ "$tries" -lt 8 ]; do
		# `-u`, or iw prints no element it does not parse: the first three runs
		# reported "report no" off a beacon that may well have carried one.
		iw dev wlan0 scan -u > "$work/scan.txt" 2>/dev/null
		grep -q 'freq: 5180' "$work/scan.txt" && break
		tries=$((tries + 1))
		sleep 0.5
	done
	five=$(grep -c 'freq: 5180' "$work/scan.txt")
	six=$(grep -c 'freq: 5975' "$work/scan.txt")
	report=$(awk '/^BSS / { inside = 0 } /freq: 5180/ { inside = 1 }
		inside && (/Unknown IE \(201\)/ || /[Rr]educed [Nn]eighbo/) { print "yes"; exit }' \
		"$work/scan.txt")
	echo "5 GHz ${five}, 6 GHz ${six}, report ${report:-no}"
}

# 5975 MHz's flag on the station's radio, which after an association says
# whether the adopted country opened 6 GHz at all.
flag5975() {
	iw phy "$(cat /sys/class/net/wlan0/phy80211/name)" channels 2>/dev/null | awk '
		$1 == "*" { inside = ($2 == 5975); if (inside) seen = 1 }
		inside && tolower($0) ~ /disabled/ { off = 1 }
		inside && /No IR/ { noir = 1 }
		END { if (!seen) print "absent"; else if (off) print "off";
		      else if (noir) print "noIR"; else print "ok" }'
}

# The 5 GHz BSS's block from the last scan, once, so the report's absence can
# be told from a parser that does not recognise how iw prints it.
dumped=
dump_block() {
	[ -n "$dumped" ] && return
	dumped=1
	awk '/^BSS / { inside = 0 } /freq: 5180/ { inside = 1 } inside' "$work/scan.txt" |
		grep -vE '^\s*\*' | head -40 | sed 's/^/    5 GHz beacon: /' >> "$out"
}

wpa() { wpa_cli -p "$work/wpa" -i wlan0 "$@" 2>/dev/null; }
state_of() { wpa status | awk -F= -v k="$1" '$1 == k { print $2 }'; }

# $1, where given, pins the join to one frequency.
join() {
	pin=
	[ -n "${1:-}" ] && pin="freq_list=$1"
	mkdir -p "$work/wpa"
	cat > "$work/wpa.conf" <<CONF
ctrl_interface=$work/wpa
sae_pwe=1
network={
	ssid="home"
	key_mgmt=SAE
	sae_password="regdom-rig"
	ieee80211w=2
	$pin
}
CONF
	wpa_supplicant -i wlan0 -D nl80211 -c "$work/wpa.conf" >> "$work/wpa.log" 2>&1 &
	supplicant=$!
	waited=0
	until [ "$(state_of wpa_state)" = COMPLETED ]; do
		waited=$((waited + 1))
		[ "$waited" -gt 150 ] && return 1
		sleep 0.1
	done
	return 0
}

wait_freq() {
	want=$1 limit=$2 tenths=0
	while [ "$tenths" -lt $((limit * 10)) ]; do
		[ "$(state_of wpa_state)" = COMPLETED ] && [ "$(state_of freq)" = "$want" ] && return 0
		sleep 0.1
		tenths=$((tenths + 1))
	done
	return 1
}

ended=
report_seen=
case_run() {
	label=$1 domain=$2
	fresh
	set_domain "$domain"
	start=$(country)
	say "$label (domain $start):"
	seen=$(plain_scan)
	row "a plain scan sees" "$seen"
	case $seen in *"report yes"*) report_seen=yes ;; esac
	dump_block
	if ! join; then
		row "joins home" "no; the domain stays $(country)"
		ended=none
		return
	fi
	first=$(state_of freq)
	row "joins home first on" "$first MHz; $(observe 10 "$start")"
	if [ "$first" = 5975 ]; then
		ended=5975
		return
	fi
	held=$(country)
	row "5975 MHz once associated" "$(flag5975)"
	wpa scan >/dev/null
	sleep 6
	bssid6=$(wpa scan_results | awk '$2 == 5975 { print $1; exit }')
	row "a scan while connected lists 6 GHz" "${bssid6:-no}; the domain is $(country)"
	wpa scan_results | sed 's/^/      scan_results: /' >> "$out"
	# The kernel's own answer beside the supplicant's: a plain scan of 5975
	# alone, which says whether 6 GHz is reachable now or only unscanned.
	tries=0 kernel6=no
	while [ "$tries" -lt 6 ]; do
		if iw dev wlan0 scan freq 5975 2>/dev/null | grep -q 'freq: 5975'; then
			kernel6=yes
			break
		fi
		tries=$((tries + 1))
		sleep 1
	done
	row "a plain scan of 5975 alone lists it" "$kernel6"
	if wait_freq 5975 20; then
		row "moves to 6 GHz by itself" "yes; the domain is $(country)"
		ended=5975
		return
	fi
	row "moves to 6 GHz by itself" "no, in 20s; still on $(state_of freq) MHz"
	if [ -n "$bssid6" ]; then
		wpa roam "$bssid6" >/dev/null
		if wait_freq 5975 15; then
			row "roams when told to" "yes; $(observe 5 "$held")"
			ended=5975
		else
			row "roams when told to" "no; on $(state_of freq) MHz, $(country)"
			ended=$(state_of freq)
		fi
	else
		ended=$first
	fi
}

say "the access points' machine: $(grep '^domain' /verdict/ap_rnr)"
case_run "CONTROL, CA set by hand" CA
control=$ended
case_run "nothing set (the world domain)" -
case_run "DE set by hand" DE
case_run "US set by hand" US
case_run "CN set by hand" CN

# **Whether 6 GHz can be scanned while associated on 5 GHz at all, here.** The
# world case adopts CA by joining 5 GHz and then finds nothing at 5975, which
# is either the adopted country or this rig: every other case scanned 6 GHz
# before associating. Same domain by hand, the join pinned to 5 GHz, and the
# same scan: if it finds the 6 GHz BSS, the adopted country is the difference.
fresh
set_domain CA
say "CA set by hand, the join pinned to 5 GHz:"
if join 5180; then
	row "joins home on" "$(state_of freq) MHz; the domain is $(country)"
	tries=0 kernel6=no
	while [ "$tries" -lt 6 ]; do
		if iw dev wlan0 scan freq 5975 2>/dev/null | grep -q 'freq: 5975'; then
			kernel6=yes
			break
		fi
		tries=$((tries + 1))
		sleep 1
	done
	row "a plain scan of 5975 alone lists it" "$kernel6"
	pinned_scan=$kernel6
else
	row "joins home on" "nothing"
	pinned_scan=unmeasured
fi
stop_case

if [ "$report_seen" != yes ]; then
	say "VERDICT bad: no scan saw element 201 in the 5 GHz beacon, so nothing here tests RNR"
elif [ "$control" != 5975 ]; then
	say "VERDICT bad: the CA control ended on '$control', not 6 GHz, so the relay or setup is at fault"
	tail -8 "$work/wpa.log" | sed 's/^/  wpa_supplicant: /' >> "$out"
else
	say "VERDICT ok"
fi
exit 0
