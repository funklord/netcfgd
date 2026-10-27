#!/bin/sh
# What cfg80211 lets a running machine do with its regulatory domain, for
# decision 0296 (project.md 10.585): which sources move it, whether it follows
# a machine from one country's access points to another's, what a disconnect
# does, and whether a country set by hand blocks what the radio hears.
#
# **It reports and does not assert, except about its own instruments.** The
# point is to find out what the kernel does, so a reading is printed whatever
# it is. What fails the run is an instrument that did not work -- no database,
# an access point that never came up, a country nobody could hear -- because a
# reading taken through a broken instrument is not a reading. An experiment
# whose setup failed says "not measured" rather than reporting the world
# domain it was left in.
#
# **The access point must not be the thing that sets the domain.** The domain
# is one setting per kernel, and hostapd's `country_code` sets it as well as
# advertising it, so with both radios in one kernel the station's readings
# would be the access point's. E1 measures that, and it does.
#
# **The way round it is to advertise without asking.** The first version ran
# hostapd in a user namespace of its own, where it could not set the domain --
# and hostapd then refused to run at all: it waits for the country change it
# asked for, and on a refusal it disables the interface
# (`COUNTRY_UPDATE->DISABLED`). So no access point configured with
# `country_code` can be a clean one. Instead `country_code` is left unset and
# the Country element (802.11d, element 7) is put in the beacon as raw bytes
# through `vendor_elements`. The station's kernel reads those bytes from the
# beacon whichever way they got there, so it cannot tell the difference; E2
# checks that the domain stays put and the country is heard.
#
# HOW IT STOPS: every wait is a poll bounded at ten seconds or less, the
# experiments are a fixed list, and the background processes (hostapd,
# wpa_supplicant, the namespace holders' `sleep 600`) are killed at each reset
# and die with the vm in any case. `make hull-regdom` bounds the whole run.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH

# Unix sockets and small writes, kept off the stored source's 9p root, which
# hwsim's payload measured as slow and which may refuse a socket outright.
mkdir -p /tmp
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null ||
	echo "note: no tmpfs on /tmp; the control sockets are on the machine's root"
work=/tmp/regdom
mkdir -p "$work"

failures=0
ok() { echo "ok   $1"; }
fail() { echo "FAIL $1"; failures=$((failures + 1)); }
row() { printf '  %-50s %s\n' "$1" "$2"; }

# The global domain's country, as `iw reg get` prints it under `global`.
country() {
	iw reg get 2>/dev/null | awk '/^global/ { g = 1; next }
		g && /^country/ { sub(":", "", $2); print $2; exit }'
}

# Wait up to $1 seconds for the global country to differ from $2, and say
# what it is and when it got there. A reading that never moves waits the whole
# bound, which is the only way to say "it did not change" at all.
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
	echo "$(country), unchanged over ${limit}s"
}

pids=
remember() { pids="$pids $1"; }
stop_all() {
	for p in $pids; do kill "$p" 2>/dev/null; done
	for p in $pids; do wait "$p" 2>/dev/null; done
	pids=
}


# A fresh regulatory state: cfg80211 unloaded and loaded again, which is the
# whole reason this is a vm. Three radios: wlan0 and wlan2 are access points,
# wlan1 the station.
fresh() {
	stop_all
	modprobe -r mac80211_hwsim 2>/dev/null
	modprobe -r mac80211 2>/dev/null
	modprobe -r cfg80211 2>/dev/null
	if lsmod | grep -q '^cfg80211 '; then
		fail "cfg80211 would not unload, so this experiment starts from the last one's state"
	fi
	modprobe cfg80211 && modprobe mac80211_hwsim radios=3 || {
		fail "the radios could not be loaded"
		return 1
	}
	waited=0
	while [ ! -e /sys/class/net/wlan2 ] && [ "$waited" -lt 50 ]; do
		sleep 0.1
		waited=$((waited + 1))
	done
	# The world domain arrives from the database a moment after loading.
	tenths=0
	while [ "$(country)" = "" ] && [ "$tenths" -lt 50 ]; do
		sleep 0.1
		tenths=$((tenths + 1))
	done
	ip link set wlan1 up
}

# The Country element for a two-letter code, as hex: id 7, length 6, the code
# and a space (any environment), then one triplet -- channels 1 to 13 at 20 dBm.
# cfg80211 takes the code and looks the rules up in its database; the triplet
# is there because the element is malformed without one.
country_element() {
	printf '0706%02x%02x20010d14' "'$(printf %.1s "$1")" "'$(printf %s "$1" | cut -c2)"
}

# An access point on $1 named $2 advertising $3. With $4 = advertised, the
# country is in the beacon and hostapd is never told it; with $4 = configured,
# it is hostapd's `country_code`, which sets the domain too. See the header.
ap_up() {
	iface=$1 ssid=$2 code=$3 how=$4
	mkdir -p "$work/hostapd-$ssid"
	cat > "$work/$ssid.conf" <<CONF
interface=$iface
driver=nl80211
ctrl_interface=$work/hostapd-$ssid
ssid=$ssid
hw_mode=g
channel=1
CONF
	if [ "$how" = configured ]; then
		printf 'country_code=%s\nieee80211d=1\n' "$code" >> "$work/$ssid.conf"
	else
		printf 'vendor_elements=%s\n' "$(country_element "$code")" >> "$work/$ssid.conf"
	fi
	log="$work/hostapd-$ssid.log"
	hostapd "$work/$ssid.conf" > "$log" 2>&1 &
	remember $!
	waited=0
	while ! grep -q 'AP-ENABLED' "$log" 2>/dev/null; do
		waited=$((waited + 1))
		[ "$waited" -gt 100 ] && return 1
		sleep 0.1
	done
	return 0
}

# What the station hears: the country advertised in the beacon of $1.
heard() {
	tries=0
	while [ "$tries" -lt 10 ]; do
		said=$(iw dev wlan1 scan 2>/dev/null | awk -v want="$1" '
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
	iw dev wlan1 connect "$1" 2>/dev/null
	waited=0
	while ! iw dev wlan1 link 2>/dev/null | grep -q '^Connected'; do
		waited=$((waited + 1))
		[ "$waited" -gt 100 ] && return 1
		sleep 0.1
	done
	return 0
}

disconnect() {
	iw dev wlan1 disconnect 2>/dev/null
	waited=0
	while iw dev wlan1 link 2>/dev/null | grep -q '^Connected'; do
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
}

echo "=== guest: kernel $(uname -r), $(iw --version)"

# C0. The instruments: the database loads, and a fresh kernel is the world.
fresh || exit 1
start=$(country)
if dmesg | grep -qiE 'regulatory.db.*(fail|error|invalid)|failed to load regulatory'; then
	fail "the kernel refused the regulatory database:"
	dmesg | grep -iE 'regulatory|regdb|cfg80211' | tail -5 | sed 's/^/       /'
	exit 1
fi
[ "$start" = 00 ] && ok "a fresh kernel starts in the world domain" ||
	fail "a fresh kernel starts in '$start', not the world domain"
iw reg set DE
loaded=$(observe 5 00)
case $loaded in
DE*) ok "the database applies a country ($loaded)" ;;
*) fail "the database applied no country: $loaded"; exit 1 ;;
esac

echo
echo "=== the access point's own effect on the domain"
fresh
if ap_up wlan0 de DE configured; then
	row "E1 hostapd country_code=DE, same kernel" "$(observe 5 00)"
else
	row "E1 hostapd country_code=DE, same kernel" "not measured: no AP-ENABLED"
	sed 's/^/       /' "$work/hostapd-de.log" | tail -5
fi

fresh
clean=
if ap_up wlan0 de DE advertised; then
	after=$(observe 5 00)
	row "E2 DE in the beacon only, hostapd told nothing" "$after"
	code=$(heard de) || code=
	row "   and the station hears its country as" "${code:-nothing}"
	case $after in
	00,*) if [ "$code" = DE ]; then
		ok "an access point advertises a country without setting it"
		clean=1
	else
		fail "the beacon carries no country the station can hear, so it cannot drive the rest"
	fi ;;
	*) fail "advertising alone still moved the domain: $after" ;;
	esac
else
	row "E2 DE in the beacon only, hostapd told nothing" "not measured: no AP-ENABLED"
	sed 's/^/       /' "$work/hostapd-de.log" | tail -5
	fail "hostapd did not come up with a raw Country element"
fi

if [ -z "$clean" ]; then
	echo
	echo "Nothing below can be measured without an access point that leaves the"
	echo "domain alone, so the run stops here."
	exit 1
fi

echo
echo "=== one country's access point (E2's state carries on)"
row "E3 after the station's scan heard DE" "$(observe 5 00)"
if connect de; then
	row "E4 associated to DE's access point" "$(observe 10 00)"
	now=$(country)
	disconnect
	row "E5 disconnected, access point still up" "$(observe 10 "$now")"
else
	row "E4 associated to DE's access point" "not measured: never connected"
fi

echo
echo "=== a machine that moves: DE's access point, then US's"
fresh
if ap_up wlan0 de DE advertised && ap_up wlan2 us US advertised; then
	if connect de; then
		row "E6 associated to DE" "$(observe 10 00)"
		now=$(country)
		disconnect
		row "E7 disconnected from DE, both still up" "$(observe 10 "$now")"
		now=$(country)
		if connect us; then
			row "E8 associated to US" "$(observe 10 "$now")"
		else
			row "E8 associated to US" "not measured: never connected"
		fi
	else
		row "E6 associated to DE" "not measured: never connected"
	fi
else
	row "E6-E8 two access points" "not measured: one did not come up"
fi

echo
echo "=== a country set by hand first (iw reg set SE), then DE's access point"
fresh
iw reg set SE
row "E9 iw reg set SE" "$(observe 5 00)"
if ap_up wlan0 de DE advertised && connect de; then
	row "E10 associated to DE after the user's SE" "$(observe 10 SE)"
	now=$(country)
	disconnect
	row "E11 disconnected, access point still up" "$(observe 10 "$now")"
else
	row "E10 associated to DE after the user's SE" "not measured"
fi

echo
echo "=== the supplicant's country= (what netcfgd's wifi.set_regdom sends)"
fresh
if ap_up wlan0 de DE advertised; then
	mkdir -p "$work/wpa"
	cat > "$work/wpa.conf" <<CONF
ctrl_interface=$work/wpa
country=SE
network={
	ssid="de"
	key_mgmt=NONE
}
CONF
	wpa_supplicant -i wlan1 -D nl80211 -c "$work/wpa.conf" > "$work/wpa.log" 2>&1 &
	remember $!
	row "E12 wpa_supplicant started with country=SE" "$(observe 5 00)"
	now=$(country)
	waited=0
	until wpa_cli -p "$work/wpa" -i wlan1 status 2>/dev/null | grep -q 'wpa_state=COMPLETED'; do
		waited=$((waited + 1))
		[ "$waited" -gt 100 ] && break
		sleep 0.1
	done
	if [ "$waited" -le 100 ]; then
		row "E13 associated to DE through the supplicant" "$(observe 10 "$now")"
		now=$(country)
		wpa_cli -p "$work/wpa" -i wlan1 disconnect >/dev/null 2>&1
		row "E14 disconnected via supplicant, AP still up" "$(observe 10 "$now")"
	else
		row "E13 associated to DE through the supplicant" "not measured: never completed"
	fi
else
	row "E12-E14 the supplicant" "not measured: no access point"
fi

echo
echo "=== the same move, with the machine idle between the two countries"
# **E7 and E8 may be this rig rather than the kernel.** cfg80211 drops a
# country it adopted from a beacon only when every interface is idle, and in
# this rig the access points share the station's kernel, so the machine is
# never idle. A laptop has no access points of its own. So here the access
# point is stopped after the disconnect, and the US one started only after the
# reading is taken.
fresh
if ap_up wlan0 de DE advertised && connect de; then
	row "E15 associated to DE" "$(observe 10 00)"
	now=$(country)
	disconnect
	stop_all
	row "E16 disconnected, and no access point running" "$(observe 10 "$now")"
	now=$(country)
	if ap_up wlan2 us US advertised && connect us; then
		row "E17 associated to US" "$(observe 10 "$now")"
	else
		row "E17 associated to US" "not measured"
	fi
else
	row "E15-E17 the idle move" "not measured"
fi

echo
echo "=== a country set by hand, then DE heard, then idle: which does it go back to?"
fresh
iw reg set SE
observe 5 00 >/dev/null
if ap_up wlan0 de DE advertised && connect de; then
	row "E20 SE by hand, then associated to DE" "$(observe 10 SE)"
	now=$(country)
	disconnect
	stop_all
	row "E21 disconnected, and no access point running" "$(observe 10 "$now")"
else
	row "E20-E21 the hand-set return" "not measured"
fi

echo
echo "=== channels 12 and 13 under each domain, on a radio that follows it"
# **What a laptop carried from the US to Europe meets, and why it is not an
# experiment with an access point in it.** The first version put an access
# point on channel 13 on radio 0 under hwsim's regtest=7, which gives it a
# driver hint of its own -- and it followed the country set by hand like every
# other radio, so its channel 13 went `off` under US and `noIR` under the world
# domain and it could not beacon there. A plain radio's channels are the global
# domain's, and a country set by hand reaches every radio, so one kernel cannot
# hold an access point on a channel its station is forbidden. Measuring the
# station against one needs a second kernel (project.md 10.585).
#
# So this is the table those readings rest on, with channel 14 as its control:
# it is Japan's alone, and a parser that read it as usable elsewhere would be
# reading every disabled channel as usable -- which is the fault the first
# version of this table had, `iw` printing "(disabled)" in lower case.

# The flag cfg80211 gives a channel on one phy: ok, noIR, off or absent.
flag_of() {
	iw phy "$1" channels 2>/dev/null | awk -v mhz="$2" '
		$1 == "*" { inside = ($2 == mhz); if (inside) seen = 1 }
		inside && tolower($0) ~ /disabled/ { off = 1 }
		inside && /No IR/ { noir = 1 }
		END { if (!seen) print "absent"; else if (off) print "off";
		      else if (noir) print "noIR"; else print "ok" }'
}
fresh
phy=$(cat /sys/class/net/wlan1/phy80211/name)
for domain in 00 US DE GB JP; do
	iw reg set "$domain"
	observe 5 "$(country)" >/dev/null
	row "G $domain (global $(country))" \
	    "12: $(flag_of "$phy" 2467)  13: $(flag_of "$phy" 2472)  14: $(flag_of "$phy" 2484)"
done
[ "$(flag_of "$phy" 2484)" = ok ] && iw reg set US && observe 5 JP >/dev/null &&
	[ "$(flag_of "$phy" 2484)" = off ] &&
	ok "channel 14 is usable under JP and not under US, so the table reads flags" ||
	fail "channel 14 did not separate JP from US, so the table above cannot be read"

echo
echo "=== roaming straight from DE's access point to US's, never disconnected"
fresh
if ap_up wlan0 de DE advertised && ap_up wlan2 us US advertised && connect de; then
	row "E18 associated to DE" "$(observe 10 00)"
	now=$(country)
	iw dev wlan1 connect us 2>/dev/null
	waited=0
	while ! iw dev wlan1 link 2>/dev/null | grep -q 'SSID: us'; do
		waited=$((waited + 1))
		[ "$waited" -gt 100 ] && break
		sleep 0.1
	done
	# `iw connect` over an existing association may simply be refused, and a
	# reading taken still on DE would look like a domain that did not follow.
	on=$(iw dev wlan1 link 2>/dev/null | awk '/SSID:/ { print $2 }')
	if [ "$on" = us ]; then
		row "E19 moved to US's access point" "$(observe 10 "$now")"
	else
		row "E19 moved to US's access point" "not measured: still on '${on:-nothing}'"
	fi
else
	row "E18-E19 the roam" "not measured"
fi

stop_all
echo
if [ "$failures" -eq 0 ]; then
	echo "regdom: every instrument worked; the readings above are the result"
	exit 0
fi
echo "regdom: $failures instrument check(s) failed, so the readings are suspect"
exit 1
