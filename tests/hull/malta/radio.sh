# The radio half of guest.sh, sourced by it: `say`, `out` and `failed` are its.
# Its own file so that a machine whose OpenWrt carries no wireless stack, armsr
# (`hull-armsr`), can say it was not run rather than fail or pass it (10.814).

# And a radio, through the wpad a stock router ships: an access point on one of the
# kernel's two simulated radios and a station on the other, both netcfgd's, and
# `iw` saying what happened. Stock OpenWrt runs hostapd and wpa_supplicant as
# services already, empty, for netifd to fill, so this is also that meeting.
# OpenWrt loads the simulator with none.
rmmod mac80211_hwsim 2>> "$out"
insmod mac80211_hwsim radios=2 2>> "$out"
sleep 2
# And OpenWrt makes no interface on a radio: netcfgd has to, from the phy (10.748).
set -- $(ls /sys/class/ieee80211 2>/dev/null)
say "phys: $*"
say "interfaces on them before netcfgd: $(ls /sys/class/net | grep -c '^wlan'), $(ps w | grep -cE '[h]ostapd|[w]pa_supplicant') stock wpad process(es)"
mkdir -p /etc/netcfgd/secrets
printf '%s' 'a passphrase of some length' > /etc/netcfgd/secrets/bigend
chmod 600 /etc/netcfgd/secrets/bigend
printf 'device wlan0 {\n\tradio { phy = "%s" }\n}\ndevice wlan1 {\n\tradio { phy = "%s" }\n\twifi { backend = "wpa_supplicant"; autoconnect = true }\n}\n' \
	"$1" "$2" >> /etc/netcfgd/netcfgd.conf
cat >> /etc/netcfgd/netcfgd.conf <<'CONF'
network "bigend" {
	wifi   { psk = "@secret:bigend"; proto = "wpa2" }
	config = "null"
}
interface wlan1 {
	config = "null"
}
interface wlan0 {
	config = "192.168.20.1/24"
}
access_point "bigend" {
	device  = "wlan0"
	channel = 6
	wifi    { psk = "@secret:bigend"; proto = "wpa2" }
}
CONF
# Settled, not glimpsed: three looks together, with the access point agreeing. And no
# fall on the way: a look that left at the first sight of it was how an access point
# restarted under its first station went unseen (10.754).
n=0
held=0
until [ "$held" -ge 3 ] || [ $n -gt 90 ]; do
	if iw dev wlan1 link 2>/dev/null | grep -q 'SSID: bigend' &&
		[ "$(iw dev wlan0 station dump 2>/dev/null | grep -c '^Station')" -ge 1 ]; then
		held=$((held + 1))
	else
		held=0
	fi
	sleep 1
	n=$((n + 1))
done
link=$(iw dev wlan1 link 2>/dev/null | grep -E 'Connected|SSID' | tr -s ' \t' ' ' | tr '\n' ';')
say "wlan1 after $n s: ${link:-not connected}"
fell=$(logread | grep -c 'wlan1: CTRL-EVENT-DISCONNECTED')
say "wlan1 fell $fell time(s) on the way"
[ "$fell" = 0 ] || failed=1
logread | grep 'RSN IE in' | sed 's/.*WPA: //' | cut -c1-120 >> "$out"
station=$(iw dev wlan0 station dump 2>/dev/null | grep -c '^Station')
say "wlan0 has $station station(s)"
clients=$(/usr/bin/ncfg wifi clients wlan0 2>&1 | head -1 | cut -c1-90)
say "netcfgd of the same: $clients"
echo "$clients" | grep -q '^1 station' || failed=1
echo "$link" | grep -q 'SSID: bigend' && [ "$station" -ge 1 ] || {
	failed=1
	ps w | grep -E '[h]ostapd|[w]pa_supplicant' | cut -c1-130 >> "$out"
	logread | grep -E 'hostapd|wpa_supplicant|supplicant|wlan[01]' | tail -14 | cut -c1-150 >> "$out"
}
/usr/bin/ncfg plan 2>&1 | grep -iE 'wlan0|access|hostapd|bigend' | head -8 | cut -c1-150 >> "$out"
say "ncfg wifi status: $(/usr/bin/ncfg wifi status 2>&1 | head -3 | cut -c1-90 | tr '\n' ';')"
say "ncfg wifi clients: $(/usr/bin/ncfg wifi clients 2>&1 | head -3 | cut -c1-90 | tr '\n' ';')"
