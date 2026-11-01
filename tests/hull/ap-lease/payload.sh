#!/bin/sh
# A station on an access point netcfgd runs, given an address by the DHCP
# server netcfgd configures, and named by it (project.md 10.601, 10.602).
#
# Each half had been run alone: `hull-dhcp-server` serves a veth, and the
# access point rigs associate a station that asks for no address. What no rig
# had done is the path a router is for -- associate, lease, be listed by name --
# because no image held hostapd and dnsmasq together. The hwsim image does now.
#
# One vm, two hwsim radios. netcfgd runs the access point on wlan0, with a
# static address and a `dhcp_server` on the same interface; wlan1's phy is
# moved into a namespace, where wpa_supplicant joins and dhcpcd asks for an
# address as `phone`. Asserted:
#
#   - the first plan starts both the access point and the DHCP server on wlan0;
#   - the station joins, and is given an address in the default range and the
#     router, over the air;
#   - `ncfg wifi clients wlan0`, through the daemon's socket, lists the
#     station by its MAC with the name `phone` and that address, in the text
#     table and in `--json`;
#   - and a second plan has nothing to do;
#   - then a guest network (10.648): a second station, `tablet`, reaches the
#     first through the access point; with `isolate_stations = true` the plan
#     restarts the access point for that field, and once both have rejoined
#     the first reaches the router and not the other station.
#
# Always exits 0 and reports through /verdict/ap-lease.
#
# HOW IT STOPS: every wait is bounded (the radios at 5 s, the daemon's socket
# at 5 s, each association at 30 s, dhcpcd at 20 s, the listing at 10 s, each
# ping at 3 s), the
# steps are a fixed list, and the vm takes the daemon, hostapd, dnsmasq,
# wpa_supplicant and dhcpcd with it.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/ap-lease
: > "$out"
say() { echo "$*" >> "$out"; echo "ap-lease: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/ap-lease
mkdir -p "$work/etc/secrets" "$work/run" "$work/sta"

build=/repo/c
for program in netcfgd ncfg; do
	if [ ! -x "$build/$program" ]; then
		say "VERDICT bad: $build/$program is not built on the host"
		exit 0
	fi
done
for program in hostapd dnsmasq wpa_supplicant dhcpcd; do
	command -v "$program" >/dev/null ||
		{ say "VERDICT bad: the image has no $program; rebuild netcfgd/hwsim"; exit 0; }
done

modprobe mac80211_hwsim radios=3
n=0
while [ ! -e /sys/class/net/wlan2 ] && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
[ -e /sys/class/net/wlan2 ] || { say "VERDICT bad: hwsim gave no third radio"; exit 0; }
# The station in a namespace of its own, so the address dhcpcd takes is not an
# address of the access point's kernel stack too -- which would deliver the
# server's replies locally and prove nothing about the air between them.
mac=$(cat /sys/class/net/wlan1/address)
phy=$(cat /sys/class/net/wlan1/phy80211/name)
ip netns add client
iw phy "$phy" set netns name client
ip -n client link set lo up

printf 'correcthorse' > "$work/etc/secrets/home"
chmod 600 "$work/etc/secrets/home"
cat > "$work/etc/netcfgd.conf" <<CONF
interface wlan0 {
	config = "192.168.4.1/24"
	dhcp_server {
		dns = ["192.168.4.1"]
	}
}

access_point "home" {
	device = "wlan0"
	ssid = "686f6d65"
	channel = 6
	wifi { psk = "@secret:home" }
}
CONF
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
"$build/ncfg" plan > "$work/plan-first.log" 2>&1
hostapd_starts=$(grep -cE '^ +[0-9]+ +backend\.start wlan0 +access_point' "$work/plan-first.log")
server_starts=$(grep -cE '^ +[0-9]+ +backend\.start wlan0 +dhcp_server' "$work/plan-first.log")
say "the first plan: $(grep -E 'backend\.start' "$work/plan-first.log" | tr -s ' ' | tr '\n' ';')"
"$build/ncfg" apply > "$work/apply.log" 2>&1
say "ncfg apply rc=$?"

# The daemon, for the socket `wifi clients` reads. The apply above already did
# the work, so it is told not to repeat it on start.
"$build/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
daemon=$!
n=0
while [ ! -e "$work/run/netcfgd.sock" ] && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
[ -e "$work/run/netcfgd.sock" ] || say "  the daemon's socket never appeared"

cat > "$work/sta.conf" <<CONF
ctrl_interface=$work/sta
network={
	ssid="home"
	psk="correcthorse"
}
CONF
ip netns exec client wpa_supplicant -B -i wlan1 -c "$work/sta.conf" -f "$work/sta.log" \
	>/dev/null 2>&1
S() { ip netns exec client wpa_cli -p "$work/sta" -i wlan1 "$@" 2>/dev/null; }
n=0
until S status | grep -q '^wpa_state=COMPLETED' || [ "$n" -gt 300 ]; do
	sleep 0.1
	n=$((n + 1))
done
joined=$(S status | sed -n 's/^wpa_state=//p')
say "the station: ${joined:-no state} after $((n / 10)) s"

: > "$work/given"
ip netns exec client timeout 20 dhcpcd -1 -4 -t 15 -h phone --script /payload/hook.sh wlan1 \
	> "$work/client.log" 2>&1
given=$(cat "$work/given")
say "the station is given: $given"
address=$(printf '%s' "$given" | sed -n 's/.*address=\(192\.168\.4\.[0-9]*\) .*/\1/p')

# The daemon reads the lease file on each request, so a name may lag dnsmasq's
# write by a moment; asked until it is there, bounded.
n=0
until "$build/ncfg" wifi clients wlan0 --json > "$work/clients.json" 2>&1 &&
    grep -q '"hostname":"phone"' "$work/clients.json" || [ "$n" -gt 100 ]; do
	sleep 0.1
	n=$((n + 1))
done
"$build/ncfg" wifi clients wlan0 > "$work/clients.txt" 2>&1
say "ncfg wifi clients wlan0:"
sed 's/^/  | /' "$work/clients.txt" >> "$out"
"$build/ncfg" plan > "$work/plan-again.log" 2>&1
again=$(grep -c '^nothing to do' "$work/plan-again.log")
say "a second plan: $(head -1 "$work/plan-again.log")"

failed=0
[ "$hostapd_starts" -eq 1 ] || { say "  the first plan did not start the access point on wlan0"; failed=1; }
[ "$server_starts" -eq 1 ] || { say "  the first plan did not start a DHCP server on wlan0"; failed=1; }
[ "$joined" = COMPLETED ] || { say "  the station did not join"; failed=1; }
host=${address##*.}
[ -n "$address" ] && [ "$host" -ge 100 ] && [ "$host" -le 249 ] ||
	{ say "  the station was not given an address in the default range"; failed=1; }
case "$given" in *" routers=192.168.4.1 "*) ;; *) say "  the router was not offered"; failed=1 ;; esac
awk -v m="$mac" -v a="$address" 'tolower($1) == tolower(m) && $2 == "phone" && $3 == a \
    {found=1} END {exit !found}' "$work/clients.txt" ||
	{ say "  the text table does not list $mac as phone at ${address:-no address}"; failed=1; }
grep -q '"hostname":"phone"' "$work/clients.json" ||
	{ say "  --json carries no hostname"; failed=1; }
grep -q "\"ipv4\":\"$address\"" "$work/clients.json" ||
	{ say "  --json carries no ipv4 $address"; failed=1; }
[ "$again" -ge 1 ] || { say "  the second plan was not empty"; failed=1; }

# **A guest network (10.648).** A second station, in a namespace of its own and
# addressed by hand outside the pool, so the only path between the two is the
# access point relaying one station's frame to the other -- which is what
# `isolate_stations` stops. The ping to the router after isolation is the
# control that the stations are still on the air: a station that had simply
# fallen off would fail the other ping too.
# The daemon stops first: it watches the file, and an edit it applied on its
# own would leave the plan below with nothing to say about the restart.
kill "$daemon" 2>/dev/null
n=0
while [ -d "/proc/$daemon" ] && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
other=$(cat /sys/class/net/wlan2/phy80211/name)
ip netns add other
iw phy "$other" set netns name other
ip -n other link set lo up
mkdir -p "$work/sta2"
sed "s|$work/sta|$work/sta2|" "$work/sta.conf" > "$work/sta2.conf"
ip netns exec other wpa_supplicant -B -i wlan2 -c "$work/sta2.conf" -f "$work/sta2.log" \
	>/dev/null 2>&1
T() { ip netns exec other wpa_cli -p "$work/sta2" -i wlan2 "$@" 2>/dev/null; }
both_joined() { # $1 tenths of a second
	n=0
	until { S status | grep -q '^wpa_state=COMPLETED' &&
	    T status | grep -q '^wpa_state=COMPLETED'; } || [ "$n" -gt "$1" ]; do
		sleep 0.1
		n=$((n + 1))
	done
	S status | grep -q '^wpa_state=COMPLETED' && T status | grep -q '^wpa_state=COMPLETED'
}
reaches() { # $1 an address, from the first station
	ip netns exec client ping -c 3 -W 1 -i 0.3 "$1" >/dev/null 2>&1
}
both_joined 300 || { say "  the second station did not join"; failed=1; }
ip -n other addr add 192.168.4.51/24 dev wlan2
if reaches 192.168.4.51; then
	say "ok   control: one station reaches the other through the access point"
else
	say "  one station does not reach the other even with nothing isolated"; failed=1
fi
sed 's/^access_point "home" {$/access_point "home" {\n\tisolate_stations = true/' \
	"$work/etc/netcfgd.conf" > "$work/etc/guest.conf"
mv "$work/etc/guest.conf" "$work/etc/netcfgd.conf"
grep -q 'isolate_stations = true' "$work/etc/netcfgd.conf" ||
	{ say "  the document was not given isolate_stations"; failed=1; }
"$build/ncfg" plan > "$work/plan-guest.log" 2>&1
grep -q 'access_point.isolate_stations' "$work/plan-guest.log" &&
    grep -qE 'backend\.stop wlan0' "$work/plan-guest.log" ||
	{ say "  the plan does not restart the access point for isolate_stations"; failed=1; }
say "the plan for isolation: $(grep -E 'backend\.(stop|start) wlan0 +access_point' \
	"$work/plan-guest.log" | tr -s ' ' | tr '\n' ';')"
"$build/ncfg" apply > "$work/apply-guest.log" 2>&1
say "ncfg apply rc=$?"
grep -q '^ap_isolate=1$' "$work/run/hostapd/wlan0.conf" 2>/dev/null ||
	{ say "  hostapd's file carries no ap_isolate=1"; failed=1; }
both_joined 300 || { say "  the stations did not rejoin the restarted access point"; failed=1; }
if reaches 192.168.4.1; then
	say "ok   isolated, the first station still reaches the router"
else
	say "  isolated, the first station does not reach the router either"; failed=1
fi
if reaches 192.168.4.51; then
	say "  isolated, one station still reaches the other"; failed=1
else
	say "ok   and no longer reaches the other station"
fi

if [ "$failed" -ne 0 ]; then
	sed 's/^/  apply: /' "$work/apply.log" | tail -6 >> "$out"
	sed 's/^/  apply-guest: /' "$work/apply-guest.log" 2>/dev/null | tail -8 >> "$out"
	ls "$work/run/hostapd" 2>&1 | sed 's/^/  run\/hostapd: /' >> "$out"
	grep -H '^ap_isolate' "$work/run/hostapd/"*.conf 2>&1 | sed 's/^/  /' >> "$out"
	sed 's/^/  hostapd: /' "$work/run/hostapd/wlan0.log" 2>/dev/null | tail -40 >> "$out"
	for p in /proc/[0-9]*; do
		case "$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)" in
		*hostapd*) say "  process ${p#/proc/}: $(tr '\0' ' ' < "$p/cmdline")" ;;
		esac
	done
	ip -br addr show dev wlan0 | sed 's/^/  ap: /' >> "$out"
	S status | grep -E '^(wpa_state|bssid)=' | sed 's/^/  phone: /' >> "$out"
	sed 's/^/  json: /' "$work/clients.json" | head -20 >> "$out"
	sed 's/^/  client: /' "$work/client.log" | tail -6 >> "$out"
	sed 's/^/  dnsmasq: /' "$work/run/dhcp-server/wlan0.log" 2>/dev/null | tail -6 >> "$out"
	sed 's/^/  leases: /' "$work/run/dhcp-server/wlan0.leases" 2>/dev/null >> "$out"
	sed 's/^/  daemon: /' "$work/daemon.log" | tail -6 >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
