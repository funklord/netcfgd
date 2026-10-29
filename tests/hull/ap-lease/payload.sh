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
#   - and a second plan has nothing to do.
#
# Always exits 0 and reports through /verdict/ap-lease.
#
# HOW IT STOPS: every wait is bounded (the radios at 5 s, the daemon's socket
# at 5 s, the association at 30 s, dhcpcd at 20 s, the listing at 10 s), the
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

modprobe mac80211_hwsim radios=2
n=0
while [ ! -e /sys/class/net/wlan1 ] && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
[ -e /sys/class/net/wlan1 ] || { say "VERDICT bad: hwsim gave no second radio"; exit 0; }
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
if [ "$failed" -ne 0 ]; then
	sed 's/^/  apply: /' "$work/apply.log" | tail -6 >> "$out"
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
