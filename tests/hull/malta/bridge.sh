# The router guide's LAN, sourced by guest.sh after prefix.sh: `say`, `out` and
# `failed` are its, and `delegated` and `advertise` prefix.sh's where it ran.
#
# What `doc/first-run.md` section 10 tells a person to write, and no step before
# this ran: one bridge over the LAN ports, the router's address and its DHCP server
# on the bridge rather than on a port, and on a tier with an ISP the third /64 of the
# delegated prefix advertised on it. A router's LAN ports are DSA ports, one netdev
# each; here they are veths netcfgd makes, `port1` to `port4`, with `host1` to
# `host4` their far ends, so a host on a port asks across the bridge as a laptop on
# a switch port would. Named apart from the guide's `lan1`..`lan4` and `br-lan`
# because wider.conf has a dummy `lan1` and OpenWrt's netifd a `br-lan`.
#
# Asked: hosts on two different ports each get a lease from the bridge's server,
# different addresses; where a prefix was delegated, each also takes an address from
# the bridge's /64 by the advertisement; and the plan after it all is empty.
#
# HOW IT STOPS: each wait counts its seconds; udhcpc quits after its tries.
lan6=
[ -n "${delegated:-}" ] && [ -n "${advertise:-}" ] && lan6=yes
if [ -n "$lan6" ]; then
	bridge_config='config     = ["192.168.8.1/24", "@pd:isp6/2=::1/64"]
	advertise { prefixes = ["@pd:isp6/2"] }'
else
	bridge_config='config     = "192.168.8.1/24"'
fi
cat >> /etc/netcfgd/netcfgd.conf <<CONF
device port1 {
	veth { peer = "host1" }
}
device port2 {
	veth { peer = "host2" }
}
device port3 {
	veth { peer = "host3" }
}
device port4 {
	veth { peer = "host4" }
}
device brlan {
	bridge {
		members = ["port1", "port2", "port3", "port4"]
	}
}
interface brlan {
	$bridge_config
	forwarding = true
	dhcp_server {
		dns = ["192.168.8.1"]
	}
}
CONF
n=0
until [ -e /sys/class/net/host1 ] && [ -e /sys/class/net/host3 ] || [ $n -gt 30 ]; do
	sleep 1
	n=$((n + 1))
done
# Hosts up before anything advertises, for prefix.sh's reasons.
for host in host1 host3; do
	sysctl -q -w "net.ipv6.conf.$host.accept_ra=2" 2>/dev/null
	sysctl -q -w "net.ipv6.conf.$host.accept_dad=0" 2>/dev/null
	ip link set "$host" up 2>/dev/null
done
n=0
# 120 s: four veths, a bridge and a server on an emulated CPU, which a loaded host
# slows several times over -- the first run here gave up at 40 s with nothing yet.
until [ -s /run/netcfgd/dhcp-server/brlan.pid ] &&
	[ "$(ls /sys/class/net/brlan/brif 2>/dev/null | wc -w)" = 4 ] || [ $n -gt 120 ]; do
	sleep 1
	n=$((n + 1))
done
say "brlan after $n s: ports $(ls /sys/class/net/brlan/brif 2>/dev/null | tr '\n' ' '); $(ip -o -4 addr show dev brlan 2>/dev/null | awk '{print $4}'); server $(cat /run/netcfgd/dhcp-server/brlan.pid 2>/dev/null || echo none)"
leased1=$(udhcpc -i host1 -n -q -t 6 -T 2 -s /bin/true 2>&1 |
	sed -n 's/.*lease of \([0-9.]*\) obtained from \([0-9.]*\).*/\1 from \2/p' | tail -1)
leased3=$(udhcpc -i host3 -n -q -t 6 -T 2 -s /bin/true 2>&1 |
	sed -n 's/.*lease of \([0-9.]*\) obtained from \([0-9.]*\).*/\1 from \2/p' | tail -1)
say "host1 on port1: ${leased1:-nothing}; host3 on port3: ${leased3:-nothing}"
case "$leased1" in
192.168.8.*" from 192.168.8.1") ;;
*) failed=1 ;;
esac
case "$leased3" in
192.168.8.*" from 192.168.8.1") ;;
*) failed=1 ;;
esac
[ "${leased1%% *}" != "${leased3%% *}" ] || failed=1
if [ -n "$lan6" ]; then
	n=0
	until ip -o -6 addr show dev host1 scope global 2>/dev/null | grep -q . &&
		ip -o -6 addr show dev host3 scope global 2>/dev/null | grep -q . || [ $n -gt 40 ]; do
		sleep 1
		n=$((n + 1))
	done
	on_bridge=$(ip -o -6 addr show dev brlan scope global 2>/dev/null | awk '{print $4}' | head -1)
	took1=$(ip -o -6 addr show dev host1 scope global 2>/dev/null | awk '{print $4}' | head -1)
	took3=$(ip -o -6 addr show dev host3 scope global 2>/dev/null | awk '{print $4}' | head -1)
	say "brlan's /64 ${on_bridge:-none}; after $n s host1 took ${took1:-nothing}, host3 ${took3:-nothing}"
	prefix=$(echo "$on_bridge" | cut -d: -f1-4)
	case "$took1" in "$prefix":*/64) ;; *) failed=1 ;; esac
	case "$took3" in "$prefix":*/64) ;; *) failed=1 ;; esac
	[ -n "$prefix" ] || failed=1
else
	say "brlan's IPv6: not run, no delegated prefix and advertiser on this tier"
fi
n=0
until /usr/bin/ncfg plan 2>/dev/null | grep -q 'nothing to do' || [ $n -gt 20 ]; do
	sleep 1
	n=$((n + 1))
done
settled=$(/usr/bin/ncfg plan 2>/dev/null | grep -c 'nothing to do')
say "the plan after the bridge, $n s on: $([ "$settled" -ge 1 ] && echo 'nothing to do' || echo 'still wants something')"
[ "$settled" -ge 1 ] || {
	failed=1
	/usr/bin/ncfg plan 2>&1 | grep -vE '^warning: (lan1|port[1-4]):' | head -24 | cut -c1-200 |
		sed 's/^/  plan: /' >> "$out"
	ip -br link 2>/dev/null | grep -E 'port|host[1-4]|brlan' | sed 's/^/  link: /' >> "$out"
	logread 2>/dev/null | grep netcfgd | grep -vE 'fuzznetd:' | tail -25 | cut -c1-200 |
		sed 's/^/  log: /' >> "$out"
}

# And a guest network the way a router has one (10.839): a second bridge whose
# port is a VLAN on a port, neither with an `interface` block, the VLAN's name
# sorting before its parent's -- the order that created the VLAN first and left
# its parent down. The port is a veth netcfgd makes, `zport`, with `zhost` its far
# end; the VLAN is `guest10`.
cat >> /etc/netcfgd/netcfgd.conf <<'CONF'
device zport {
	veth { peer = "zhost" }
}
device guest10 {
	vlan {
		parent = "zport"
		id     = 10
	}
}
device brguest {
	bridge {
		members = ["guest10"]
	}
}
interface brguest {
	config = "192.168.10.1/24"
}
CONF
# Read from /sys: OpenWrt's BusyBox `ip` has no `-br`, which the first version of
# this step used and so read nothing while netcfgd had done all of it.
state_of() {
	f=$(cat "/sys/class/net/$1/flags" 2>/dev/null)
	[ -n "$f" ] && [ $((f & 1)) = 1 ] && echo up || echo down
}
n=0
until [ "$(state_of brguest)" = up ] && [ "$(state_of zport)" = up ] &&
	[ "$(state_of guest10)" = up ] &&
	ip -o -4 addr show dev brguest 2>/dev/null | grep -q '192.168.10.1/' || [ $n -gt 60 ]; do
	sleep 1
	n=$((n + 1))
done
guest="zport=$(state_of zport) guest10=$(state_of guest10) brguest=$(state_of brguest) $(ip -o -4 addr show dev brguest 2>/dev/null | awk '{print $4}')"
say "the guest bridge on a VLAN after $n s: $guest"
case "$guest" in
"zport=up guest10=up brguest=up 192.168.10.1/24") ;;
*)
	failed=1
	/usr/bin/ncfg plan 2>&1 | grep -E 'zport|guest10|brguest' | head -8 | cut -c1-200 |
		sed 's/^/  plan: /' >> "$out"
	logread 2>/dev/null | grep netcfgd | grep -E 'zport|guest10|brguest' | tail -6 |
		cut -c1-200 | sed 's/^/  log: /' >> "$out"
	;;
esac
