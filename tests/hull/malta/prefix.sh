# The IPv6 half of a WAN, sourced by guest.sh: `say`, `out` and `failed` are its.
# Run where the payload put an ISP on the far side of a NIC and said so in
# /payload/isp6 -- `hull-armsr`, whose outer machine runs kea-dhcp6 on the tap the
# guest's virtio NIC is, delegating from 2001:db8:1234::/48 at /56 (10.815).
#
# What a router on a DHCPv6 ISP is for: ask for a prefix on the WAN, number the
# LAN out of it and tell the LAN's hosts, with OpenWrt's own odhcp6c under
# netcfgd and nobody typing `ncfg apply` when the prefix arrives -- under procd
# there is nobody to. The document is `tests/live/delegation.sh`'s (decision
# 0009), whose CPE applies by hand after the prefix comes; here the daemon has
# to see it itself.
#
# The advertisement is uradvd's where the payload brought it (/payload/uradvd.apk):
# OpenWrt 25.12 has no radvd in any feed, and uradvd is in its packages feed
# (10.817). The LAN is a veth pair, so a host is there to act on it: `host6` is
# no interface of the document's and hears from netcfgd only by the wire.
#
# HOW IT STOPS: each wait counts its seconds.

# The NIC was renamed `isp6` before netifd's own test (see guest.sh), so the stock
# `lan` bridge does not hold it and `eth0` stays the name netifd's config claims.
# DAD off for the reason cpe.sh gives: a solicit needs a link-local that is usable.
sed 's/^/  at the rename: /' /tmp/nic.log >> "$out" 2>/dev/null
say "  now: $(nic_state isp6)"
say "isp6: $(cat /sys/class/net/isp6/address 2>/dev/null || echo missing), $(ip -o -6 addr show dev isp6 scope link 2>/dev/null | awk '{print $4}'), carrier $(cat /sys/class/net/isp6/carrier 2>/dev/null), disable_ipv6 $(cat /proc/sys/net/ipv6/conf/isp6/disable_ipv6 2>/dev/null)"
advertise=
if [ -e /payload/uradvd.apk ]; then
	# From a file onto a root in RAM, so told it may, as netcfgd's own package is
	# in tests/hull/openwrt/payload.sh (10.813).
	force=
	[ -e /payload/ramdisk-root ] && force=--force-non-repository
	apk add --allow-untrusted --no-network $force /payload/uradvd.apk 2>&1 | grep -v WARNING |
		tail -2 >> "$out"
	say "uradvd: $(command -v uradvd || echo not installed), enabled by the package: $(ls /etc/rc.d | grep -c uradvd)"
	advertise='	advertise { prefixes = ["@pd:isp6"] }'
fi
cat >> /etc/netcfgd/netcfgd.conf <<CONF
device lan6 {
	veth {
		peer = "host6"
	}
}
interface isp6 {
	config = "dhcp6 pd_length 56"
}
interface lan6 {
	config     = "@pd:isp6=::1/64"
	forwarding = true
$advertise
}
CONF
# The host end, before anything advertises, for the reasons delegation.sh gives:
# a host switched on after the first advertisement waits for the next, and
# `accept_ra=2` is what takes one on a machine that forwards, which a router is.
n=0
until [ -e /sys/class/net/host6 ] || [ $n -gt 30 ]; do
	sleep 1
	n=$((n + 1))
done
sysctl -q -w net.ipv6.conf.host6.accept_ra=2 2>/dev/null
sysctl -q -w net.ipv6.conf.host6.accept_dad=0 2>/dev/null
ip link set host6 up 2>/dev/null
n=0
until [ -s /run/netcfgd/prefixes/isp6 ] || [ $n -gt 120 ]; do
	sleep 1
	n=$((n + 1))
done
delegated=$(head -1 /run/netcfgd/prefixes/isp6 2>/dev/null)
say "delegated on isp6 after $n s: ${delegated:-nothing}, by $(pidof odhcp6c | wc -w) odhcp6c"
if [ -z "$delegated" ]; then
	failed=1
	say "  all-nodes on isp6: $(ping -6 -c 2 -W 2 -I isp6 ff02::1 2>&1 | grep -c 'bytes from') repl(ies)"
	ps w | grep '[o]dhcp6c' | cut -c1-120 >> "$out"
	for log in /run/netcfgd/dhcp/*.log; do
		[ -f "$log" ] && tail -8 "$log" | sed "s|^|  $log: |" | cut -c1-130 >> "$out"
	done
	nft list ruleset 2>/dev/null | grep -nE 'hook input|policy|546|dhcpv6' | head -8 >> "$out"
	# odhcp6c says what it made of the server's answers only when asked to: so,
	# netcfgd's stopped, one run by hand, at its loudest (`-l7`) and to stderr, for 20 s.
	kill $(pidof odhcp6c) 2>/dev/null
	sleep 1
	odhcp6c -e -l7 -P 56 -s /bin/true isp6 > /tmp/odhcp6c.log 2>&1 &
	probe=$!
	sleep 20
	kill $probe 2>/dev/null
	grep -v '^$' /tmp/odhcp6c.log | tail -25 | cut -c1-160 | sed 's/^/  odhcp6c: /' >> "$out"
	cat /proc/sys/net/ipv6/conf/isp6/forwarding /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null |
		tr '\n' ' ' | sed 's/^/  forwarding (isp6, all): /' >> "$out"
	echo >> "$out"
else
	# Relational, as cpe.sh's: lan6's network is the delegated one's.
	network=${delegated%%::*}
	n=0
	got=
	until [ -n "$got" ] || [ $n -gt 60 ]; do
		got=$(ip -o -6 addr show dev lan6 2>/dev/null | awk '{print $4}' | grep -v '^fe80' | head -1)
		[ -n "$got" ] || sleep 1
		n=$((n + 1))
	done
	say "lan6 carries ${got:-nothing} after $n s more, with no apply asked for"
	case "$got" in
	"$network":*) ;;
	*)
		failed=1
		/usr/bin/ncfg plan 2>&1 | head -6 | cut -c1-120 | sed 's/^/  plan: /' >> "$out"
		;;
	esac
	# And the hosts told: an address the kernel made itself (`dynamic`, an
	# advertisement's lifetime on it) out of the delegated network, and the
	# router as the default route -- the lifetime uradvd would otherwise have
	# sent is 0, which says it is not one.
	if [ -n "$advertise" ]; then
		ip link set host6 down
		ip link set host6 up
		n=0
		host=
		until [ -n "$host" ] || [ $n -gt 40 ]; do
			host=$(ip -6 -o addr show dev host6 2>/dev/null | grep "inet6 $network:" |
				grep dynamic | awk '{print $4}' | head -1)
			[ -n "$host" ] || sleep 1
			n=$((n + 1))
		done
		route=$(ip -6 route show default dev host6 2>/dev/null | head -1)
		say "host6 took ${host:-nothing} after $n s, default route ${route:-none}, by $(pidof uradvd | wc -w) uradvd"
		case "$host" in
		"$network":*) [ -n "$route" ] || failed=1 ;;
		*)
			failed=1
			ps w | grep '[u]radvd' | cut -c1-160 >> "$out"
			tail -5 /run/netcfgd/radvd/lan6.log 2>/dev/null | sed 's/^/  uradvd: /' >> "$out"
			/usr/bin/ncfg plan 2>&1 | grep -iE 'advert|uradvd|radvd' | head -4 |
				cut -c1-160 | sed 's/^/  plan: /' >> "$out"
			;;
		esac
	fi
fi
