# The stock services restarted under netcfgd, sourced by guest.sh after lan.sh:
# `say`, `out` and `failed` are its.
#
# What LuCI's "Save & Apply" does to a router a dozen times a day: `network`,
# `firewall` and `dnsmasq` restarted. The firewall's restart is `fw4 flush`, which
# deletes netcfgd's table with every other (0318); netifd's restart takes down
# what it manages and may take more; and the stock dnsmasq, enabled on every
# OpenWrt and stopped for the tests before this one, comes back up beside
# netcfgd's own on lan4. After each, netcfgd's state has to be there within a
# few ticks, and a host on lan4 still has to be served (10.821).
#
# HOW IT STOPS: each wait counts its seconds; udhcpc quits after its tries.
state() {
	echo "$(nft list table inet netcfgd 2>/dev/null | grep -c .) table line(s)," \
		"lan4 $(ip -o -4 addr show dev lan4 2>/dev/null | awk '{print $4}')," \
		"$(pidof dnsmasq | wc -w) dnsmasq"
}
whole() {
	nft list table inet netcfgd > /dev/null 2>&1 &&
		ip -o -4 addr show dev lan4 2>/dev/null | grep -q '192.168.7.1/' &&
		[ -s /run/netcfgd/dhcp-server/lan4.pid ] &&
		[ -d "/proc/$(cat /run/netcfgd/dhcp-server/lan4.pid)" ]
}
say "before the restarts: $(state)"
for service in network firewall dnsmasq; do
	/etc/init.d/$service restart > /dev/null 2>&1
	n=0
	until whole || [ $n -gt 20 ]; do
		sleep 1
		n=$((n + 1))
	done
	say "after \`$service restart\`: whole after $n s: $(state)"
	whole || failed=1
done
# And the LAN served with OpenWrt's own dnsmasq running, as it is on every router.
# The firewall is stopped again first, as the router guide says to: restarted, fw4
# rejects input on a device with no zone, a DHCP server's included -- which is what
# first read as the two dnsmasqs clashing (10.821). They do not: both hold
# 0.0.0.0:67, a broadcast DISCOVER reaches both, and the stock one has no range for
# lan4 and leaves it to netcfgd's.
/etc/init.d/firewall stop > /dev/null 2>&1
n=0
until whole || [ $n -gt 20 ]; do
	sleep 1
	n=$((n + 1))
done
say "the firewall stopped again: whole after $n s: $(state)"
leased=$(udhcpc -i client4 -n -q -t 6 -T 2 -s /bin/true 2>&1 |
	sed -n 's/.*lease of \([0-9.]*\) obtained from \([0-9.]*\).*/\1 from \2/p' | tail -1)
say "client4 beside the stock dnsmasq: ${leased:-nothing}; $(netstat -lunp 2>/dev/null | grep -c ':67 ') socket(s) on port 67"
case "$leased" in
192.168.7.*" from 192.168.7.1") ;;
*)
	failed=1
	ps w | grep '[d]nsmasq' | cut -c1-160 >> "$out"
	logread | grep -E 'dnsmasq-dhcp|DHCP' | tail -8 | cut -c1-160 | sed 's/^/  syslog: /' >> "$out"
	nft list ruleset 2>/dev/null | grep -E '^table|hook input' | sed 's/^/  nft: /' >> "$out"
	;;
esac

# And the LAN's resolver. On OpenWrt that is the stock dnsmasq, which binds port 53
# on every address the router has as it appears (`bind-dynamic`), the LAN's
# included -- so `dns_forward` cannot be had beside it: netcfgd's dnsmasq for the
# LAN would not start ("Address in use"), and took the LAN's DHCP down with it
# (10.825). What fits OpenWrt is to leave the forwarder off and offer the router,
# which the stock dnsmasq answers: checked here, the offer and the answer both.
sed -i 's/dns = \["192.168.7.53"\]/dns = ["192.168.7.1"]/' /etc/netcfgd/netcfgd.conf
n=0
until grep -q '192.168.7.1' /run/netcfgd/dhcp-server/lan4.conf 2>/dev/null && whole || [ $n -gt 30 ]; do
	sleep 1
	n=$((n + 1))
done
offered=$(udhcpc -i client4 -n -q -t 6 -T 2 -s /bin/true -O dns 2>&1 | grep -c 'lease of')
answer=$(nslookup localhost 192.168.7.1 2>&1 | sed -n 's/^Address[^:]*: *\(127\.0\.0\.1\).*/\1/p' | head -1)
say "the router offered as the LAN's resolver after $n s: $offered lease(s); localhost at 192.168.7.1 is ${answer:-not answered}, by $(netstat -lunp 2>/dev/null | grep '192.168.7.1:53 ' | awk '{print $NF}' | head -1)"
grep -q 'dhcp-option=.*6,192.168.7.1\|option:dns-server,192.168.7.1' /run/netcfgd/dhcp-server/lan4.conf 2>/dev/null ||
	say "  lan4.conf offers: $(grep -i 'dhcp-option' /run/netcfgd/dhcp-server/lan4.conf 2>/dev/null | tr '\n' ' ')"
[ "$offered" -ge 1 ] && [ "$answer" = 127.0.0.1 ] && whole || failed=1

# And `dns_forward` there after all, as the holder decided (10.827): its forwarder
# cannot have port 53 beside the stock dnsmasq, and where that took the LAN's DHCP
# down with it, the server now comes back without the forwarder, offers the
# router's address -- the stock dnsmasq answers it -- and the plan says so.
sed -i 's/dns = \["192.168.7.1"\]/dns_forward = true/' /etc/netcfgd/netcfgd.conf
n=0
until grep -q '^# forwarder off: ' /run/netcfgd/dhcp-server/lan4.conf 2>/dev/null && whole ||
	[ $n -gt 30 ]; do
	sleep 1
	n=$((n + 1))
done
printf '#!/bin/sh\n[ "$1" = bound ] && echo "offered dns $dns"\nexit 0\n' > /tmp/show-dns
chmod 755 /tmp/show-dns
offered=$(udhcpc -i client4 -n -q -t 6 -T 2 -s /tmp/show-dns -O dns 2>&1 |
	sed -n 's/^offered dns //p' | tail -1)
warned=$(/usr/bin/ncfg plan 2>&1 | grep -c 'DNS forwarder on lan4 is not running')
say "dns_forward beside the stock dnsmasq, after $n s: $(sed -n 's/^# forwarder off: //p' /run/netcfgd/dhcp-server/lan4.conf 2>/dev/null | cut -c1-90); offered dns ${offered:-nothing}; plan warns: $warned"
rm -f /tmp/show-dns
[ "$offered" = 192.168.7.1 ] && [ "$warned" -ge 1 ] && whole || {
	failed=1
	tail -4 /run/netcfgd/dhcp-server/lan4.log 2>/dev/null | sed 's/^/  dnsmasq: /' >> "$out"
	/usr/bin/ncfg plan 2>&1 | head -12 | cut -c1-160 | sed 's/^/  plan: /' >> "$out"
}
