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
