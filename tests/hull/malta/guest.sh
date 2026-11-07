#!/bin/sh
# Inside OpenWrt: the router test, then what only a real kernel can answer, then
# the verdict on the console and a reboot, which ends qemu.
#
# The second half is a document wide enough to reach what byte order can break:
# a vlan id, a bridge, a route, and nftables, whose ports are big-endian inside
# messages whose integers are native. Three witnesses, none of them netcfgd's own
# word for what it did: the kernel's vlan table, `nft`, and then `ncfg plan` having
# nothing to do, which needs everything observed to compare equal to what was asked.
#
# HOW IT STOPS: the router test bounds its own waits, each wait here counts its
# seconds, and `reboot -f` is unconditional.
sh /payload/payload.sh

out=/verdict/wider
: > "$out"
say() { echo "$*" >> "$out"; }
failed=0

cp /payload/wider.conf /etc/netcfgd/netcfgd.conf
ip link del dummy0 2>/dev/null
/etc/init.d/netcfgd start
n=0
until grep -q '^vlan10 ' /proc/net/vlan/config 2>/dev/null &&
	ip addr show dev vlan10 2>/dev/null | grep -q 'inet 192.168.10.1/' || [ $n -gt 60 ]; do
	sleep 1
	n=$((n + 1))
done
say "applied after $n s"
line=$(grep '^vlan10 ' /proc/net/vlan/config 2>/dev/null | tr -s ' ')
say "the kernel's vlan table: ${line:-nothing}"
echo "$line" | grep -q '| 10 | lan0' || failed=1
master=$(cat /sys/class/net/lan1/master/uevent 2>/dev/null | sed -n 's/^INTERFACE=//p')
say "lan1 is a port of: ${master:-nothing}"
[ "$master" = br0 ] || failed=1
route=$(ip route show 198.51.100.0/24 2>/dev/null)
say "the route: ${route:-nothing}"
echo "$route" | grep -q 'via 203.0.113.2' || failed=1

n=0
until nft list table inet netcfgd > /tmp/ruleset 2>&1 || [ $n -gt 30 ]; do
	sleep 1
	n=$((n + 1))
done
say "nft: $(grep -c . /tmp/ruleset) line(s) in netcfgd's table"
grep -E 'dport' /tmp/ruleset | sed 's/^[[:space:]]*//' | cut -c1-110 >> "$out"
grep -q 'tcp dport 443 dnat ip to 192.168.1.10:8443' /tmp/ruleset || failed=1
grep -q 'udp dport 137 drop' /tmp/ruleset && grep -q 'udp dport 138 drop' /tmp/ruleset || failed=1

n=0
until /usr/bin/ncfg plan > /tmp/plan 2>&1 && grep -q 'nothing to do' /tmp/plan || [ $n -gt 30 ]; do
	sleep 1
	n=$((n + 1))
done
say "a second plan says: $(head -3 /tmp/plan | cut -c1-100 | tr '\n' ' ')"
grep -q 'nothing to do' /tmp/plan || failed=1
/usr/bin/ncfg status > /tmp/status 2>&1
say "ncfg status left with $?, $(grep -c . /tmp/status) line(s)"

# And the manager a stock router has: netifd, told of `eth0` by OpenWrt itself and
# running all along. Given the same device, netcfgd has to say so (10.746).
say "netifd: $(pidof netifd | wc -w) process(es), $(grep -c eth0 /etc/config/network) eth0 line(s)"
printf 'device eth0 {\n\tkind = "dummy"\n}\ninterface eth0 {\n\tconfig = "192.168.3.1/24"\n}\n' \
	>> /etc/netcfgd/netcfgd.conf
n=0
until { /usr/bin/ncfg plan 2>&1; logread; } | grep -q 'netifd also manages' || [ $n -gt 30 ]; do
	sleep 1
	n=$((n + 1))
done
told=$({ /usr/bin/ncfg plan 2>&1; logread; } | grep 'netifd also manages' | tail -1 | cut -c1-150)
say "netcfgd says: ${told:-nothing of netifd}"
[ -n "$told" ] || failed=1

# A WAN port on DHCP, the commonest thing a router is told: OpenWrt's busybox
# udhcpc under netcfgd, on one end of a pair netcfgd makes, and OpenWrt's dnsmasq
# on the other. The stock dnsmasq is stopped for the port, and with no `lan` here
# it was serving nothing; the stock firewall rejects input on a device it has no
# zone for, which a DHCP server's socket is behind and a client's raw one is not.
/etc/init.d/dnsmasq stop 2>/dev/null
/etc/init.d/firewall stop 2>/dev/null
insmod /payload/veth.ko 2>> "$out"
printf 'device wan1 {\n\tveth {\n\t\tpeer = "isp1"\n\t}\n}\ninterface isp1 {\n\tconfig = "192.168.77.1/24"\n}\ninterface wan1 {\n\tconfig = "dhcp"\n}\n' \
	>> /etc/netcfgd/netcfgd.conf
n=0
until ip addr show dev isp1 2>/dev/null | grep -q 'inet 192.168.77.1/' || [ $n -gt 30 ]; do
	sleep 1
	n=$((n + 1))
done
say "the far end is up after $n s"
dnsmasq --conf-file=/dev/null --port=0 --interface=isp1 --bind-interfaces \
	--dhcp-range=192.168.77.50,192.168.77.60,1h --dhcp-leasefile=/tmp/leases \
	--pid-file=/tmp/isp.pid 2>> "$out"
n=0
until ip addr show dev wan1 2>/dev/null | grep -q 'inet 192.168.77.' || [ $n -gt 60 ]; do
	sleep 1
	n=$((n + 1))
done
lease=$(ip addr show dev wan1 2>/dev/null | sed -n 's/.*inet \(192.168.77.[0-9]*\).*/\1/p')
say "wan1 took ${lease:-nothing} after $n s, by $(pidof udhcpc | wc -w) udhcpc"
say "dnsmasq gave: $(cut -d' ' -f3 /tmp/leases 2>/dev/null | tr '\n' ' ')"
[ -n "$lease" ] && grep -q "$lease" /tmp/leases 2>/dev/null || {
	failed=1
	say "dnsmasq running: $(pidof dnsmasq | wc -w), tables: $(nft list tables 2>/dev/null | tr '\n' ' ')"
	ps w | grep -E '[u]dhcpc|[d]nsmasq' | cut -c1-120 >> "$out"
	logread | grep -E 'dnsmasq|udhcpc' | tail -10 | cut -c1-130 >> "$out"
}
[ -f /tmp/isp.pid ] && kill "$(cat /tmp/isp.pid)"
if [ "$failed" -ne 0 ]; then
	logread 2>/dev/null | grep netcfgd | tail -14 | sed 's/^/  log: /' >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
/etc/init.d/netcfgd stop

echo GUEST-BEGIN
uname -srm
grep -E 'MemTotal|MemAvailable' /proc/meminfo
cat /verdict/openwrt
cat "$out"
echo GUEST-END
sleep 1
reboot -f
