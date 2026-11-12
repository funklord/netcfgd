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
#
# Where the payload gave the guest NICs with an ISP behind them (/payload/isp6,
# /payload/pppoe), they are renamed first, found by the MAC the payload gave each:
# OpenWrt's netifd puts `eth0` in its `lan` bridge at boot, and the netifd test
# below needs `eth0` to be a name netifd claims and nothing holds.
nic() {
	for dev in /sys/class/net/*; do
		# A NIC, not what carries its address: netifd's `br-lan` takes its
		# port's MAC, and matching that renamed the bridge and left the port
		# down (10.815).
		[ -e "$dev/device" ] || continue
		[ "$(cat "$dev/address" 2>/dev/null)" = "$1" ] || continue
		ip link set "${dev##*/}" nomaster 2>/dev/null
		ip link set "${dev##*/}" down
		ip link set "${dev##*/}" name "$2"
		# IPv6 back on: netifd switches it off on a port of its bridge, and
		# whether it got to `eth0` before this did is a race -- one run had a
		# link-local here and the next had none (10.815).
		sysctl -q -w "net.ipv6.conf.$2.disable_ipv6=0" 2>/dev/null
		sysctl -q -w "net.ipv6.conf.$2.accept_dad=0" 2>/dev/null
		ip link set "$2" up
		sleep 1
		echo "$2 was ${dev##*/}: $(nic_state "$2")" >> /tmp/nic.log
	done
}
nic_state() {
	d=/sys/class/net/$1
	echo "carrier $(cat $d/carrier 2>/dev/null), $(cat $d/operstate 2>/dev/null)," \
		"master $(basename "$(readlink $d/master 2>/dev/null)" 2>/dev/null)," \
		"rx $(cat $d/statistics/rx_packets 2>/dev/null) tx $(cat $d/statistics/tx_packets 2>/dev/null)," \
		"flags $(cat $d/flags 2>/dev/null)"
}
[ -e /payload/isp6 ] && nic 52:54:00:12:34:56 isp6
[ -e /payload/pppoe ] && nic 52:54:00:12:34:57 dsl0
[ -e /payload/home ] && nic 52:54:00:12:34:58 home0
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

# And a LAN served, on every tier: lan.sh, beside this file.
. /payload/lan.sh

# And IPv6 from the ISP, where there is one: prefix.sh, beside this file.
if [ -e /payload/isp6 ]; then
	. /payload/prefix.sh
else
	say "prefix delegation: not run, no ISP on this tier (hull-armsr runs it)"
fi

# And PPPoE, where there is a concentrator: pppoe.sh, beside this file.
if [ -e /payload/pppoe ]; then
	. /payload/pppoe.sh
else
	say "pppoe: not run, no access concentrator on this tier (hull-armsr runs it)"
fi

# And a WireGuard tunnel, where the payload brought the module: wg.sh.
if [ -d /payload/wg ]; then
	. /payload/wg.sh
else
	say "wireguard: not run, no module or peer on this tier (hull-armsr runs it)"
fi

# And the stock services restarted under all of it, on every tier: restart.sh.
. /payload/restart.sh

# And a radio, where the image has a wireless stack: radio.sh, beside this file.
if [ -e /payload/no-radio ]; then
	say "radio: not run, $(cat /payload/no-radio)"
else
	. /payload/radio.sh
fi

# What a person has: the package, on this machine. Before the rest of this file
# would have mattered, it has to install, say nothing was started, and go again.
/etc/init.d/netcfgd stop 2>/dev/null
# procd's stop returns before the process has gone, so wait for it, bounded, as
# the shared payload does after its own: counted the moment after a quick apk
# del and add, the daemon still leaving read as one the install had started.
n=0
while [ -n "$(pidof netcfgd)" ] && [ $n -lt 15 ]; do sleep 1; n=$((n + 1)); done
# The shared payload installed it with apk (10.813), so it is taken away the same
# way: files deleted under apk's feet leave it listed, and an add then does nothing.
apk del netcfgd > /dev/null 2>&1
installed=$(apk add --allow-untrusted --no-network --force-non-repository /payload/netcfgd.apk 2>&1 | grep -v WARNING |
	tail -2 | cut -c1-100 | tr '\n' ';')
say "apk: $installed"
listed=$(apk info -e netcfgd 2>/dev/null | grep -c '^netcfgd$')
enabled=$(ls /etc/rc.d 2>/dev/null | grep -c netcfgd)
running=$(pidof netcfgd | wc -w)
say "installed $listed, enabled $enabled, running $running, $(/usr/bin/ncfg --version 2>&1 | head -1)"
[ "$listed" = 1 ] && [ "$enabled" = 0 ] && [ "$running" = 0 ] || failed=1
/usr/bin/ncfg --version 2>/dev/null | grep -q '^ncfg ' || failed=1
# What a firmware upgrade keeps, by `sysupgrade`'s own list, archived and restored:
# what it leaves out is what an upgrade would lose. A router handed to netcfgd has to
# come back still run by it, and as the same node.
/etc/init.d/netcfgd enable
logger keep-mark-one
/etc/init.d/netcfgd start
looks=0
until [ -S /run/netcfgd/fuzznet.sock ] || [ "$looks" -gt 30 ]; do sleep 1; looks=$((looks + 1)); done
sleep 2
# Past a mark, so a line from a daemon before this one cannot answer for it.
node_key() {
	logread | sed -n "/$1/,\$s/.*fuzznetd: identity \([0-9a-f]\{16\}\).*/\1/p" | tail -1
}
before=$(node_key keep-mark-one)
/etc/init.d/netcfgd stop
sleep 2
# `sysupgrade -b` refuses on a ramdisk, which is what this image runs from, so the
# archive is made from `-l`: the list `-b` would have archived.
tar czf /tmp/keep.tgz $(sysupgrade -l 2>/dev/null)
say "sysupgrade kept: $(tar tzf /tmp/keep.tgz | grep -cE 'netcfgd|fuzznet|ncfg') of ours in $(tar tzf /tmp/keep.tgz | wc -l)"
conf=$(tar tzf /tmp/keep.tgz | grep -c 'etc/netcfgd/')
# What a new image is: no netcfgd in apk's database and none of its files, so the
# package is taken away through apk and what apk leaves goes by hand.
apk del netcfgd > /dev/null 2>&1
rm -rf /etc/netcfgd /root/.local/share/fuzznet /usr/sbin/netcfgd /usr/bin/ncfg \
	/etc/init.d/netcfgd /etc/rc.d/S21netcfgd /etc/rc.d/K89netcfgd
tar xzf /tmp/keep.tgz -C /
rm -f /tmp/keep.tgz
logger keep-mark-two
/etc/init.d/netcfgd start
looks=0
until [ -S /run/netcfgd/fuzznet.sock ] || [ "$looks" -gt 30 ]; do sleep 1; looks=$((looks + 1)); done
sleep 2
after=$(node_key keep-mark-two)
say "after the restore: $(ls /etc/rc.d | grep -c netcfgd) start links, $(pidof netcfgd | wc -w) running, node $before then $after"
[ "$conf" -ge 1 ] && [ -n "$before" ] && [ "$before" = "$after" ] && [ -n "$(pidof netcfgd)" ] &&
	[ -e /etc/rc.d/S21netcfgd ] || failed=1
/etc/init.d/netcfgd stop
# And the package installed again over what the upgrade kept, which apk has no
# record of: what a person does next, and what the router guide has to tell them.
readd=$(apk add --allow-untrusted --no-network --force-non-repository /payload/netcfgd.apk 2>&1 |
	grep -v WARNING | tail -2 | cut -c1-140 | tr '\n' ';')
say "apk add over the kept files: $readd listed $(apk info -e netcfgd 2>/dev/null | grep -c '^netcfgd$')"
/etc/init.d/netcfgd disable
apk del netcfgd > /dev/null 2>&1
[ ! -e /usr/sbin/netcfgd ] && [ ! -e /etc/init.d/netcfgd ] || failed=1
say "after removal: $(apk info -e netcfgd 2>/dev/null | grep -c '^netcfgd$') installed, $(ls /usr/sbin/netcfgd 2>/dev/null | wc -l) program"

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
