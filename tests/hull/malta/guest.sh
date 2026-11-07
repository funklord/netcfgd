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
