#!/bin/sh
# netcfgd under OpenWrt's procd (project.md 10.672).
#
# The shipped init script, `packaging/procd/netcfgd`, as an OpenWrt package
# would install it, and these, each with what makes it mean something:
#
#   - procd starts it and lists it running, and the address its document
#     asks for appears on a device netcfgd created;
#   - killed with -9, procd starts another, which is the `respawn` the script
#     is the whole supervision policy for;
#   - an edit to the file alone is applied, by the daemon's inotify watch;
#   - `/etc/init.d/netcfgd reload` applies a second edit, through `ncfg reload`;
#   - **an edit made the moment procd respawns the daemon is applied** --
#     which it was not before 10.672: the daemon compiled before its watch
#     was open, and an edit between the two was lost until the next one;
#   - `stop` takes the process away and leaves the address, since a stop
#     holds (0134).
#
# Always exits 0 and reports through /verdict/openwrt. BusyBox's `sleep`
# takes whole seconds, which is why every wait here counts them.
#
# HOW IT STOPS: every wait is bounded (ubus at 40 s, each change at 20 s),
# the steps are a fixed list, and the vm takes procd and netcfgd with it.
out=/verdict/openwrt
: > "$out"
say() { echo "$*" >> "$out"; echo "openwrt: $*"; }
address() { ip addr show dev dummy0 2>/dev/null | grep -o 'inet [0-9.]*' | tr '\n' ' '; }
wait_for() { # $1 the address; prints the seconds it took, or "never"
	n=0
	until ip addr show dev dummy0 2>/dev/null | grep -q "inet $1/" || [ $n -gt 20 ]; do
		sleep 1
		n=$((n + 1))
	done
	[ $n -gt 20 ] && echo never || echo $n
}
failed=0

say "pid 1 is $(cat /proc/1/comm); $(head -1 /etc/openwrt_release)"
n=0
until ubus call service list >/dev/null 2>&1 || [ $n -gt 40 ]; do sleep 1; n=$((n + 1)); done
ubus call service list >/dev/null 2>&1 || { say "VERDICT bad: procd's ubus never answered"; exit 0; }
insmod /payload/dummy.ko 2>> "$out"

mkdir -p /etc/netcfgd
printf 'device dummy0 {\n\tkind = "dummy"\n}\ninterface dummy0 {\n\tconfig = "192.0.2.1/32"\n}\n' \
	> /etc/netcfgd/netcfgd.conf
cp /payload/netcfgd /usr/sbin/netcfgd && chmod 755 /usr/sbin/netcfgd
ln -sf /usr/sbin/netcfgd /usr/bin/ncfg
cp /repo/packaging/procd/netcfgd /etc/init.d/netcfgd && chmod 755 /etc/init.d/netcfgd

/etc/init.d/netcfgd start
took=$(wait_for 192.0.2.1)
listed=$(ubus call service list '{"name":"netcfgd"}' 2>/dev/null | grep -c '"running": true')
say "started by procd: listed running $listed time(s), dummy0 $(address)after $took s"
[ "$took" != never ] && [ "$listed" -ge 1 ] || failed=1

first=$(pidof netcfgd)
kill -9 "$first"
n=0
until { [ -n "$(pidof netcfgd)" ] && [ "$(pidof netcfgd)" != "$first" ]; } || [ $n -gt 20 ]; do
	sleep 1
	n=$((n + 1))
done
second=$(pidof netcfgd)
say "killed $first; procd started ${second:-nothing}"
[ -n "$second" ] && [ "$second" != "$first" ] || failed=1

# The race: the edit as soon as the new pid is there, no wait at all.
kill -9 "$second"
until { [ -n "$(pidof netcfgd)" ] && [ "$(pidof netcfgd)" != "$second" ]; }; do :; done
sed -i 's#192.0.2.1/#192.0.2.2/#' /etc/netcfgd/netcfgd.conf
took=$(wait_for 192.0.2.2)
say "an edit as procd respawns it: dummy0 $(address)after $took s"
[ "$took" != never ] || failed=1

n=0
until /usr/bin/ncfg status >/dev/null 2>&1 || [ $n -gt 20 ]; do sleep 1; n=$((n + 1)); done
sed -i 's#192.0.2.2/#192.0.2.3/#' /etc/netcfgd/netcfgd.conf
took=$(wait_for 192.0.2.3)
say "an edit alone: dummy0 $(address)after $took s"
[ "$took" != never ] || failed=1

sed -i 's#192.0.2.3/#192.0.2.4/#' /etc/netcfgd/netcfgd.conf
said=$(/etc/init.d/netcfgd reload 2>&1 | head -1)
took=$(wait_for 192.0.2.4)
say "reload ($said): dummy0 $(address)after $took s"
[ "$took" != never ] || failed=1

/etc/init.d/netcfgd stop
n=0
while [ -n "$(pidof netcfgd)" ] && [ $n -lt 15 ]; do sleep 1; n=$((n + 1)); done
left=$(pidof netcfgd)
say "stopped: process ${left:-gone}, dummy0 $(address)"
[ -z "$left" ] && address | grep -q 192.0.2.4 || failed=1

if [ "$failed" -ne 0 ]; then
	logread 2>/dev/null | grep netcfgd | grep -v 'no netfilter socket' | tail -12 |
		sed 's/^/  log: /' >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
