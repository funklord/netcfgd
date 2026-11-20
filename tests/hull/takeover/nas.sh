#!/bin/sh
# dl180g6-01 as it is today, then switched to netcfgd (project.md 10.884).
#
# Phase A: sysvinit has booted the image with ifupdown (eth0 by DHCP, eth1
# static) and iptables-persistent loading rules.v4 from rcS.d -- the box as
# system-notes captured it. Phase B: netcfgd installed the way the package
# would install it, given the translated document, and selected with
# netcfgd_select.sh; iptables-persistent retired by hand, which is the step
# the switcher does not do. The router probes both phases from outside;
# this checks what only the inside can see, then writes the verdict.
#
# Always exits 0 and reports through /verdict/nas.
#
# HOW IT STOPS: every wait is bounded (240 s at most); the listeners exit
# by themselves after ten minutes; the machine ends with this.
set -u
PATH=/usr/sbin:/sbin:/usr/bin:/bin
v=/verdict
out=$v/nas
: > "$out"
failed=0
say() { echo "$*" >> "$out"; echo "nas: $*"; }
check() { # $1 what, $2 actual, $3 expected
	if [ "$2" = "$3" ]; then say "ok   $1"; else say "FAIL $1 -- expected '$3', got '$2'"; failed=1; fi
}
gap() { # $1 what, $2 actual, $3 wanted: a known gap, reported and not failed
	if [ "$2" = "$3" ]; then say "ok   $1"; else say "GAP  $1 -- wanted '$3', got '$2'"; fi
}
waitfor() { n=0; while ! eval "$1" >/dev/null 2>&1 && [ "$n" -lt "$(($2 * 2))" ]; do sleep 0.5; n=$((n + 1)); done; eval "$1" >/dev/null 2>&1; }
from_router() { sed -n "s/^$2 //p" $v/router-$1; }

say "     pid 1: $(cat /proc/1/comm), $(cat /etc/devuan_version 2>/dev/null)"
say "     kernel $(uname -r); modules $(ls /lib/modules 2>&1 | tr '\n' ' '); nf_tables: $(modprobe nf_tables 2>&1 && echo loaded)"
# **sysv-rc or OpenRC under sysvinit**: the DL180s run the first, ml350 the
# second (project.md 10.845), and `hull-takeover-openrc` boots this payload
# on an image of that shape. Either way init reaches runlevel 2; OpenRC also
# records its own softlevel.
if ! waitfor '[ "$(runlevel 2>/dev/null | cut -d" " -f2)" = 2 ]' 120; then
	say "VERDICT bad: sysvinit never reached runlevel 2 ($(runlevel 2>&1))"
	exit 0
fi
rc=sysv-rc
if [ -d /run/openrc ]; then
	rc=openrc
	waitfor '[ -f /run/openrc/softlevel ]' 60
fi
say "     rc system: $rc"
python3 /payload/listen.py 22 2049 635 8443 &

# ---- Phase A, as the box is today.
waitfor 'ip -4 addr show eth0 | grep -q 10.0.0.11' 120
check "A: ifupdown's dhclient leased eth0 its reserved 10.0.0.11" \
	"$(ip -4 -br addr show eth0 | grep -o 10.0.0.11)" "10.0.0.11"
check "A: eth1 has its static storage address" "$(ip -4 -br addr show eth1 | grep -o 10.1.0.1/24)" "10.1.0.1/24"
check "A: iptables-persistent loaded rules.v4 at boot" "$(iptables -S INPUT | head -1)" "-P INPUT DROP"
ip -6 -o addr show dev eth0 scope link | awk '{ sub("/.*", "", $4); print $4 }' > $v/nas-ll
touch $v/nas-A-ready
if ! waitfor "[ -f $v/router-A-done ]" 240; then
	say "VERDICT bad: the router never probed phase A"
	exit 0
fi

# ---- Phase B: netcfgd, installed as the package installs it.
install -m 0755 /repo/c/netcfgd /usr/sbin/netcfgd
ln -sf /usr/sbin/netcfgd /usr/bin/ncfg
install -m 0755 /repo/packaging/sysvinit/netcfgd /etc/init.d/netcfgd
# dhcpcd's hook, which `make install` and the package place: without it
# netcfgd refuses to start dhcpcd, saying why (a lease's nameservers would
# never reach it). The rig's first run missed it, and the log said so.
install -d /usr/libexec/netcfgd
install -m 0755 /repo/packaging/hooks/dhcpcd-hook /usr/libexec/netcfgd/dhcpcd-hook
install -d /etc/netcfgd
install -m 0644 /payload/netcfgd.conf /etc/netcfgd/netcfgd.conf
ncfg plan > $v/nas-plan.txt 2>&1
check "B: the translated document compiles and plans" "$(grep -c 'error' $v/nas-plan.txt)" "0"
# Before the flush, iptables-nft's tables are still there: the plan names
# them, each with its family, as nft does -- `ip filter` and `ip6 filter`.
check "B: the plan names iptables' IPv4 table beside netcfgd's" \
	"$(grep -c '`ip filter/INPUT (input)' $v/nas-plan.txt)" "1"
check "B: and its IPv6 table, as another" \
	"$(grep -c 'ip6 filter/INPUT (input)' $v/nas-plan.txt)" "1"
# The firewall handover, by hand: netcfgd does not touch another program's
# table, so rules.v4 would go on filtering beside netcfgd's.
netfilter-persistent flush > $v/nas-flush.log 2>&1
if [ "$rc" = openrc ]; then
	# Out of whichever runlevels OpenRC put it in.
	for level in $(rc-update show -v 2>/dev/null | sed -n 's/^ *netfilter-persistent | *//p'); do
		rc-update del netfilter-persistent "$level" >> $v/nas-flush.log 2>&1
	done
else
	update-rc.d netfilter-persistent disable >> $v/nas-flush.log 2>&1
fi
sh /repo/packaging/netcfgd_select.sh netcfgd > $v/nas-select.log 2>&1
say "     select exited $?"
waitfor 'ip -4 addr show eth0 | grep -q 10.0.0.11 && ! pgrep -x dhclient' 120
check "B: no dhclient left from ifupdown" "$(pgrep -x dhclient | wc -l)" "0"
check "B: the switcher does not credit it to an absent NetworkManager" \
	"$(grep -c 'left behind by networkmanager' $v/nas-select.log)" "0"
check "B: netcfgd's DHCP client holds eth0's lease" "$(ip -4 -br addr show eth0 | grep -o 10.0.0.11)" "10.0.0.11"
check "B: eth1 keeps its storage address" "$(ip -4 -br addr show eth1 | grep -o 10.1.0.1/24)" "10.1.0.1/24"
check "B: netcfgd is running" "$(pgrep -x netcfgd | wc -l | tr -d ' ')" "1"
check "B: iptables holds no rules of its own now" "$(iptables -S INPUT | head -1)" "-P INPUT ACCEPT"
if [ "$rc" = openrc ]; then
	# The runlevels OpenRC reads, not /etc/rc?.d, which nothing reads here.
	check "B: netcfgd starts at boot" "$(rc-update show 2>/dev/null | grep -c '^ *netcfgd |')" "1"
	check "B: ifupdown does not" "$(rc-update show 2>/dev/null | grep -c '^ *networking |')" "0"
	check "B: iptables-persistent does not" "$(rc-update show 2>/dev/null | grep -c '^ *netfilter-persistent |')" "0"
else
	# Start links only: `update-rc.d disable` turns an S link into a K link in
	# the same directory, so a disabled script is still listed there.
	check "B: netcfgd starts at boot" "$(ls /etc/rc2.d | grep -c '^S.*netcfgd$')" "1"
	check "B: ifupdown does not" "$(ls /etc/rcS.d /etc/rc2.d | grep -c '^S.*networking$')" "0"
	check "B: iptables-persistent does not" "$(ls /etc/rcS.d /etc/rc2.d | grep -c '^S.*netfilter-persistent$')" "0"
fi
ncfg status > $v/nas-status.txt 2>&1
for f in /run/netcfgd/dhcpcd/* /run/netcfgd/udhcpc/*; do
	[ -f "$f" ] && { echo "== $f"; cat "$f"; } >> $v/nas-dhcp.txt 2>&1
done
ps -eo pid,args | grep -E '[d]hcpcd|[u]dhcpc|[d]hclient|[n]etcfgd' >> $v/nas-dhcp.txt 2>&1
cp /var/log/netcfgd.log $v/nas-netcfgd.log 2>/dev/null
check "B: netcfgd's log is kept under sysvinit" "$(test -s /var/log/netcfgd.log && echo kept)" "kept"
touch $v/nas-B-ready
if ! waitfor "[ -f $v/router-B-done ]" 240; then
	say "VERDICT bad: the router never probed phase B"
	exit 0
fi

for phase in A B; do
	check "$phase: ping on the LAN" "$(from_router $phase ping-lan)" open
	check "$phase: ping on the storage net" "$(from_router $phase ping-storage)" open
	check "$phase: ssh on the LAN" "$(from_router $phase ssh-lan)" open
	check "$phase: ssh on the storage net" "$(from_router $phase ssh-storage)" open
	check "$phase: NFS refused on the LAN" "$(from_router $phase nfs-lan)" closed
	check "$phase: NFS on the storage net" "$(from_router $phase nfs-storage)" open
	check "$phase: mountd on the storage net" "$(from_router $phase mountd-storage)" open
	check "$phase: IPv6 ping on the LAN" "$(from_router $phase ping-lan-v6)" open
	check "$phase: ssh over IPv6 on the LAN" "$(from_router $phase ssh-lan-v6)" open
	check "$phase: the admin desktop reaches ssh after a burst" "$(from_router $phase ssh-admin-after-burst)" open
done
check "A: UniFi closed (not the NAS role yet)" "$(from_router A unifi-lan)" closed
check "B: UniFi open (the NAS role)" "$(from_router B unifi-lan)" open
check "A: NFS over IPv6 on the LAN open, as rules.v6 left it" "$(from_router A nfs-lan-v6)" open
check "B: NFS over IPv6 on the LAN closed by the inet table" "$(from_router B nfs-lan-v6)" closed
check "A: the SSH guard drops a burst after 8 new connections" "$(from_router A ssh-burst-opened)" 7
check "B: the SSH guard drops a burst after 8 new connections" "$(from_router B ssh-burst-opened)" 7

if [ "$failed" -eq 0 ]; then say "VERDICT ok"; else say "VERDICT bad"; fi
exit 0
