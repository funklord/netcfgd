#!/bin/sh
# The router and the admin desktop at once: dnsmasq leasing dl180g6-01's
# reserved 10.0.0.11 on the LAN, and the probes, from the LAN (10.0.0.1, and
# 10.0.0.3, ml350's address, exempt from the SSH guard) and from the storage
# net (10.1.0.5). Results go to /verdict/router-A and router-B.
#
# HOW IT STOPS: every wait is bounded (240 s at most), and the machine
# ends when this does.
set -u
PATH=/usr/sbin:/sbin:/usr/bin:/bin
v=/verdict
ip link set lo up
ip link set eth0 up && ip addr add 10.0.0.1/16 dev eth0 && ip addr add 10.0.0.3/16 dev eth0
ip link set eth1 up && ip addr add 10.1.0.5/24 dev eth1
dnsmasq --port=0 --interface=eth0 --bind-interfaces --dhcp-authoritative \
	--dhcp-range=10.0.0.11,10.0.0.11,255.255.0.0,12h \
	--dhcp-option=option:router,10.0.0.1 --dhcp-leasefile=/tmp/leases \
	--pid-file=/tmp/dnsmasq.pid --log-facility=/tmp/dnsmasq.log

waitfor() { # $1 file, $2 seconds
	n=0
	while [ ! -f "$1" ] && [ "$n" -lt "$(($2 * 2))" ]; do sleep 0.5; n=$((n + 1)); done
	[ -f "$1" ]
}
p() { python3 /payload/probe.py "$@"; }

matrix() { # $1 phase
	out=$v/router-$1
	: > "$out"
	ll=$(cat $v/nas-ll 2>/dev/null)
	{
		echo "ping-lan $(ping -c1 -W2 10.0.0.11 >/dev/null 2>&1 && echo open || echo closed)"
		echo "ping-storage $(ping -c1 -W2 10.1.0.1 >/dev/null 2>&1 && echo open || echo closed)"
		echo "ssh-lan $(p 10.0.0.11 22 10.0.0.1)"
		echo "ssh-storage $(p 10.1.0.1 22 10.1.0.5)"
		echo "nfs-lan $(p 10.0.0.11 2049 10.0.0.1)"
		echo "nfs-storage $(p 10.1.0.1 2049 10.1.0.5)"
		echo "mountd-storage $(p 10.1.0.1 635 10.1.0.5)"
		echo "unifi-lan $(p 10.0.0.11 8443 10.0.0.1)"
		echo "nfs-lan-v6 $(p "$ll" 2049 - eth0)"
		echo "ssh-lan-v6 $(p "$ll" 22 - eth0)"
		echo "ping-lan-v6 $(ping -6 -c1 -W2 "$ll%eth0" >/dev/null 2>&1 && echo open || echo closed)"
		# The guard: twelve new connections from one address in a row, then
		# the admin desktop's address once.
		n=0; opened=0
		while [ "$n" -lt 12 ]; do
			[ "$(p 10.0.0.11 22 10.0.0.1)" = open ] && opened=$((opened + 1))
			n=$((n + 1))
		done
		echo "ssh-burst-opened $opened"
		echo "ssh-admin-after-burst $(p 10.0.0.11 22 10.0.0.3)"
	} >> "$out"
}

for phase in A B; do
	if ! waitfor $v/nas-$phase-ready 240; then
		echo "router: nas never said phase $phase was ready" > $v/router-$phase
		exit 0
	fi
	matrix $phase
	touch $v/router-$phase-done
done
