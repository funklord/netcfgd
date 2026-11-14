#!/bin/sh
# A full tunnel -- all of IPv4 into an XFRM interface -- with the peer behind a
# router, so only a default route reaches it: whether IKE's own packets still
# leave by the uplink when the tunnel's default route beats the uplink's
# (project.md 10.858, 10.859). Run as probe.sh is, with this file in its place;
# packaging/hooks/ipsec-updown must be mounted at /hook/ipsec-updown:
#
#   sg docker -c "docker run --rm --name ncfg-ipsec-full --stop-timeout 5 \
#     --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
#     -v $PWD/tests/ipsec:/probe:ro \
#     -v $PWD/packaging/hooks/ipsec-updown:/hook/ipsec-updown:ro \
#     alpine:3.21 timeout 200 sh /probe/fulltunnel.sh"
#
# `-e PROBE_PEER_ROUTE=1` adds a host route to the peer by the uplink first.
#
# HOW IT STOPS: every wait is bounded; the charons die with the container.
set -u
say() { echo "full: $*"; }
apk add -q strongswan iproute2 iputils >/dev/null 2>&1 || { say "apk add failed"; exit 1; }
CHARON=/usr/lib/strongswan/charon

# No router: a container's /proc/sys is read-only, so nothing in it forwards.
# Host addresses and `onlink` routes instead, so that on the client only a
# default route reaches the peer, as on the internet.
for ns in cli srv; do ip netns add $ns; ip -n $ns link set lo up; done
ip link add c0 type veth peer name s0; ip link set c0 netns cli; ip link set s0 netns srv
ip -n cli addr add 192.0.2.2/32 dev c0; ip -n cli link set c0 up
ip -n srv addr add 198.51.100.1/32 dev s0; ip -n srv link set s0 up
ip -n cli route add default via 198.51.100.1 dev c0 onlink metric 100
ip -n srv route add 192.0.2.2/32 dev s0
ip -n srv route add default via 192.0.2.2 dev s0 onlink
# Behind the server: the inner side, and a host standing for "the internet".
ip -n srv addr add 10.99.0.1/32 dev lo
ip -n srv addr add 203.0.113.1/32 dev lo
ip -n cli link add ipsec0 type xfrm if_id 7 && ip -n cli link set ipsec0 up

for side in srv cli; do
	mkdir -p /etc/$side
	cat > /etc/$side/strongswan.conf <<CONF
charon {
	install_virtual_ip = no
	install_routes = no
	plugins {
		include /etc/strongswan.d/charon/*.conf
		vici { socket = unix:///tmp/$side.vici }
	}
}
CONF
done
cat > /etc/srv/swanctl.conf <<'CONF'
connections {
	rw {
		local_addrs = 198.51.100.1
		pools = p
		local {
			auth = psk
			id = srv
		}
		remote {
			auth = psk
			id = cli
		}
		children {
			all {
				local_ts = 0.0.0.0/0
			}
		}
	}
}
pools {
	p {
		addrs = 10.98.0.0/24
	}
}
secrets {
	ike-1 {
		id-1 = srv
		id-2 = cli
		secret = "probe-secret"
	}
}
CONF
cat > /etc/cli/swanctl.conf <<'CONF'
connections {
	home {
		remote_addrs = 198.51.100.1
		vips = 0.0.0.0
		local {
			auth = psk
			id = cli
		}
		remote {
			auth = psk
			id = srv
		}
		children {
			all {
				remote_ts = 0.0.0.0/0
				if_id_in = 7
				if_id_out = 7
				updown = /hook/ipsec-updown ipsec0 /tmp/ncfg
			}
		}
	}
}
secrets {
	ike-1 {
		id-1 = srv
		id-2 = cli
		secret = "probe-secret"
	}
}
CONF

for side in srv cli; do
	ip netns exec $side unshare -m sh -c "
		mount -t tmpfs tmpfs /run
		STRONGSWAN_CONF=/etc/$side/strongswan.conf NCFG_RUN_DIR=/tmp/ncfg $CHARON > /tmp/$side.log 2>&1 &
		n=0; until [ -S /tmp/$side.vici ] || [ \$n -gt 50 ]; do sleep 0.1; n=\$((n+1)); done
		swanctl --load-all --file /etc/$side/swanctl.conf --uri unix:///tmp/$side.vici > /tmp/$side.load 2>&1
		sleep 120
	" &
done
n=0
until [ -S /tmp/srv.vici ] && [ -S /tmp/cli.vici ] || [ $n -gt 100 ]; do sleep 0.1; n=$((n + 1)); done
sleep 2
if [ -n "${PROBE_PEER_ROUTE:-}" ]; then
	ip -n cli route add 198.51.100.1/32 via 198.51.100.1 dev c0 onlink
	say "a host route to the peer by the uplink, added first"
fi
ip netns exec cli swanctl --initiate --child all --uri unix:///tmp/cli.vici > /tmp/init.log 2>&1
say "initiate: $(grep -o 'CHILD_SA all{[0-9]*} established[^.]*\|initiate failed.*' /tmp/init.log | head -1 | cut -c1-120)"
report=$(cat /tmp/ncfg/reported.d/ipsec0/all 2>/dev/null)
say "the report: $(echo "$report" | grep -v '^#' | tr '\n' ' ')"
# What netcfgd does with that report: the address, and the default route on
# the tunnel at a better metric than the uplink's.
vip=$(echo "$report" | sed -n 's/^address=//p' | head -1)
ip -n cli addr add "$vip" dev ipsec0
ip -n cli route add default dev ipsec0 metric 50
say "client routes: $(ip -n cli route | tr '\n' ';')"
say "the peer is reached by: $(ip -n cli route get 198.51.100.1 | head -1)"
say "ping the internet host through the tunnel: $(ip netns exec cli ping -c 2 -W 2 203.0.113.1 2>&1 | grep -o '[0-9]* received')"
# IKE's own packets, after the tunnel's default route took over.
ip netns exec cli swanctl --rekey --ike home --uri unix:///tmp/cli.vici > /tmp/rekey.log 2>&1
sleep 4
say "IKE rekey: $(tail -1 /tmp/rekey.log | cut -c1-100); retransmits $(grep -c 'retransmit' /tmp/cli.log)"
ip netns exec cli swanctl --rekey --child all --uri unix:///tmp/cli.vici > /tmp/rekeyc.log 2>&1
sleep 4
say "CHILD rekey: $(tail -1 /tmp/rekeyc.log | cut -c1-100); retransmits $(grep -c 'retransmit' /tmp/cli.log)"
say "ping after the rekeys: $(ip netns exec cli ping -c 2 -W 2 203.0.113.1 2>&1 | grep -o '[0-9]* received')"
say "the report after: $(grep -v '^#' /tmp/ncfg/reported.d/ipsec0/all 2>/dev/null | tr '\n' ' ')"
grep -iE 'retransmit|giving up|error' /tmp/cli.log | head -5 | sed 's/^/full:   cli: /'
