#!/bin/sh
# The full tunnel of fulltunnel.sh authenticated the way a commercial VPN
# profile is (project.md 10.867): the server by a certificate from its own CA,
# the client by EAP-MSCHAPv2 -- a username and a password -- trusting that CA.
# The holder's PrivadoVPN profile is this shape. Run as fulltunnel.sh is;
# packaging/hooks/ipsec-updown must be mounted at /hook/ipsec-updown:
#
#   sg docker -c "docker run --rm --name ncfg-ipsec-full --stop-timeout 5 \
#     --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
#     -v $PWD/tests/ipsec:/probe:ro \
#     -v $PWD/packaging/hooks/ipsec-updown:/hook/ipsec-updown:ro \
#     alpine:3.21 timeout 200 sh /probe/fulltunnel.sh"
#
# The host route to the peer by the uplink is added first, as netcfgd does
# (10.860); `-e PROBE_NO_PEER_ROUTE=1` leaves it out.
#
# HOW IT STOPS: every wait is bounded; the charons die with the container.
set -u
say() { echo "eap: $*"; }
apk add -q strongswan iproute2 iputils >/dev/null 2>&1 || { say "apk add failed"; exit 1; }
# A CA, and the server's certificate from it, named for the id the client asks for.
mkdir -p /etc/srv/x509 /etc/srv/private /etc/srv/x509ca /etc/cli/x509ca
pki --gen --type rsa --size 2048 --outform pem > /tmp/ca.key
pki --self --ca --lifetime 30 --in /tmp/ca.key --type rsa --dn "CN=probe CA" \
	--outform pem > /etc/srv/x509ca/ca.pem
cp /etc/srv/x509ca/ca.pem /etc/cli/x509ca/ca.pem
pki --gen --type rsa --size 2048 --outform pem > /etc/srv/private/server.key
pki --pub --in /etc/srv/private/server.key --type rsa |
	pki --issue --lifetime 30 --cacert /etc/srv/x509ca/ca.pem --cakey /tmp/ca.key \
	--dn "CN=vpn.example" --san vpn.example --flag serverAuth --flag ikeIntermediate \
	--outform pem > /etc/srv/x509/server.pem
say "certificates: $(ls /etc/srv/x509 /etc/srv/x509ca | tr '\n' ' ')"
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
			auth = pubkey
			certs = server.pem
			id = vpn.example
		}
		remote {
			auth = eap-mschapv2
			eap_id = %any
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
	eap-1 {
		id = probe-user
		secret = "probe-password"
	}
}
CONF
cat > /etc/cli/swanctl.conf <<'CONF'
connections {
	home {
		remote_addrs = 198.51.100.1
		vips = 0.0.0.0
		local {
			auth = eap-mschapv2
			eap_id = probe-user
		}
		remote {
			auth = pubkey
			id = vpn.example
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
	eap-1 {
		id = probe-user
		secret = "probe-password"
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
if [ -z "${PROBE_NO_PEER_ROUTE:-}" ]; then
	ip -n cli route add 198.51.100.1/32 via 198.51.100.1 dev c0 onlink
	say "a host route to the peer by the uplink, added first"
fi
ip netns exec cli swanctl --initiate --child all --uri unix:///tmp/cli.vici > /tmp/init.log 2>&1
say "initiate: $(grep -o 'CHILD_SA all{[0-9]*} established[^.]*\|initiate failed.*' /tmp/init.log | head -1 | cut -c1-120)"
say "authenticated: $(grep -oE 'authentication of .vpn.example. with [A-Z0-9_-]+ successful|EAP method EAP_MSCHAPV2 succeeded[^,]*' /tmp/init.log | tr '\n' ';')"
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
