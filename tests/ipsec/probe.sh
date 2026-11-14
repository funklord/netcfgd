#!/bin/sh
# strongSwan's half of IPsec, measured for decision 0324 (project.md 10.857).
#
# Runs INSIDE an alpine container, because the development host's strongSwan
# has neither `swanctl` nor the vici plugin. From the repository root:
#
#   sg docker -c "docker run --rm --name ncfg-ipsec-probe --stop-timeout 5 \
#     --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
#     -v $PWD/tests/ipsec:/probe:ro alpine:3.21 timeout 150 sh /probe/probe.sh"
#
# with `-e PROBE_INSTALL_VIP=no` for charon to report the virtual IP and not
# install it, and `-e PROBE_PLACE=1` to place it from outside as netcfgd will.
# It fetches strongswan, iproute2 and iputils with apk.
# Two network namespaces, a charon in each with its own strongswan.conf and its
# own /run (a private mount namespace), IKEv2 with a pre-shared key, a virtual
# IP from the server's pool, and the client's child SA bound to an XFRM
# interface by if_id. Measures what netcfgd's IPsec step 3 depends on.
#
# HOW IT STOPS: every wait is a bounded loop; the charons die with the
# container; the container is --rm and the caller's timeout kills it.
set -u
say() { echo "probe: $*"; }
apk add -q strongswan iproute2 iputils >/dev/null 2>&1 || { say "apk add failed"; exit 1; }
CHARON=$(ls /usr/libexec/ipsec/charon /usr/lib/strongswan/charon 2>/dev/null | head -1)
say "$(apk list --installed strongswan 2>/dev/null | cut -d" " -f1 | head -1); charon at ${CHARON:-none}"

ip netns add srv && ip netns add cli || { say "no netns"; exit 1; }
ip link add vs type veth peer name vc
ip link set vs netns srv; ip link set vc netns cli
ip -n srv addr add 192.0.2.1/24 dev vs; ip -n srv link set vs up; ip -n srv link set lo up
ip -n cli addr add 192.0.2.2/24 dev vc; ip -n cli link set vc up; ip -n cli link set lo up
ip -n srv addr add 10.99.0.1/32 dev lo
# The server is policy-based; its replies need any route to find a device before
# the policy takes them.
ip -n srv route add 10.98.0.0/24 via 192.0.2.2
# What netcfgd's step 1 makes.
ip -n cli link add ipsec0 type xfrm if_id 7 && ip -n cli link set ipsec0 up
say "client: $(ip -n cli -d link show ipsec0 | grep -o 'xfrm if_id 0x[0-9a-f]*')"

for side in srv cli; do
	mkdir -p /etc/$side/conf.d
	cat > /etc/$side/strongswan.conf <<CONF
charon {
	load_modular = yes
	install_virtual_ip = $([ $side = cli ] && echo "${PROBE_INSTALL_VIP:-yes}" || echo yes)
	install_virtual_ip_on = $([ $side = cli ] && echo ipsec0 || echo lo)
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
		local_addrs = 192.0.2.1
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
			net {
				local_ts = 10.99.0.1/32
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
		} }
CONF
cat > /etc/cli/swanctl.conf <<'CONF'
connections {
	home {
		remote_addrs = 192.0.2.1
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
			net {
				remote_ts = 10.99.0.1/32
				if_id_in = 7
				if_id_out = 7
				updown = /tmp/updown.sh
			}
		}
	}
}
secrets {
	ike-1 {
			id-1 = srv
			id-2 = cli
			secret = "probe-secret"
		} }
CONF

# What strongSwan hands a child's `updown` command: written down, for whether
# netcfgd can take the virtual IP and the if_id from it (0324).
cat > /tmp/updown.sh <<'UPDOWN'
#!/bin/sh
env | grep -E '^PLUTO_(VERB|MY_SOURCEIP|IF_ID_IN|IF_ID_OUT|PEER|MY_CLIENT|PEER_CLIENT|CONNECTION|UNIQUEID)=' |
	sort > "/tmp/updown.$PLUTO_VERB"
UPDOWN
chmod 755 /tmp/updown.sh

# A charon per side, each in a private mount namespace with its own /run, so
# their pid files cannot meet -- which is the question for netcfgd running
# its own charon beside a system one.
for side in srv cli; do
	ip netns exec $side unshare -m sh -c "
		mount -t tmpfs tmpfs /run
		mkdir -p /run/shared
		STRONGSWAN_CONF=/etc/$side/strongswan.conf $CHARON > /tmp/$side.log 2>&1 &
		echo \$! > /tmp/$side.pid
		n=0; until [ -S /tmp/$side.vici ] || [ \$n -gt 50 ]; do sleep 0.1; n=\$((n+1)); done
		swanctl --load-all --file /etc/$side/swanctl.conf --uri unix:///tmp/$side.vici > /tmp/$side.load 2>&1
		sleep 30
	" &
done
n=0
until [ -S /tmp/srv.vici ] && [ -S /tmp/cli.vici ] || [ $n -gt 100 ]; do sleep 0.1; n=$((n + 1)); done
sleep 2
grep -v x509 /tmp/srv.load | sed "s/^/probe:   load srv: /"
grep -v x509 /tmp/cli.load | sed "s/^/probe:   load cli: /"
ip netns exec cli swanctl --initiate --child net --uri unix:///tmp/cli.vici > /tmp/init.log 2>&1
say "initiate: $(tail -2 /tmp/init.log | tr '\n' ' ' | cut -c1-200)"
say "the vips charon reports: $(ip netns exec cli swanctl --list-sas --raw --uri unix:///tmp/cli.vici 2>&1 | grep -o 'local-vips=\[[^]]*\]' | head -1)"
if [ -n "${PROBE_PLACE:-}" ]; then
	vip=$(ip netns exec cli swanctl --list-sas --raw --uri unix:///tmp/cli.vici 2>&1 | sed -n 's/.*local-vips=\[\([0-9.]*\).*/\1/p' | head -1)
	ip -n cli addr add "$vip/32" dev ipsec0 && say "placed $vip on ipsec0 from outside charon"
fi
for verb in /tmp/updown.up-client /tmp/updown.down-client; do
	[ -e "$verb" ] || continue
	say "updown ${verb#/tmp/updown.}: $(tr '\n' ' ' < "$verb")"
done
say "client addresses on ipsec0: $(ip -n cli -o -4 addr show dev ipsec0 | awk '{print $4}' | tr '\n' ' ')"
say "client SAs: $(ip netns exec cli ip xfrm state | grep -c '^src') state(s), if_id in them: $(ip netns exec cli ip xfrm state | grep -o 'if_id 0x[0-9a-f]*' | sort -u | tr '\n' ' ')"
ip -n cli route add 10.99.0.1/32 dev ipsec0 2>/dev/null
src=$(ip -n cli -o -4 addr show dev ipsec0 | awk '{print $4}' | cut -d/ -f1 | head -1)
say "ping 10.99.0.1 from ${src:-none} through ipsec0: $(ip netns exec cli ping -c 2 -W 2 ${src:+-I $src} 10.99.0.1 2>&1 | grep -o '[0-9]* received')"
say "client packets on ipsec0: $(ip -n cli -s link show ipsec0 | awk '/TX:/{getline; print "tx " $2}')"
say "charon logs: srv $(grep -c . /tmp/srv.log) lines, cli $(grep -ciE 'error|fail' /tmp/cli.log) error lines"
grep -iE 'error|fail|virtual IP|installing' /tmp/cli.log | head -8 | sed 's/^/probe:   cli: /'
