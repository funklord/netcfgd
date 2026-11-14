#!/bin/sh
# netcfgd and strongSwan in one run (project.md 10.862): the full tunnel of
# fulltunnel.sh, with netcfgd itself -- built here, for musl -- making the XFRM
# interface, taking the virtual IP and the default route from the report the
# shipped ipsec-updown writes, and pinning the peer to the uplink. From the
# repository root:
#
#   sg docker -c "docker run --rm --name ncfg-ipsec-e2e --stop-timeout 5 \
#     --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
#     -v $PWD:/src:ro alpine:3.21 timeout 600 sh /src/tests/ipsec/e2e.sh"
#
# The C build's sources are copied in without their objects and built inside,
# so the host's glibc objects are never reused.
#
# HOW IT STOPS: the build is bounded by the caller's timeout, every wait is a
# bounded loop, and the charons die with the container.
set -u
say() { echo "e2e: $*"; }
apk add -q make build-base linux-headers pkgconf strongswan iproute2 iputils >/dev/null 2>&1 ||
	{ say "apk add failed"; exit 1; }
# The C build's sources and nothing else: the tree is gigabytes with its build
# output and hull images, and a container's writable layer is the host's `/`
# -- the first run of this copied all of it and was killed short of filling
# the disk. 81 MB this way.
mkdir -p /work
tar -C /src -cf - --exclude='*.o' --exclude='*.d' --exclude='*.a' --exclude='*_test' \
	--exclude='*_replay' --exclude='*_fuzz' --exclude='c/netcfgd' --exclude='c/ncfg' \
	--exclude='fuzznet/build' --exclude='.git' c client fuzznet VERSION | tar -C /work -xf -
cd /work
make -C c clean >/dev/null 2>&1 || true
make -s -C c > /tmp/build.log 2>&1 || { say "build failed: $(tail -3 /tmp/build.log)"; exit 1; }
NCFG=/work/c/ncfg
say "built: $($NCFG --version 2>&1 | head -1)"
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
# netcfgd's document on the client: the uplink as it stands, and the tunnel.
mkdir -p /tmp/ncfg-etc /tmp/ncfg
cat > /tmp/ncfg-etc/netcfgd.conf <<'CONF'
interface c0 {
	config = "192.0.2.2/32"
}
device ipsec0 {
	xfrm { if_id = 7 }
}
interface ipsec0 {
	config = "reported"
}
CONF
apply() {
	ip netns exec cli "$NCFG" apply --oneshot --config-dir /tmp/ncfg-etc \
		--factory-dir /tmp/ncfg-none --run-dir /tmp/ncfg > /tmp/apply.log 2>&1
	say "apply $1: $(grep -c '^ok' /tmp/apply.log) ok, $(grep -vc '^ok\|nftables\|^$' /tmp/apply.log) other"
}
apply "before the tunnel"
# **charon runs the updown as its own account** -- `ipsec`, uid 100, no
# capabilities, on Alpine -- so it cannot write in netcfgd's root-owned run
# directory, and on the first runs here it silently wrote nothing
# (project.md 10.862). By hand, the interface's report directory is that
# account's, standing in for netcfgd preparing it, which is not built yet.
mkdir -p /tmp/ncfg/reported.d/ipsec0 && chown ipsec /tmp/ncfg/reported.d/ipsec0
say "netcfgd made: $(ip -n cli -d link show ipsec0 2>&1 | grep -o 'xfrm if_id 0x[0-9a-f]*')"

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
				updown = /src/packaging/hooks/ipsec-updown ipsec0 /tmp/ncfg
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
ip netns exec cli swanctl --initiate --child all --uri unix:///tmp/cli.vici > /tmp/init.log 2>&1
say "initiate: $(grep -o 'CHILD_SA all{[0-9]*} established[^.]*\|initiate failed.*' /tmp/init.log | head -1 | cut -c1-120)"
report=$(cat /tmp/ncfg/reported.d/ipsec0/all 2>/dev/null)
say "the report: $(echo "$report" | grep -v '^#' | tr '\n' ' ')"
apply "with the report"
grep -v '^ok' /tmp/apply.log | grep -v nftables | head -4 | sed 's/^/e2e:   apply: /'
say "client routes: $(ip -n cli route | tr '\n' ';')"
say "the peer is reached by: $(ip -n cli route get 198.51.100.1 | head -1)"
# **By which device, and counted there**: the server answers 203.0.113.1
# outside the tunnel as well, so a ping alone passed on the first run with no
# report written and nothing in ipsec0 at all.
say "the internet host is routed by: $(ip -n cli route get 203.0.113.1 | head -1)"
tx_before=$(ip -n cli -s link show ipsec0 | awk '/TX:/{getline; print $2}')
say "ping the internet host through the tunnel: $(ip netns exec cli ping -c 2 -W 2 203.0.113.1 2>&1 | grep -o '[0-9]* received')"
say "packets out of ipsec0 for it: $(( $(ip -n cli -s link show ipsec0 | awk '/TX:/{getline; print $2}') - tx_before ))"
# IKE's own packets, after the tunnel's default route took over.
ip netns exec cli swanctl --rekey --ike home --uri unix:///tmp/cli.vici > /tmp/rekey.log 2>&1
sleep 4
say "IKE rekey: $(tail -1 /tmp/rekey.log | cut -c1-100); retransmits $(grep -c 'retransmit' /tmp/cli.log)"
ip netns exec cli swanctl --rekey --child all --uri unix:///tmp/cli.vici > /tmp/rekeyc.log 2>&1
sleep 4
say "CHILD rekey: $(tail -1 /tmp/rekeyc.log | cut -c1-100); retransmits $(grep -c 'retransmit' /tmp/cli.log)"
say "ping after the rekeys: $(ip netns exec cli ping -c 2 -W 2 203.0.113.1 2>&1 | grep -o '[0-9]* received')"
apply "after the rekeys"
say "a second plan: $(ip netns exec cli "$NCFG" plan --config-dir /tmp/ncfg-etc --factory-dir /tmp/ncfg-none --run-dir /tmp/ncfg 2>&1 | grep -v nftables | head -1)"
ip netns exec cli swanctl --terminate --ike home --uri unix:///tmp/cli.vici > /dev/null 2>&1
sleep 2
say "terminated; the report: '$(grep -v '^#' /tmp/ncfg/reported.d/ipsec0/all 2>/dev/null | tr '\n' ' ')'"
apply "after the tunnel"
say "routes after: $(ip -n cli route | tr '\n' ';')"
grep -iE 'retransmit|giving up|error' /tmp/cli.log | head -5 | sed 's/^/full:   cli: /'
