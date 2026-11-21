#!/bin/sh
# An IPsec tunnel on OpenWrt 25.12, with OpenWrt's own strongSwan (project.md
# 10.870, 10.872).
#
# The router is this machine's root namespace. netcfgd is its package under
# procd; charon is OpenWrt's, started by OpenWrt's `swanctl` procd service,
# which loads `/etc/swanctl/conf.d` (10.870 read that from the package; this
# runs it). The connection names the hook the package ships,
# `/usr/libexec/netcfgd/ipsec-updown`, and no `report_writer`, because
# OpenWrt's charon was read to stay root. Checked, in order:
#
#   - OpenWrt's service loads the operator's conf.d connection;
#   - its charon runs as uid 0, which is why no `report_writer` is needed;
#   - netcfgd makes ipsec0 with the connection's if_id;
#   - `ncfg tunnel up ipsec0` brings the child up, the packaged hook writes
#     the report, and the daemon puts the virtual IP and the far side's
#     subnet on ipsec0 without being asked again;
#   - a ping to the far side leaves by ipsec0, counted there, and is answered;
#   - `ncfg tunnel down ipsec0` empties the report and the address goes.
#
# WHAT THIS RIG IS NOT: strongSwan's files are unpacked with `apk extract`,
# not installed with `apk add`, because OpenWrt's `strongswan` package
# depends on kmod-* packages for a kernel this vm does not run -- it runs the
# host's, and the host's IPsec modules are handed in instead, as hull-openwrt
# hands in dummy.ko. And the tunnel is split, 10.99.0.0/24, so the vm's own
# uplink is never routed into it; the full tunnel and the peer pin are
# tests/ipsec/e2e.sh's.
#
# Always exits 0 and reports through /verdict/openwrt-ipsec.
#
# HOW IT STOPS: every wait is bounded (ubus at 40 s, each change at 20 s), the
# steps are a fixed list, and the vm takes procd, netcfgd and both charons
# with it.
out=/verdict/openwrt-ipsec
: > "$out"
say() { echo "$*" >> "$out"; echo "openwrt-ipsec: $*"; }
failed=0
check() { # $1 what, $2 got, $3 wanted
	if [ "$2" = "$3" ]; then
		say "ok   $1"
	else
		say "FAIL $1: got '$2', wanted '$3'"
		failed=1
	fi
}
bad() {
	say "VERDICT bad: $*"
	logread 2>/dev/null | grep -E 'netcfgd|charon|swanctl|procd|oom' | tail -20 |
		sed 's/^/  log: /' >> "$out"
	exit 0
}
# Seconds until `$1` succeeds, or "never" after 20.
within() {
	n=0
	until eval "$1" >/dev/null 2>&1 || [ $n -gt 20 ]; do
		sleep 1
		n=$((n + 1))
	done
	[ $n -gt 20 ] && echo never || echo $n
}

say "pid 1 is $(cat /proc/1/comm); $(grep DISTRIB_RELEASE /etc/openwrt_release)"
n=0
until ubus call service list >/dev/null 2>&1 || [ $n -gt 40 ]; do sleep 1; n=$((n + 1)); done
ubus call service list >/dev/null 2>&1 || bad "procd's ubus never answered"

# The host's IPsec modules, in dependency order (the Makefile wrote the list).
while read -r module; do
	insmod "/payload/module/$module.ko" 2>> "$out" || bad "insmod $module"
done < /payload/module/order
ip link add ncfg-probe type dummy 2>/dev/null; ip link del ncfg-probe 2>/dev/null

# ip-full and unshare for the far end's namespace: real packages, installed.
apk add --allow-untrusted --no-network /payload/apk/tools/*.apk > /tmp/tools.log 2>&1 ||
	bad "apk would not add ip-full and unshare: $(tail -2 /tmp/tools.log)"
# OpenWrt's strongSwan, unpacked (see the header for why not added).
for package in /payload/apk/swan/*.apk; do
	apk extract --allow-untrusted --destination / "$package" >> /tmp/swan.log 2>&1 ||
		bad "apk extract $package"
done
[ -x /usr/lib/ipsec/charon ] && [ -x /etc/init.d/swanctl ] || bad "no charon or no swanctl service"
apk add --allow-untrusted --no-network /payload/netcfgd.apk > /tmp/netcfgd.log 2>&1 ||
	bad "apk would not add netcfgd: $(tail -2 /tmp/netcfgd.log)"
check "the package carries the hook" \
	"$([ -x /usr/libexec/netcfgd/ipsec-updown ] && echo yes || echo no)" yes

# The wire: c0 is the router's uplink, s0 the far end's.
ip netns add srv || bad "ip netns add"
ip link add c0 type veth peer name s0 || bad "veth"
ip link set s0 netns srv
ip -n srv link set lo up
ip -n srv addr add 192.0.2.1/24 dev s0
ip -n srv link set s0 up
ip -n srv addr add 10.99.0.1/32 dev lo
ip -n srv route add default via 192.0.2.2 dev s0

# The far end: a charon of its own, with /var/run on its own tmpfs so its pid
# file and vici socket are not the router's.
mkdir -p /etc/srv
cat > /etc/srv/strongswan.conf <<'CONF'
charon {
	load_modular = yes
	install_routes = no
	plugins {
		include /etc/strongswan.d/charon/*.conf
		vici { socket = unix:///tmp/srv.vici }
	}
}
CONF
cat > /etc/srv/swanctl.conf <<'CONF'
connections {
	rw {
		local_addrs = 192.0.2.1
		pools = p
		proposals = aes128-sha256-modp2048
		local {
			auth = psk
			id = srv
		}
		remote {
			auth = psk
			id = router
		}
		children {
			net {
				local_ts = 10.99.0.0/24
				esp_proposals = aes128-sha256
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
		id-2 = router
		secret = "rig-secret"
	}
}
CONF
ip netns exec srv unshare -m sh -c '
	mount -t tmpfs tmpfs /var/run
	STRONGSWAN_CONF=/etc/srv/strongswan.conf /usr/lib/ipsec/charon > /tmp/srv.log 2>&1 &
	n=0; until [ -S /tmp/srv.vici ] || [ $n -gt 20 ]; do sleep 1; n=$((n+1)); done
	swanctl --load-all --file /etc/srv/swanctl.conf --uri unix:///tmp/srv.vici > /tmp/srv.load 2>&1
	sleep 600
' &
took=$(within '[ -S /tmp/srv.vici ]')
[ "$took" != never ] || bad "the far end's charon never opened its socket: $(tail -3 /tmp/srv.log)"

# The router's side, as an operator writes it: the connection in conf.d with
# the three lines 0325 asks for, and charon told to leave the address alone.
mkdir -p /etc/swanctl/conf.d
cat > /etc/swanctl/conf.d/home.conf <<'CONF'
connections {
	home {
		remote_addrs = 192.0.2.1
		vips = 0.0.0.0
		proposals = aes128-sha256-modp2048
		local {
			auth = psk
			id = router
		}
		remote {
			auth = psk
			id = srv
		}
		children {
			net {
				remote_ts = 10.99.0.0/24
				esp_proposals = aes128-sha256
				if_id_in = 7
				if_id_out = 7
				updown = /usr/libexec/netcfgd/ipsec-updown ipsec0
			}
		}
	}
}
secrets {
	ike-1 {
		id-1 = srv
		id-2 = router
		secret = "rig-secret"
	}
}
CONF
cat > /etc/strongswan.d/netcfgd.conf <<'CONF'
charon {
	install_virtual_ip = no
	install_routes = no
}
CONF
/etc/init.d/swanctl start
took=$(within 'swanctl --list-conns | grep -q home')
check "OpenWrt's swanctl service loads the conf.d connection" \
	"$([ "$took" != never ] && echo loaded || echo "not loaded")" loaded
pid=$(pidof charon | tr ' ' '\n' | while read -r p; do
	[ "$(readlink /proc/$p/ns/net)" = "$(readlink /proc/1/ns/net)" ] && echo "$p"; done | head -1)
check "and its charon runs as root" \
	"$(awk '/^Uid:/ { print $2 }' /proc/${pid:-0}/status 2>/dev/null)" 0

mkdir -p /etc/netcfgd
cat > /etc/netcfgd/netcfgd.conf <<'CONF'
interface c0 {
	config = "192.0.2.2/24"
}
device ipsec0 {
	xfrm { if_id = 7; connection = "home"; child = "net" }
}
interface ipsec0 {
	config = "reported"
}
CONF
/etc/init.d/netcfgd start
took=$(within 'ip -d link show ipsec0 | grep -q "if_id 0x7"')
check "netcfgd makes ipsec0 with the connection's if_id" \
	"$([ "$took" != never ] && echo made || echo "not made")" made
took=$(within 'ip addr show dev c0 | grep -q "inet 192.0.2.2/"')
[ "$took" != never ] || bad "c0 never got its address"

# The daemon answers once its node is open, which takes a few seconds on a
# machine this size: asked too early, `ncfg` cannot reach it.
took=$(within 'ncfg status')
[ "$took" != never ] || bad "the daemon never answered ncfg status"
said=$(ncfg tunnel up ipsec0 2>&1)
say "     ncfg said: $(echo "$said" | head -2 | tr '\n' ' ')"
check "ncfg tunnel up is answered" \
	"$(echo "$said" | grep -o 'asked for ipsec0 up')" "asked for ipsec0 up"
took=$(within 'ip addr show dev ipsec0 | grep -q "inet 10.98.0.1/32"')
say "     the report: $(grep -v '^#' /run/netcfgd/reported.d/ipsec0/net 2>/dev/null | tr '\n' ' ')"
if [ "$took" = never ]; then
	# Which half failed: the same initiate, by hand, with what swanctl says.
	swanctl --initiate --child net --ike home --timeout 20 > /tmp/by-hand.log 2>&1
	say "     by hand: rc $? $(grep -vE 'plugin|^\[' /tmp/by-hand.log | tail -3 | tr '\n' ' ')"
	say "     netcfgd's swanctl: $(ls -l /proc/$(pidof netcfgd | cut -d' ' -f1)/exe 2>/dev/null | sed 's/.*-> //'); PATH of procd's netcfgd: $(tr '\0' '\n' < /proc/$(pidof netcfgd | cut -d' ' -f1)/environ 2>/dev/null | grep '^PATH=')"
	took=$(within 'ip addr show dev ipsec0 | grep -q "inet 10.98.0.1/32"')
	say "     after the initiate by hand: the report: $(grep -v '^#' /run/netcfgd/reported.d/ipsec0/net 2>/dev/null | tr '\n' ' '); address ${took}"
fi
check "the daemon puts the virtual IP on ipsec0" \
	"$([ "$took" != never ] && echo arrived || echo never)" arrived
check "  and routes the far side's subnet into it" \
	"$(ip route show 10.99.0.0/24 | grep -o 'dev ipsec0')" "dev ipsec0"
before=$(awk '/ipsec0:/ { print $11 }' /proc/net/dev)
received=$(ping -c 2 -W 2 10.99.0.1 2>&1 | grep -o '[0-9]* packets received' | cut -d' ' -f1)
after=$(awk '/ipsec0:/ { print $11 }' /proc/net/dev)
check "a ping to the far side is answered" "${received:-0}" 2
check "  and it left by ipsec0" "$(( ${after:-0} - ${before:-0} ))" 2

said=$(ncfg tunnel down ipsec0 2>&1)
say "     ncfg said: $(echo "$said" | head -2 | tr '\n' ' ')"
check "ncfg tunnel down is answered" \
	"$(echo "$said" | grep -o 'asked for ipsec0 down')" "asked for ipsec0 down"
took=$(within '! ip addr show dev ipsec0 | grep -q "inet 10.98.0.1/"')
check "  and the virtual IP goes with the tunnel" \
	"$([ "$took" != never ] && echo gone || echo kept)" gone

if [ "$failed" -ne 0 ]; then
	swanctl --list-sas 2>&1 | head -12 | sed 's/^/  sas: /' >> "$out"
	sed 's/^/  srv load: /' /tmp/srv.load >> "$out" 2>/dev/null
	grep -vE 'loaded plugins|LIB\]|loading|feature' /tmp/srv.log | tail -15 | sed 's/^/  srv: /' >> "$out"
	logread 2>/dev/null | grep -iE 'charon|swanctl|IKE|CHILD|ipsec-updown' | tail -25 |
		sed 's/^/  router: /' >> "$out"
	logread 2>/dev/null | grep -E 'netcfgd|charon|ipsec-updown' | tail -20 |
		sed 's/^/  log: /' >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
