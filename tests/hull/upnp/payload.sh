#!/bin/sh
# UPnP and NAT-PMP on a router netcfgd runs (project.md 10.670, decision 0310).
#
# One vm, three namespaces' worth of hosts: the router is the vm's own
# namespace, with `lan0` towards a host in `lan` (192.168.7.10) and `wan0`
# towards a host in `wan` (81.0.0.9, an address miniupnpd takes as public --
# it ignores the documentation ranges). netcfgd configures both interfaces,
# NAT on the uplink, a forward chain that drops by policy, and `global {
# upnp { } }`.
#
# What is asserted, and the control for each:
#
#   - before the apply, `upnpc` finds no router: the control that shows the
#     client can tell;
#   - after it, the LAN host maps 18080 to its own 8080, and a connection
#     from the wan host to the router's 18080 reaches the LAN host -- which
#     only the mapping can make true, since nothing else forwards that port;
#   - a mapping to ANOTHER host is refused (secure mode);
#   - `ncfg status` lists the mapping, which no document wrote;
#   - a second plan has nothing to do, and says the holder's warning;
#   - with `upnp` removed and applied again, miniupnpd is gone and so is the
#     table, mappings and all -- the third fact 0310 measured, that the
#     daemon leaves them behind, met by netcfgd.
#
# Always exits 0 and reports through /verdict/upnp.
#
# HOW IT STOPS: every wait is bounded (each upnpc at 15 s, each connection at
# 5 s, the server at 10 s), the steps are a fixed list, and the vm takes
# miniupnpd with it.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/upnp
: > "$out"
say() { echo "$*" >> "$out"; echo "upnp: $*"; }
mount -t tmpfs -o size=64m tmpfs /tmp 2>/dev/null
work=/tmp/upnp
mkdir -p "$work/etc" "$work/run"
exec 2>> "$work/setup.log"

build=/repo/c
for program in netcfgd ncfg; do
	if [ ! -x "$build/$program" ]; then
		say "VERDICT bad: $build/$program is not built on the host"
		exit 0
	fi
done

ip link set lo up
ip netns add lan
ip netns add wan
# Not `h` for a veth end: `ip link set h` reads it as `help` (the wds rig's
# lesson).
ip link add lan0 type veth peer name peer netns lan
ip link add wan0 type veth peer name peer netns wan
ip netns exec lan ip addr add 192.168.7.10/24 dev peer
ip netns exec lan ip addr add 192.168.7.11/24 dev peer
ip netns exec lan ip link set peer up
ip netns exec lan ip link set lo up
ip netns exec lan ip route add default via 192.168.7.1
ip netns exec wan ip addr add 81.0.0.9/24 dev peer
ip netns exec wan ip link set peer up

write_config() { # $1 = 1 for upnp on
	cat > "$work/etc/netcfgd.conf" <<CONF
interface lan0 {
	config     = "192.168.7.1/24"
	forwarding = true
}
interface wan0 {
	config     = "81.0.0.1/24"
	nat        = true
	forwarding = true
}
firewall {
	forward {
		policy = "drop"
		accept "established" {
			state = ["established", "related"]
		}
		accept "outbound" {
			interface = "lan0"
		}
		accept "mapped" {
			interface  = "wan0"
			translated = true
		}
	}
}
CONF
	if [ "$1" = 1 ]; then
		cat >> "$work/etc/netcfgd.conf" <<CONF
global {
	upnp {
		lan    = ["lan0"]
		uplink = "wan0"
	}
}
CONF
	fi
}
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"

# A server on the LAN host's 8080, answering one connection, bounded.
serve() {
	ip netns exec lan timeout 10 python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('192.168.7.10', 8080)); s.listen(1); s.settimeout(9)
c, _ = s.accept(); c.send(b'mapped'); c.close()" &
	sleep 1
}
reach() {
	ip netns exec wan timeout 5 python3 -c "
import socket
try:
	s = socket.create_connection(('81.0.0.1', 18080), 3); print(s.recv(16).decode() or 'empty')
except OSError as e:
	print('refused' if 'refused' in str(e) else 'silent')" 2>/dev/null
}
ask() { # $1 internal address
	ip netns exec lan timeout 15 upnpc -m 192.168.7.10 -a "$1" 8080 18080 TCP 2>&1 |
		grep -E 'is redirected|failed|No IGD|No valid' | head -1
}

write_config 0
"$build/ncfg" apply > "$work/apply0.log" 2>&1
say "without upnp: apply rc=$?; upnpc says: $(ask 192.168.7.10)"

write_config 1
"$build/ncfg" apply > "$work/apply1.log" 2>&1
applied=$?
say "with upnp: apply rc=$applied"
n=0
until [ -s "$work/run/upnp/miniupnpd.pid" ] || [ "$n" -gt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
other=$(ask 192.168.7.11)
mapped=$(ask 192.168.7.10)
say "  a mapping to another host: ${other:-nothing}"
say "  the LAN host's own mapping: ${mapped:-nothing}"
serve
crossed=$(reach)
say "  from the uplink side through 18080: ${crossed:-nothing}"
table=$(nft list table inet netcfgd_upnp 2>/dev/null | grep -c 'dnat ip to 192.168.7.10:8080')
shown=$("$build/ncfg" status 2>/dev/null | grep -c 'TCP 18080 -> 192.168.7.10:8080')
say "  ncfg status lists the mapping: $shown time(s)"

"$build/ncfg" plan > "$work/plan.log" 2>&1
again=$(grep -c '^nothing to do' "$work/plan.log")
warned=$(grep -c 'may open a port on this router' "$work/plan.log")
say "  a second plan: $(grep -v -i 'warning' "$work/plan.log" | head -1)"
say "  and it says the holder's warning: $warned time(s)"

write_config 0
"$build/ncfg" apply > "$work/apply2.log" 2>&1
removed=$?
gone_table=$(nft list table inet netcfgd_upnp >/dev/null 2>&1 && echo present || echo gone)
gone_daemon=$(pidof miniupnpd >/dev/null 2>&1 && echo running || echo stopped)
say "upnp removed: apply rc=$removed, table $gone_table, miniupnpd $gone_daemon"

failed=0
[ "$applied" -eq 0 ] || { say "  the apply with upnp failed"; failed=1; }
case "$mapped" in *redirected*) ;; *) say "  the LAN host could not map its own port"; failed=1 ;; esac
case "$other" in *redirected*) say "  secure mode let a host map a port to another"; failed=1 ;; esac
[ "$crossed" = mapped ] || { say "  nothing crossed the mapping"; failed=1 ;}
[ "$table" -ge 1 ] || { say "  the mapping was not in netcfgd_upnp"; failed=1; }
[ "$shown" -eq 1 ] || { say "  ncfg status did not list the mapping"; failed=1; }
[ "$again" -ge 1 ] || { say "  the second plan was not empty"; failed=1; }
[ "$warned" -eq 1 ] || { say "  the plan did not warn, once, that any LAN device may open ports"; failed=1; }
[ "$removed" -eq 0 ] && [ "$gone_table" = gone ] && [ "$gone_daemon" = stopped ] ||
	{ say "  removing upnp left something behind"; failed=1; }
if [ "$failed" -ne 0 ]; then
	sed 's/^/  apply: /' "$work/apply1.log" | tail -12 >> "$out"
	sed 's/^/  plan: /' "$work/plan.log" | head -8 >> "$out"
	tail -6 "$work/run/upnp/miniupnpd.log" 2>/dev/null | sed 's/^/  miniupnpd: /' >> "$out"
	tail -6 "$work/setup.log" | sed 's/^/  setup: /' >> "$out"
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
