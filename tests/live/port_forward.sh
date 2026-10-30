#!/bin/sh
# Port forwards (decision 0298), applied by ncfg to a real kernel and followed
# by a connection through them.
#
#     unshare -rn sh tests/live/port_forward.sh
#
# The router is this namespace; a "wan" and a "lan" namespace hang off it on
# veth pairs. netcfgd forwards tcp 443 arriving on `wan0` to 192.168.1.10:8443
# in the lan one, and a client in the wan one connects to the router's own
# address and must reach the server behind it. Asserted:
#
#   - `nft list ruleset` shows the prerouting chain and the rule as nft itself
#     would write it, with the forward's identity comment;
#   - a second plan has nothing to do, so the decoder reads the kernel's form
#     of the rule back as the document's;
#   - `ncfg status` lists the forward on `wan0`;
#   - a connection to 203.0.113.1:443 from the wan side reaches the lan server;
#   - the rule is reflected and given a return path (0299), and a host on the
#     lan dialling the same public address reaches the server too -- and does
#     not once the forward says `hairpin = false`;
#   - a rule added by hand to the prerouting chain is a difference, and the
#     next apply replaces it;
#   - and a document with no forward leaves no prerouting chain.
#
# A user and network namespace can hold an nftables table and its NAT, which
# `firewall.sh` measured for the filter half; the NAT half needs the host's
# `nft_nat` and `nft_chain_nat`, which a namespace cannot load, so their
# absence is a skip that says so.
#
# HOW IT STOPS: a fixed list of steps. The three child namespaces are `sleep
# 120` processes killed by the EXIT trap; each server lives at most 10 s and
# each client 5 s, under `timeout`; every wait is a bounded loop. Everything is
# in namespaces this process owns, so the table and the links go with it.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"
# nft, ip and nsenter live in sbin, which an ordinary PATH may not carry.
PATH="$PATH:/usr/sbin:/sbin"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "port_forward.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "port_forward.sh: skipping: $1"
	exit 0
}

[ "$(id -u)" = 0 ] || skip "run it as: unshare -rn sh tests/live/port_forward.sh"
for tool in nft ip python3 nsenter unshare timeout; do
	command -v "$tool" >/dev/null 2>&1 || skip "$tool is not installed"
done
[ -x "$build/ncfg" ] || skip "ncfg is not built (make -C c)"
grep -q '^nft_chain_nat ' /proc/modules 2>/dev/null ||
	skip "this kernel has no nft_chain_nat loaded, and a namespace cannot load it"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-pf.XXXXXX")
wan_pid=
lan_pid=
inside_pid=
cleanup() {
	[ -n "$wan_pid" ] && kill "$wan_pid" 2>/dev/null || true
	[ -n "$lan_pid" ] && kill "$lan_pid" 2>/dev/null || true
	[ -n "$inside_pid" ] && kill "$inside_pid" 2>/dev/null || true
	rm -rf "$work"
	return 0
}
trap cleanup EXIT INT TERM

failures=0
check() { # $1 what, $2 actual, $3 expected
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1"
		echo "       expected: $3"
		echo "       actual:   $2"
		failures=$((failures + 1))
	fi
}
has() { # $1 what, $2 file, $3 fixed text it must hold
	check "$1" "$(grep -cF -- "$3" "$2" || true)" "1"
}

# Three namespaces of our own, each held open by a sleep: a host outside on
# the wan side, the server on the lan side, and a second lan host beside it --
# the client hairpin is for (0299). The lan side is a bridge, so the two lan
# hosts share one segment with the router, as a home network does.
unshare -n sleep 120 &
wan_pid=$!
unshare -n sleep 120 &
lan_pid=$!
unshare -n sleep 120 &
inside_pid=$!
own=$(readlink /proc/$$/ns/net)
n=0
while { [ "$(readlink "/proc/$wan_pid/ns/net" 2>/dev/null)" = "$own" ] ||
    [ "$(readlink "/proc/$lan_pid/ns/net" 2>/dev/null)" = "$own" ] ||
    [ "$(readlink "/proc/$inside_pid/ns/net" 2>/dev/null)" = "$own" ]; } && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
W() { nsenter --net="/proc/$wan_pid/ns/net" "$@"; }
L() { nsenter --net="/proc/$lan_pid/ns/net" "$@"; }
I() { nsenter --net="/proc/$inside_pid/ns/net" "$@"; }

ip link set lo up
ip link add wan0 type veth peer name peer0
ip link set peer0 netns "$wan_pid"
ip link add lan0 type veth peer name peer1
ip link set peer1 netns "$lan_pid"
W ip link set lo up
W ip addr add 203.0.113.2/24 dev peer0
W ip link set peer0 up
L ip link set lo up
L ip link add br0 type bridge
L ip link set peer1 master br0
L ip link add side0 type veth peer name side1
L ip link set side1 netns "$inside_pid"
L ip link set side0 master br0
L ip link set peer1 up
L ip link set side0 up
L ip addr add 192.168.1.10/24 dev br0
L ip link set br0 up
I ip link set lo up
I ip addr add 192.168.1.20/24 dev side1
I ip link set side1 up

# One connection answered by the server, which says who it saw; and one made,
# printing the answer or `refused`. Each bounded, each one connection.
serve() { # $1 how long to wait for a client
	rm -f "$work/listening"
	L timeout "$1" python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("192.168.1.10", 8443)); s.listen(1)
open(sys.argv[1], "w").close()
s.settimeout(int(sys.argv[2]) - 1)
try:
    c, peer = s.accept(); c.sendall(("through, from %s\n" % peer[0]).encode()); c.close()
except OSError:
    pass
' "$work/listening" "$1" > "$work/server.log" 2>&1 &
	n=0
	while [ ! -e "$work/listening" ] && [ "$n" -lt 50 ]; do
		sleep 0.1
		n=$((n + 1))
	done
}
dial() { # $1 the namespace function to dial from
	"$1" timeout 5 python3 -c '
import socket
try:
    s = socket.create_connection(("203.0.113.1", 443), timeout=3)
    print(s.recv(100).decode().strip() or "refused")
except OSError:
    print("refused")
' 2>&1 || true
}

mkdir -p "$work/etc" "$work/run"
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
ncfg="$build/ncfg"
write_config() { # $1 the wan interface's port_forward block, or nothing
	cat > "$work/etc/netcfgd.conf" <<CONF
interface wan0 {
	config = "203.0.113.1/24"
	forwarding = true
$1
}
interface lan0 {
	config = "192.168.1.1/24"
	forwarding = true
}
CONF
}
write_config '	port_forward "web" { protocol = "tcp"; port = 443; to = "192.168.1.10"; to_port = 8443 }'

"$ncfg" apply > "$work/apply.log" 2>&1 || true
check "ncfg applies the forward" \
	"$(grep -c 'ok   nftables.replace' "$work/apply.log" || true)" "1"
nft list ruleset > "$work/listed" 2>&1 || true
has "the prerouting chain is a nat chain at dstnat" "$work/listed" \
	"type nat hook prerouting priority dstnat; policy accept;"
has "and the rule is what nft writes for the forward, with its identity" "$work/listed" \
	'iifname "wan0" tcp dport 443 dnat ip to 192.168.1.10:8443 comment "name=wan0/web sha256='
has "its reflection, for the uplink's address arriving anywhere else" "$work/listed" \
	'iifname != "wan0" ip daddr 203.0.113.1 tcp dport 443 dnat ip to 192.168.1.10:8443 comment "name=wan0/web@reflect sha256='
has "and its return path, masquerading the host's own network towards it" "$work/listed" \
	'oifname "lan0" ip saddr 192.168.1.0/24 ip daddr 192.168.1.10 tcp dport 8443 masquerade comment "name=wan0/web@hairpin sha256='
"$ncfg" plan > "$work/plan.log" 2>&1 || true
check "a second plan has nothing to do, so the kernel's form reads back" \
	"$(head -1 "$work/plan.log")" "nothing to do"
"$ncfg" status > "$work/status.log" 2>&1 || true
has "ncfg status lists the forward on wan0" "$work/status.log" \
	"forwards tcp 443 to 192.168.1.10:8443 (web)"

# A server behind the router, and a client outside it aimed at the router.
L ip route add default via 192.168.1.1
W ip route add default via 203.0.113.1
I ip route add default via 192.168.1.1
serve 10
check "a connection to the router's port 443 reaches the server behind it" \
	"$(dial W)" "through, from 203.0.113.2"

# Hairpin (0299): the host beside the server dials the same public address.
# The server sees the router, which is what the return path costs and is how
# the answer comes back the way the client expects.
serve 10
check "a lan host dialling the router's public address reaches the server" \
	"$(dial I)" "through, from 192.168.1.1"

# **The hairpin control**: the same, not reflected, must not get through.
write_config '	port_forward "web" { protocol = "tcp"; port = 443; to = "192.168.1.10"; to_port = 8443; hairpin = false }'
"$ncfg" apply > "$work/apply.log" 2>&1 || true
serve 8
check "and with hairpin = false it does not" "$(dial I)" "refused"
write_config '	port_forward "web" { protocol = "tcp"; port = 443; to = "192.168.1.10"; to_port = 8443 }'
"$ncfg" apply > "$work/apply.log" 2>&1 || true

# A hand edit inside netcfgd's prerouting chain is not netcfgd's.
nft add rule inet netcfgd prerouting tcp dport 80 dnat ip to 192.168.1.10
"$ncfg" plan > "$work/plan.log" 2>&1 || true
check "a rule added by hand is a difference the plan replaces" \
	"$(grep -c 'nftables.replace' "$work/plan.log" || true)" "1"
"$ncfg" apply > "$work/apply.log" 2>&1 || true
nft list ruleset > "$work/listed" 2>&1 || true
check "and the apply leaves only the document's forward and its reflection" \
	"$(grep -c 'dnat ip to' "$work/listed" || true)" "2"

write_config ""
"$ncfg" apply > "$work/apply.log" 2>&1 || true
nft list ruleset > "$work/listed" 2>&1 || true
check "a document with no forward leaves no prerouting chain" \
	"$(grep -c 'hook prerouting' "$work/listed" || true)" "0"

# **The control.** The same server and the same connection with no forward:
# it must fail, or the connection above proved something other than the
# translation -- a route, or a listener on the router itself.
serve 8
check "and with no forward the same connection does not get through" "$(dial W)" "refused"

if [ "$failures" -ne 0 ]; then
	echo "port_forward.sh: $failures check(s) failed; the last apply said:"
	tail -8 "$work/apply.log"
	exit 1
fi
echo "port_forward.sh: all checks passed"
