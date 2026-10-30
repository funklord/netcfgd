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
#   - a rule added by hand to the prerouting chain is a difference, and the
#     next apply replaces it;
#   - and a document with no forward leaves no prerouting chain.
#
# A user and network namespace can hold an nftables table and its NAT, which
# `firewall.sh` measured for the filter half; the NAT half needs the host's
# `nft_nat` and `nft_chain_nat`, which a namespace cannot load, so their
# absence is a skip that says so.
#
# HOW IT STOPS: a fixed list of steps. The two child namespaces are `sleep 120`
# processes killed by the EXIT trap; the server lives at most 20 s and the
# client 5 s, each under `timeout`; every wait is a bounded loop. Everything is
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
cleanup() {
	[ -n "$wan_pid" ] && kill "$wan_pid" 2>/dev/null || true
	[ -n "$lan_pid" ] && kill "$lan_pid" 2>/dev/null || true
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

# Two namespaces of our own, each held open by a sleep.
unshare -n sleep 120 &
wan_pid=$!
unshare -n sleep 120 &
lan_pid=$!
own=$(readlink /proc/$$/ns/net)
n=0
while { [ "$(readlink "/proc/$wan_pid/ns/net" 2>/dev/null)" = "$own" ] ||
    [ "$(readlink "/proc/$lan_pid/ns/net" 2>/dev/null)" = "$own" ]; } && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
W() { nsenter --net="/proc/$wan_pid/ns/net" "$@"; }
L() { nsenter --net="/proc/$lan_pid/ns/net" "$@"; }

ip link set lo up
ip link add wan0 type veth peer name peer0
ip link set peer0 netns "$wan_pid"
ip link add lan0 type veth peer name peer1
ip link set peer1 netns "$lan_pid"
W ip link set lo up
W ip addr add 203.0.113.2/24 dev peer0
W ip link set peer0 up
L ip link set lo up
L ip addr add 192.168.1.10/24 dev peer1
L ip link set peer1 up

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
"$ncfg" plan > "$work/plan.log" 2>&1 || true
check "a second plan has nothing to do, so the kernel's form reads back" \
	"$(head -1 "$work/plan.log")" "nothing to do"
"$ncfg" status > "$work/status.log" 2>&1 || true
has "ncfg status lists the forward on wan0" "$work/status.log" \
	"forwards tcp 443 to 192.168.1.10:8443 (web)"

# A server behind the router, and a client outside it aimed at the router.
L ip route add default via 192.168.1.1
W ip route add default via 203.0.113.1
L timeout 20 python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("192.168.1.10", 8443)); s.listen(1)
open(sys.argv[1], "w").close()
c, peer = s.accept(); c.sendall(("through, from %s\n" % peer[0]).encode()); c.close()
' "$work/listening" > "$work/server.log" 2>&1 &
n=0
while [ ! -e "$work/listening" ] && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
W timeout 5 python3 -c '
import socket
s = socket.create_connection(("203.0.113.1", 443), timeout=4)
print(s.recv(100).decode().strip())
' > "$work/client.log" 2>&1 || true
check "a connection to the router's port 443 reaches the server behind it" \
	"$(cat "$work/client.log")" "through, from 203.0.113.2"

# A hand edit inside netcfgd's prerouting chain is not netcfgd's.
nft add rule inet netcfgd prerouting tcp dport 80 dnat ip to 192.168.1.10
"$ncfg" plan > "$work/plan.log" 2>&1 || true
check "a rule added by hand is a difference the plan replaces" \
	"$(grep -c 'nftables.replace' "$work/plan.log" || true)" "1"
"$ncfg" apply > "$work/apply.log" 2>&1 || true
nft list ruleset > "$work/listed" 2>&1 || true
check "and the apply leaves only the document's forward" \
	"$(grep -c 'dnat ip to' "$work/listed" || true)" "1"

write_config ""
"$ncfg" apply > "$work/apply.log" 2>&1 || true
nft list ruleset > "$work/listed" 2>&1 || true
check "a document with no forward leaves no prerouting chain" \
	"$(grep -c 'hook prerouting' "$work/listed" || true)" "0"

# **The control.** The same server and the same connection with no forward:
# it must fail, or the connection above proved something other than the
# translation -- a route, or a listener on the router itself.
rm -f "$work/listening"
L timeout 10 python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("192.168.1.10", 8443)); s.listen(1)
open(sys.argv[1], "w").close()
s.settimeout(8)
try:
    c, peer = s.accept(); c.sendall(b"through\n"); c.close()
except OSError:
    pass
' "$work/listening" > /dev/null 2>&1 &
n=0
while [ ! -e "$work/listening" ] && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
W timeout 5 python3 -c '
import socket
try:
    s = socket.create_connection(("203.0.113.1", 443), timeout=3)
    print(s.recv(100).decode().strip())
except OSError as e:
    print("refused")
' > "$work/client.log" 2>&1 || true
check "and with no forward the same connection does not get through" \
	"$(cat "$work/client.log")" "refused"

if [ "$failures" -ne 0 ]; then
	echo "port_forward.sh: $failures check(s) failed; the last apply said:"
	tail -8 "$work/apply.log"
	exit 1
fi
echo "port_forward.sh: all checks passed"
