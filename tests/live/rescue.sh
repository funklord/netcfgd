#!/bin/sh
# netrescue end to end (0326): ports to a document, the document to its own
# netcfgd, a lease to a default route, and the gateway answering -- then the
# same with no server at all, where it has to keep its fallback and climb.
#
#     sh tests/live/rescue.sh        (it enters its own namespace)
#
# WHAT IS REAL AND WHAT IS NOT
#   The daemon, the DHCP exchange (busybox udhcpd on the far end of a veth
#   pair, udhcpc driven by netcfgd), the route and the echo are all real. The
#   ports are not: a veth has no `device` in sysfs, so netrescue would rightly
#   not call it a port, and this hands it a sysfs directory naming the veth
#   as one with `--sysfs`. That seam is the only thing standing in.
#
#   The gateway is the far end's address in the same namespace, so its echo
#   is answered locally. What that proves is the wiring -- a default route
#   arrived from a lease netcfgd's client took, and netrescue read it and
#   asked -- not that a packet crossed a wire.
#
# WHAT STOPS IT
#   Every netrescue here runs with `--for`, its own bound, and is killed by
#   its pid on exit besides; netrescue stops the daemon it started. The
#   waits are counted loops. udhcpd is killed by its pid, and so is the
#   loop that makes ARP traffic for the listening phase, which also stops by
#   itself after 120 pings or when the work directory goes.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

PATH="$PATH:/usr/sbin:/sbin"
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "rescue.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "rescue.sh: skipping: $1"
	exit 0
}

[ -x "$build/netrescue" ] || skip "netrescue is not built (make -C c)"
command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v busybox >/dev/null 2>&1 || skip "no busybox"
busybox --list | grep -qx udhcpc || skip "this busybox has no udhcpc"
busybox --list | grep -qx udhcpd || skip "this busybox has no udhcpd"

if [ -z "${NCFG_RESCUE_NS:-}" ]; then
	NCFG_RESCUE_NS=1
	export NCFG_RESCUE_NS
	exec unshare --map-root-user --net -- sh "$0" "$@"
fi
ip link add rscp$$ type dummy 2>/dev/null || skip "cannot create a link in a namespace"
ip link del rscp$$

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-rescue.XXXXXX")
server=
rescuer=
chatter=
neighbour=
# The DHCP clients netcfgd started outlive netrescue on purpose -- a daemon
# that stops leaves its backends for the next one to adopt -- so the test
# stops them, by the pid file netcfgd wrote and only where the process still
# names this run's directory. Found leaving one udhcpc per phase behind.
stop_clients() {
	for file in "$work"/*/run/udhcpc/*.pid; do
		[ -f "$file" ] || continue
		pid=$(cat "$file" 2>/dev/null || true)
		case "$pid" in [0-9]*) ;; *) continue ;; esac
		case "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)" in
		*"$work"*) kill "$pid" 2>/dev/null || true ;;
		esac
		rm -f "$file"
	done
}
cleanup() {
	for pid in $rescuer $server $chatter $neighbour; do
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
	stop_clients
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

failures=0
contains() {
	case "$2" in
	*"$3"*) echo "ok   $1" ;;
	*)
		echo "FAIL $1"
		echo "       expected to contain: $3"
		failures=$((failures + 1))
		;;
	esac
}
missing() {
	case "$2" in
	*"$3"*)
		echo "FAIL $1"
		echo "       expected NOT to contain: $3"
		failures=$((failures + 1))
		;;
	*) echo "ok   $1" ;;
	esac
}

# `lo` up: the gateway's echo is answered locally, and local delivery goes
# over loopback, which a fresh namespace has down.
ip link set lo up

# `cli` is the port; sysfs is told so.
ip link add cli type veth peer name srv
ip link set srv up
ip addr add 10.45.0.1/24 dev srv
mkdir -p "$work/sys/cli" "$work/devices/fake"
printf '1\n' > "$work/sys/cli/type"
printf '1\n' > "$work/sys/cli/carrier"
ln -s ../../devices/fake "$work/sys/cli/device"

cat > "$work/udhcpd.conf" <<EOF
start 10.45.0.20
end 10.45.0.20
interface srv
option subnet 255.255.255.0
option router 10.45.0.1
option lease 600
lease_file $work/udhcpd.leases
pidfile $work/udhcpd.pid
EOF
: > "$work/udhcpd.leases"

# Wait up to $2 seconds for $1 to appear in the report.
wait_for() {
	waited=0
	while ! grep -q "$1" "$work/rescue.out" 2>/dev/null; do
		waited=$((waited + 1))
		[ "$waited" -gt "$(( $2 * 5 ))" ] && return 1
		sleep 0.2
	done
	return 0
}

# ---- 1. A server answers: rung 1 is enough.
busybox udhcpd -f "$work/udhcpd.conf" > "$work/udhcpd.log" 2>&1 &
server=$!

"$build/netrescue" --dir "$work/one" --sysfs "$work/sys" --wait 30 --for 40 \
	> "$work/rescue.out" 2>&1 &
rescuer=$!
if wait_for "reachable:" 30; then
	echo "ok   a lease, a default route, and the gateway answers"
else
	echo "FAIL no gateway answered within 30 s"
	sed 's/^/       /' "$work/rescue.out"
	sed 's/^/       netcfgd: /' "$work/one/netcfgd.log" 2>/dev/null | tail -20
	failures=$((failures + 1))
fi
report=$(cat "$work/rescue.out")
contains "the port is named with its carrier" "$report" "ports: cli (carrier)"
contains "rung 1 is written, the fallback on the one port" "$report" "rung 1: DHCP on every Ethernet port"
contains "and it says which gateway" "$report" "gateway 10.45.0.1 answers, at rung 1"
missing "and it did not climb" "$report" "rung 2"
addresses=$(ip -4 -br addr show cli)
contains "the lease is on the port" "$addresses" "10.45.0.20"
contains "and the fallback beside it" "$addresses" "10.0.0.250/16"
contains "the kernel's IPv6 link-local address is left on it" "$(ip -6 -br addr show cli)" "fe80::"
contains "the report is in its log as well" "$(cat "$work/one/netrescue.log")" "answers, at rung 1"


kill "$rescuer"
wait "$rescuer" 2>/dev/null || true
rescuer=
contains "a signal stops it and says so" "$(cat "$work/rescue.out")" "stopping: asked to"
if [ -n "$(ps -eo pid=,args= | grep "[n]etcfgd --config-dir $work/one" || true)" ]; then
	echo "FAIL the daemon it started outlived it"
	failures=$((failures + 1))
else
	echo "ok   and the daemon it started went with it"
fi
kill "$server"
wait "$server" 2>/dev/null || true
server=
stop_clients

# ---- 2. Nothing answers: the fallback stays and the ladder climbs.
ip addr flush dev cli
ip addr del 10.45.0.1/24 dev srv
"$build/netrescue" --dir "$work/two" --sysfs "$work/sys" --wait 4 --listen 2 --for 30 \
	> "$work/rescue.out" 2>&1 &
rescuer=$!
if wait_for "starting again from the first" 30; then
	echo "ok   with no gateway it climbed every rung and started again"
else
	echo "FAIL it never went round the ladder"
	sed 's/^/       /' "$work/rescue.out"
	failures=$((failures + 1))
fi
report=$(cat "$work/rescue.out")
contains "it says why" "$report" "not yet: no default route"
contains "it listened at rung 2" "$report" "listening on cli"
contains "and said it heard too little" "$report" "not enough to say what network it is"
contains "rung 3 was written" "$report" "rung 3:"
contains "and rung 4" "$report" "rung 4:"
contains "the document at the top asked for 100/full" "$report" "forced to 100/full"
contains "the fallback is on the port whatever the rung" "$(ip -4 -br addr show cli)" "10.0.0.250/16"
wait "$rescuer" 2>/dev/null || true
rescuer=
contains "--for bounds it" "$(cat "$work/rescue.out")" "--for 30 s has run out"

stop_clients

# ---- 3. No DHCP, but a network to hear: the listening rung learns it.
# The far end is 10.46.0.1 and asks for addresses around it, which is the
# traffic a gateway makes; netrescue should take its /24 and route through it.
# It also holds .250 without ever being heard using it, so the first address
# netrescue would pick is one only its probe can find taken.
ip addr flush dev cli
ip addr add 10.46.0.1/24 dev srv
ip addr add 10.46.0.250/24 dev srv
(
	n=0
	while [ "$n" -lt 120 ] && [ -d "$work" ]; do
		busybox ping -c 1 -W 1 "10.46.0.$((10 + n % 20))" >/dev/null 2>&1 || true
		n=$((n + 1))
	done
) &
chatter=$!
"$build/netrescue" --dir "$work/three" --sysfs "$work/sys" --wait 4 --listen 4 --for 40 \
	> "$work/rescue.out" 2>&1 &
rescuer=$!
if wait_for "reachable:" 40; then
	echo "ok   with no DHCP it learned the network by listening and reached the gateway"
else
	echo "FAIL it never reached the gateway by listening"
	sed 's/^/       /' "$work/rescue.out"
	failures=$((failures + 1))
fi
report=$(cat "$work/rescue.out")
contains "it says what it learned" "$report" "learned on cli"
contains "the gateway by its traffic" "$report" "gateway 10.46.0.1 by traffic"
contains "and it reached it at the listening rung" "$report" "answers, at rung 2"
contains "the probe found .250 in use" "$report" "10.46.0.250 is in use on cli"
contains "and the next address is on the port" "$(ip -4 -br addr show cli)" "10.46.0.249/24"
kill "$rescuer" 2>/dev/null || true
wait "$rescuer" 2>/dev/null || true
rescuer=
kill "$chatter" 2>/dev/null || true
wait "$chatter" 2>/dev/null || true
stop_clients

# ---- 4. A name on the link: NAME.local asked by a neighbour.
# The neighbour is in a namespace of its own, as a laptop on the cable is a
# host of its own: in this one a query arriving on a port from an address
# the namespace holds is dropped as a martian, which IPv4 does and IPv6 does
# not -- found as an IPv4 query that was never answered. Asked the way a
# resolver that is not a responder asks, from a port other than 5353, so the
# answer comes back to it, over both families; three seconds a question.
if command -v python3 >/dev/null 2>&1 && command -v nsenter >/dev/null 2>&1; then
	ip link add m0 type veth peer name m1
	mkdir -p "$work/sys4/m0"
	printf '1\n' > "$work/sys4/m0/type"
	printf '1\n' > "$work/sys4/m0/carrier"
	ln -s ../../devices/fake "$work/sys4/m0/device"
	unshare --net -- sleep 120 &
	neighbour=$!
	waited=0
	while [ "$(readlink /proc/$neighbour/ns/net 2>/dev/null)" = "$(readlink /proc/$$/ns/net)" ] &&
	    [ "$waited" -lt 50 ]; do
		waited=$((waited + 1))
		sleep 0.1
	done
	ip link set m1 netns "$neighbour"
	nsenter -t "$neighbour" -n ip link set lo up
	nsenter -t "$neighbour" -n ip link set m1 up
	nsenter -t "$neighbour" -n ip addr add 10.0.0.1/16 dev m1
	"$build/netrescue" --dir "$work/four" --sysfs "$work/sys4" --wait 30 --for 30 \
		--name rescuetest > "$work/rescue.out" 2>&1 &
	rescuer=$!
	wait_for "rung 1:" 10 || true
	waited=0
	while ! ip -4 -br addr show m0 | grep -q 10.0.0.250 && [ "$waited" -lt 50 ]; do
		waited=$((waited + 1))
		sleep 0.2
	done
	m0_6=$(ip -6 -br addr show m0 | awk '{ print $3 }' | cut -d/ -f1)
	answers=$(nsenter -t "$neighbour" -n python3 - <<'PY' 2>&1
import socket, struct
def query(name, kind):
    b = struct.pack('>HHHHHH', 0x4242, 0, 1, 0, 0, 0)
    for label in name.split('.'):
        b += bytes([len(label)]) + label.encode()
    return b + b'\0' + struct.pack('>HH', kind, 1)
def ask(family, group, kind):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(3)
    if family == socket.AF_INET:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('10.0.0.1'))
        s.sendto(query('rescuetest.local', kind), (group, 5353))
    else:
        index = socket.if_nametoindex('m1')
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
        s.sendto(query('rescuetest.local', kind), (group, 5353, 0, index))
    try:
        data, _ = s.recvfrom(1500)
    except socket.timeout:
        return 'nothing'
    if data[:2] != b'\x42\x42':
        return 'a wrong id'
    if kind == 1:
        return socket.inet_ntop(socket.AF_INET, data[-4:])
    return socket.inet_ntop(socket.AF_INET6, data[-16:])
def ask_as_responder(kind):
    # From 5353 and joined to the group, as avahi and Bonjour ask: the
    # answer goes to the group rather than back to the asker.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 5353))
    membership = socket.inet_aton('224.0.0.251') + socket.inet_aton('10.0.0.1')
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('10.0.0.1'))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    s.settimeout(3)
    s.sendto(query('rescuetest.local', kind), ('224.0.0.251', 5353))
    try:
        while True:
            data, sender = s.recvfrom(1500)
            if data[2] & 0x80:
                return socket.inet_ntop(socket.AF_INET, data[-4:]) + ' from ' + sender[0]
    except socket.timeout:
        return 'nothing'
print('A', ask(socket.AF_INET, '224.0.0.251', 1))
print('AAAA', ask(socket.AF_INET6, 'ff02::fb', 28))
print('group', ask_as_responder(1))
PY
)
	contains "rescuetest.local answers a neighbour over IPv4 with the port's address" "$answers" "A 10.0.0.250"
	contains "and over IPv6 with its link-local address" "$answers" "AAAA $m0_6"
	contains "and to a responder asking from 5353, to the group" "$answers" "group 10.0.0.250 from 10.0.0.250"
	contains "it says what it answers to" "$(cat "$work/rescue.out")" "answering to rescuetest.local"
	kill "$rescuer" 2>/dev/null || true
	wait "$rescuer" 2>/dev/null || true
	rescuer=
	kill "$neighbour" 2>/dev/null || true
	wait "$neighbour" 2>/dev/null || true
	neighbour=
	ip link del m0 2>/dev/null || true
	stop_clients
else
	echo "skip mDNS: no python3 or nsenter to ask with"
fi

# ---- 5. What a person typing it gets wrong.
out=$("$build/netrescue" --wait 0 2>&1 || true)
contains "a wait of zero is refused" "$out" "is not something it takes"

if [ "$failures" -ne 0 ]; then
	echo "rescue.sh: $failures failed"
	exit 1
fi
echo "rescue.sh: all passed"
