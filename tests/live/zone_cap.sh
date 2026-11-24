#!/bin/sh
# A zone's per-client cap, measured as throughput (project.md 10.928).
#
#     unshare -rn sh tests/live/zone_cap.sh
#
# This namespace is the router netcfgd configures; a guest client and an
# upstream server sit in namespaces of their own on veths. With `client_limit =
# "5mbit"` on the guest zone, iperf3 is run both ways through the router, and
# with a written `accept established` first in the forward chain, as real
# ones have -- which a cap placed among the zone's rules would let every
# download past -- and then once more with the cap taken out -- the control that says the rig can
# carry far more, so a low number is the cap and not the rig.
#
# HOW IT STOPS: every iperf3 runs under `timeout` and serves one test (`-1`);
# the namespace holders are `sleep 120`, killed by the EXIT trap.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"
PATH="$PATH:/usr/sbin:/sbin"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "zone_cap.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "zone_cap.sh: skipping: $1"
	exit 0
}

[ "$(id -u)" = 0 ] || skip "run it as: unshare -rn sh tests/live/zone_cap.sh"
for tool in nft ip iperf3 python3 nsenter unshare timeout; do
	command -v "$tool" >/dev/null 2>&1 || skip "$tool is not installed"
done
[ -x "$build/ncfg" ] || skip "ncfg is not built (make -C c)"

work=$(mktemp -d /tmp/zcap.XXXXXX)
holders=
cleanup() {
	for pid in $holders; do
		kill "$pid" 2>/dev/null || true
	done
	rm -rf -- "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
ncfg="$build/ncfg"

failures=0
check() {
	if [ "$2" = "$3" ]; then
		printf 'ok   %s\n' "$1"
	else
		printf 'FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$3" "$2"
		failures=$((failures + 1))
	fi
}

unshare -n sleep 120 &
guest_pid=$!
unshare -n sleep 120 &
up_pid=$!
holders="$guest_pid $up_pid"
own=$(readlink /proc/$$/ns/net)
n=0
while { [ "$(readlink "/proc/$guest_pid/ns/net" 2>/dev/null)" = "$own" ] ||
    [ "$(readlink "/proc/$up_pid/ns/net" 2>/dev/null)" = "$own" ]; } && [ "$n" -lt 50 ]; do
	sleep 0.1
	n=$((n + 1))
done
G() { nsenter --net="/proc/$guest_pid/ns/net" "$@"; }
U() { nsenter --net="/proc/$up_pid/ns/net" "$@"; }

ip link set lo up
ip link add zg0 type veth peer name gpeer
ip link set gpeer netns "$guest_pid"
ip link add zw0 type veth peer name upeer
ip link set upeer netns "$up_pid"
G ip link set lo up
G ip addr add 10.81.0.2/24 dev gpeer
G ip link set gpeer up
G ip route add default via 10.81.0.1
U ip link set lo up
U ip addr add 10.82.0.2/24 dev upeer
U ip link set upeer up
U ip route add default via 10.82.0.1

write() { # $1: the guest zone's extra keys
	cat > "$work/etc/netcfgd.conf" <<CONF
zone "guest" { reach = ["internet"]$1 }
zone "internet" { reach = [] }
interface zg0 { config = "10.81.0.1/24"; zone = "guest"; forwarding = true }
interface zw0 { config = "10.82.0.1/24"; zone = "internet"; forwarding = true }
firewall {
	input { policy = "accept" }
	forward {
		policy = "drop"
		accept "established" { state = ["established", "related"] }
	}
	output { policy = "accept" }
}
CONF
}

# Mbit/s the receiver counted over six seconds; $1 is `-R` for the server
# sending, empty for the guest sending.
measure() {
	U timeout 20 iperf3 -s -1 -B 10.82.0.2 > /dev/null 2>&1 &
	server=$!
	n=0
	until U sh -c 'ss -ltn 2>/dev/null | grep -q ":5201 "' || [ "$n" -gt 50 ]; do
		sleep 0.1
		n=$((n + 1))
	done
	G timeout 20 iperf3 -c 10.82.0.2 -t 6 -J $1 > "$work/iperf.json" 2>/dev/null || true
	wait "$server" 2>/dev/null || true
	python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(int(d["end"]["sum_received"]["bits_per_second"] / 1e6))
except Exception:
    print(-1)
' "$work/iperf.json"
}

write '; client_limit = "5mbit"'
"$ncfg" apply > "$work/apply" 2>&1 || true
check "the capped configuration applies" "$(grep -c '^FAIL' "$work/apply" || true)" "0"
up=$(measure "")
down=$(measure -R)
echo "  capped: up $up Mbit/s, down $down Mbit/s"
check "what a guest client sends is held near 5 Mbit/s" \
	"$([ "$up" -ge 1 ] && [ "$up" -le 6 ] && echo held || echo "$up")" "held"
check "and what it receives" \
	"$([ "$down" -ge 1 ] && [ "$down" -le 6 ] && echo held || echo "$down")" "held"

# 10.931: the same client capped by its address, in a zone of hosts rather
# than by the link it is on.
cat > "$work/etc/netcfgd.conf" <<'CONF'
zone "kids" { reach = ["internet"]; hosts = ["10.81.0.2"]; client_limit = "5mbit" }
zone "internet" { reach = [] }
interface zg0 { config = "10.81.0.1/24"; forwarding = true }
interface zw0 { config = "10.82.0.1/24"; zone = "internet"; forwarding = true }
firewall {
	input { policy = "accept" }
	forward {
		policy = "drop"
		accept "established" { state = ["established", "related"] }
	}
	output { policy = "accept" }
}
CONF
"$ncfg" apply > "$work/apply" 2>&1 || true
by_up=$(measure "")
by_down=$(measure -R)
echo "  capped by address: up $by_up Mbit/s, down $by_down Mbit/s"
check "a client in a zone of hosts is held near 5 Mbit/s each way" \
	"$([ "$by_up" -ge 1 ] && [ "$by_up" -le 6 ] && [ "$by_down" -ge 1 ] && [ "$by_down" -le 6 ] && echo held || echo "$by_up/$by_down")" "held"

# 10.933: the same client in a zone whose hosts are a slot's members, the
# slot opened by the zone itself: uncapped until it is written into the slot,
# with no apply between, and capped from then on.
cat > "$work/etc/netcfgd.conf" <<'CONF'
zone "kids" { reach = ["internet"]; hosts = ["@slot:kids"]; client_limit = "5mbit" }
zone "internet" { reach = [] }
interface zg0 { config = "10.81.0.1/24"; forwarding = true }
interface zw0 { config = "10.82.0.1/24"; zone = "internet"; forwarding = true }
firewall {
	input { policy = "accept" }
	forward {
		policy = "drop"
		accept "established" { state = ["established", "related"] }
		accept "others" { interface = "zg0" }
	}
	output { policy = "accept" }
}
CONF
"$ncfg" apply > "$work/apply" 2>&1 || true
check "a zone of a slot's members applies" "$(grep -c '^FAIL' "$work/apply" || true)" "0"
outside=$(measure "")
# The set write `ncfg slot add` makes through the daemon (firewall.sh drives
# that path); here the element is written directly, as nothing else runs.
nft add element inet netcfgd slot-kids-4 '{ 10.81.0.2 }' > "$work/slot" 2>&1 || true
member_up=$(measure "")
member_down=$(measure -R)
echo "  outside the slot: up $outside Mbit/s; a member: up $member_up, down $member_down Mbit/s"
check "a client not yet in the slot is not capped" \
	"$([ "$outside" -ge 60 ] && echo free || echo "$outside")" "free"
check "and once written into it, held near 5 Mbit/s each way with no apply" \
	"$([ "$member_up" -ge 1 ] && [ "$member_up" -le 6 ] && [ "$member_down" -ge 1 ] && [ "$member_down" -le 6 ] && echo held || echo "$member_up/$member_down")" "held"
"$ncfg" plan > "$work/plan" 2>&1 || true
check "and the plan is still converged" "$(tail -1 "$work/plan")" "nothing to do"

write ''
"$ncfg" apply > "$work/apply" 2>&1 || true
free_up=$(measure "")
echo "  uncapped: up $free_up Mbit/s"
check "without the cap the same rig carries ten times that" \
	"$([ "$free_up" -ge 60 ] && echo far-more || echo "$free_up")" "far-more"

echo
if [ "$failures" -eq 0 ]; then
	echo "zone_cap.sh: all checks passed"
else
	echo "zone_cap.sh: $failures check(s) failed"
	exit 1
fi
