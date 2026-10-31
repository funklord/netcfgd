#!/bin/sh
# The ISP: kea-dhcp6 delegating a prefix on the segment.
#
# Always exits 0 and reports through its verdict file, for the reason
# tests/hull/wire/payload.sh gives: hull plans a (machines ...) file together
# and the first failure stops the rest, so a payload that exits non-zero takes
# its sibling with it and the collector then blames the wrong machine.
set -u
out=/verdict/isp
say() { printf '%s\n' "$*" >> "$out"; }
: > "$out"

say "kea $(dpkg-query -W -f='${Version}' kea-dhcp6-server 2>/dev/null)"
if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so there is no segment to serve"
	exit 0
fi
# **DAD off, and the link-local waited for, before kea binds.** kea opens its
# sockets at config time and joins the DHCPv6 multicast groups then; a
# link-local still tentative under DAD is not a usable source, so a server
# started too early can configure cleanly and answer nothing. That is the shape
# of this rig's intermittency -- it passed once and failed three times with the
# server reporting itself healthy every time, and the client's solicit reaching
# a wire that demonstrably carries multicast.
sysctl -q -w net.ipv6.conf.eth1.accept_dad=0 2>/dev/null || true
ip link set eth1 up
ip -6 addr add 2001:db8:aaaa::1/64 dev eth1 nodad
waited=0
while [ "$waited" -lt 100 ]; do
	if ip -o -6 addr show dev eth1 scope link | grep -q 'tentative'; then
		waited=$((waited + 1))
		sleep 0.1
		continue
	fi
	break
done
say "link-local settled after $((waited / 10))s: $(ip -o -6 addr show dev eth1 scope link | awk '{print $4}')"
# Read it back rather than trusting the call -- tests/hull/wire learned that.
ip -o -6 addr show dev eth1 | sed 's/^/  addr: /' >> "$out"

mkdir -p /run/kea
# The pool and the delegated length are `tests/live/delegation.sh`'s, so the
# two tiers delegate the same prefix and a reader comparing them is comparing
# like with like.
cat > /run/kea/kea.json <<'JSON'
{ "Dhcp6": {
  "interfaces-config": { "interfaces": [ "eth1" ] },
  "lease-database": { "type": "memfile", "persist": false },
  "valid-lifetime": 600,
  "subnet6": [ {
      "id": 1,
      "subnet": "2001:db8:aaaa::/48",
      "pools": [ { "pool": "2001:db8:aaaa::100 - 2001:db8:aaaa::200" } ],
      "pd-pools": [ { "prefix": "2001:db8:1234::", "prefix-len": 48, "delegated-len": 56 } ],
      "interface": "eth1"
  } ]
} }
JSON
kea-dhcp6 -c /run/kea/kea.json > /run/kea/kea.log 2>&1 &
kea_pid=$!
waited=0
while [ "$waited" -lt 50 ]; do
	if grep -q 'DHCP6_STARTED\|server has completed' /run/kea/kea.log 2>/dev/null; then
		break
	fi
	waited=$((waited + 1))
	sleep 0.2
done
if ! kill -0 "$kea_pid" 2>/dev/null; then
	say "VERDICT bad: kea did not stay up"
	sed 's/^/  kea: /' /run/kea/kea.log >> "$out"
	exit 0
fi
say "kea is serving on eth1, pd-pool 2001:db8:1234::/48 delegated at /56"
say "VERDICT ok: the ISP is up"

# **It has to outlive its own payload.** The CPE needs an ISP to ask, and a
# machine whose command returns is a machine hull stops -- so this stands
# until the CPE has its verdict. It is started only after this one is ready
# (hull.conf), so a fixed lifetime would be counting the CPE's boot as well;
# the ceiling is its own, so a wedged sibling cannot leave this running.
waited=0
until grep -q '^VERDICT' /verdict/cpe 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 300 ] && break
	sleep 1
done
say "the ISP stood ${waited}s, until the CPE's verdict, and is standing down"
sed 's/^/  kea: /' /run/kea/kea.log >> "$out"
