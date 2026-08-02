#!/bin/sh
# A real delegated prefix, from a real server, turned into a real address.
#
#     sudo sh tests/live/delegation.sh
#
# This is decision 0009's whole loop, which nothing had ever run end to end: the
# document asks for a prefix, `odhcp6c` solicits one, the ISP delegates one, the
# hook netcfgd generated reports it, and netcfgd derives an address on the LAN
# from the `@pd:` reference. Every one of those steps was tested separately and
# the joins between them were not -- which is how three separate defects in the
# dhcpcd half survived for as long as they did (decision 0050).
#
# `kea-dhcp6` is the ISP. A veth pair is the line. There is no hardware here.
#
# **Needs real root**, so `make live` does not run it: odhcp6c binds port 546
# and opens a packet socket, and kea binds 547. The same bucket as `hwsim.sh`
# and `pppoe-session.sh`, and it makes its own namespaces for the same reason.
#
# It also needs **odhcp6c**, which Debian does not package -- decision 0050 is
# why netcfgd will not pretend dhcpcd can do this instead. It builds from source
# in a couple of minutes:
#
#     git clone https://github.com/openwrt/libubox && cd libubox
#     cmake -B build -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF && cmake --build build
#     sudo cmake --install build
#     git clone https://github.com/openwrt/odhcp6c && cd odhcp6c
#     cmake -B build && cmake --build build
#
# On OpenWrt, where prefix delegation is the ordinary case, it is already there.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

if [ "$(id -u)" != "0" ]; then
	echo "delegation.sh: needs real root: odhcp6c binds port 546 and kea binds 547."
	echo "delegation.sh:   sudo sh tests/live/delegation.sh"
	exit 0
fi

if [ -z "${NCFG_PD_NS:-}" ]; then
	NCFG_PD_NS=1
	export NCFG_PD_NS
	exec unshare -mn sh "$0" "$@"
fi

for tool in odhcp6c kea-dhcp6 ip; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "delegation.sh: skipping: no $tool (see the header for odhcp6c)"
		exit 0
	}
done
[ -x "$repo/target/debug/ncfg" ] || {
	echo "delegation.sh: skipping: ncfg is not built"
	exit 0
}

work=$(mktemp -d /tmp/ncfg-pd.XXXXXX)
cleanup() {
	pkill -f 'kea-dhcp6 -c' 2>/dev/null || true
	pkill -f 'odhcp6c' 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run" /run/kea /var/lib/kea

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
ncfg="$repo/target/debug/ncfg"

failures=0
check() {
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1"
		echo "       expected: $3"
		echo "       actual:   $2"
		failures=$((failures + 1))
	fi
}

ip link set lo up
ip link add isp0 type veth peer name wan0
ip link add lan0 type dummy
ip link set isp0 up
ip link set wan0 up
ip link set lan0 up

# Duplicate address detection has to finish before anything binds a link-local
# address, or the bind fails with "Cannot assign requested address" on an
# address `ip addr` will happily show. kea does exactly that if it starts too
# early, and the error names the address rather than the reason.
waited=0
while [ "$(ip -6 -o addr show scope link | grep -c tentative)" != "0" ] ||
	[ "$(ip -6 -o addr show scope link | wc -l)" -lt 2 ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 100 ] && break
	sleep 0.1
done

cat > "$work/kea.json" <<'JSON'
{ "Dhcp6": {
  "interfaces-config": { "interfaces": [ "isp0" ] },
  "lease-database": { "type": "memfile", "persist": false },
  "valid-lifetime": 600,
  "subnet6": [ {
      "id": 1,
      "subnet": "2001:db8:aaaa::/48",
      "pools": [ { "pool": "2001:db8:aaaa::100 - 2001:db8:aaaa::200" } ],
      "pd-pools": [ { "prefix": "2001:db8:1234::", "prefix-len": 48, "delegated-len": 56 } ],
      "interface": "isp0"
  } ]
} }
JSON
kea-dhcp6 -c "$work/kea.json" > "$work/kea.log" 2>&1 &
sleep 2

# The router shape from decision 0009: the WAN asks for a prefix, and the LAN
# takes an address out of it. Nothing in the document is the prefix itself --
# `@pd:wan0` is a reference, and what it refers to does not exist until an ISP
# says so.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface wan0 {
	config = "dhcp6 pd_length 56"
}

interface lan0 {
	kind   = "dummy"
	config = "@pd:wan0=::1/64"
}
CONF

"$ncfg" plan > "$work/plan.txt" 2>&1 || true
# Before the lease: the address cannot be derived and the plan says what it is
# waiting for rather than failing or inventing one.
check "a reference with nothing behind it waits rather than failing" \
	"$(grep -c 'delegat' "$work/plan.txt" || true)" "1"

"$ncfg" apply > "$work/apply.txt" 2>&1 || true

prefixes="$work/run/prefixes/wan0"
waited=0
while [ ! -s "$prefixes" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 200 ] && break
	sleep 0.1
done

check "odhcp6c solicited and the ISP delegated" \
	"$(grep -c '^2001:db8:1234::/56$' "$prefixes" 2>/dev/null || true)" "1"
if [ ! -s "$prefixes" ]; then
	echo "--- odhcp6c said:"; tail -10 "$work/apply.txt" || true
	echo "--- kea said:"; tail -10 "$work/kea.log" || true
fi
# The lifetimes odhcp6c appends are not part of the prefix. It reports
# `2001:db8:1234::/56,365,590,178,290` and the hook keeps what is before the
# first comma.
check "and the hook kept the prefix without the lifetimes" \
	"$(grep -c ',' "$prefixes" 2>/dev/null || true)" "0"

# The second apply is the one that derives the address, because the reference
# had nothing behind it until now. `@pd:wan0=::1/64` is the first address of
# the first /64 of what the ISP gave.
"$ncfg" apply > "$work/apply2.txt" 2>&1 || true
check "netcfgd derived the LAN address from it" \
	"$(ip -6 addr show lan0 | grep -c '2001:db8:1234::1/64' || true)" "1"
# `0x6e` is 110: iproute2 prints an address protocol in hex and a route
# protocol in decimal, for the same tag. Worth knowing before writing the
# obvious assertion and watching it fail on a correct address.
check "and tagged it as its own, so it can be withdrawn again" \
	"$(ip -6 addr show lan0 | grep -c 'proto 0x6e' || true)" "1"

"$ncfg" plan > "$work/replan.txt" 2>&1 || true
check "and the next plan has nothing to do" \
	"$(grep -cE 'addr\.|route\.' "$work/replan.txt" || true)" "0"

# The lease going away takes the address with it. odhcp6c is stopped rather
# than the lease being expired, which is the same thing from netcfgd's side: the
# hook empties the file and the reference has nothing behind it again.
pkill -f odhcp6c 2>/dev/null || true
: > "$prefixes"
"$ncfg" apply > "$work/gone.txt" 2>&1 || true
check "a prefix that goes takes the address derived from it" \
	"$(ip -6 addr show lan0 | grep -c '2001:db8:1234::1/64' || true)" "0"

echo
if [ "$failures" -eq 0 ]; then
	echo "delegation.sh: all checks passed"
else
	echo "delegation.sh: $failures check(s) failed"
	exit 1
fi
