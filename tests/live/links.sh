#!/bin/sh
# Every link type netcfgd can create, against a real kernel.
#
# The fixture harness in netcfgd-plan asserts what the *plan* says. This
# asserts what the kernel ends up holding, which is a different claim and the
# one that catches an attribute encoded in the wrong byte order, in the wrong
# unit, or nested in the wrong place.
#
# Both failure modes are real and they differ. A byte-swapped vlan ethertype is
# rejected outright, so the apply fails and the operator knows. A forward delay
# in the wrong unit is *accepted*: the bridge comes up with a 40ms delay
# instead of 4s and nothing anywhere says so. The second is why this file
# checks values rather than exit statuses.
#
# Runs under `unshare -rn`: creating links needs CAP_NET_ADMIN, not root.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "links.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "links.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8) to check the result with"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d /tmp/ncfg-links.XXXXXX)
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface bond0 {
	bond { members = "veth-a veth-b"; mode = "active-backup"; miimon = 100 }
	config = "null"
}

interface veth-a { veth { peer = "veth-b" }; config = "null" }

interface br0 {
	bridge { stp = true; forward_delay = 4 }
	config = "10.9.0.1/24"
}

interface br0.42 {
	vlan { parent = "br0"; id = 42; protocol = "dot1ad" }
	config = "null"
}

interface vx100 {
	vxlan { id = 100; parent = "br0"; local = "10.9.0.1"; remote = "10.9.0.2"; port = 4789 }
	config = "null"
}

# Everything below came out of the pre-freeze format audit.
interface mgmt-vrf { vrf { table = 100 }; config = "null" }
interface base0    { kind = "dummy"; config = "10.7.0.1/24" }
interface mv0      { macvlan { parent = "base0"; mode = "bridge" }; config = "null" }
interface gre1     { tunnel { mode = "gre"; local = "10.7.0.1"; remote = "10.7.0.2"; key = 42 }; config = "null" }
interface sit1     { tunnel { mode = "sit"; local = "10.7.0.1"; remote = "10.7.0.3"; ttl = 64 }; config = "null" }
interface gnv0     { tunnel { mode = "geneve"; remote = "10.7.0.4"; vni = 500 }; config = "null" }

# Per-port VLAN membership: how a switch is provisioned on a current kernel.
interface brv2 { bridge { vlan_filtering = true }; vlans = "10"; config = "null" }
# Driver offloads. A veth is the right device for once: it takes the features
# message, unlike the ring, link-mode and wake-on-LAN messages -- which is
# exactly why those three are still unimplemented.
interface off0 {
	veth    { peer = "off0p" }
	ethtool { gso = "off"; tso = "on" }
	config  = "null"
}

# An IPv6 interface identifier. A veth, deliberately: the kernel refuses a
# token on any device that does not do neighbour discovery, so a dummy gets
# "Device does not do neighbour discovery" and would test only the error path.
interface tok0 {
	veth       { peer = "tok0p" }
	ipv6_token = "::5"
	config     = "null"
}

# A filtering bridge the config gives no vlans to. The kernel puts vlan 1 on it
# and netcfgd must leave it there -- the authority is over what is configured.
interface brkeep { bridge { vlan_filtering = true }; config = "null" }
interface lan1 {
	veth   { peer = "lan1p" }
	master = "brv2"
	vlans  = "
		10 pvid untagged
		20
		30-32
	"
	config = "null"
}
CONF

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
ncfg="$repo/target/debug/ncfg"

failures=0
missing() {
	case "$2" in
	*"$3"*)
		echo "FAIL $1"
		echo "       expected NOT to contain: $3"
		echo "       actual:                  $2"
		failures=$((failures + 1))
		;;
	*) echo "ok   $1" ;;
	esac
}

contains() {
	case "$2" in
	*"$3"*) echo "ok   $1" ;;
	*)
		echo "FAIL $1"
		echo "       expected to contain: $3"
		echo "       actual:              $2"
		failures=$((failures + 1))
		;;
	esac
}

if ! "$ncfg" apply > "$work/apply.log" 2>&1; then
	# CAP_NET_ADMIN is the usual reason, and the caller may not have arranged
	# it -- `make live` does, a bare run does not.
	if grep -q 'Operation not permitted' "$work/apply.log"; then
		skip "no CAP_NET_ADMIN (run under unshare -rn)"
	fi
	echo "links.sh: apply failed" >&2
	cat "$work/apply.log" >&2
	exit 1
fi

detail() { ip -d link show "$1" 2>&1; }

contains "a bond gets its mode"        "$(detail bond0)"  "mode active-backup"
contains "and its monitoring interval" "$(detail bond0)"  "miimon 100"

# The kernel counts forward delay in hundredths of a second and the config
# counts it in seconds, because that is what every other tool uses. 4 -> 400.
contains "a bridge gets spanning tree" "$(detail br0)"    "stp_state 1"
contains "and its forward delay, converted" "$(detail br0)" "forward_delay 400"

# Big-endian on the wire. The kernel refuses the byte-swapped value, so getting
# this wrong fails the apply -- checked by sending the wrong one.
contains "a vlan gets the right tag protocol" "$(detail br0.42)" "protocol 802.1ad"
contains "and its id"                  "$(detail br0.42)" "id 42"

contains "a vxlan gets its vni"        "$(detail vx100)"  "id 100"
contains "and both endpoints"          "$(detail vx100)"  "remote 10.9.0.2 local 10.9.0.1"
contains "and its port"                "$(detail vx100)"  "dstport 4789"

# Creating one end of a veth creates both, and the peer has no `interface`
# block. The planner has to know it will appear or it is configured on the
# *next* apply -- which a daemon reaches and `--oneshot` never does.
contains "a veth pair exists"          "$(ip -br link show type veth)" "veth-b@veth-a"
# `gso = off` removes it and `tso = on` leaves the other alone -- the kernel
# takes a mask, so a request names exactly what changes.
offloads=$("$repo/target/debug/ncfg" status 2>/dev/null | awk '
	/^[^ ]/ { iface = $1 } iface == "off0" && $1 == "offloads" { print }')
missing "gso is turned off"            "$offloads" "tx-generic-segmentation"
contains "and tso left on"             "$offloads" "tx-tcp-segmentation"
# The prefix would come from a router advertisement; the host half is this.
contains "an ipv6 token is set"        "$(ip token show dev tok0)" "token ::5 dev tok0"
contains "the declared end is enslaved" "$(detail veth-a)" "master bond0"
contains "and so is the peer"          "$(detail veth-b)" "master bond0"

# A VRF is what `RoutingRule.l3mdev` matches, and until the audit nothing could
# create one -- a rule field that could only ever match something netcfgd could
# not build.
contains "a vrf owns its table"        "$(detail mgmt-vrf)" "vrf table 100"
contains "a dummy can be declared"     "$(ip -br addr show base0)" "10.7.0.1/24"
contains "a macvlan gets its mode"     "$(detail mv0)"    "macvlan mode bridge"

# GRE and the ip tunnels do *not* share attribute numbering, which is how the
# first version of this failed. GRE puts endpoints at 6 and 7 where sit puts
# them at 2 and 3, so sending one numbering to the other lands the local
# address in a flags field.
contains "a gre tunnel gets its endpoints" "$(detail gre1)" "remote 10.7.0.2 local 10.7.0.1"
# A key with no flag bit is silently ignored, and two ends with different keys
# would then pass traffic as though neither had one.
contains "and its key, which needs the flag" "$(detail gre1)" "ikey 0.0.0.42"
contains "a sit tunnel uses the other numbering" "$(detail sit1)" "remote 10.7.0.3 local 10.7.0.1"
contains "and its ttl"                 "$(detail sit1)"   "ttl 64"
contains "a geneve tunnel gets its vni" "$(detail gnv0)"  "geneve id 500"

# The VLANs read back from the kernel, through netcfgd's own observation --
# `bridge` is not installed everywhere and this is the path that matters.
# Per interface, not across the whole host. The first version of this check
# collected every vid from the JSON and looked for a 1 -- which found the one
# on `brv`, a filtering bridge the config gives no vlans to and netcfgd
# correctly leaves alone. A check that cannot tell those apart reports a bug
# that is not there, and would have hidden the one that is.
vlans_of() {
	"$ncfg" status 2>/dev/null | awk -v want="$1" '
		/^[^ ]/ { iface = $1 }
		iface == want && /^    vlan / { printf "%s ", $2 }
	'
}

contains "a port gets its pvid"    "$(vlans_of lan1)" "10 "
contains "and a tagged vlan"       "$(vlans_of lan1)" "20 "
contains "and every id in a range" "$(vlans_of lan1)" "32 "
contains "a bridge can hold one itself" "$(vlans_of brv2)" "10 "

# The kernel adds vlan 1 when a port joins a filtering bridge. A configured
# port owns its list, so it goes -- every real trunk setup starts by deleting
# it, and leaving it would mean the document does not describe the port.
case " $(vlans_of lan1)" in
*" 1 "*)
	echo "FAIL the kernel default vlan 1 was left on the configured port"
	failures=$((failures + 1))
	;;
*) echo "ok   the kernel default vlan 1 is gone from the configured port" ;;
esac

# And the bridge the config says nothing about keeps its own. The authority is
# over ports that are configured, not over the bridge.
contains "an unconfigured bridge keeps vlan 1" "$(vlans_of brkeep)" "1 "

# One apply, not two. This is the property the veth peer nearly broke.
second=$("$ncfg" apply 2>&1)
contains "one apply converges" "$second" "nothing to do"

echo
if [ "$failures" -eq 0 ]; then
	echo "links.sh: all checks passed"
else
	echo "links.sh: $failures failed"
	exit 1
fi
