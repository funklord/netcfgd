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

# A VLAN whose name does not encode its id, which is the only operator decision
# 0059's silence ever depended on: renaming `br0.42` to `br0.43` is a create and
# a delete already, and this one is not.
interface work-net {
	vlan   { parent = "br0"; id = 77 }
	config = "10.6.0.1/24"
}

# Declared as one kind here and edited into another below.
interface flip0 { kind = "dummy"; config = "null" }

# Everything below came out of the pre-freeze format audit.
interface mgmt-vrf { vrf { table = 100 }; config = "null" }
interface base0    { kind = "dummy"; config = "10.7.0.1/24" }
# A second parent, for the checks that move a virtual link from one to another.
interface base1    { kind = "dummy"; config = "null" }
interface mv0      { macvlan { parent = "base0"; mode = "bridge" }; config = "null" }
interface gre1     { tunnel { mode = "gre"; parent = "base0"; local = "10.7.0.1"; remote = "10.7.0.2"; key = 42 }; config = "null" }
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
# A bond's monitoring interval moves on a live bond; its *mode* does not, and
# the kernel says so with ENOTEMPTY rather than by ignoring it. The first
# version of decision 0057's bond half planned the mode anyway, which failed the
# apply and then planned the same thing again on the next reconcile -- and, in
# the same message, stopped the interval being set at all.
sed -i 's/mode = "active-backup"; miimon = 100/mode = "balance-rr"; miimon = 250/' \
	"$work/etc/netcfgd.conf"
bond_plan=$("$ncfg" plan 2>&1 || true)
contains "an edited miimon is planned" "$bond_plan" "bond.miimon"
contains "and the mode is explained rather than attempted" "$bond_plan" \
	"will not change it while the bond has members"
"$ncfg" apply > "$work/apply-bond.txt" 2>&1 || { cat "$work/apply-bond.txt" >&2; exit 1; }
contains "the kernel took the interval" "$(detail bond0)" "miimon 250"
contains "and kept the mode it will not change" "$(detail bond0)" "mode active-backup"
contains "and the next plan has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

contains "a bridge gets spanning tree" "$(detail br0)"    "stp_state 1"
contains "and its forward delay, converted" "$(detail br0)" "forward_delay 400"

# And the conversion runs in both directions, which is what this pair is really
# for. The observation reads the kernel's hundredths and the document counts
# seconds; a reader that forgot to divide would make every bridge differ from
# itself by a factor of a hundred, and the plan would rebuild it forever. A
# fixture cannot see that -- it builds the observation in model units -- so the
# only place it shows is here, on a plan that has to be empty.
contains "a bridge that was just applied plans nothing" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# Then the half decision 0057 added: editing a bridge's own settings used to
# plan nothing at all, because they were sent inside `link.create` and never
# again. A bridge's name encodes nothing, so there was no second signal.
sed -i 's/bridge { stp = true; forward_delay = 4 }/bridge { stp = false; forward_delay = 20 }/' \
	"$work/etc/netcfgd.conf"
plan_text=$("$ncfg" plan 2>&1 || true)
contains "an edited bridge setting is planned" "$plan_text" "link.set_bridge"
contains "and the reason names the field that moved" "$plan_text" "bridge.stp"
"$ncfg" apply > "$work/apply-bridge.txt" 2>&1 || { cat "$work/apply-bridge.txt" >&2; exit 1; }
contains "and the kernel has it afterwards" "$(detail br0)" "stp_state 0"
contains "and the delay, converted again" "$(detail br0)" "forward_delay 2000"
contains "and the next plan has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# Big-endian on the wire. The kernel refuses the byte-swapped value, so getting
# this wrong fails the apply -- checked by sending the wrong one.
contains "a vlan gets the right tag protocol" "$(detail br0.42)" "protocol 802.1ad"
contains "and its id"                  "$(detail br0.42)" "id 42"

contains "a vxlan gets its vni"        "$(detail vx100)"  "id 100"
contains "and both endpoints"          "$(detail vx100)"  "remote 10.9.0.2 local 10.9.0.1"
contains "and its port"                "$(detail vx100)"  "dstport 4789"
# The underlay, which for a VXLAN alone is an attribute inside its own nest. It
# was sent as the outer `IFLA_LINK` for as long as VXLANs have existed here and
# did nothing at all: the document named a parent and the kernel routed the outer
# packets itself. `ip` says it in one word, and nothing was reading that word.
contains "and the underlay the document named" "$(detail vx100)" "dev br0"

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
# The same defect in the same place: a tunnel's underlay is `IFLA_GRE_LINK` or
# `IFLA_IPTUN_LINK` inside the nest, and the outer attribute netcfgd was sending
# left the tunnel with no parent at all -- `gre1@NONE`. The kernel reports it
# outside, which is why one word of the header is the check.
contains "and the underlay the document named" "$(ip link show gre1)" "gre1@base0"
# A key with no flag bit is silently ignored, and two ends with different keys
# would then pass traffic as though neither had one.
contains "and its key, which needs the flag" "$(detail gre1)" "ikey 0.0.0.42"
contains "a sit tunnel uses the other numbering" "$(detail sit1)" "remote 10.7.0.3 local 10.7.0.1"
contains "and its ttl"                 "$(detail sit1)"   "ttl 64"
contains "a geneve tunnel gets its vni" "$(detail gnv0)"  "geneve id 500"

# ---------------------------------------------------------------------------
# The rest of decision 0057's list, which is decision 0058: a macvlan's mode, a
# tunnel's endpoints and a VXLAN's were all sent inside `link.create` and never
# again, so editing any of them planned nothing at all.
#
# Every answer below was measured against a kernel before it was written, and no
# two families agreed. Three of them refuse an edit outright, so netcfgd says
# what is wrong instead of emitting an action that fails and is planned again on
# the next reconcile.
contains "the kinds 0058 compares plan nothing when just applied" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# The kernel is asked rather than remembered. If it ever starts taking one of
# these, the sentence netcfgd prints becomes a lie and this is what says so.
refuses() {
	label=$1
	shift
	if out=$("$@" 2>&1); then
		echo "FAIL $label"
		echo "       the kernel accepted: $*"
		failures=$((failures + 1))
	else
		echo "ok   $label -- $out"
	fi
}

# A macvlan's mode moves among private, vepa and bridge.
sed -i '/macvlan/s/mode = "bridge"/mode = "vepa"/' "$work/etc/netcfgd.conf"
mv_plan=$("$ncfg" plan 2>&1 || true)
contains "an edited macvlan mode is planned" "$mv_plan" "link.set_macvlan"
contains "and the reason names the field"    "$mv_plan" "macvlan.mode"
"$ncfg" apply > "$work/apply-macvlan.txt" 2>&1 || { cat "$work/apply-macvlan.txt" >&2; exit 1; }
contains "and the kernel has it afterwards" "$(detail mv0)" "macvlan mode vepa"
contains "and the next plan has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# ...and not into or out of passthru, which is the fourth mode and the one the
# kernel refuses in both directions.
sed -i '/macvlan/s/mode = "vepa"/mode = "passthru"/' "$work/etc/netcfgd.conf"
mv_pass=$("$ncfg" plan 2>&1 || true)
contains "a passthru edit is explained rather than attempted" "$mv_pass" \
	"into or out of passthru"
missing "and no action is planned for it" "$mv_pass" "link.set_macvlan"
refuses "and the kernel does refuse it" ip link set mv0 type macvlan mode passthru
sed -i '/macvlan/s/mode = "passthru"/mode = "vepa"/' "$work/etc/netcfgd.conf"

# A GRE tunnel's endpoints move -- and the key has to survive the move. That is
# the whole-nest rule: `ipgre_netlink_parms` starts from a zeroed struct, so a
# request carrying only the remote leaves the tunnel with no local address, no
# TTL and no key. `ip` hides this by reading the device and refilling every field
# before it sends anything, which is why this is checked here and not with `ip`.
sed -i '/gre1/s/remote = "10.7.0.2"/remote = "10.7.0.9"/' "$work/etc/netcfgd.conf"
gre_plan=$("$ncfg" plan 2>&1 || true)
contains "an edited tunnel endpoint is planned" "$gre_plan" "link.set_tunnel"
contains "and the reason names the field"      "$gre_plan" "tunnel.remote"
"$ncfg" apply > "$work/apply-gre.txt" 2>&1 || { cat "$work/apply-gre.txt" >&2; exit 1; }
contains "and the kernel has the new endpoint" "$(detail gre1)" \
	"remote 10.7.0.9 local 10.7.0.1"
contains "and the key the request had to carry with it" "$(detail gre1)" "ikey 0.0.0.42"

# The other numbering, which resets the same way: sit puts its endpoints where
# GRE puts a flags word, so this is a second decoder and a second encoder.
sed -i '/sit1/s/remote = "10.7.0.3"/remote = "10.7.0.8"/' "$work/etc/netcfgd.conf"
sit_plan=$("$ncfg" plan 2>&1 || true)
contains "an ip tunnel's endpoint is planned too" "$sit_plan" "link.set_tunnel"
"$ncfg" apply > "$work/apply-sit.txt" 2>&1 || { cat "$work/apply-sit.txt" >&2; exit 1; }
contains "and the kernel has it"       "$(detail sit1)" "remote 10.7.0.8 local 10.7.0.1"
contains "with the ttl it was created with" "$(detail sit1)" "ttl 64"
contains "and the next plan has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# A geneve tunnel takes a remote and refuses a VNI, so the change netcfgd sends
# leaves the VNI out -- which is what lets the remote beside it move at all.
sed -i '/gnv0/s/remote = "10.7.0.4"/remote = "10.7.0.7"/' "$work/etc/netcfgd.conf"
"$ncfg" apply > "$work/apply-geneve.txt" 2>&1 || { cat "$work/apply-geneve.txt" >&2; exit 1; }
contains "a geneve remote moves"       "$(detail gnv0)" "remote 10.7.0.7"
contains "and it keeps the vni the request left out" "$(detail gnv0)" "geneve id 500"

# The VNI and the remote edited together, which is the case that says whether
# the change nest really leaves the VNI out. Restating the VNI it already has is
# accepted by the kernel, so a nest that carried it would pass every check above
# and fail exactly here -- where the value in the document is a new one.
sed -i '/gnv0/s/vni = 500/vni = 501/' "$work/etc/netcfgd.conf"
sed -i '/gnv0/s/remote = "10.7.0.7"/remote = "10.7.0.5"/' "$work/etc/netcfgd.conf"
gnv_plan=$("$ncfg" plan 2>&1 || true)
contains "an edited vni is explained rather than attempted" "$gnv_plan" \
	"will not change the VNI of a geneve tunnel"
contains "and the remote beside it is still planned" "$gnv_plan" "link.set_tunnel"
refuses "and the kernel does refuse the vni" ip link set gnv0 type geneve id 501
"$ncfg" apply > "$work/apply-geneve2.txt" 2>&1 || { cat "$work/apply-geneve2.txt" >&2; exit 1; }
contains "the remote moved anyway"     "$(detail gnv0)" "remote 10.7.0.5"
contains "and the vni the kernel will not change is untouched" "$(detail gnv0)" \
	"geneve id 500"
sed -i '/gnv0/s/vni = 501/vni = 500/' "$work/etc/netcfgd.conf"

# A VXLAN is the same shape with two refusals rather than one, and the second is
# the surprise: the kernel refuses the port's *presence*, at the value it already
# has. A change that carried the port could therefore never move an endpoint.
sed -i '/vxlan/s/remote = "10.9.0.2"/remote = "10.9.0.9"/' "$work/etc/netcfgd.conf"
vx_plan=$("$ncfg" plan 2>&1 || true)
contains "an edited vxlan endpoint is planned" "$vx_plan" "link.set_vxlan"
"$ncfg" apply > "$work/apply-vxlan.txt" 2>&1 || { cat "$work/apply-vxlan.txt" >&2; exit 1; }
contains "and the kernel has it"       "$(detail vx100)" "remote 10.9.0.9 local 10.9.0.1"
contains "and keeps the port the request left out" "$(detail vx100)" "dstport 4789"
refuses "the kernel refuses the port even unchanged" \
	ip link set vx100 type vxlan dstport 4789

# All three edited at once, for the reason the geneve pair above is: the two the
# kernel refuses have to be reported *and* leave the one it takes working.
sed -i '/vxlan/s/id = 100/id = 101/' "$work/etc/netcfgd.conf"
sed -i '/vxlan/s/port = 4789/port = 4790/' "$work/etc/netcfgd.conf"
sed -i '/vxlan/s/remote = "10.9.0.9"/remote = "10.9.0.5"/' "$work/etc/netcfgd.conf"
vx_refused=$("$ncfg" plan 2>&1 || true)
contains "an edited vni is explained rather than attempted" "$vx_refused" \
	"will not change the VNI of a VXLAN"
contains "and so is an edited port" "$vx_refused" \
	"will not change the destination port of a VXLAN"
contains "and the endpoint beside them is still planned" "$vx_refused" "link.set_vxlan"
refuses "and the kernel does refuse the vni" ip link set vx100 type vxlan id 101
"$ncfg" apply > "$work/apply-vxlan2.txt" 2>&1 || { cat "$work/apply-vxlan2.txt" >&2; exit 1; }
contains "the endpoint moved anyway"   "$(detail vx100)" "remote 10.9.0.5"
contains "and the vni and port the kernel will not change are untouched" \
	"$(detail vx100)" "id 100"
contains "the port too"                "$(detail vx100)" "dstport 4789"
sed -i '/vxlan/s/id = 101/id = 100/' "$work/etc/netcfgd.conf"
sed -i '/vxlan/s/port = 4790/port = 4789/' "$work/etc/netcfgd.conf"
contains "and the document that matches again plans nothing" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

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

# ---------------------------------------------------------------------------
# The last shape on 0057's list, which is 0059: what the kernel takes and
# ignores. `ip link set work-net type vlan id 78` succeeds and changes nothing,
# so the only way to apply an edited id is to delete the interface and make it
# again -- with everything on it.
contains "a vlan gets the id its name does not carry" "$(detail work-net)" "id 77"
contains "and its address"              "$(ip -br addr show work-net)" "10.6.0.1/24"

sed -i '/work-net/,+1s/id = 77/id = 78/' "$work/etc/netcfgd.conf"
vlan_plan=$("$ncfg" plan 2>&1 || true)
contains "an edited vlan id plans a delete" "$vlan_plan" "link.delete work-net"
contains "and a create after it"        "$vlan_plan" "link.create work-net"
contains "and the reason names the field" "$vlan_plan" "vlan.id"
# The kernel's own answer, asked rather than remembered: it takes this request
# and changes nothing, which is why there is no `link.set_vlan` to emit.
before=$(detail work-net | grep -o "id 7[0-9]")
ip link set work-net type vlan id 78 2>&1 | head -1
if [ "$before" = "$(detail work-net | grep -o "id 7[0-9]")" ]; then
	echo "ok   the kernel accepts an id change and ignores it ($before)"
else
	echo "FAIL the kernel changed a vlan id in place; link.set_vlan would be the answer"
	failures=$((failures + 1))
fi

"$ncfg" apply > "$work/apply-vlan.txt" 2>&1 || { cat "$work/apply-vlan.txt" >&2; exit 1; }
contains "the remade interface has the new id" "$(detail work-net)" "id 78"
# The point of the exercise. The address went with the interface, and the passes
# after the delete are what put it back -- which only works because they see an
# observation the doomed interface is not in.
contains "and its address came back"    "$(ip -br addr show work-net)" "10.6.0.1/24"
contains "and the next plan has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# An interface that exists as a different kind entirely. Before 0059 this planned
# a `link.up` and nothing else, on a device that was not what the document said.
contains "the interface starts as a dummy" "$(detail flip0)" "dummy"
sed -i 's|interface flip0 { kind = "dummy"|interface flip0 { macvlan { parent = "base0"; mode = "bridge" }|' \
	"$work/etc/netcfgd.conf"
flip_plan=$("$ncfg" plan 2>&1 || true)
contains "a wrong kind plans a delete"  "$flip_plan" "link.delete flip0"
contains "and the reason is the kind"   "$flip_plan" "kind: macvlan (was dummy)"
"$ncfg" apply > "$work/apply-flip.txt" 2>&1 || { cat "$work/apply-flip.txt" >&2; exit 1; }
contains "and the interface comes back as the right one" "$(detail flip0)" \
	"macvlan mode bridge"
contains "and the next plan has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# And the safety property, which matters more here than anywhere else in a plan:
# netcfgd will not throw away a link it did not create. This one is made by hand,
# so nothing in /run records it as netcfgd's.
ip link add link br0 name hand-vlan type vlan id 90
cat >> "$work/etc/netcfgd.conf" <<'CONF'
interface hand-vlan {
	vlan   { parent = "br0"; id = 91 }
	config = "null"
}
CONF
hand_plan=$("$ncfg" plan 2>&1 || true)
contains "a link netcfgd did not create is explained" "$hand_plan" \
	"will not do to a link it did not create"
missing "and not deleted"               "$hand_plan" "link.delete hand-vlan"
missing "and not recreated either"      "$hand_plan" "link.create hand-vlan"
contains "and the kernel still has it, untouched" "$(detail hand-vlan)" "id 90"
# Out of the way again, so the checks below see the document they expect.
ip link del hand-vlan
sed -i '/^interface hand-vlan {$/,/^}$/d' "$work/etc/netcfgd.conf"

# A parent is one word in the document and two answers from the kernel. A VXLAN's
# underlay is in its own nest and moves on a live device; a VLAN's is the outer
# attribute, which the kernel accepts and ignores -- so that one is remade
# (0060).
sed -i '/vxlan/s/parent = "br0"/parent = "base0"/' "$work/etc/netcfgd.conf"
under_plan=$("$ncfg" plan 2>&1 || true)
contains "a moved vxlan underlay is set in place" "$under_plan" "link.set_vxlan"
contains "and the reason names it"      "$under_plan" "vxlan.parent"
missing "and the interface is not thrown away" "$under_plan" "link.delete vx100"
"$ncfg" apply > "$work/apply-under.txt" 2>&1 || { cat "$work/apply-under.txt" >&2; exit 1; }
contains "and the kernel moved it"     "$(detail vx100)" "dev base0"
contains "and the next plan has nothing to do" 	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

sed -i '/work-net/,+1s/parent = "br0"/parent = "base0"/' "$work/etc/netcfgd.conf"
vlan_parent=$("$ncfg" plan 2>&1 || true)
contains "a moved vlan parent is remade" "$vlan_parent" "link.delete work-net"
contains "and the reason is the parent" "$vlan_parent" "parent: base0 (was br0)"
# The kernel's own answer, asked rather than remembered.
refuses_silently() {
	before=$(ip link show "$1" | head -1 | awk '{print $2}')
	ip link set "$1" link "$2" 2>&1 | head -1
	if [ "$before" = "$(ip link show "$1" | head -1 | awk '{print $2}')" ]; then
		echo "ok   the kernel accepts a parent change on a $3 and ignores it ($before)"
	else
		echo "FAIL the kernel moved a $3's parent in place; a set would be the answer"
		failures=$((failures + 1))
	fi
}
refuses_silently work-net base0 vlan
refuses_silently mv0 base1 macvlan
"$ncfg" apply > "$work/apply-vparent.txt" 2>&1 || { cat "$work/apply-vparent.txt" >&2; exit 1; }
contains "the remade vlan sits on the new parent" "$(ip link show work-net)" "work-net@base0"
contains "and its address came back"    "$(ip -br addr show work-net)" "10.6.0.1/24"
contains "and the next plan has nothing to do" 	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

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
