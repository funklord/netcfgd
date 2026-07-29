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
CONF

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
ncfg="$repo/target/debug/ncfg"

failures=0
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
contains "the declared end is enslaved" "$(detail veth-a)" "master bond0"
contains "and so is the peer"          "$(detail veth-b)" "master bond0"

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
