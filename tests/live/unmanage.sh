#!/bin/sh
# Handing a device away, against a real kernel.
#
# Two policies with one mechanism (decision 0037). `managed = false` alone
# means netcfgd stops operating and changes nothing; adding
# `on_unmanage = "clear"` means it removes everything it owns first, then stops.
#
#     unshare -rn sh tests/live/unmanage.sh
#
# The property worth the most here is the one in the middle: clearing is
# defined by *ownership*, so it removes what carries netcfgd's tag and leaves
# what does not. That is what makes one rule safe on every device, and it can
# only be checked against a kernel that really does tag addresses -- a fixture
# would be asserting the tag scheme against itself.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "unmanage.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "unmanage.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-unmanage.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

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

# Two devices, and the difference between them is the point. `probe0` is one
# netcfgd creates; `borrowed0` already exists when netcfgd first sees it, which
# is what a physical NIC looks like to the ownership rules.
ip link add borrowed0 type dummy

managed_config() {
	cat > "$work/etc/netcfgd.conf" <<CONF
interface probe0 {
	kind   = "dummy"
	config = "10.5.5.1/24"
	routes = "default via 10.5.5.254"
}

interface borrowed0 {
	config = "10.6.6.1/24"
}
CONF
}

unmanaged_config() {
	cat > "$work/etc/netcfgd.conf" <<CONF
device probe0    { managed = false$1 }
device borrowed0 { managed = false$1 }

interface probe0 {
	kind   = "dummy"
	config = "10.5.5.1/24"
	routes = "default via 10.5.5.254"
}

interface borrowed0 {
	config = "10.6.6.1/24"
}
CONF
}

managed_config
"$ncfg" apply > "$work/apply.log" 2>&1 || {
	if grep -q 'Operation not permitted' "$work/apply.log" 2>/dev/null; then
		skip "no CAP_NET_ADMIN (run under unshare -rn)"
	fi
	cat "$work/apply.log" >&2
	exit 1
}
check "the device starts configured" \
	"$(ip -brief addr show probe0 2>/dev/null | grep -c '10.5.5.1/24' || true)" "1"

# ------------------------------------------------------------ walking away

unmanaged_config ""
"$ncfg" apply > "$work/leave.log" 2>&1 || true

check "unmanaging plans nothing" \
	"$("$ncfg" plan 2>/dev/null | grep -cE '^ +[0-9]+ ' || true)" "0"
# The whole point: netcfgd stops operating and the device keeps working. An
# address pulled out on the way past is the failure the flag exists to prevent.
check "and the address is still there" \
	"$(ip -brief addr show probe0 2>/dev/null | grep -c '10.5.5.1/24' || true)" "1"
# One per unmanaged device: a plan that does nothing about two blocks somebody
# wrote should say so about both of them.
check "and it says why nothing happened, for each of them" \
	"$("$ncfg" plan 2>&1 | grep -c 'managed = false' || true)" "2"

# ------------------------------------------------------------- and clearing

# An address netcfgd did not put there, added behind its back to the device it
# did not create. Clearing must leave this one alone: whoever takes the device
# over keeps their own configuration, and that is the property that makes one
# rule safe on every device.
ip addr add 192.0.2.9/24 dev borrowed0

unmanaged_config '; on_unmanage = "clear"'
check "clearing plans the removal of what netcfgd owns" \
	"$("$ncfg" plan 2>/dev/null | grep -c 'addr.del' || true)" "2"

"$ncfg" apply > "$work/clear.log" 2>&1 || true

check "the address netcfgd added is gone" \
	"$(ip -brief addr show borrowed0 2>/dev/null | grep -c '10.6.6.1/24' || true)" "0"
check "the address somebody else added is not" \
	"$(ip -brief addr show borrowed0 2>/dev/null | grep -c '192.0.2.9/24' || true)" "1"
check "and the device it did not create is still there" \
	"$(ip -brief link show borrowed0 2>/dev/null | grep -c borrowed0 || true)" "1"

# A device netcfgd *created* goes away entirely, and everything living on it
# goes with it. That is not an exception to "only what netcfgd owns" -- the
# device itself is one of the things netcfgd owns, and clearing undoes what
# netcfgd did. Handing a virtual device over intact is what `leave` is for.
check "a device netcfgd created is removed with everything on it" \
	"$(ip -brief link show probe0 2>/dev/null | grep -c probe0 || true)" "0"

# Self-terminating: the policy is a state, so once it holds there is nothing
# left to do. A clear that re-ran every apply would fight whoever took over.
check "and a second plan has nothing to do" \
	"$("$ncfg" plan 2>/dev/null | grep -cE '^ +[0-9]+ ' || true)" "0"

echo
if [ "$failures" -eq 0 ]; then
	echo "unmanage.sh: all checks passed"
else
	echo "unmanage.sh: $failures check(s) failed"
	exit 1
fi
