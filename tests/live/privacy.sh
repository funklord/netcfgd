#!/bin/sh
# RFC 4941 temporary addresses against a real kernel.
#
# What netcfgd owns here is one sysctl per interface,
# `net.ipv6.conf.<iface>.use_tempaddr`, and what the *kernel* owns is the address
# it builds from the next router advertisement. So this checks the sysctl and says
# nothing about the address: an interface with no router on the segment will never
# have a temporary address however this is set, and a test that waited for one
# would be testing radvd.
#
# The read path is why this cannot be a fixture. `2` is the only value the
# document can ask for, and a reader that accepted "anything but 0" would agree
# with a kernel set to `1` -- which is the state where a temporary address exists
# and the *stable* one is still preferred, so nothing an operator asked for is
# true. Only a real /proc says which.
#
# Runs under `unshare -rn`: /proc/sys/net is per network namespace.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "privacy.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "privacy.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"
[ -d /proc/sys/net/ipv6 ] || skip "this kernel has no IPv6 (ipv6.disable=1)"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-privacy.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
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

write_config() { cat > "$work/etc/netcfgd.conf"; }

apply() {
	if ! "$ncfg" apply > "$work/apply.log" 2>&1; then
		if grep -q 'Operation not permitted' "$work/apply.log"; then
			skip "no CAP_NET_ADMIN (run under unshare -rn)"
		fi
		echo "FAIL apply: $1"
		cat "$work/apply.log"
		failures=$((failures + 1))
	fi
}

tempaddr() { cat "/proc/sys/net/ipv6/conf/$1/use_tempaddr" 2>/dev/null || echo "(absent)"; }
first_line() { "$ncfg" plan 2>&1 | head -1; }

write_config <<'CONF'
interface priv0 {
	kind   = "dummy"
	config = "slaac privacy prefer_temporary"
}

interface plain0 {
	kind   = "dummy"
	config = "slaac"
}
CONF

apply "asking for temporary addresses"
# 2, not 1: the document can only ask for "prefer the temporary one", and 1 is
# the state where one exists and is not preferred.
check "the interface that asked prefers temporary addresses" "$(tempaddr priv0)" "2"
check "and the one that did not is left at the kernel default" "$(tempaddr plain0)" "0"
check "a second plan has nothing to do" "$(first_line)" "nothing to do"

# The withdraw direction. netcfgd set it, so netcfgd puts it back -- without
# this, deleting the key from the config leaves the machine in a state the
# document no longer describes, which constraint 1 does not allow.
write_config <<'CONF'
interface priv0 {
	kind   = "dummy"
	config = "slaac"
}

interface plain0 {
	kind   = "dummy"
	config = "slaac"
}
CONF
plan=$("$ncfg" plan 2>&1 || true)
case "$plan" in
*sysctl.set_privacy*) echo "ok   dropping the key plans the sysctl back" ;;
*)
	echo "FAIL dropping the key plans the sysctl back"
	echo "       actual: $plan"
	failures=$((failures + 1))
	;;
esac
apply "withdrawing temporary addresses"
check "and the kernel is back to the default" "$(tempaddr priv0)" "0"
check "and then there is nothing to do" "$(first_line)" "nothing to do"

# The kernel's middle value, which is the reason the read is `== 2` and not
# `!= 0`. `1` generates a temporary address and still prefers the stable one, so
# an interface sitting at 1 has *not* got what the document asked for -- and a
# reader that accepted anything non-zero would agree with it and plan nothing.
# Nothing here contained a 1 until this case existed, which made the claim in this
# file's header true of the code and false of the test.
ip link add mid0 type dummy
echo 1 > /proc/sys/net/ipv6/conf/mid0/use_tempaddr
write_config <<'CONF'
interface priv0 {
	kind   = "dummy"
	config = "slaac"
}

interface plain0 {
	kind   = "dummy"
	config = "slaac"
}

interface mid0 {
	kind   = "dummy"
	config = "slaac privacy prefer_temporary"
}
CONF
plan=$("$ncfg" plan 2>&1 || true)
case "$plan" in
*sysctl.set_privacy*) echo "ok   an interface the kernel left at 1 is corrected" ;;
*)
	echo "FAIL an interface the kernel left at 1 is corrected"
	echo "       actual: $plan"
	failures=$((failures + 1))
	;;
esac
apply "correcting the middle value"
check "and the kernel ends up at 2"    "$(tempaddr mid0)" "2"

# A value netcfgd did not set is not netcfgd's to undo. Set by hand, with a
# document that says nothing about it: netcfgd has no record, so it stays.
ip link add hand0 type dummy
echo 2 > /proc/sys/net/ipv6/conf/hand0/use_tempaddr
write_config <<'CONF'
interface priv0 {
	kind   = "dummy"
	config = "slaac"
}

interface plain0 {
	kind   = "dummy"
	config = "slaac"
}

interface mid0 {
	kind   = "dummy"
	config = "slaac privacy prefer_temporary"
}

interface hand0 {
	kind   = "dummy"
	config = "slaac"
}
CONF
apply "leaving somebody else's sysctl alone"
check "a setting netcfgd never made survives" "$(tempaddr hand0)" "2"
check "and nothing is planned for it" "$(first_line)" "nothing to do"

echo
if [ "$failures" -eq 0 ]; then
	echo "privacy.sh: all checks passed"
else
	echo "privacy.sh: $failures failed"
	exit 1
fi
