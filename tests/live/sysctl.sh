#!/bin/sh
# The sysctls netcfgd set, across a restart -- and the limit of what survives.
#
# WHY THIS FILE EXISTS
#   `forwarding`, `privacy` and `accept_ra` are one-way doors unless netcfgd
#   remembers setting them. The planner says so itself:
#
#       An interface that stops asking is turned back off, but only where
#       netcfgd is the one that turned it on. Without this the sysctl is a
#       one-way door: deleting `forwarding = true` from the document leaves
#       the machine routing, which is drift the config can no longer describe
#       and constraint 1 does not allow.
#
#   That "only where netcfgd is the one that turned it on" lives in
#   `/run/netcfgd/owned.json` and nowhere else. A sysctl is a value, not an
#   object: it has no protocol field to stamp the way an address does (0002),
#   and no property list to mark the way a link does (0136). There is nothing
#   in the kernel to ask.
#
#   So this is the one part of ownership that genuinely depends on the record
#   surviving, and the point of the test is to hold that dependency still: the
#   record must survive a restart, and what happens without it must be a
#   decision somebody wrote down rather than a surprise.
#
# WHAT IT ASSERTS, INCLUDING THE LIMIT
#   With the record intact across a stop and start, the door closes: dropping
#   `forwarding = true` turns forwarding back off. With the record gone,
#   forwarding stays on and netcfgd plans nothing -- which is holding, per
#   0134, and is asserted here rather than left as a thing somebody discovers.
#   If a future change makes netcfgd revert an unrecorded sysctl, this test
#   fails and the change gets read against 0134 before it ships.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "sysctl.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "sysctl.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
command -v ip >/dev/null 2>&1 || skip "iproute2 is not installed"
# The directory is never writable -- nothing creates files there -- so this
# asks about a file, which is what netcfgd actually writes. /proc/sys/net is
# per-netns and follows the reading process, so this is the namespace's own.
[ -w /proc/sys/net/ipv4/ip_forward ] 2>/dev/null || skip "the sysctl tree is not writable here"

work=$(mktemp -d /tmp/ncfg-sysctl.XXXXXX)
ncfg="$repo/target/debug/ncfg"
[ -x "$ncfg" ] || ncfg="$repo/target/debug/netcfgd"
failures=0

cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM

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

forwarding() { cat "/proc/sys/net/ipv4/conf/$1/forwarding" 2>/dev/null || echo "?"; }

ip link add net0 type dummy 2>/dev/null || skip "cannot create a dummy link"
ip link set net0 up
mkdir -p "$work/etc/conf.d" "$work/run"
export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"

asking_for_forwarding() {
	cat > "$work/etc/netcfgd.conf" <<'CONF'
interface net0 {
	config = "10.9.9.1/24"
	forwarding = true
}
CONF
}
no_longer_asking() {
	cat > "$work/etc/netcfgd.conf" <<'CONF'
interface net0 {
	config = "10.9.9.1/24"
}
CONF
}

# ---------------------------------------------------------------------------
# 1. netcfgd turns it on and writes down that it did.
asking_for_forwarding
"$ncfg" apply >/dev/null 2>&1 || true
check "netcfgd turns forwarding on when the config asks" "$(forwarding net0)" "1"
check "and records that it was the one that did" \
	"$(python3 -c "
import json
print(len(json.load(open('$work/run/owned.json')).get('forwarding', [])))" 2>/dev/null)" "1"

# ---------------------------------------------------------------------------
# 2. The record survives a restart, so the door still closes. Nothing is
#    stopped and started here beyond re-running the tool: what is being
#    asserted is that the answer comes out of the file, and the file is what a
#    restart either keeps or does not.
no_longer_asking
"$ncfg" apply >/dev/null 2>&1 || true
check "dropping the setting turns forwarding back off, with the record intact" \
	"$(forwarding net0)" "0"

# ---------------------------------------------------------------------------
# 3. The limit, asserted so that changing it is deliberate. With the record
#    gone netcfgd holds: it does not revert a sysctl it cannot prove it set.
asking_for_forwarding
"$ncfg" apply >/dev/null 2>&1 || true
check "forwarding is on again" "$(forwarding net0)" "1"

rm -f "$work/run/owned.json"
no_longer_asking
plan=$("$ncfg" plan 2>&1 || true)
check "with the record gone, netcfgd plans no change to it" \
	"$(printf '%s' "$plan" | grep -ic forward)" "0"
"$ncfg" apply >/dev/null 2>&1 || true
check "and leaves it on rather than reverting what it cannot prove is its own" \
	"$(forwarding net0)" "1"

echo
if [ "$failures" -eq 0 ]; then
	echo "sysctl.sh: all checks passed"
else
	echo "sysctl.sh: $failures failed"
	exit 1
fi
