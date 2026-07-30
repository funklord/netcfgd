#!/bin/sh
# NAT and forwarding against a real kernel.
#
# nftables is the second netlink protocol netcfgd speaks and it agrees with
# rtnetlink about almost nothing: integers are big-endian, changes are
# transactional, and a message with a wrong attribute number is refused with an
# errno that describes the wrong thing. Every one of those was got wrong first
# and none of them is visible in a unit test, because the thing that knows is
# the kernel.
#
# So this checks what the kernel holds, not what netcfgd believes: the table
# appears, re-applying changes nothing, a second interface is added and removed
# without the first flapping, and dropping `nat` from the config takes the
# whole table away rather than leaving it behind.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "nat.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "nat.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d /tmp/ncfg-nat.XXXXXX)
daemon=
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	rm -rf "$work"
}
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

# What netcfgd's own table masquerades, as the kernel reports it. Read through
# `ncfg status --json` rather than by asking nft(8), which is not installed
# everywhere and would test a different code path than the daemon uses.
uplinks() {
	"$ncfg" status --json 2>/dev/null |
		sed -n '/"nat": \[/,/\]/p' |
		sed -n 's/^ *"\(.*\)",*$/\1/p' |
		tr '\n' ' ' |
		sed 's/ $//'
}

forwards() {
	"$ncfg" status 2>/dev/null | awk -v want="$1" '
		/^[^ ]/ { iface = $1 }
		iface == want && $1 == "forwarding" { found = 1 }
		END { print (found ? "yes" : "no") }'
}

write_config() {
	cat > "$work/etc/netcfgd.conf"
}

apply() {
	if ! "$ncfg" apply > "$work/apply.log" 2>&1; then
		echo "FAIL apply: $1"
		cat "$work/apply.log"
		failures=$((failures + 1))
	fi
}

start_daemon() {
	"$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
	daemon=$!
	waited=0
	while [ ! -e "$work/run/netcfgd.sock" ]; do
		waited=$((waited + 1))
		if [ "$waited" -gt 60 ]; then
			if grep -q 'Operation not permitted' "$work/daemon.log" 2>/dev/null; then
				skip "no CAP_NET_ADMIN (run under unshare -rn)"
			fi
			cat "$work/daemon.log" >&2
			echo "nat.sh: the daemon never started" >&2
			exit 1
		fi
		sleep 0.1
	done
}

# A LAN side that forwards and an uplink that translates: the smallest thing
# that is actually a router.
write_config <<'CONF'
interface lan0 {
	kind       = "dummy"
	config     = "192.168.9.1/24"
	forwarding = true
}

interface wan0 {
	kind   = "dummy"
	config = "10.9.9.2/24"
	nat    = true
}
CONF

start_daemon

# nftables may be missing entirely, which is a legitimate kernel and not a
# failure of this code. Told apart from a bug by trying once and reading the
# error, rather than by guessing from `lsmod`.
apply "the first apply"
if grep -q 'cannot reach nftables' "$work/apply.log" 2>/dev/null; then
	skip "this kernel has no nf_tables"
fi

check "the uplink is masqueraded" "$(uplinks)" "wan0"
check "the LAN side forwards" "$(forwards lan0)" "yes"
check "the uplink does not forward" "$(forwards wan0)" "no"

# The idempotence gate, against the kernel rather than against the fake. A
# `nat.replace` that did not compare with what is installed would be planned
# again here, and a table that accumulated rules instead of being replaced
# would show `wan0` twice.
plan=$("$ncfg" plan 2>&1)
check "a second plan has nothing to do" \
	"$(printf '%s' "$plan" | grep -c 'nat.replace' || true)" "0"
apply "the second apply"
check "re-applying changes nothing" "$(uplinks)" "wan0"

# Adding an uplink rewrites the whole table. The one already there has to
# survive that, which is the part a wholesale replacement can get wrong.
write_config <<'CONF'
interface lan0 {
	kind       = "dummy"
	config     = "192.168.9.1/24"
	forwarding = true
}

interface wan0 {
	kind   = "dummy"
	config = "10.9.9.2/24"
	nat    = true
}

interface wan1 {
	kind   = "dummy"
	config = "10.9.10.2/24"
	nat    = true
}
CONF
apply "adding a second uplink"
check "both uplinks are masqueraded" "$(uplinks)" "wan0 wan1"

# And removing one leaves the other alone.
write_config <<'CONF'
interface lan0 {
	kind       = "dummy"
	config     = "192.168.9.1/24"
	forwarding = true
}

interface wan0 {
	kind   = "dummy"
	config = "10.9.9.2/24"
}

interface wan1 {
	kind   = "dummy"
	config = "10.9.10.2/24"
	nat    = true
}
CONF
apply "dropping one uplink"
check "only the remaining uplink is masqueraded" "$(uplinks)" "wan1"

# The case a bolted-on implementation gets wrong: there is nothing left to add,
# so nothing is planned, and the machine keeps translating after the config
# stopped asking. The table has to go, not just its rules.
write_config <<'CONF'
interface lan0 {
	kind   = "dummy"
	config = "192.168.9.1/24"
}

interface wan0 {
	kind   = "dummy"
	config = "10.9.9.2/24"
}

interface wan1 {
	kind   = "dummy"
	config = "10.9.10.2/24"
}
CONF
apply "removing NAT entirely"
check "no interface is masqueraded" "$(uplinks)" ""
check "forwarding is turned back off" "$(forwards lan0)" "no"

echo
if [ "$failures" -eq 0 ]; then
	echo "nat.sh: all checks passed"
else
	echo "nat.sh: $failures failed"
	exit 1
fi
