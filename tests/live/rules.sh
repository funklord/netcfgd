#!/bin/sh
# Policy routing rules against a real kernel.
#
# Rules are the one thing the kernel keys purely by number: a rule is
# identified by (family, priority), and adding a second at the same priority is
# EEXIST rather than a replacement. So a changed selector is a delete and an
# add, in that order, and getting the order wrong looks like "the config has no
# effect" rather than like an error.
#
# Ownership is FRA_PROTOCOL, the same tag decision 0002 puts on routes. That is
# what this checks hardest: a rule somebody else installed at a priority
# netcfgd wants must survive, and be reported.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "rules.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "rules.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-rules.XXXXXX")
daemon=
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	# Retry: a signalled daemon writes on its way out, so a single `rm -rf`
	# races the process the lines above have just asked to stop. A trap that
	# exits non-zero fails the whole run after every check has passed, which is
	# how this surfaced -- three times, in three different scripts.
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
	if [ -d "$work" ]; then
		echo "note: $work outlived five seconds of trying to remove it" >&2
	fi
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

# Asked of the kernel through ip(8), not of netcfgd, so this is a statement
# about the machine rather than about what netcfgd believes.
rule_at() { ip rule show 2>/dev/null | sed -n "s/^$1:[[:space:]]*//p"; }
rule_count() { ip rule show 2>/dev/null | grep -c "^$1:" || true; }

write_config() { cat > "$work/etc/netcfgd.conf"; }

apply() {
	if ! "$ncfg" apply > "$work/apply.log" 2>&1; then
		echo "FAIL apply: $1"
		cat "$work/apply.log"
		failures=$((failures + 1))
	fi
}

write_config <<'CONF'
interface probe0 {
	kind   = "dummy"
	config = "10.9.9.1/24"
}

rule "uplink" {
	priority = 1000
	from     = "10.9.0.0/16"
	lookup   = 100
}
CONF

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
		echo "rules.sh: the daemon never started" >&2
		exit 1
	fi
	sleep 0.1
done

apply "the first apply"
check "the rule is installed" \
	"$(rule_at 1000 | grep -c 'from 10.9.0.0/16 lookup 100' || true)" "1"

# Idempotence. A rule reconciler that compared only the key would reinstall on
# every apply; one that compared nothing would never notice a change.
plan=$("$ncfg" plan 2>&1)
check "a second plan has nothing to do" \
	"$(printf '%s' "$plan" | grep -c 'rule\.' || true)" "0"

# Changing a selector. The kernel keys on priority, so this is a delete and an
# add; if the add went first it would be EEXIST and the config would silently
# not take effect.
write_config <<'CONF'
interface probe0 {
	kind   = "dummy"
	config = "10.9.9.1/24"
}

rule "uplink" {
	priority = 1000
	from     = "10.8.0.0/16"
	lookup   = 100
}
CONF
apply "changing the selector"
check "the selector changed" \
	"$(rule_at 1000 | grep -c 'from 10.8.0.0/16' || true)" "1"
check "and there is still only one rule at that priority" "$(rule_count 1000)" "1"

# A rule netcfgd did not install, at a priority it wants. It must survive, and
# the plan must say why nothing happened.
#
# The load-bearing assertions here are the warning and the absence of a planned
# delete. "It is left where it was" passes even with the planner's ownership
# check removed, because the kernel refuses a delete carrying FRA_PROTOCOL 110
# against a rule that has none -- a real second layer, and the reason that
# check alone would not have caught a regression.
ip rule add priority 2000 from 172.16.0.0/12 lookup 200
write_config <<'CONF'
interface probe0 {
	kind   = "dummy"
	config = "10.9.9.1/24"
}

rule "uplink" {
	priority = 1000
	from     = "10.8.0.0/16"
	lookup   = 100
}

rule "clash" {
	priority = 2000
	from     = "192.168.0.0/16"
	lookup   = 300
}
CONF
plan=$("$ncfg" plan 2>&1)
check "a foreign rule is reported" \
	"$(printf '%s' "$plan" | grep -c 'netcfgd does not own' || true)" "1"
# The uplink rule stays in the config through this step precisely so that the
# foreign rule is the only thing a delete could be aimed at -- otherwise this
# counts the legitimate withdrawal of the uplink and says nothing.
check "and no delete is planned at all" \
	"$(printf '%s' "$plan" | grep -c 'rule\.del' || true)" "0"
apply "an apply that cannot place its rule"
check "and it is left exactly where it was" \
	"$(rule_at 2000 | grep -c 'from 172.16.0.0/12 lookup 200' || true)" "1"
ip rule del priority 2000

# Dropping the rule from the config withdraws it.
write_config <<'CONF'
interface probe0 {
	kind   = "dummy"
	config = "10.9.9.1/24"
}
CONF
apply "dropping the rule"
check "the rule is gone" "$(rule_count 1000)" "0"
check "and the kernel's own rules are untouched" \
	"$(rule_count 0)$(rule_count 32766)$(rule_count 32767)" "111"

echo
if [ "$failures" -eq 0 ]; then
	echo "rules.sh: all checks passed"
else
	echo "rules.sh: $failures failed"
	exit 1
fi
