#!/bin/sh
# Two applies at once, against one machine.
#
#     sh tests/live/apply_race.sh        # needs its own network namespace
#
# WHY THIS EXISTS
#   An apply is observe, plan, act. Nothing serialised the three: the only
#   lock in the tree guarded the ownership record's read-modify-write, so two
#   applies could plan against a machine the other was in the middle of
#   changing. The pair that meets in practice is an operator's `ncfg apply`
#   and the daemon's own reconcile, which runs every few seconds.
#
#   Measured before the fix, five rounds of two simultaneous applies against
#   one interface: **five failed actions, one per round**, every one a
#   `route.add` for a route the other apply had installed between this one's
#   observation and its action.
#
#   `addr.add` does not show it, and the asymmetry is worth knowing: addresses
#   are added with `NLM_F_REPLACE`, so adding one that is already there is
#   success, while a route is added with `NLM_F_CREATE` alone and `EEXIST` is
#   a failed action. Tolerating that would have been the wrong fix -- `EEXIST`
#   for a route means the *key* exists, not that its gateway is what netcfgd
#   asked for, so a tolerant add would report success over a route pointing
#   somewhere else.
#
# WHAT IT DRIVES
#   Two `ncfg apply` runs launched together, five times, over four addresses
#   and two routes -- enough actions that the window between plan and act is
#   wide enough to hit. It asserts no failed actions and the full
#   configuration afterwards.
#
# WHAT IT DELIBERATELY DOES NOT COVER
#   The daemon reconciling against a CLI apply. That is the same lock through
#   the same helper, and driving it would mean a daemon whose loop is timed to
#   land inside the window -- a slower test for a weaker signal.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "apply_race.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "apply_race.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

# Its own network namespace, refused rather than assumed: this makes an
# interface, and a script that makes interfaces must not do it on the real
# network.
if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
	skip "this makes an interface and must not do it on the machine's own network; run it under \`unshare -rn\`, as the Makefile does"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-race.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_RESOLV_CONF="$work/resolv.conf"
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

ip link add r0 type dummy 2>/dev/null || skip "cannot make a dummy interface"

cat > "$work/etc/netcfgd.conf" <<CONF
interface r0 {
	config = ["10.13.0.1/24", "10.13.1.1/24", "10.13.2.1/24", "10.13.3.1/24"]
	routes = [
		"10.99.0.0/16 via 10.13.0.254",
		"10.98.0.0/16 via 10.13.1.254",
	]
}
CONF

# Five rounds, because a race that shows once in five is still a race and one
# round would report a machine's scheduling rather than netcfgd's behaviour.
rounds=5
failed_actions=0
round=1
while [ "$round" -le "$rounds" ]; do
	ip addr flush dev r0 2>/dev/null || true
	ip link set r0 down 2>/dev/null || true

	"$ncfg" apply > "$work/a-$round.log" 2>&1 &
	"$ncfg" apply > "$work/b-$round.log" 2>&1 &
	wait

	this=$(grep -hcE '^FAIL' "$work/a-$round.log" "$work/b-$round.log" | paste -sd+ | bc)
	failed_actions=$((failed_actions + this))
	round=$((round + 1))
done

check "five rounds of two simultaneous applies leave no failed action" \
	"$failed_actions" "0"

# **And the machine ends up configured**, which is the half a count of
# failures cannot see: two applies that both refused to start would also
# report zero.
check "and the interface carries every address the document asked for" \
	"$(ip -4 -br addr show r0 | grep -oE '10\.13\.[0-3]\.1/24' | wc -l)" "4"
check "and both routes are installed" \
	"$(ip -4 route show dev r0 | grep -cE '^10\.9[89]\.0\.0/16')" "2"

# The lock is a file, and a file that is never created is a lock nobody takes.
check "the apply lock is where the message would name it" \
	"$([ -e "$work/run/apply.lock" ] && echo present || echo absent)" "present"

if [ "$failures" -eq 0 ]; then
	echo "apply_race.sh: all checks passed"
else
	echo "apply_race.sh: $failures check(s) failed"
	sed 's/^/       /' "$work"/a-*.log "$work"/b-*.log >&2
	exit 1
fi
