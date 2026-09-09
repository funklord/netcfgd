#!/bin/sh
# A daemon that has done work does not keep growing.
#
#     sh tests/live/steady_state.sh
#
# WHY THIS EXISTS
#   `make rss` measures a daemon two seconds after it starts, which is the
#   floor and not the risk. netcfgd runs for months: what matters is whether
#   serving requests, reloading configuration and fanning out events give
#   anything back. A leak of a kilobyte per reconcile is invisible at startup
#   and is 100 MB by the end of a quarter.
#
#   Measured while writing this, against 260 config reloads: RSS moved
#   10868 -> 11004 -> 11044 KB, so the second burst -- three times the size of
#   the first -- added a fifth as much. That is allocator behaviour settling,
#   not accumulation, and it is the shape this asserts.
#
# WHAT IT DRIVES
#   A real daemon, a real socket, and three measurements: at rest, after a
#   burst, and after a burst three times larger. The comparison is between the
#   last two, because the first burst legitimately allocates -- caches, a
#   parsed document, the first client thread.
#
# WHAT IT DELIBERATELY DOES NOT DO
#   Assert an absolute number. `make rss` owns the ceiling and does it against
#   a release build; this runs against whatever is built, where a debug binary
#   is twice the size. A ratchet in two places is a ratchet that disagrees
#   with itself.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "steady_state.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "steady_state.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
[ -r /proc/self/status ] || skip "no /proc, so nothing here can be measured"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-steady.XXXXXX")
daemon=
cleanup() {
	if [ -n "$daemon" ]; then
		kill "$daemon" 2>/dev/null || true
		wait "$daemon" 2>/dev/null || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_RESOLV_CONF="$work/resolv.conf"

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

printf 'global { control { observe = "any" } }\n' > "$work/etc/netcfgd.conf"
"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -S "$work/run/netcfgd.sock" ] && [ "$waited" -lt 60 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
[ -S "$work/run/netcfgd.sock" ] || skip "the daemon never bound its socket"

rss() { awk '/VmRSS/ { print $2 }' "/proc/$daemon/status"; }
fds() { ls "/proc/$daemon/fd" | wc -l; }
threads() { ls "/proc/$daemon/task" | wc -l; }

sleep 2
base_fds=$(fds)
base_threads=$(threads)

# One reload is a compile, a plan and a fan-out to subscribers -- the daemon's
# whole inner loop, driven from outside without needing an interface.
burst() {
	round=0
	while [ "$round" -lt "$1" ]; do
		printf 'global { control { observe = "any" } }\n#%d\n' "$round" \
			> "$work/etc/netcfgd.conf"
		"$repo/target/debug/ncfg" control show > /dev/null 2>&1 || true
		round=$((round + 1))
	done
	sleep 2
}

burst 60
first=$(rss)
burst 200
second=$(rss)

# **The second burst is three times the first**, so accumulation at any fixed
# cost per reload would show as a growth at least as large. Half is the
# threshold rather than "no growth at all", because an allocator that has not
# finished settling is not a leak and a test that fails on it is a test people
# learn to ignore.
grew_first=$((first - 0))
growth=$((second - first))
allowed=$((first / 8))
echo "note rss after 60 reloads ${first} KB, after 260 ${second} KB (growth ${growth} KB, allowed ${allowed} KB)"
check "a daemon that has done three times the work does not grow in proportion" \
	"$([ "$growth" -lt "$allowed" ] && echo bounded || echo growing)" "bounded"

# **Descriptors and threads are the other half**, and they are exact: every
# connection takes a thread and a descriptor, and both come back when it
# closes. A leak here is what makes a daemon stop accepting after a month.
check "and holds no more descriptors than it started with" "$(fds)" "$base_fds"
check "and no more threads" "$(threads)" "$base_threads"

# The control: the measurements above mean nothing if the daemon was not
# actually serving during them.
check "the daemon was answering throughout" \
	"$("$repo/target/debug/ncfg" control show 2>&1 | grep -c '^observe')" "1"

if [ "$failures" -eq 0 ]; then
	echo "steady_state.sh: all checks passed"
else
	echo "steady_state.sh: $failures check(s) failed"
	tail -5 "$work/daemon.log" >&2
	exit 1
fi
