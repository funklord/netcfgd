#!/bin/sh
# netcfgd removes what keeps taking /etc/resolv.conf back.
#
# WHY THIS RUNS IN ITS OWN PID NAMESPACE, AND DO NOT REMOVE IT
#   The sweep signals processes by program name, found by scanning /proc. The
#   rest of the suite runs under `unshare -rn`, which is a *network* namespace
#   only -- /proc there still shows every process on the machine. Exercising
#   this under that would let the test terminate the developer's real
#   NetworkManager or dhclient. `unshare -rnp --fork --mount-proc` gives /proc
#   a view containing nothing but this test's own children, which is the only
#   safe way to run it at all.
#
#   That is also why the Makefile runs this one bare, like slaac.sh and
#   dhcpcd.sh: it makes the namespaces it needs itself.
#
# WHAT IT PROVES
#   1. an unsupervised writer that keeps taking the file back is terminated;
#   2. a process netcfgd started is not, even with the same program name --
#      netcfgd starts its own dhcpcd, and killing that to defend a file that
#      client's lease filled in would be the worst outcome available;
#   3. patience: a single foreign write is not enough to get anybody killed;
#   4. and the blunt half, asserted rather than discovered: the sweep matches
#      by program name and cannot know who wrote the file, so an idle process
#      of a known writing program is terminated alongside the one that would
#      not stop. That is the cost of there being no way to ask the kernel who
#      wrote a path without CAP_SYS_ADMIN.
#
# POSIX sh, not bash.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "resolv_defended.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "resolv_defended.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

# Re-exec inside a pid namespace, once. Without the guard this would recurse.
if [ -z "${NCFG_RESOLV_NS:-}" ]; then
	unshare -rnp --fork --mount-proc true 2>/dev/null || \
		skip "no pid namespaces here (unshare -rnp)"
	NCFG_RESOLV_NS=1 exec unshare -rnp --fork --mount-proc "$0" "$@"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-defend.XXXXXX")
daemon=
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	# Anything the test started that netcfgd did not remove. Killed by pid,
	# never by pattern -- the rule this project keeps paying for.
	for p in ${started:-}; do kill -9 "$p" 2>/dev/null || true; done
	rm -rf "$work" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run" "$work/bin" "$work/run/dhcp"

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

cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	on_drift = "reconcile"
	dns {
		mode    = "write_resolv_conf"
		servers = "192.0.2.53"
	}
}
CONF
printf 'nameserver 127.0.0.53\n' > "$work/resolv.conf"

# `comm` is what the sweep matches, and `comm` is the executable's name -- so a
# copy of /bin/sh called `dhclient` is a process the sweep sees as dhclient.
# This is why the list is matched against comm rather than argv: a shell
# pretending by argv would not have fooled it, and a real daemon renamed by a
# wrapper would not have been found.
cp /bin/sh "$work/bin/dhclient"
started=

export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run" NCFG_RESOLV_CONF="$work/resolv.conf"
"$repo/target/debug/netcfgd" > "$work/d.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		cat "$work/d.log" >&2; echo "the daemon never started" >&2; exit 1
	fi
	sleep 0.1
done

await_ours() {
	waited=0
	while ! grep -q '^nameserver 192.0.2.53' "$work/resolv.conf" 2>/dev/null; do
		waited=$((waited + 1)); [ "$waited" -gt 300 ] && return 1; sleep 0.1
	done
	return 0
}
await_ours || true
check "netcfgd owns the file to begin with" \
	"$(grep -c '^nameserver 192.0.2.53' "$work/resolv.conf" || true)" "1"

# 1. Patience. One foreign write must not get anybody killed.
"$work/bin/dhclient" -c 'sleep 3600' &
bystander=$!
started="$bystander"
printf 'nameserver 203.0.113.99\n' > "$work/resolv.conf"
await_ours || true
check "a single foreign write is put back" \
	"$(grep -c '^nameserver 192.0.2.53' "$work/resolv.conf" || true)" "1"
check "and nobody is terminated for one write" \
	"$([ -d "/proc/$bystander" ] && echo alive || echo gone)" "alive"

# 2. A process netcfgd started is off limits, even by the same name. Recorded
#    the way the backends record theirs: <run>/<kind>/<iface>.pid
"$work/bin/dhclient" -c 'sleep 3600' &
protected=$!
started="$started $protected"
echo "$protected" > "$work/run/dhcp/probe0.pid"

# 3. The interference: takes the file back over and over.
"$work/bin/dhclient" -c 'while true; do printf "nameserver 203.0.113.99\n" > "$0"; sleep 1; done' \
	"$work/resolv.conf" &
pest=$!
started="$started $pest"

# Wait for netcfgd to lose patience. Three reclaims at the loop's tick, plus
# room for a loaded machine.
waited=0
while [ -d "/proc/$pest" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 900 ] && break
	sleep 0.1
done
check "a writer that keeps taking the file back is terminated" \
	"$([ -d "/proc/$pest" ] && echo alive || echo gone)" "gone"
check "and netcfgd said which process and why" \
	"$(grep -c 'terminated dhclient (pid '"$pest"')' "$work/d.log" || true)" "1"
# **The bystander goes too, and that is the honest reading of the design.**
# It wrote once, an hour of sleeping ago, and it is killed because the sweep
# matches a program name -- nothing can ask the kernel who wrote a file. Pinned
# so that a later narrowing is a deliberate change with a failing test, rather
# than something nobody notices either way.
check "and an idle process of the same program goes with it" \
	"$([ -d "/proc/$bystander" ] && echo alive || echo gone)" "gone"
check "the process netcfgd started is left alone" \
	"$([ -d "/proc/$protected" ] && echo alive || echo gone)" "alive"

await_ours || true
check "and the file is netcfgd's again afterwards" \
	"$(grep -c '^nameserver 192.0.2.53' "$work/resolv.conf" || true)" "1"

echo
if [ "$failures" -eq 0 ]; then
	echo "resolv_defended.sh: all checks passed"
else
	echo "resolv_defended.sh: $failures check(s) failed"
	sed 's/^/       /' "$work/d.log" >&2
	exit 1
fi
