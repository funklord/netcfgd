#!/bin/sh
# netcfgd defends the resolv.conf it owns, against a real kernel and a running
# daemon.
#
# WHY THIS FILE EXISTS
#   `dns_mode = "write_resolv_conf"` writes a file whose first line says
#   "Edits will be overwritten". They were not. Reported from a systemd
#   machine, and the cause was two independent filters, either of which alone
#   was enough to lose it (0165):
#
#     1. the observation took `observed.dns` from netcfgd's own record of what
#        it had delivered, so a foreign overwrite was invisible -- the planner
#        compared desired against a record that still said "delivered";
#     2. the drift loop restricts a plan to the interfaces that opted into
#        reconciling, and `dns.apply` belongs to no interface, so it was
#        dropped even once the plan carried it.
#
#   Both are fixed, and this is what says so. It needs a *running daemon*,
#   because the whole property is about the loop rather than about one apply.
#
# WHAT IT WOULD MISS
#   It does not drive systemd-resolved -- there is none on the machines this
#   suite runs on. A shell overwriting the file stands in for any other writer,
#   which is honest for the first case and not for the second: making resolved
#   stay down is `Conflicts=` in netcfgd-exclusive.conf, checked by reading the
#   file rather than by running systemd.
#
# POSIX sh, not bash.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "resolv_owned.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "resolv_owned.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-resolv.XXXXXX")
daemon=
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1)); [ "$waited" -gt 50 ] && break; sleep 0.1
	done
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

# Two scopes, because one is the case where a re-render could disagree with
# what was written and rewrite for ever. An interface scope and the globals
# are flattened in a defined order; if the observation rebuilt them in another
# order the file would differ from itself on every pass.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	on_drift = "reconcile"
	dns {
		mode    = "write_resolv_conf"
		servers = "192.0.2.53 192.0.2.54"
		search  = "example.invalid"
	}
}
device probe0 { kind = "dummy" }
interface probe0 {
	dns {
		servers = "198.51.100.1"
	}
}
CONF

printf 'nameserver 127.0.0.53\n' > "$work/resolv.conf"
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run" NCFG_RESOLV_CONF="$work/resolv.conf"

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

"$repo/target/debug/netcfgd" > "$work/d.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		if grep -q 'Operation not permitted' "$work/d.log" 2>/dev/null; then
			skip "no CAP_NET_ADMIN (run under unshare -rn)"
		fi
		cat "$work/d.log" >&2; echo "resolv_owned.sh: the daemon never started" >&2; exit 1
	fi
	sleep 0.1
done

# Wait for the outcome rather than sleeping for it.
await_ours() {
	waited=0
	while ! grep -q '^nameserver 192.0.2.53' "$work/resolv.conf" 2>/dev/null; do
		waited=$((waited + 1))
		[ "$waited" -gt 200 ] && return 1
		sleep 0.1
	done
	return 0
}

await_ours || true
check "netcfgd writes the file it was told to own" \
	"$(grep -c '^nameserver 192.0.2.53' "$work/resolv.conf" || true)" "1"
check "and the interface scope is in it, ahead of the globals" \
	"$(grep -c '^nameserver 198.51.100.1' "$work/resolv.conf" || true)" "1"

# **The property the report was about.** Another resolver rewrites it.
printf 'nameserver 203.0.113.99\n' > "$work/resolv.conf"
check "a foreign write really did land" \
	"$(grep -c '^nameserver 203.0.113.99' "$work/resolv.conf" || true)" "1"

await_ours || true
check "and netcfgd puts its own back" \
	"$(grep -c '^nameserver 192.0.2.53' "$work/resolv.conf" || true)" "1"
check "with the foreign server gone" \
	"$(grep -c '^nameserver 203.0.113.99' "$work/resolv.conf" || true)" "0"

# **A rewrite loop would be worse than the bug**, so this asserts the other
# direction: nothing touching the file means netcfgd does not touch it either.
# A fixed sleep is right here -- there is no outcome to wait for, and returning
# early would only mean not having looked long enough.
before=$(stat -c '%i %Y %Z' "$work/resolv.conf")
sleep 12
after=$(stat -c '%i %Y %Z' "$work/resolv.conf")
check "and does not rewrite it when nothing has changed" \
	"$([ "$before" = "$after" ] && echo same || echo rewritten)" "same"

# The half that cannot be driven here, checked by reading the file that
# carries it: systemd-resolved is the daemon that owns this path, and a kill
# would not hold because its unit has Restart=.
exclusive="$repo/packaging/systemd/netcfgd-exclusive.conf"
check "the exclusive drop-in tells systemd to stand resolved down" \
	"$(grep -c '^Conflicts=systemd-resolved.service$' "$exclusive")" "1"
check "and orders itself after it, since Conflicts alone does not" \
	"$(grep -c '^After=systemd-resolved.service$' "$exclusive")" "1"

echo
if [ "$failures" -eq 0 ]; then
	echo "resolv_owned.sh: all checks passed"
else
	echo "resolv_owned.sh: $failures check(s) failed"
	sed 's/^/       /' "$work/d.log" >&2
	exit 1
fi
