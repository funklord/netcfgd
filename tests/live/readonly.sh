#!/bin/sh
# The read-only-root layout: factory defaults under a writable overlay.
#
# Design section 10.4. On an OpenWrt-class device `/` is a squashfs and `/etc`
# is the writable half of an overlay, so the config an image ships cannot live
# in the same place as the config an operator edits. netcfgd reads a factory
# directory first and the writable one after, and `ncfg reset` discards the
# second.
#
# What this checks is the part that only shows up with a daemon running: that a
# reset is seen, that the machine falls back to the factory configuration
# rather than to nothing, and that applying afterwards moves the interface to
# the factory's answer instead of tearing it down.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "readonly.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "readonly.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d /tmp/ncfg-ro.XXXXXX)
daemon=
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/factory" "$work/etc/conf.d" "$work/run"

export NCFG_FACTORY_DIR="$work/factory"
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

address_of() {
	ip -br -4 addr show "$1" 2>/dev/null | awk '{print $3}'
}

# Applied through the daemon, not locally. `ncfg apply` on its own compiles
# the config in the client and applies it there, so it would prove only that
# `ncfg` reads the factory layer -- the daemon could ignore it entirely and
# every check here would still pass. `--confirm-within` needs netcfgd running
# and applies the document the daemon compiled, which is the thing under test.
apply() {
	if ! "$ncfg" apply --confirm-within 30 > "$work/apply.log" 2>&1; then
		echo "FAIL apply: $1"
		cat "$work/apply.log"
		failures=$((failures + 1))
		return
	fi
	if ! "$ncfg" confirm >> "$work/apply.log" 2>&1; then
		echo "FAIL confirm: $1"
		cat "$work/apply.log"
		failures=$((failures + 1))
	fi
}

# Likewise: the daemon's view of the document, asked over the control socket
# rather than compiled again in the client.
daemon_says() {
	if "$ncfg" explain interface probe0 2>/dev/null | grep -q "$1"; then
		echo yes
	else
		echo no
	fi
}

# What the image ships.
cat > "$work/factory/netcfgd.conf" <<'CONF'
interface probe0 {
	kind   = "dummy"
	config = "192.168.1.1/24"
}
CONF

# What the operator changed on this particular unit.
cat > "$work/etc/conf.d/10-local.conf" <<'CONF'
override interface probe0 {
	kind   = "dummy"
	config = "10.44.0.1/24"
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
		echo "readonly.sh: the daemon never started" >&2
		exit 1
	fi
	sleep 0.1
done

apply "the first apply"
check "the writable layer wins over the factory" \
	"$(address_of probe0)" "10.44.0.1/24"
check "and the daemon is the one that read both layers" \
	"$(daemon_says '10.44.0.1/24')" "yes"

# A dry run changes nothing. This is the guard against a reset that fires
# because somebody typed the command to see what it did.
"$ncfg" reset > "$work/reset.log" 2>&1
check "a bare reset removes nothing" \
	"$(grep -c 'nothing was removed' "$work/reset.log" || true)" "1"
check "and says what it would have removed" \
	"$(grep -c 'would remove.*10-local.conf' "$work/reset.log" || true)" "1"
check "and the config is still there" \
	"$([ -f "$work/etc/conf.d/10-local.conf" ] && echo yes || echo no)" "yes"

# Resetting into the factory directory would delete the defaults being
# restored. Reachable through a wrong --config-dir in a unit file, which is
# exactly when nobody is watching.
if "$ncfg" reset --yes --config-dir "$work/factory" > "$work/bad.log" 2>&1; then
	echo "FAIL resetting the factory directory onto itself was allowed"
	failures=$((failures + 1))
else
	check "resetting the factory onto itself is refused" \
		"$(grep -c 'delete the defaults' "$work/bad.log" || true)" "1"
fi
check "the factory config survived that" \
	"$([ -f "$work/factory/netcfgd.conf" ] && echo yes || echo no)" "yes"

# The real thing.
"$ncfg" reset --yes > "$work/reset2.log" 2>&1
check "the writable config is gone" \
	"$([ -f "$work/etc/conf.d/10-local.conf" ] && echo yes || echo no)" "no"
check "and the factory config is not" \
	"$([ -f "$work/factory/netcfgd.conf" ] && echo yes || echo no)" "yes"

# The daemon has to notice by itself: a reset is a config edit, and inotify is
# what carries it. Waited for rather than slept through.
waited=0
while [ "$(daemon_says '192.168.1.1/24')" = "no" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		echo "FAIL the daemon never noticed the reset"
		failures=$((failures + 1))
		break
	fi
	sleep 0.1
done
check "the daemon falls back to the factory document" \
	"$(daemon_says '192.168.1.1/24')" "yes"

# And the point of the whole exercise: a reset returns the machine to factory
# defaults, not to an unconfigured state.
apply "applying after the reset"
check "the interface takes the factory address" \
	"$(address_of probe0)" "192.168.1.1/24"

echo
if [ "$failures" -eq 0 ]; then
	echo "readonly.sh: all checks passed"
else
	echo "readonly.sh: $failures failed"
	exit 1
fi
