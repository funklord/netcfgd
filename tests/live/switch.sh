#!/bin/sh
# Carrier-based switching, with the daemon running and nothing else touched.
#
# This is the laptop feature: wired preferred while the cable is in, wifi when
# it is not, and the operator runs no command for either. So the test pulls a
# cable and waits, rather than applying a plan -- an `ncfg apply` between the
# two would prove something nobody experiences.
#
# Two veth pairs stand in for the uplinks. What matters is carrier, and
# downing a veth's far end takes carrier off the near one exactly as unplugging
# does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "switch.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "switch.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

work=$(mktemp -d /tmp/ncfg-switch.XXXXXX)
cleanup() {
	[ -n "${daemon:-}" ] && kill "$daemon" 2>/dev/null
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface eth-lan {
	veth       { peer = "eth-peer" }
	preference = 100
	config     = "10.1.0.2/24"
	routes     = "default via 10.1.0.1"
}

interface wl-fake {
	veth       { peer = "wl-peer" }
	preference = 600
	config     = "10.2.0.2/24"
	routes     = "default via 10.2.0.1"
}
CONF

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"

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

# Which interface the kernel would actually use, which is the only question
# this feature is about.
chosen() { ip route show default | head -1 | sed -n 's/.* dev \([^ ]*\).*/\1/p'; }

# Wait rather than sleep a fixed time: the daemon reacts to a netlink event and
# a fixed sleep is either flaky or slow. Fifty tries at 100ms is five seconds,
# which is far longer than a reconcile and short enough to fail usefully.
settle_to() {
	waited=0
	while [ "$(chosen)" != "$1" ]; do
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && return 1
		sleep 0.1
	done
	return 0
}

"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!

waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 50 ]; then
		if grep -q 'Operation not permitted' "$work/daemon.log" 2>/dev/null; then
			skip "no CAP_NET_ADMIN (run under unshare -rn)"
		fi
		cat "$work/daemon.log" >&2
		echo "switch.sh: the daemon never started" >&2
		exit 1
	fi
	sleep 0.1
done

# Both far ends up, so both uplinks have carrier.
ip link set eth-peer up 2>/dev/null || skip "cannot bring the veth peers up"
ip link set wl-peer up

settle_to eth-lan || true
check "the wired uplink wins while it has carrier" "$(chosen)" "eth-lan"

# The whole feature: pull the cable and run nothing.
ip link set eth-peer down
settle_to wl-fake || true
check "unplugging switches to wifi on its own" "$(chosen)" "wl-fake"

# A route left down a dead cable would still be preferred on metric, and the
# kernel would black-hole traffic rather than use the link that works. So the
# route has to be gone, not merely deprioritised.
if ip route show default | grep -q "dev eth-lan"; then
	echo "FAIL the route down the dead cable is still installed"
	ip route show default
	failures=$((failures + 1))
else
	echo "ok   and withdraws the route rather than leaving it linkdown"
fi

ip link set eth-peer up
settle_to eth-lan || true
check "plugging back in switches back" "$(chosen)" "eth-lan"

# The daemon does this because a preferred interface is always reconciled, not
# because the drift policy says so. Nothing in the config above mentions drift,
# and the default is to report rather than act -- so if this ever regresses to
# depending on it, the checks above fail rather than the machine quietly
# announcing a problem it could have fixed.
if grep -qi 'drift' "$work/daemon.log"; then
	echo "note: the daemon logged drift:"
	grep -i 'drift' "$work/daemon.log" | head -3
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "switch.sh: all checks passed"
else
	echo "switch.sh: $failures failed"
	exit 1
fi
