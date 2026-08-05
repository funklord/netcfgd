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
# a fixed sleep is either flaky or slow.
#
# This is the test's patience, not a deadline the daemon is being held to --
# every check here is about *which* uplink wins, never how fast. It polls, so a
# wider bound costs nothing when the answer is already right, which it is within
# 100ms in every run measured. Fifty tries proved too tight exactly once, in a
# full `make live` on a cold Alpine container: the daemon had not applied at all
# by five seconds, `chosen` was empty, and the check reported `expected eth-lan,
# actual` with nothing to say a wait had run out.
#
# Widening is not a demonstrated fix -- the failure has not reproduced in 24
# further runs under deliberate load, with either bound -- but the timeout being
# silent is a defect on its own terms, and that is what is fixed here.
settle_to() {
	waited=0
	while [ "$(chosen)" != "$1" ]; do
		waited=$((waited + 1))
		if [ "$waited" -gt 150 ]; then
			echo "       waited 15s for the default route to be on $1; it is:"
			ip route show default 2>&1 | sed 's/^/         /' || true
			echo "         (empty above means netcfgd had not applied at all)"
			return 1
		fi
		sleep 0.1
	done
	return 0
}

# Wait for an uplink to win, and assert it, in one operation.
#
# `settle_to X` followed by `check ... "$(chosen)" X` samples twice, and the
# daemon is running: a reconcile in flight can withdraw and reinstall the
# default routes between the two reads. That happened -- `expected: eth-lan,
# actual:` with nothing, and no timeout message above it, which is what says
# the wait had already *succeeded* and the second read caught the gap.
#
# So the assertion is the wait. It reports the last value it saw rather than a
# fresh one, which cannot disagree with what it waited for.
settled() {
	if settle_to "$2"; then
		echo "ok   $1"
	else
		echo "FAIL $1"
		echo "       expected: $2"
		echo "       actual:   $(chosen)"
		failures=$((failures + 1))
	fi
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

# The socket is bound before the first apply runs (netcfgd-daemon serves, then
# converges), so the peers are not guaranteed to exist the moment it appears.
# The window is far smaller than the fork+exec of ip(8) below and has never been
# caught open here -- this loop has measured zero iterations every time it was
# asked. It stays because the ordering is real and costs nothing when it holds,
# and because a full-suite run once failed on the line below with "cannot bring
# the veth peers up", which was reported as a permissions problem and is not
# one. That failure was not reproduced; if it returns, this reports it with the
# daemon log instead of guessing.
waited=0
while ! ip link show eth-peer >/dev/null 2>&1 || ! ip link show wl-peer >/dev/null 2>&1; do
	waited=$((waited + 1))
	if [ "$waited" -gt 100 ]; then
		cat "$work/daemon.log" >&2
		echo "switch.sh: the daemon started but never created the veth pairs" >&2
		exit 1
	fi
	sleep 0.1
done

# Both far ends up, so both uplinks have carrier. Not a skip: the peers exist by
# here and the daemon started, so a failure is a real one and its error is worth
# reading rather than discarding down /dev/null.
ip link set eth-peer up
ip link set wl-peer up

settled "the wired uplink wins while it has carrier" eth-lan

# The whole feature: pull the cable and run nothing.
ip link set eth-peer down
settled "unplugging switches to wifi on its own" wl-fake

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
settled "plugging back in switches back" eth-lan

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
