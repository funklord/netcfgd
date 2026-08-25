#!/bin/sh
# Adopting the network after the ownership record is gone.
#
# WHY THIS FILE EXISTS
#   netcfgd must survive being restarted without dropping what it configured
#   (project.md section 10, decision 0134), and a restart is exactly when the
#   record is lost: the unit sets `RuntimeDirectory=netcfgd`, whose default
#   `RuntimeDirectoryPreserve=no` means systemd deletes `/run/netcfgd` when the
#   service stops. So the daemon that comes back has the network but not the
#   note saying which parts of it are its own.
#
#   Holding is the safe direction and it is not sufficient. A netcfgd that
#   cannot recognise its own work can never remove it either, so a network
#   deleted from the config stays on the machine for ever, and `ncfg apply`
#   reports success having done nothing. That is a daemon quietly ceasing to
#   reconcile, which is the failure 0132 exists to prevent.
#
# WHAT IT PROVES
#   The kernel carries the evidence. netcfgd stamps 110 on the addresses and
#   routes it installs (0002), one code path installs each, and both record
#   `Origin::Static` -- so an object wearing the tag is netcfgd's, from config,
#   whatever `/run` remembers. This runs the whole cycle with the record
#   deleted in the middle and checks the second daemon acts on what the first
#   one left.
#
# THE HALF THAT MUST NOT MOVE
#   An address netcfgd did not install must survive all of this. The tag is
#   what separates them, so the test puts a foreign address alongside and
#   checks it is still there at the end. Without that this suite would pass
#   just as well for a netcfgd that removed everything it found.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "adopt.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "adopt.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
command -v ip >/dev/null 2>&1 || skip "iproute2 is not installed"

work=$(mktemp -d /tmp/ncfg-adopt.XXXXXX)
ncfg="$repo/target/debug/ncfg"
[ -x "$ncfg" ] || ncfg="$repo/target/debug/netcfgd"
daemon=
failures=0

cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	wait "$daemon" 2>/dev/null || true
	rm -rf "$work"
}
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

# Starts the daemon and waits for its socket. Bounded by the counter.
start_daemon() {
	"$repo/target/debug/netcfgd" > "$work/$1.log" 2>&1 &
	daemon=$!
	waited=0
	while [ ! -e "$work/run/netcfgd.sock" ]; do
		waited=$((waited + 1))
		if [ "$waited" -gt 60 ]; then
			cat "$work/$1.log" >&2
			echo "adopt.sh: the daemon never started" >&2
			exit 1
		fi
		sleep 0.1
	done
	sleep 2
}

stop_daemon() {
	[ -n "$daemon" ] || return 0
	kill "$daemon" 2>/dev/null || true
	wait "$daemon" 2>/dev/null || true
	daemon=
	rm -f "$work/run/netcfgd.sock"
}

ip link add net0 type dummy 2>/dev/null || skip "cannot create a dummy link"
ip link set net0 up
mkdir -p "$work/etc/conf.d" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface net0 {
	config = "10.9.9.1/24"
	routes = "default via 10.9.9.254"
}
CONF

# An address that is emphatically not netcfgd's, added before it ever runs and
# carrying no tag of netcfgd's. Nothing below may take this away.
ip addr add 10.8.8.1/24 dev net0

start_daemon d1

# ---------------------------------------------------------------------------
# 1. The first daemon configures the interface and marks what it installed.
check "netcfgd installs the address from config" \
	"$(ip -4 addr show net0 | grep -c '10\.9\.9\.1')" "1"
check "and stamps its protocol tag on it" \
	"$(ip -d -4 addr show net0 | grep -c 'proto 0x6e')" "1"
check "and installs the route with the same tag" \
	"$(ip -4 route show dev net0 | grep '10\.9\.9\.254' | grep -c 'proto 110')" "1"
check "and the foreign address is untouched" \
	"$(ip -4 addr show net0 | grep -c '10\.8\.8\.1')" "1"

# ---------------------------------------------------------------------------
# 2. Stopping holds the network (0134), and the record goes the way systemd
#    takes it.
stop_daemon
check "stopping the daemon leaves the address up" \
	"$(ip -4 addr show net0 | grep -c '10\.9\.9\.1')" "1"
check "and leaves the route up" \
	"$(ip -4 route show dev net0 | grep -c '10\.9\.9\.254')" "1"

rm -f "$work/run/owned.json"
check "the ownership record is gone" \
	"$([ -e "$work/run/owned.json" ] && echo present || echo gone)" "gone"

# ---------------------------------------------------------------------------
# 3. The config stops asking for either. A daemon that adopted what it found
#    takes them away; one that lost track of its own work cannot.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface net0 {
}
CONF

start_daemon d2
sleep 1

check "the restarted daemon removes the address it no longer wants" \
	"$(ip -4 addr show net0 | grep -c '10\.9\.9\.1')" "0"
check "and removes the route" \
	"$(ip -4 route show dev net0 | grep -c '10\.9\.9\.254')" "0"

# The half that must not move. If this fails the suite above proves nothing,
# because a netcfgd that removes everything satisfies every check before it.
check "and leaves the address that was never its own" \
	"$(ip -4 addr show net0 | grep -c '10\.8\.8\.1')" "1"

echo
if [ "$failures" -eq 0 ]; then
	echo "adopt.sh: all checks passed"
else
	echo "adopt.sh: $failures failed"
	exit 1
fi
