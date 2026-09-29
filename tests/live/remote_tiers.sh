#!/bin/sh
# What a remote connection may do, asked of the daemon rather than inferred.
#
# WHY THIS FILE EXISTS
#   0128 splits remote access in two: the agent decides *who* the caller is,
#   because it terminates fuzznet's protocol and the daemon sees only a unix
#   socket; and the daemon decides what remote can *ever* do, whoever it is,
#   because origin is which socket a connection arrived on and there is no
#   field to forge. The second half is the property worth having -- a
#   compromised agent reaches what the remote policy allows and not the
#   machine.
#
#   **That half had never been exercised.** `control_exposure.sh` checks who
#   may *open* the remote socket, which is 0159's question and a different one.
#   Nothing had ever connected to it and been told what it may do, because
#   until `bridge/` there was nothing to connect with.
#
# WHAT MAKES THIS MORE THAN ONE ASSERTION
#   Reading the remote tiers alone would pass against a daemon that handed the
#   same answer to every caller. The discriminator is that the **same running
#   daemon** answers differently on its two sockets: the local policy on one
#   and the remote policy on the other. That is origin deciding, and it is the
#   only arrangement the wrong implementations fail.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"
export build
bridge="$repo/bridge/netcfgd-remote"

daemon_flags=
if "$build/netcfgd" --help 2>&1 | grep -q -- '--try-the-c-daemon'; then
	daemon_flags=--try-the-c-daemon
fi

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "remote_tiers.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "remote_tiers.sh: skipping: $1"
	exit 0
}

[ -x "$build/netcfgd" ] || skip "netcfgd is not built"
# **Built rather than skipped over.** The bridge links fuzznet and its vendored
# Monocypher, so a tree whose submodules are not initialised has no program to
# ask with -- and a skip there would hide exactly the integration this checks.
[ -x "$bridge" ] || skip "the bridge is not built (make -C bridge)"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-rtier.XXXXXX")
daemon=
cleanup() {
	if [ -n "$daemon" ]; then
		kill "$daemon" 2>/dev/null || true
		wait "$daemon" 2>/dev/null || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run" "$work/ctrl"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_WPA_CTRL_DIR="$work/ctrl"

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

start_daemon() {
	rm -f "$work/run/netcfgd.sock" "$work/run/remote.sock"
	"$build/netcfgd" $daemon_flags --no-apply-on-start > "$work/daemon.log" 2>&1 &
	daemon=$!
	i=0
	while [ ! -e "$work/run/netcfgd.sock" ] && [ "$i" -lt 50 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	[ -e "$work/run/netcfgd.sock" ] || {
		echo "remote_tiers.sh: the daemon never bound its socket" >&2
		cat "$work/daemon.log" >&2
		exit 1
	}
}

stop_daemon() {
	if [ -n "$daemon" ]; then
		kill "$daemon" 2>/dev/null || true
		wait "$daemon" 2>/dev/null || true
		daemon=
	fi
}

# A local policy that grants everything and a remote one that does not, with
# the agent open so an unprivileged run can connect at all. The two must
# differ, or this file cannot tell origin from identity.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	control {
		observe = "any"
		wifi    = "any"
		admin   = "any"
	}
	remote {
		agent   = "any"
		observe = true
		wifi    = true
		admin   = false
	}
}
CONF
start_daemon

check "the remote socket exists when a remote policy does" \
	"$([ -S "$work/run/remote.sock" ] && echo yes || echo no)" "yes"

check "a local connection gets the local policy" \
	"$("$bridge" --tiers "$work/run/netcfgd.sock" 2>&1)" \
	"observe 1  wifi 1  admin 1"

# The case the file exists for, and the one the daemon's own tests could not
# reach: admin is refused because of where the connection arrived, not because
# of who made it -- the same process, the same uid, one socket apart.
check "and the same daemon bounds the same caller on the remote socket" \
	"$("$bridge" --tiers "$work/run/remote.sock" 2>&1)" \
	"observe 1  wifi 1  admin 0"

stop_daemon

# **No remote block, no socket.** Constraint 2 applied where the difference is
# a security property rather than tidiness: a machine that never configured
# remote access has nothing listening for it.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	control {
		observe = "any"
		wifi    = "any"
		admin   = "any"
	}
}
CONF
start_daemon
check "a machine that configured no remote access has no remote socket" \
	"$([ -e "$work/run/remote.sock" ] && echo present || echo absent)" "absent"
check "and the bridge cannot reach one" \
	"$("$bridge" --tiers "$work/run/remote.sock" >/dev/null 2>&1 && echo connected || echo refused)" \
	"refused"
stop_daemon

if [ "$failures" -eq 0 ]; then
	echo "remote_tiers.sh: all checks passed"
else
	echo "remote_tiers.sh: $failures check(s) failed" >&2
fi
exit $([ "$failures" -eq 0 ] && echo 0 || echo 1)
