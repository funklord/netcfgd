#!/bin/sh
# Who may open the remote socket, against a real daemon.
#
#     sh tests/live/remote_socket.sh
#
# Decision 0159. The remote socket's mode was computed from the *local* control
# policy, and `check` short-circuits to the remote booleans for an
# `Origin::Remote` connection -- consulting no principal and no peer. So a
# `control` block opening `observe` to a group or to `any`, which is the shape
# `debian/postinst` ships, opened a socket that grants whatever `remote` allows.
# Measured before the fix, as an ordinary user against `observe = "any"` with
# `admin = "root"`: `reload` refused on the local socket and accepted on the
# remote one.
#
# **The mode is the property, not the connect.** The daemon under test runs as
# whoever ran this script, so the socket's owner is that user and an owner can
# always open their own 0600 file; in production the owner is root and the mode
# is what shuts everybody else out. The escalation is therefore asserted as the
# permission bits, which is the thing that differs between a fixed daemon and a
# broken one whoever runs it.
#
# No namespace: this binds unix sockets and reads their modes. It touches no
# interface.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "remote_socket.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "remote_socket.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-rsock.XXXXXX")
daemon=
cleanup() {
	if [ -n "$daemon" ]; then
		kill "$daemon" 2>/dev/null || true
		wait "$daemon" 2>/dev/null || true
	fi
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

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

# The daemon is restarted per case: the sockets are bound once, at startup,
# from the document it read then.
start_daemon() {
	rm -f "$work/run/netcfgd.sock" "$work/run/remote.sock"
	"$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
	daemon=$!
	i=0
	while [ ! -e "$work/run/netcfgd.sock" ] && [ "$i" -lt 50 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -e "$work/run/netcfgd.sock" ]; then
		echo "remote_socket.sh: the daemon never bound its socket" >&2
		cat "$work/daemon.log" >&2
		exit 1
	fi
}

stop_daemon() {
	if [ -n "$daemon" ]; then
		kill "$daemon" 2>/dev/null || true
		wait "$daemon" 2>/dev/null || true
		daemon=
	fi
}

mode() {
	if [ -e "$1" ]; then
		stat -c '%a' "$1"
	else
		echo absent
	fi
}

# A wide local policy, and a remote policy that names no agent.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	control {
		observe = "any"
		wifi    = "root"
		admin   = "root"
	}
	remote {
		observe = true
		wifi    = true
		admin   = true
	}
}
CONF
start_daemon

# Both in one case, because the property is that they *differ*. Asserting the
# remote mode alone would also pass if the local socket had been narrowed to
# match, which is the other way to make them agree and is the wrong one.
check "a local policy of any opens the local socket" \
	"$(mode "$work/run/netcfgd.sock")" "666"
check "and leaves the remote socket to root" \
	"$(mode "$work/run/remote.sock")" "600"
check "and the daemon says who it opened it to" \
	"$(grep -c 'remote access is open .* to `root`' "$work/daemon.log" || true)" "1"
stop_daemon

# The same local policy, with an agent named. 0128's mechanism, pointed at the
# policy that describes the agent rather than at the one describing local users.
#
# **A secondary group, never the primary one.** A socket is created owned by
# its creator's primary group, so naming that group makes the ownership check
# pass whether the chown happened or not -- measured: with the fix reverted, an
# assertion against `id -gn` still said ok. The first group that is not the
# primary is one the chown has to have moved it to.
group=
for candidate in $(id -Gn); do
	if [ "$candidate" != "$(id -gn)" ]; then
		group=$candidate
		break
	fi
done
[ -n "$group" ] || skip "this user has no secondary group, so a chown cannot be observed"
cat > "$work/etc/netcfgd.conf" <<CONF
global {
	control {
		observe = "root"
		wifi    = "root"
		admin   = "root"
	}
	remote {
		observe = true
		admin   = true
		agent   = "group:$group"
	}
}
CONF
start_daemon

check "a named agent opens the remote socket to its group" \
	"$(mode "$work/run/remote.sock")" "660"
check "and the local socket keeps its own answer" \
	"$(mode "$work/run/netcfgd.sock")" "600"
check "and the socket belongs to the group named" \
	"$(stat -c '%G' "$work/run/remote.sock")" "$group"
stop_daemon

# No remote policy at all: constraint 2, and the case every machine is in.
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

check "a machine that never configured remote has no remote socket" \
	"$(mode "$work/run/remote.sock")" "absent"
stop_daemon

if [ "$failures" -eq 0 ]; then
	echo "remote_socket.sh: all checks passed"
else
	echo "remote_socket.sh: $failures check(s) failed"
	exit 1
fi
