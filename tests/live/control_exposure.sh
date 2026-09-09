#!/bin/sh
# What netcfgd's control sockets expose to a local caller, against a real daemon.
#
#     sh tests/live/control_exposure.sh
#
# Two findings, one scaffold, because both are the same question asked of the
# same two files: what can somebody on this machine reach, and what does the
# answer tell them.
#
# **Who may open the remote socket (0159).** The remote socket's mode was computed from the *local* control
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
# **What the observe tier discloses (0160)**, in the last case: an interface
# name reaching `Path::join` made the two errors around it into an existence
# oracle over the whole filesystem.
#
# No namespace: this binds unix sockets and reads their modes. It touches no
# interface.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "control_exposure.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "control_exposure.sh: skipping: $1"
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
mkdir -p "$work/etc" "$work/run" "$work/ctrl"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
# This run's own supplicant directory, exported before any daemon starts so the
# daemon inherits it. Set after `start_daemon` it would be read by the CLI and
# not by the process that does the joining, and the last case below would then
# be answered from whatever `/run/wpa_supplicant` this machine happens to hold
# -- which is a real directory here, with a real socket in it.
export NCFG_WPA_CTRL_DIR="$work/ctrl"

failures=0
contains() {
	case "$2" in
	*"$3"*) echo "ok   $1" ;;
	*)
		echo "FAIL $1"
		echo "       expected to contain: $3"
		echo "       actual:              $2"
		failures=$((failures + 1))
		;;
	esac
}
missing() {
	case "$2" in
	*"$3"*)
		echo "FAIL $1"
		echo "       expected NOT to contain: $3"
		echo "       actual:                  $2"
		failures=$((failures + 1))
		;;
	*) echo "ok   $1" ;;
	esac
}
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
		echo "control_exposure.sh: the daemon never bound its socket" >&2
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
# ------------------------------------------ a connection that says nothing

# **The cap protects the daemon from clients; nothing protected it from a
# connection that is not one.** `handle` blocked in `read_request` with no
# deadline, so a caller that connected and stayed silent held a slot for ever
# -- and sixty-four of them held every slot the cap allows. Any local user can
# do it wherever the policy opens the socket, which `observe = "any"` above
# does. Decision 0183.
#
# Two things are asserted, and they were two separate faults. That the slots
# come back, and that while they are gone the client is told *which wall it
# met*: the daemon answers the cap on accept and closes, so the client's write
# landed on a closed socket and reported `Broken pipe` while the daemon's own
# sentence sat unread in its receive buffer.
start_daemon
python3 - "$work/run/netcfgd.sock" "$repo/target/debug/ncfg" > "$work/cap.log" 2>&1 <<'PROBE' || true
import socket, subprocess, sys, time

sock, ncfg = sys.argv[1], sys.argv[2]

# More than the cap, opened as fast as they can be, so the wall is reached
# before the first of them times out.
held = []
for _ in range(70):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(sock)
    held.append(connection)

def reload_says():
    done = subprocess.run([ncfg, "reload"], capture_output=True, text=True, timeout=30)
    lines = (done.stdout or done.stderr).splitlines()
    return lines[0] if lines else "<nothing>"

print("full:", reload_says())
# The deadline is ten seconds; this waits it out with a margin rather than
# racing it.
time.sleep(13)
print("later:", reload_says())
PROBE

contains "a client that meets the connection cap is told so, not left with a write error" \
	"$(grep '^full:' "$work/cap.log" || true)" "too many connections"
missing "and not left holding the kernel's word for a closed socket" \
	"$(grep '^full:' "$work/cap.log" || true)" "Broken pipe"
# **What changes is that the cap is gone, not what the daemon then says.**
# A first version asserted "reloaded", which is what root gets; run as an
# ordinary user the same request is refused by the `admin` tier and the check
# failed for a reason that had nothing to do with connection slots. The
# property is that the answer is no longer about capacity -- and that there is
# an answer at all, so this cannot pass on silence.
missing "and silent connections give their slots back, so the daemon recovers" \
	"$(grep '^later:' "$work/cap.log" || true)" "too many connections"
contains "and the daemon is answering rather than saying nothing" \
	"$(grep -c '^later: .' "$work/cap.log" || true)" "1"
stop_daemon

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

# **The observe tier answers no questions about the filesystem.** 0160: the
# interface name in a `wifi_status` reaches `dir.join(interface)`, and `join`
# with an absolute path replaces the base -- so the two errors around it, "no
# control socket at X" and "cannot reach X: <errno>", told an unprivileged
# caller whether X existed. Measured before the fix, against this daemon:
# `/etc/shadow` answered "Permission denied" and `/etc/no-such-file` answered
# "no control socket at ...".
#
# **The check is that the two answers do not DIFFER**, not that they fail.
# Every probe here fails either way -- there is no supplicant at any of them --
# so asserting "this errors" would pass against the oracle it exists to close.
# **The two probes are the same length and the same shape**, differing only in
# whether the file is there. The first version of this used `/etc/shadow`
# against a long made-up path and failed honestly: one was refused for the `/`
# and the other for being 29 characters, so the answers differed about the
# *name*. That is not a leak -- the caller wrote the name -- but it is not the
# question either, and a pair that varies two things at once cannot answer it.
# The path is removed from the text before comparing, for the same reason: a
# message quoting what the caller sent tells them nothing they did not send.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	control {
		observe = "any"
	}
}
CONF
start_daemon

# `ncfg wifi status` sends `WifiStatus` to the daemon and prints what comes
# back, which is the path the report came in on.
probe() {
	"$repo/target/debug/ncfg" wifi status "$1" 2>&1 | head -1 |
		sed "s|$1||g" | tr -s ' '
}

present=$(probe /etc/passwd)
absent=$(probe /etc/passwe)
if [ "$present" = "$absent" ]; then
	same=same
else
	same="different: [$present] vs [$absent]"
fi
check "a path that exists and one that does not get the same answer" "$same" "same"
check "and the answer is about the name rather than about the filesystem" \
	"$("$repo/target/debug/ncfg" wifi status /etc/passwd 2>&1 |
		grep -c 'is not an interface name' || true)" "1"
check "while an ordinary name still gets the real diagnosis" \
	"$("$repo/target/debug/ncfg" wifi status wlan0 2>&1 |
		grep -c 'no control socket' || true)" "1"
stop_daemon

stop_daemon

if [ "$failures" -eq 0 ]; then
	echo "control_exposure.sh: all checks passed"
else
	echo "control_exposure.sh: $failures check(s) failed"
	exit 1
fi
