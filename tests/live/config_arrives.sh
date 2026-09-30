#!/bin/sh
# A configuration written while the daemon is running: does it reach the machine?
#
#     unshare -rn sh tests/live/config_arrives.sh
#
# ## Why this exists
#
# project.md 10.307 is fifty-two minutes in which a machine did not match its
# own configuration and netcfgd said nothing. The configuration was correct by
# 12:55:17; what applied it was a daemon restart at 13:47 for an unrelated
# reason. 10.330 closed the "nothing said so" half for the policies that do not
# act, and explicitly did not close this one: that machine's radio was under the
# default policy, which is `reconcile`, so the daemon should have applied it.
#
# **No live test covered the path at all.** Thirty scripts write configuration
# while a daemon runs, and every one of them either calls `ncfg apply`
# afterwards or starts the daemon with `--no-apply-on-start` and drives it by
# hand. The one question 10.307 asks -- write a file, touch nothing else, does
# the machine change -- had no witness.
#
# So this script calls `apply` nowhere. That is the point of it, and a future
# edit adding one to "make it pass" has removed the test rather than fixed it.
#
# ## What it drives
#
# Dummy interfaces in a network namespace, and netcfgd's own reload path. No
# radio, because the question is not about radios: 10.307's write was a
# `network` block, but what it turns on is whether a *written file* is noticed
# and acted on, and an address on a dummy link asks that with nothing faked.
#
# ## The three writes, and why the second is the one 10.307 made
#
#   1. a key changed in `netcfgd.conf` itself;
#   2. the same change arriving as a **drop-in** under `conf.d/`, which is what
#      every `ncfg wifi` and every GUI dialog writes, and what the machine in
#      10.307 was handed. It says `override`, because a drop-in redefining a
#      block without it is refused -- which this script got wrong first, and
#      the compiler said so in one sentence naming both files and the line;
#   3. a whole new interface arriving in a drop-in, which is the case where
#      netcfgd has to notice something it has never seen rather than a value
#      that moved.
#
# Each is given ten seconds. A reload that takes longer than that on an
# otherwise idle namespace is a failure whatever the eventual outcome: 10.307's
# operator waited fifty-two minutes.
set -eu

name=config_arrives.sh
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"

# Kept for the reason drift.sh keeps it: asked of the binary rather than
# inferred from the path, so a build from before 0265 still gets the flag.
daemon_flags=
if "$build/netcfgd" --help 2>&1 | grep -q -- '--try-the-c-daemon'; then
	daemon_flags=--try-the-c-daemon
fi

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "$name: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "$name: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$build/netcfgd" ] || skip "netcfgd is not built"
ip link add probe-ns type dummy 2>/dev/null || skip "no namespace to make links in"
ip link del probe-ns 2>/dev/null || true

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-arrives.XXXXXX")
daemon=
cleanup() {
	if [ -n "$daemon" ]; then
		kill "$daemon" 2>/dev/null || true
		wait "$daemon" 2>/dev/null || true
	fi
	# The retry is drift.sh's: a signalled daemon writes on its way out, so a
	# single `rm -rf` races the process just asked to stop, and a trap that
	# exits non-zero fails a run whose every check passed.
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc/conf.d" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"

failures=0
checks=0
check() {
	checks=$((checks + 1))
	if [ "$2" = "$3" ]; then
		printf 'ok   %s\n' "$1"
	else
		printf 'FAIL %s\n' "$1"
		printf '       expected: %s\n' "$3"
		printf '       actual:   %s\n' "$2"
		failures=$((failures + 1))
	fi
}

# Ten seconds, in tenths, and it returns as soon as the condition holds. The
# bound is the assertion: a reload nobody is waiting on is not a reload.
awaits() {
	i=0
	while [ "$i" -lt 100 ]; do
		if eval "$1" >/dev/null 2>&1; then
			return 0
		fi
		i=$((i + 1))
		sleep 0.1
	done
	return 1
}

has_address() {
	ip -br addr show "$1" 2>/dev/null | grep -c "$2" || true
}

start_daemon() {
	"$build/netcfgd" $daemon_flags > "$work/daemon.log" 2>&1 &
	daemon=$!
	i=0
	while [ ! -e "$work/run/netcfgd.sock" ] && [ "$i" -lt 100 ]; do
		i=$((i + 1))
		sleep 0.1
	done
	if [ ! -e "$work/run/netcfgd.sock" ]; then
		echo "$name: the daemon never bound its socket" >&2
		cat "$work/daemon.log" >&2
		exit 1
	fi
}

# ------------------------------------------------------- the running machine

cat > "$work/etc/netcfgd.conf" <<'CONF'
device arrive0 {
	kind = "dummy"
}
interface arrive0 {
	config = "10.20.0.1/24"
}
CONF

start_daemon
awaits 'ip -br addr show arrive0 2>/dev/null | grep -q 10.20.0.1' || true
check "the daemon converged on what it was started with" \
	"$(has_address arrive0 10.20.0.1)" 1

# --------------------------------------------- 1: netcfgd.conf itself changes

cat > "$work/etc/netcfgd.conf" <<'CONF'
device arrive0 {
	kind = "dummy"
}
interface arrive0 {
	config = "10.20.0.1/24
10.20.0.2/24"
}
CONF

awaits 'ip -br addr show arrive0 2>/dev/null | grep -q 10.20.0.2' || true
check "a value changed in netcfgd.conf reaches the machine, with no apply" \
	"$(has_address arrive0 10.20.0.2)" 1

# ------------------------------------------------- 2: a drop-in under conf.d
#
# **The shape 10.307 was handed.** Every `ncfg wifi add` and every GUI dialog
# writes here rather than into netcfgd.conf, so a reload that covered the one
# file and not this directory would present exactly as that afternoon did.

cat > "$work/etc/conf.d/50-arrive.conf" <<'CONF'
override interface arrive0 {
	config = "10.20.0.1/24
10.20.0.2/24
10.20.0.3/24"
}
CONF

awaits 'ip -br addr show arrive0 2>/dev/null | grep -q 10.20.0.3' || true
check "a drop-in written under conf.d reaches it too" \
	"$(has_address arrive0 10.20.0.3)" 1

# ------------------------------------------- 3: an interface it has not seen
#
# A value that moved is one thing; a link netcfgd has never been told about is
# another, and it is what adding a network to a machine actually looks like.

cat > "$work/etc/conf.d/60-second.conf" <<'CONF'
device arrive1 {
	kind = "dummy"
}
interface arrive1 {
	config = "10.21.0.1/24"
}
CONF

awaits 'ip -br addr show arrive1 2>/dev/null | grep -q 10.21.0.1' || true
check "an interface that did not exist when the daemon started is created" \
	"$(has_address arrive1 10.21.0.1)" 1

# ------------------------------------- 4: a drop-in that does not compile
#
# **The remaining candidate for 10.307, and the reason this section exists.**
# Everything above passes, so "a written file is never noticed" is refuted for
# the ordinary case. What is left is a file that IS noticed and cannot be used:
# one bad drop-in fails the whole load, netcfgd keeps the configuration it has,
# and the machine sits exactly as it did -- which is what fifty-two minutes of
# nothing looks like from outside.
#
# `ncfg show` refuses such a directory in one sentence naming both files and
# the line. The question is whether the DAEMON says anything at all.

cat > "$work/etc/conf.d/70-broken.conf" <<'CONF'
interface arrive0 {
	mtu = "this is not a number"
CONF

awaits 'grep -q "does not compile" "$work/daemon.log"' || true
check "a configuration it cannot compile is said out loud" \
	"$(grep -c 'does not compile' "$work/daemon.log" || true)" 1
check "naming the file and the line, which is what a person acts on" \
	"$(grep -c '70-broken' "$work/daemon.log" || true)" 1

# **Said once.** The watch fires per write and a broken file stays broken, so
# without the de-duplication this is a line per pass for as long as somebody
# takes to fix it -- which is `drift.sh`'s storm in the one place an operator
# is already having a bad time.
touch "$work/etc/netcfgd.conf"
sleep 1
touch "$work/etc/netcfgd.conf"
sleep 1
check "and said once, not on every pass while the file stays broken" \
	"$(grep -c 'does not compile' "$work/daemon.log" || true)" 1

# And the machine is left as it was rather than half-changed, which is the
# half that already worked and is worth pinning while the other is here.
check "and the machine keeps the configuration that did compile" \
	"$(has_address arrive0 10.20.0.3)" 1

# **And recovery, which nothing else would ever mention.** An operator told the
# configuration is broken has to be told when it is not, or the only way to
# find out is to try something.
rm -f "$work/etc/conf.d/70-broken.conf"
awaits 'grep -q "compiles again" "$work/daemon.log"' || true
check "and says so when it compiles again" \
	"$(grep -c 'compiles again' "$work/daemon.log" || true)" 1
check "and the configuration that was waiting is applied" \
	"$(has_address arrive1 10.21.0.1)" 1

# ----------------------------------------------------------------- and quiet
#
# Whatever the three above did, a daemon that applied them should not also be
# complaining that the machine does not match -- 10.330's warning firing here
# would mean netcfgd could see the work and declined it, which is the other way
# this could fail.

check "and it never warned that the machine does not match" \
	"$(grep -c 'does not match its configuration' "$work/daemon.log" || true)" 0

if [ "$failures" -eq 0 ]; then
	echo "$name: $checks check(s), all passed"
else
	echo "$name: $failures of $checks check(s) failed"
	echo "--- the daemon's log ---"
	cat "$work/daemon.log"
	exit 1
fi
