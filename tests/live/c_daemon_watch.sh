#!/bin/sh
# What `c_daemon_tryout.sh` does when the network goes, proved against stubs.
#
#     sh tests/live/c_daemon_watch.sh
#
# ## Why this exists
#
# That script is a safety net, and a safety net nobody has dropped anything
# into is a claim. What it promises is narrow and checkable: when the network
# stops answering it stops the C daemon, starts the Rust one, and says so --
# and when the network is fine it does none of that. Both halves are decisions
# made from the output of `ping`, `getent` and `systemctl`, so both can be
# driven by putting this test's own versions of those three in front.
#
# ## What it touches
#
# Nothing. `systemctl`, `ping` and `getent` are shell scripts in a directory
# this test made, first on `PATH`; the daemon is another one, named through
# `NCFG_TRYOUT_DAEMON`; and the machine's own network is not read, because the
# stub `ip` answers with a gateway that does not exist. **It needs root only
# because the script it drives refuses without it** -- and it refuses for a
# reason that has nothing to do with this: it stops a service.
set -eu

name=c_daemon_watch.sh
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
failures=0
checks=0

check() {
	checks=$((checks + 1))
	if [ "$1" = 0 ]; then
		printf '%-64s ok\n' "$2"
	else
		printf '%-64s FAILED\n' "$2"
		failures=$((failures + 1))
	fi
}

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "$name: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "$name: skipping: $1"
	exit 0
}

[ "$(id -u)" = 0 ] || skip "not root, and the script under test refuses without it"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-watch.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/bin"

# The state the stubs keep between calls: whether the network answers, and what
# `systemctl` was asked to do. Files rather than variables, because each stub
# is its own process.
echo up > "$work/net"
: > "$work/systemctl.log"

cat > "$work/bin/ping" <<'STUB'
#!/bin/sh
[ "$(cat "$NCFG_WATCH_WORK/net")" = up ]
STUB

cat > "$work/bin/getent" <<'STUB'
#!/bin/sh
[ "$(cat "$NCFG_WATCH_WORK/net")" = up ]
STUB

cat > "$work/bin/systemctl" <<'STUB'
#!/bin/sh
echo "$*" >> "$NCFG_WATCH_WORK/systemctl.log"
case "$1" in
is-active) cat "$NCFG_WATCH_WORK/active" ;;
stop)      echo down > "$NCFG_WATCH_WORK/active" ;;
start)     echo active > "$NCFG_WATCH_WORK/active"
           # Starting the Rust daemon is what brings the network back, which
           # is the whole point of the fallback -- so the stub says so.
           echo up > "$NCFG_WATCH_WORK/net" ;;
esac
exit 0
STUB

# A gateway on a network nobody has, so a stub that leaked would fail rather
# than quietly read the machine's own route.
cat > "$work/bin/ip" <<'STUB'
#!/bin/sh
echo "default via 192.0.2.1 dev tryout0 proto static metric 1"
STUB

# A daemon that does nothing and stays up until it is signalled, which is every
# property the script under test cares about.
cat > "$work/bin/fake-netcfgd" <<'STUB'
#!/bin/sh
echo "fake netcfgd: $*"
# Bounded: if the script under test fails to stop it, it goes on its own rather
# than outliving the test.
sleep 120
STUB

chmod +x "$work/bin/"*
echo active > "$work/active"

export NCFG_WATCH_WORK="$work"
export NCFG_TRYOUT_DAEMON="$work/bin/fake-netcfgd"
export PATH="$work/bin:$PATH"

# ---------------------------------------------------------------- the network
# stays up: the tryout runs its course and hands back at the deadline, having
# stopped the service once and started it once.

say_out="$work/up.out"
if sh "$repo/tests/live/c_daemon_tryout.sh" --interval 1 --failures 2 --minutes 0 \
    >"$say_out" 2>&1; then
	:
fi
check 0 "a tryout with the network up runs and returns"
grep -q "stopping netcfgd.service" "$say_out" && check 0 "  it stopped the Rust daemon" ||
	check 1 "  it stopped the Rust daemon"
grep -q "the C daemon is running" "$say_out" && check 0 "  and started the C one" ||
	check 1 "  and started the C one"
grep -q "starting the Rust daemon again" "$say_out" &&
	check 0 "  and handed the machine back when the time was up" ||
	check 1 "  and handed the machine back when the time was up"
grep -q "^stop netcfgd$" "$work/systemctl.log" && check 0 "  through systemctl stop" ||
	check 1 "  through systemctl stop"
grep -q "^start netcfgd$" "$work/systemctl.log" && check 0 "  and systemctl start" ||
	check 1 "  and systemctl start"
grep -q "no network" "$say_out" && check 1 "  and never said the network was gone" ||
	check 0 "  and never said the network was gone"

# ------------------------------------------------------------ the network goes
# away while the C daemon holds the machine. Two misses and it hands back --
# and the fallback is what makes the network answer again.

echo active > "$work/active"
: > "$work/systemctl.log"
down_out="$work/down.out"
( sleep 2; echo down > "$work/net" ) &
dropper=$!
sh "$repo/tests/live/c_daemon_tryout.sh" --interval 1 --failures 2 --minutes 1 \
    >"$down_out" 2>&1 && code=0 || code=$?
wait "$dropper" 2>/dev/null || true

check "$( [ "$code" = 1 ] && echo 0 || echo 1 )" \
	"a tryout whose network goes away leaves with 1"
grep -q "no network (2 of 2)" "$down_out" &&
	check 0 "  having counted the misses it was told to allow" ||
	check 1 "  having counted the misses it was told to allow"
grep -q "handing the machine back" "$down_out" && check 0 "  and said so" ||
	check 1 "  and said so"
grep -q "^start netcfgd$" "$work/systemctl.log" &&
	check 0 "  and started the Rust daemon, which is the fallback" ||
	check 1 "  and started the Rust daemon, which is the fallback"
grep -q "is back and steady after" "$down_out" &&
	check 0 "  and waited for the network rather than claiming it was back" ||
	check 1 "  and waited for the network rather than claiming it was back"

# And the one thing a fallback must never do: leave the C daemon running.
if pgrep -f "fake-netcfgd" >/dev/null 2>&1; then
	check 1 "  with nothing of the C daemon left running"
	pkill -f "fake-netcfgd" 2>/dev/null || true
else
	check 0 "  with nothing of the C daemon left running"
fi

# ------------------------------------------------- the network that comes back
# and goes again. This is the machine's own behaviour, measured: the Rust
# daemon adopts the supplicant it finds and then re-hands it its networks,
# which disconnects and re-associates -- so for about eight seconds after
# `systemctl start netcfgd` returns there is no default route. A handback that
# asked once, straight away, answered "came back after 0s" into that window.
#
# The stub `systemctl start` here says the network is up, and a second later
# takes it away for four -- which is the shape of that, in miniature.

echo active > "$work/active"
echo down > "$work/net"
: > "$work/systemctl.log"
cat > "$work/bin/systemctl" <<'STUB'
#!/bin/sh
echo "$*" >> "$NCFG_WATCH_WORK/systemctl.log"
case "$1" in
is-active) cat "$NCFG_WATCH_WORK/active" ;;
stop)      echo down > "$NCFG_WATCH_WORK/active" ;;
start)     echo active > "$NCFG_WATCH_WORK/active"
           echo up > "$NCFG_WATCH_WORK/net"
           # The restart takes the association down a moment after it returns,
           # and brings it back four seconds later.
           ( sleep 1; echo down > "$NCFG_WATCH_WORK/net"
             sleep 4; echo up > "$NCFG_WATCH_WORK/net" ) & ;;
esac
exit 0
STUB
chmod +x "$work/bin/systemctl"
echo up > "$work/net"

flap_out="$work/flap.out"
( sleep 2; echo down > "$work/net" ) &
dropper=$!
sh "$repo/tests/live/c_daemon_tryout.sh" --interval 1 --failures 2 --minutes 1 \
    >"$flap_out" 2>&1 && code=0 || code=$?
wait "$dropper" 2>/dev/null || true

check "$( [ "$code" = 1 ] && echo 0 || echo 1 )" \
	"a handback whose network flaps still leaves with 1"
steady=$(sed -n 's/.*is back and steady after \([0-9]*\)s.*/\1/p' "$flap_out")
check "$( [ -n "$steady" ] && echo 0 || echo 1 )" \
	"  and reports the network back only once it is steady"
check "$( [ -n "$steady" ] && [ "$steady" -ge 5 ] && echo 0 || echo 1 )" \
	"  which is after the flap, not in the window before it ($steady s)"

# Put the plain stub back for the case below.
cat > "$work/bin/systemctl" <<'STUB'
#!/bin/sh
echo "$*" >> "$NCFG_WATCH_WORK/systemctl.log"
case "$1" in
is-active) cat "$NCFG_WATCH_WORK/active" ;;
stop)      echo down > "$NCFG_WATCH_WORK/active" ;;
start)     echo active > "$NCFG_WATCH_WORK/active"
           echo up > "$NCFG_WATCH_WORK/net" ;;
esac
exit 0
STUB
chmod +x "$work/bin/systemctl"

# ------------------------------------------------------- a network already down
# is not a tryout: it would stop the working daemon to start an experiment on a
# machine that is already broken.

echo active > "$work/active"
echo down > "$work/net"
: > "$work/systemctl.log"
sh "$repo/tests/live/c_daemon_tryout.sh" --interval 1 --failures 2 --minutes 1 \
    >"$work/refuse.out" 2>&1 && code=0 || code=$?
check "$( [ "$code" = 1 ] && echo 0 || echo 1 )" \
	"a tryout refuses to start when the network is already down"
grep -q "fix that first" "$work/refuse.out" && check 0 "  and says why" ||
	check 1 "  and says why"
grep -q "^stop netcfgd$" "$work/systemctl.log" &&
	check 1 "  without having stopped anything" ||
	check 0 "  without having stopped anything"

echo "$name: $checks checks, $failures failed"
[ "$failures" = 0 ]
