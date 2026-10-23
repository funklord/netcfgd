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
# **The pattern is this run's own path, and that is the load-bearing half.**
# `pkill -f fake-netcfgd` matches any run's stub, because the stub's name is the
# same in every `$work`; the path is not. A bare name in the cleanup reaches a
# concurrent run's process, and a bare name in the check further down -- the one
# asserting nothing of the C daemon is left running -- reports somebody else's
# stub as this script's failure to stop its own. Both are matched by
# `$work/bin/fake-netcfgd` now, which no other run can be carrying.
#
# **The retry around the removal is the shape nineteen sibling scripts carry**
# (project.md 10.476), and this script was added to `make live` after that pass
# so it never got it. Unlike theirs, the race it guards has NOT been
# demonstrated here, and the honest version of that is worth writing down
# because the comfortable version was written first:
#
#   * `/tmp/ncfg-watch.H0ilKH` was found after a full suite run, 80K, holding
#     four `netcfgd-c-tryout.*.log` files, with this script reporting 26 checks
#     and 0 failures in that same run.
#   * A probe in this cleanup reported **no stub alive** and a work directory
#     of 84K, so nothing was writing when the removal ran. The race is refuted
#     for that run, not confirmed.
#   * Stopping this script mid-run leaves no directory, and so does stopping
#     the suite's own `timeout ... unshare ... sh` invocation of it. A trap
#     skipped by a kill is refuted too.
#
# So what left that directory is unknown, and its mtime -- the one thing that
# would have attributed it to a run -- was destroyed by removing it before the
# question was asked. The retry costs five seconds in the worst case and says
# so when it gives up, which is worth having against an unexplained leak; it is
# not evidence that the leak was this.
cleanup() {
	pkill -f "$work/bin/fake-netcfgd" 2>/dev/null || true
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

# **Every probe the tryout might choose, not just `getent`.** The tryout picks
# the first resolver probe that exists -- `getent`, then `nslookup`, then
# `host` -- because musl has no `getent` at all. Stubbing only `getent` left
# the real busybox `nslookup` in the path on Alpine, which cannot resolve
# inside `unshare -rn`, so the network read as down for every look and nine of
# this script's checks failed about a network that was up. A stub per name, so
# the fixture covers the choice rather than one branch of it.
for probe in getent nslookup host; do
	cat > "$work/bin/$probe" <<'STUB'
#!/bin/sh
[ "$(cat "$NCFG_WATCH_WORK/net")" = up ]
STUB
done

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

# **The tryout's log goes in this test's directory, not in `/tmp`.** It names
# its log with `mktemp` under `$TMPDIR`, one per run -- so without this the
# fake daemon's output landed beside the real runs' evidence and stayed there:
# nine stray `netcfgd-c-tryout.*.log` files after one afternoon, each 53 bytes
# of stub.
export TMPDIR="$work"
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
# Matched by the full path for the trap's reason: a bare `fake-netcfgd` would
# report another run's stub as this one's failure to stop its own.
if pgrep -f "$work/bin/fake-netcfgd" >/dev/null 2>&1; then
	check 1 "  with nothing of the C daemon left running"
	pkill -f "$work/bin/fake-netcfgd" 2>/dev/null || true
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

# ----------------------------------------------------------- a switch, rehearsed
# What `ncfg wifi connect <ssid>` does to this supervisor. A switch takes the
# association down **on purpose** and the new one takes seconds to come up --
# EAP is a full handshake and a lease follows it -- so the network is gone for
# longer than an accident would take, and the supervisor must be told to
# expect that rather than treating it as the failure it looks like.
#
# Measured on the machine this was written for: an association re-established
# in about 3s and a default route back 8s after that. So the default of three
# misses at five seconds -- fifteen seconds -- is inside the window a switch
# can take, and `--failures 6` is what the tryout's own hint says to use.
#
# Both halves are checked here: the default hands back during a switch, and
# the longer count rides it out. Neither is a bug; which one is wanted is the
# operator's, and what matters is that the difference is real rather than
# hoped for.

rehearse_switch() {
	# $1 how many misses to allow, $2 how long the switch takes, $3 the file
	echo active > "$work/active"
	echo up > "$work/net"
	: > "$work/systemctl.log"
	( sleep 2; echo down > "$work/net"; sleep "$2"; echo up > "$work/net" ) &
	switcher=$!
	sh "$repo/tests/live/c_daemon_tryout.sh" --interval 1 --failures "$1" --minutes 1 \
	    >"$3" 2>&1 && switch_code=0 || switch_code=$?
	wait "$switcher" 2>/dev/null || true
}

rehearse_switch 2 6 "$work/switch-short.out"
check "$( [ "$switch_code" = 1 ] && echo 0 || echo 1 )" \
	"a switch longer than the misses allowed hands the machine back"
grep -q "handing the machine back" "$work/switch-short.out" &&
	check 0 "  which is the supervisor doing what it was told" ||
	check 1 "  which is the supervisor doing what it was told"

rehearse_switch 10 6 "$work/switch-long.out"
check "$( [ "$switch_code" = 0 ] && echo 0 || echo 1 )" \
	"and the same switch with misses enough to cover it is ridden out"
grep -q "no network" "$work/switch-long.out" &&
	check 0 "  having noticed the association go, rather than not looking" ||
	check 1 "  having noticed the association go, rather than not looking"
grep -q "the network answered again after" "$work/switch-long.out" &&
	check 0 "  and said when it came back, which is the switch completing" ||
	check 1 "  and said when it came back, which is the switch completing"
grep -q "handing the machine back to the Rust daemon" "$work/switch-long.out" &&
	check 1 "  without handing anything back" ||
	check 0 "  without handing anything back"
# And the C daemon is still the one holding the machine at the end of it.
grep -q "the .* minutes are up; handing back" "$work/switch-long.out" &&
	check 0 "  the tryout ran to its own deadline with the daemon still up" ||
	check 1 "  the tryout ran to its own deadline with the daemon still up"

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
