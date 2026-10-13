#!/bin/sh
# IPv4 link-local addressing, end to end: `config = "link-local"` to a client
# running on the interface, and back again.
#
#     unshare -rn sh tests/live/link_local.sh
#
# WHY THIS FILE EXISTS
#   `autoip_test.c` drives `ncfg_autoip_start` and `ncfg_autoip_stop` directly
#   and `plan_gaps_test.c` drives the two plan passes, so every part of this is
#   already covered. What neither can ask is whether the parts are WIRED: the
#   tenth backend kind has to reach the plan from the document's addressing, the
#   executor from the plan, and the observation from the machine, and a missing
#   arm in any of the three leaves a build whose unit suite is green and whose
#   `config = "link-local"` does nothing. That is the shape the warning this
#   feature replaced described for two generations, so it is the shape worth
#   checking from outside.
#
# NO DAEMON, AND THE INTERFACE NAME CARRIES THIS RUN'S PID
#   `ncfg apply` is its own executor (`cli_machine.c`), so no daemon is started
#   here and there is nothing to adopt between sections.
#
#   The interface name is `ll<pid>` deliberately. netcfgd identifies its IPv4LL
#   client by two whole arguments -- `--force-bind` and the interface -- and
#   `autoip.h` says plainly that this is the weakest ownership claim of the ten
#   kinds, because unlike every other backend there is no path under this run's
#   own directory in the client's argv to match on. The net namespace makes the
#   interface private but `/proc` is the machine's, so a second copy of this
#   script running at the same time would be looking at a process list
#   containing the other's client. A name nothing else can be using is what
#   makes the two runs independent.
#
# THE STAND-IN, AND WHAT IT HAS TO GET RIGHT
#   `avahi-autoipd -D -w` forks and the parent exits 0 once an address has been
#   acquired, so the stand-in has to daemonise too or `ncfg_backend_run` would
#   read the exit of the only process there was. Its child holds the arguments
#   netcfgd passed in its own command line, because that is what netcfgd looks
#   for -- a child that `exec`ed something else would be invisible to the thing
#   under test.
#
#   It stops on its own: it watches for its own directory going away and gives
#   up after ten minutes regardless. A stand-in that outlives the run is the
#   failure `openvpn.sh`'s header describes finding nine times over.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "link_local.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "link_local.sh: skipping: $1"
	exit 0
}

[ -x "$build/ncfg" ] || skip "ncfg is not built (make -C c)"
[ -x "$build/netcfgd" ] || skip "netcfgd is not built, and --supported is asked of it"
command -v ip >/dev/null 2>&1 || skip "no ip(8), so no dummy interface can be made"
ip link add name "llp$$" type dummy 2>/dev/null || skip "cannot create a link: run under unshare -rn"
ip link del "llp$$" 2>/dev/null || true

iface="ll$$"
work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-link-local.XXXXXX")
fake="$work/bin/avahi-autoipd"

# **Killed by the pid netcfgd recorded, never by a pattern.** The pid file is
# netcfgd's own and is the handle this script is testing the existence of; a
# `pkill -f` on the interface name would reach a client belonging to anything
# else that happens to carry it. Removing `$work` is what stops the stand-in in
# the case where even the pid file is gone, since it watches for that.
cleanup() {
	recorded=$(cat "$work/run/autoip/$iface.pid" 2>/dev/null || true)
	case "$recorded" in
	[0-9]*)
		kill "$recorded" 2>/dev/null || true
		;;
	esac
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

mkdir -p "$work/etc" "$work/run" "$work/bin"
export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
ncfg="$build/ncfg"

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

cat > "$fake" <<'FAKE'
#!/bin/sh
# A stand-in IPv4LL client. See link_local.sh's header for what it has to get
# right; the two halves are daemonising and keeping the arguments.
set -eu
here=$(dirname -- "$0")
if [ "${1:-}" = "--supervise" ]; then
	shift
	# **Bounded twice**: the run directory going away, and ten minutes.
	# Nothing else stops this, so both are written here rather than assumed of
	# whoever started it.
	rounds=0
	while [ -d "$here" ] && [ "$rounds" -lt 300 ]; do
		sleep 2
		rounds=$((rounds + 1))
	done
	exit 0
fi
printf '%s\n' "$*" >> "$here/../invocations"
"$0" --supervise "$@" &
exit 0
FAKE
chmod +x "$fake"
# The seam, not PATH: `backend_run.c` searches /usr/sbin before PATH on
# purpose, so on a machine that has avahi-autoipd installed a stand-in on PATH
# would be ignored and the real client started on a real interface.
export NCFG_AVAHI_AUTOIPD="$fake"

# --------------------------------------------------------------- the taxonomy

check "the daemon answers for a link_local backend at all" \
	"$("$build/netcfgd" --supported 2>/dev/null \
	    | grep -c '"subject":"backend.start","name":"link_local"' || true)" "1"

# ----------------------------------------------------------------- the start

cat > "$work/etc/netcfgd.conf" <<CONF
device $iface { kind = "dummy" }
interface $iface {
	config = "link-local"
}
CONF

"$ncfg" plan > "$work/plan.txt" 2>&1 || true
check "the plan starts a backend for the link-local address" \
	"$(grep -c "backend.start $iface" "$work/plan.txt" || true)" "1"
check "and says nothing about nobody claiming a 169.254 address" \
	"$(grep -c '169.254.0.0/16' "$work/plan.txt" || true)" "0"

"$ncfg" apply > "$work/apply.txt" 2>&1 || true
check "the apply reports the start" \
	"$(grep -c "backend.start $iface" "$work/apply.txt" || true)" "1"
check "  and reports no failure" \
	"$(grep -ci 'error\|failed' "$work/apply.txt" || true)" "0"

check "netcfgd recorded the pid of the client it started" \
	"$([ -f "$work/run/autoip/$iface.pid" ] && echo yes || echo no)" "yes"
pid=$(cat "$work/run/autoip/$iface.pid" 2>/dev/null || echo 0)
check "  and that pid is a process that is running" \
	"$([ -d "/proc/$pid" ] && echo yes || echo no)" "yes"
# The marker netcfgd matches on, read from the machine rather than from
# netcfgd: both arguments, as whole NUL-delimited elements, which is what
# `cmdline_has_argument` requires and what a single string with a space in it
# would not satisfy.
check "  and it carries both of the arguments netcfgd identifies it by" \
	"$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null \
	    | grep -cxE -- "--force-bind|$iface" || true)" "2"

# The four arguments `autoip.h` calls load-bearing, as one line, so a change to
# any of them is one failure naming the whole invocation rather than four.
#
# **This pins the argv; it does not validate it, and the difference matters.**
# The stand-in above accepts anything -- it records its arguments and
# daemonises -- so both sides of this comparison were written in one sitting by
# one hand, which `evidence.md` calls one witness rather than two. The flags
# came from `avahi-autoipd`'s upstream documentation, because it is not
# installed on the machine this was written on and has no local man page
# (project.md 10.479). Only a real client can say they are right.
#
# What makes that an acceptable gap rather than a hidden one is that being
# wrong about a flag cannot be quiet: `ncfg_autoip_start` turns a non-zero exit
# into the client's own complaint lines, and -- the case a careless version
# would miss -- an exit of 0 with no process carrying netcfgd's markers into a
# refusal saying netcfgd has nothing it could stop later. So a wrong flag is a
# failed apply with a reason, not an address nobody claimed.
check "and the client was started with exactly the four arguments that matter" \
	"$(cat "$work/invocations" 2>/dev/null || true)" "-D -w --force-bind $iface"

# ------------------------------------------------- not started a second time

"$ncfg" plan > "$work/plan2.txt" 2>&1 || true
check "a client already running is not started again" \
	"$(grep -c "backend.start $iface" "$work/plan2.txt" || true)" "0"
check "  nor stopped, because the document still asks for the address" \
	"$(grep -c "backend.stop $iface" "$work/plan2.txt" || true)" "0"
"$ncfg" apply > "$work/apply2.txt" 2>&1 || true
check "  and a second apply leaves the same one process, not two" \
	"$(cat "$work/invocations" 2>/dev/null | wc -l | tr -d ' ')" "1"

# **The space after the colon is why this is written loosely.** The first
# version matched `"kind":"link_local"` and counted none: the daemon's JSON is
# pretty-printed, so the text is `"kind": "link_local"`. The check reported a
# defect in the observation where the observation was correct -- confirmed by
# reading `status --json` directly -- which is a fixture that does not reach
# the thing it is asking about.
check "the observation reports the client as running" \
	"$("$ncfg" status --json 2>/dev/null | grep -c '"kind": *"link_local"' || true)" "1"
check "  and says in the same entry that it is running" \
	"$("$ncfg" status --json 2>/dev/null | grep -A2 '"kind": *"link_local"' \
	    | grep -c '"running": *true' || true)" "1"

# -------------------------------------------------------------- and the stop

# The addressing goes and the client goes with it. Without the arm in
# `backend_wanted` this is the check that fails: the default arm answers
# "wanted" for a kind no pass names, so the client would keep a 169.254 address
# nobody had asked for -- and `--force-bind` means it keeps it alongside
# whatever replaced it.
cat > "$work/etc/netcfgd.conf" <<CONF
device $iface { kind = "dummy" }
interface $iface {
	config = "null"
}
CONF

"$ncfg" plan > "$work/plan3.txt" 2>&1 || true
check "an address the document stopped asking for plans a stop" \
	"$(grep -c "backend.stop $iface" "$work/plan3.txt" || true)" "1"
"$ncfg" apply > "$work/apply3.txt" 2>&1 || true
waited=0
while [ -d "/proc/$pid" ] && [ "$waited" -lt 50 ]; do
	sleep 0.1
	waited=$((waited + 1))
done
check "  and the client netcfgd started is gone" \
	"$([ -d "/proc/$pid" ] && echo yes || echo no)" "no"
check "  and the record of it with it" \
	"$([ -f "$work/run/autoip/$iface.pid" ] && echo yes || echo no)" "no"

# ------------------------------------------------- a machine with no client

# The refusal names the path that was looked for. It used to name
# `avahi-autoipd` whichever was asked for, which sends an operator who pointed
# the seam at a path of their own to look at a machine that may well have a
# client installed.
cat > "$work/etc/netcfgd.conf" <<CONF
device $iface { kind = "dummy" }
interface $iface {
	config = "link-local"
}
CONF
NCFG_AVAHI_AUTOIPD="$work/bin/not-installed-here" "$ncfg" apply \
	> "$work/apply4.txt" 2>&1 || true
check "a client that is not installed is refused by the path asked for" \
	"$(grep -c 'not-installed-here' "$work/apply4.txt" || true)" "1"
check "  and nothing was recorded for a client that never started" \
	"$([ -f "$work/run/autoip/$iface.pid" ] && echo yes || echo no)" "no"

if [ "$failures" -eq 0 ]; then
	echo "link_local.sh: all checks passed"
else
	echo "link_local.sh: $failures check(s) failed"
	exit 1
fi
