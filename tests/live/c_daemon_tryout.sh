#!/bin/sh
# Run the C port's daemon on this machine, with something watching that can
# hand the machine back.
#
#     sudo sh tests/live/c_daemon_tryout.sh            # 15 minutes, then back
#     sudo sh tests/live/c_daemon_tryout.sh --dry-run  # say it, do none of it
#
# ## What this is for
#
# `netcfgd --try-the-c-daemon` is the only way this build's reconcile loop
# runs, and `daemon_main.c` says why the default is a refusal: no netcfgd
# written in C has run a machine, and a loop is the one part of the program
# that acts with nobody at the keyboard. This is the "somebody watching" that
# refusal asks for. It is not a test in the `make check` sense -- it proves
# nothing on its own -- it is the arrangement that makes the evidence
# collectable without the machine being the thing that pays for it.
#
# ## What it does to the machine, and what it undoes
#
# In order, and each step is undone by `restore` however this ends -- the
# deadline, Ctrl-C, a lost network, or the C daemon exiting on its own:
#
#   1. records whether `netcfgd.service` is running, so the state to go back
#      to is what was here rather than what this script assumes;
#   2. stops it. **wpa_supplicant and dhcpcd keep running**: the unit is
#      `KillMode=process`, deliberately (0134, 0142), and that is what makes
#      this survivable -- the association is not netcfgd's to hold;
#   3. starts the C daemon with `--no-apply-on-start`, so it observes,
#      adopts what is already running, and changes nothing until asked;
#   4. watches the network. Every INTERVAL seconds it pings the default
#      gateway and resolves a name; FAILURES consecutive misses and it falls
#      back;
#   5. falls back: SIGTERM to the C daemon, `systemctl start netcfgd`, and
#      waits for the network to come back -- reporting how long that took,
#      which is the number worth knowing.
#
# **`/run/netcfgd` is wiped when the unit stops** (`RuntimeDirectoryPreserve=
# restart` keeps it across a restart and not across a stop), so the C daemon
# starts with no ownership record and no supplicant pid file. That is the case
# `ncfg_supplicant_adopt` exists for: the surviving supplicant still carries
# `-P /run/netcfgd/supplicant/<iface>.pid` in its own argv and still answers on
# its control socket, so the C daemon finds it by that marker and adopts it
# rather than starting a second one. Two supplicants on one radio drop the
# association, which is the failure this whole arrangement is arranged around.
#
# ## What it does not do
#
# It does not switch networks, apply anything, or edit the configuration. That
# is the operator's to type once this is running -- `ncfg wifi connect`,
# `ncfg apply`, `ncfg plan` -- and this is what is underneath when they do.
set -eu

name=c_daemon_tryout.sh
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

# How long between checks, how many misses before handing back, and how long
# the whole tryout lasts. Every loop in this script is bounded by one of them:
# a supervisor that can run for ever is the thing it is supposed to prevent.
interval=5
failures=3
minutes=15
dry_run=

while [ $# -gt 0 ]; do
	case "$1" in
	--dry-run) dry_run=yes ;;
	--interval) interval=${2:?--interval needs a value}; shift ;;
	--failures) failures=${2:?--failures needs a value}; shift ;;
	--minutes) minutes=${2:?--minutes needs a value}; shift ;;
	-h|--help) sed -n '2,12p' "$0"; exit 0 ;;
	*) echo "$name: unknown argument \`$1'" >&2; exit 2 ;;
	esac
	shift
done

say() { echo "$name: $*"; }
die() { echo "$name: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "this has to run as root: it stops and starts a daemon"

# **The daemon is a parameter, which is this project's rule for every program
# it starts** -- `backend_internal.h` records what its absence cost elsewhere:
# a check that meant to drive a stand-in reached the machine's real daemon and
# proved nothing. Here it is what lets `c_daemon_watch.sh` drive this script's
# decisions without a netcfgd of any kind.
daemon=${NCFG_TRYOUT_DAEMON:-$repo/c/netcfgd}
[ -x "$daemon" ] || die "the C daemon is not built -- run make -C c"
command -v systemctl >/dev/null 2>&1 || die "no systemctl; this script knows only systemd"

# The gateway to ping and the name to resolve, read once from the machine as it
# is *now* -- before anything is stopped. Reading them later would read them
# from whatever state the tryout had reached, which is the state under test.
gateway=$(ip route show default 2>/dev/null | awk '/default/ {print $3; exit}')
[ -n "$gateway" ] || die "this machine has no default route, so there is nothing to watch"
resolve=${NCFG_TRYOUT_NAME:-deb.debian.org}
device=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')

say "watching $gateway via ${device:-?}, resolving $resolve"
say "checks every ${interval}s, handing back after $failures misses, for $minutes minutes"

# ------------------------------------------------------------------- the net

reachable() {
	ping -c 1 -W 2 -n "$gateway" >/dev/null 2>&1 || return 1
	# A name, because a gateway that answers on a link carrying nothing else
	# is exactly the half-up state a ping alone calls healthy.
	getent hosts "$resolve" >/dev/null 2>&1 || return 1
	return 0
}

# Wait for the network, bounded. Answers 0 when it came back, 1 when it did
# not -- and the caller says so rather than looping again.
wait_for_net() {
	waited=0
	while [ "$waited" -lt "${1:-60}" ]; do
		if reachable; then
			echo "$waited"
			return 0
		fi
		sleep 2
		waited=$((waited + 2))
	done
	echo "$waited"
	return 1
}

# --------------------------------------------------------------- the daemons

was_active=
c_pid=
restored=

restore() {
	# Idempotent: it is the exit trap and the fallback both, and either may
	# have run first.
	[ -z "$restored" ] || return 0
	restored=yes
	if [ -n "$c_pid" ] && kill -0 "$c_pid" 2>/dev/null; then
		say "stopping the C daemon (pid $c_pid)"
		kill -TERM "$c_pid" 2>/dev/null || true
		# Bounded, then SIGKILL: a daemon that will not stop must not keep the
		# machine while this script waits for it.
		waited=0
		while [ "$waited" -lt 10 ] && kill -0 "$c_pid" 2>/dev/null; do
			sleep 1
			waited=$((waited + 1))
		done
		kill -KILL "$c_pid" 2>/dev/null || true
	fi
	if [ "$was_active" = active ]; then
		say "starting the Rust daemon again"
		systemctl start netcfgd || say "WARNING: systemctl start netcfgd failed"
		if took=$(wait_for_net 60); then
			say "the network came back after ${took}s"
		else
			say "WARNING: the network is still down after ${took}s -- look at it"
		fi
	else
		say "netcfgd.service was not running before this, so it is left stopped"
	fi
}

trap 'restore' EXIT INT TERM

was_active=$(systemctl is-active netcfgd 2>/dev/null || true)
say "netcfgd.service is currently: ${was_active:-unknown}"

if ! reachable; then
	die "the network is already down by this script's own test; fix that first"
fi

if [ -n "$dry_run" ]; then
	say "--dry-run: would stop netcfgd.service, start"
	say "  $daemon --try-the-c-daemon --no-apply-on-start"
	say "  and watch $gateway plus $resolve, handing back on $failures misses"
	restored=yes   # nothing was changed, so there is nothing to put back
	exit 0
fi

say "stopping netcfgd.service (the supplicant and the client keep running)"
systemctl stop netcfgd

log=${TMPDIR:-/tmp}/netcfgd-c-tryout.log
say "starting the C daemon, log in $log"
"$daemon" --try-the-c-daemon --no-apply-on-start >>"$log" 2>&1 &
c_pid=$!
sleep 2
if ! kill -0 "$c_pid" 2>/dev/null; then
	say "the C daemon exited immediately; the last of $log:"
	tail -5 "$log" >&2 || true
	exit 1
fi
say "the C daemon is running as pid $c_pid"
say "it applies nothing until asked: try \`ncfg status\`, \`ncfg plan\`,"
say "  \`ncfg wifi status\`, and then \`ncfg wifi connect <ssid>\` to switch"
say "Ctrl-C hands the machine back"

# ------------------------------------------------------------------ watching

deadline=$(( $(date +%s) + minutes * 60 ))
missed=0
while [ "$(date +%s)" -lt "$deadline" ]; do
	if ! kill -0 "$c_pid" 2>/dev/null; then
		say "the C daemon exited on its own; handing back"
		tail -5 "$log" >&2 || true
		exit 1
	fi
	if reachable; then
		if [ "$missed" -gt 0 ]; then
			say "the network answered again after $missed miss(es)"
		fi
		missed=0
	else
		missed=$((missed + 1))
		say "no network ($missed of $failures)"
		if [ "$missed" -ge "$failures" ]; then
			say "handing the machine back to the Rust daemon"
			exit 1
		fi
	fi
	sleep "$interval"
done

say "the $minutes minutes are up; handing back"
