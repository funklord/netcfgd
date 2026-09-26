#!/bin/sh
# Every message carries a severity and a subsystem, and a level can turn them down.
#
#     sh tests/live/log_shape.sh
#
# WHY THIS EXISTS
#   netcfgd's output was fifty `eprintln!("netcfgd: ...")` calls: one stream,
#   no severity, no subsystem, and no way to ask for less. Measured on the
#   reporting machine the same day this was written, an adoption line printed
#   every five seconds for twenty minutes -- ordinary, correct, and
#   indistinguishable at a glance from the failure causing it.
#
#   The shape is `flog`'s, the C logging library two of the sibling projects
#   share: `[subsystem] Label: text`, with `Critical`, `Error`, `Warning`, `!`
#   for a note, and no label at all for the ordinary levels. Decision 0187.
#
# WHAT IT DRIVES
#   A real daemon, three times: at the default level, turned down, and told a
#   level that does not exist.
#
# WHAT IT DELIBERATELY DOES NOT COVER
#   Which severity each of the fifty messages carries. That is a judgement per
#   message and it is made where the message is; a test that pinned all fifty
#   would be a copy of the source with a worse diff.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/target/debug}"
export build

# **The C port's reconcile loop runs by default now** (0265), so this probe
# finds nothing and `daemon_flags` stays empty. It is kept rather than deleted
# because it is asked of the binary rather than inferred from the path: a build
# from before that decision still needs the flag, and one that never had it --
# the Rust daemon, which would refuse the option -- is left exactly as it was.
# The probe is dead weight the day nobody builds such a daemon any more.
daemon_flags=
if "$build/netcfgd" --help 2>&1 | grep -q -- '--try-the-c-daemon'; then
	daemon_flags=--try-the-c-daemon
fi
export daemon_flags

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "log_shape.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "log_shape.sh: skipping: $1"
	exit 0
}

[ -x "$build/netcfgd" ] || skip "netcfgd is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-log.XXXXXX")
daemon=
cleanup() {
	if [ -n "$daemon" ]; then
		kill "$daemon" 2>/dev/null || true
		wait "$daemon" 2>/dev/null || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_RESOLV_CONF="$work/resolv.conf"

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

printf 'global { control { observe = "any" } }\n' > "$work/etc/netcfgd.conf"

# One daemon, started, given a moment to say what it says at startup, stopped.
say() {
	rm -f "$work/run/netcfgd.sock"
	if [ -n "${1:-}" ]; then
		NCFG_LOG="$1" "$build/netcfgd" $daemon_flags > "$work/said" 2>&1 &
	else
		"$build/netcfgd" $daemon_flags > "$work/said" 2>&1 &
	fi
	daemon=$!
	waited=0
	while [ ! -S "$work/run/netcfgd.sock" ] && [ "$waited" -lt 60 ]; do
		waited=$((waited + 1))
		sleep 0.1
	done
	sleep 1
	kill "$daemon" 2>/dev/null || true
	wait "$daemon" 2>/dev/null || true
	daemon=
	cat "$work/said"
}

# ---------------------------------------------------------- the default level

said=$(say)
contains "an ordinary message names its subsystem" "$said" "[config]"
contains "and reads as a sentence, with no label in front of it" \
	"$said" "[config] watching"
# flog prints `!` for a note and nothing for info, which is the distinction
# this whole shape exists to make visible at a glance.
contains "a note is marked, and marked the way flog marks one" "$said" "[confirm] !:"

# ------------------------------------------------------------ turned down

# `warning` accepts critical, error and warning -- and this startup emits an
# info and a note, so a correct filter leaves nothing at all.
#
# **Counting every line rather than every log line, and that is the stronger
# check.** It went the other way for a few hours: the C port used to print a
# safety notice about `--try-the-c-daemon` that no level could filter, this
# counted it, and the check was rewritten to count only lines carrying a
# `[subsystem]` tag. 0265 removed the notice with the gate it was about, so the
# reason for that rewrite is gone -- and the stricter form also catches output
# that is not a log line at all, which the narrower one waved through. Reverted
# rather than kept: a change whose cause has been removed is not made right by
# an argument found for it afterwards.
said=$(say warning)
check "a level below what is emitted silences it completely" \
	"$(printf '%s' "$said" | grep -c .)" "0"

# The control, and it is the one that matters: silence is also what a daemon
# that failed to start produces, so the level has to be shown letting the same
# messages through again.
said=$(say info)
contains "and the same run says it again at the level that takes it" \
	"$said" "[config] watching"

# ------------------------------------------------- a level that is not one

# The house rule, applied to the log's own input: a setting nobody can act on
# must not be silently ignored.
said=$(say shouting)
contains "a level that does not exist is refused out loud" "$said" "not a level"
contains "and the message says which level still applies" "$said" "info"
contains "and lists the ones that would have worked" "$said" "critical, error, warning"
contains "and the daemon carries on rather than refusing to start" \
	"$said" "[config] watching"

if [ "$failures" -eq 0 ]; then
	echo "log_shape.sh: all checks passed"
else
	echo "log_shape.sh: $failures check(s) failed"
	exit 1
fi
