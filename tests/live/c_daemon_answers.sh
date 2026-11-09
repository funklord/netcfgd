#!/bin/sh
# Every request the command line makes, against a running daemon with no node.
#
#     unshare -rn sh tests/live/c_daemon_answers.sh
#
# `tool/ledger_gate.py` says the request taxonomy is whole. It says nothing
# about the **answers**: whether each verb reaches the daemon over its socket,
# gets something back, and leaves the daemon standing for the next one.
#
# Until 0317 this asked the C daemon and the Rust one the same questions and
# compared the answers byte for byte, one client against two daemons so that a
# difference was the daemon's. That comparison is what it was for, and it went
# with the Rust. What is left is the half that needs one daemon: each verb is
# answered, a writing verb leaves the file it had to write, and the daemon is
# still there at the end.
#
# WHY NOTHING HERE APPLIES
#   The comparison learned it: `hook_state` disagreed between the two daemons
#   while a third process applied, because the drift pass observes without the
#   apply lock -- deliberately, "a pass that only observes never takes it" --
#   and so reports whichever instant it sampled. Nothing here moves the
#   machine underneath a question.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "c_daemon_answers.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "c_daemon_answers.sh: skipping: $1"
	exit 0
}

[ -x "$repo/c/netcfgd" ] || skip "the C daemon is not built (make -C c)"
[ -x "$repo/c/ncfg" ] || skip "the C ncfg is not built, and it is the client"
# **Runnable, not merely present.** `[ -x ]` answers "is there an executable
# file", which is not "can this machine run it" -- and the two differ wherever
# the libc the binary was linked against is not the one installed. Measured on
# Alpine 2026-10-23: this tree's glibc `netcfgd` is `-x` there, and running it gets
# `not found` from the shell, because the ELF interpreter it names is absent.
# So the skip never fired, and a comparison binary that could not run reported
# as a missing file several checks later.
"$repo/c/netcfgd" --version >/dev/null 2>&1 || skip "the C daemon will not run here (a glibc build on musl)"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-c-daemon-answers.XXXXXX")
c_pid=""
cleanup() {
	[ -n "$c_pid" ] && kill "$c_pid" 2>/dev/null || true
	# **Waited for, not just signalled**: `kill` returns before the child has
	# stopped writing, and the `rm` below then races it (project.md 10.476).
	[ -n "$c_pid" ] && wait "$c_pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

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

# A document with nothing in it that needs hardware: an interface that does not
# exist, which is a state the daemon can describe without creating anything.
document() {
	cat <<'CONF'
device dd0 { kind = "dummy" }
interface dd0 {
	config = "10.9.120.1/24"
	routes = ["10.9.121.0/24 via 10.9.120.2 metric 100"]
}
CONF
}

# Wait for a socket, bounded. A daemon that never binds is a failure with its
# log, not a hang.
bound() {
	waited=0
	while [ "$waited" -lt 100 ]; do
		[ -S "$1" ] && return 0
		sleep 0.1
		waited=$((waited + 1))
	done
	return 1
}

# ---------------------------------------------------------------- reading

mkdir -p "$work/etc" "$work/run"
document > "$work/etc/netcfgd.conf"
export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"

# No node, so the daemon binds its own socket and this asks over it.
"$repo/c/netcfgd" --fuzznet-dir "" --no-apply-on-start > "$work/daemon.log" 2>&1 &
c_pid=$!
if ! bound "$work/run/netcfgd.sock"; then
	echo "FAIL the daemon never bound its socket"
	tail -3 "$work/daemon.log" | sed 's/^/       /'
	exit 1
fi
echo "ok   the daemon binds a socket"

ask() {
	timeout 30 "$repo/c/ncfg" "$@" 2>&1 || true
}

# Each of these reaches the daemon and each says something: an answer, or a
# refusal with a reason. Ten characters is short enough for the shortest real
# answer and long enough that an empty one, or a bare `ncfg:`, fails.
for verb in \
	"status --json" "show --json" "plan --json" "status" "plan" \
	"explain interface dd0" "explain address dd0 10.9.120.1/24" \
	"wifi status" "wifi scan" "wifi clients" "modem status" \
	"control show" "profile get" "profile list" \
	"confirm" "revert" "reload" \
	"config rm nothing" "wifi forget nothing"
do
	# shellcheck disable=SC2086
	said=$(ask $verb)
	if [ "${#said}" -lt 10 ]; then
		echo "FAIL \`ncfg $verb\`: the answer is too short to be one"
		printf '%s\n' "$said" | head -2 | sed 's/^/       /'
		failures=$((failures + 1))
		continue
	fi
	echo "ok   \`ncfg $verb\` is answered"
done
# **Answered is not reached.** Most of these verbs work with no daemon at all
# -- the client observes and compiles for itself -- so the loop above cannot
# tell a daemon that answered from one that was never asked. A reload is the
# daemon's alone, and so is the word for it.
check "and a reload is the daemon's" "$(ask reload | grep -c '^reloaded' || true)" "1"
check "and the daemon is still running after all of them" \
	"$(tr '\0' ' ' < "/proc/$c_pid/cmdline" 2>/dev/null | grep -c netcfgd || true)" "1"

kill "$c_pid" 2>/dev/null || true
wait "$c_pid" 2>/dev/null || true
c_pid=""

# ----------------------------------------------------------------- writing

# A configuration directory of its own, so that what is found afterwards is
# what these verbs wrote and nothing the reading pass left.
mkdir -p "$work/w/etc/secrets" "$work/w/run"
document > "$work/w/etc/netcfgd.conf"
export NCFG_CONFIG_DIR="$work/w/etc"
export NCFG_RUN_DIR="$work/w/run"
"$repo/c/netcfgd" --fuzznet-dir "" --no-apply-on-start > "$work/w/daemon.log" 2>&1 &
c_pid=$!
if ! bound "$work/w/run/netcfgd.sock"; then
	echo "FAIL the daemon never bound its socket for the writing pass"
	tail -3 "$work/w/daemon.log" | sed 's/^/       /'
	exit 1
fi
{
	printf 'device extra0 { kind = "dummy" }\n' | ask config put extra
	ask config rm extra
	printf 'device extra0 { kind = "dummy" }\n' | ask config put extra
	printf 'hunter2hunter2' | ask secret set dd-secret
	ask wifi add TestNet --open
	ask profile save saved
	ask profile list
} > "$work/w/answers" 2>&1

# Named rather than counted: each is the file one of the verbs above had to
# write -- the drop-in from `config put`, the credential from `secret set`,
# and the profile from `profile save` with the selection drop-in that choosing
# it leaves.
for wanted in conf.d/extra.conf secrets/dd-secret profile/saved/00-saved.conf \
	conf.d/90-profile.conf
do
	check "\`$wanted\` was written" \
		"$([ -f "$work/w/etc/$wanted" ] && echo yes || echo no)" "yes"
done
check "  and the credential is the one that was given" \
	"$(cat "$work/w/etc/secrets/dd-secret" 2>/dev/null)" "hunter2hunter2"
check "  in a file nobody else can read" \
	"$(stat -c '%a' "$work/w/etc/secrets/dd-secret" 2>/dev/null)" "600"
check "  and the drop-in says what was put" \
	"$(cat "$work/w/etc/conf.d/extra.conf" 2>/dev/null)" 'device extra0 { kind = "dummy" }'
# The configuration is root's here, so `wifi add` goes through the daemon
# rather than straight to a file, and says so. (Both daemons refused it with
# "is not a radio on this machine" while the comparison ran; adding a network
# no longer needs the radio present.)
check "\`wifi add\` went through the daemon" \
	"$(grep -c "added \`TestNet\` through netcfgd" "$work/w/answers" || true)" "1"
check "  and left its drop-in" \
	"$([ -f "$work/w/etc/conf.d/wifi-TestNet.conf" ] && echo yes || echo no)" "yes"

if [ "$failures" -eq 0 ]; then
	echo "c_daemon_answers.sh: all checks passed"
else
	echo "c_daemon_answers.sh: $failures check(s) failed"
	exit 1
fi
