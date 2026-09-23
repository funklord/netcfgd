#!/bin/sh
# Both daemons, one client, the same requests.
#
#     unshare -rn sh tests/live/c_daemon_answers.sh
#
# `tool/ledger_gate.py` says the two request taxonomies are whole -- thirty-two
# names, none either way. It says nothing about the **answers**, and the daemon
# is the last thing in `doc/c-transition.md`'s porting order, "last, because
# they are what the others are for".
#
# So this asks both daemons the same questions and compares what comes back.
# The client is the C `ncfg` in both cases, deliberately: one client against two
# daemons means a difference is the daemon's, where two clients against two
# daemons would leave it ambiguous. `NCFG_RUN_DIR` is what selects which daemon
# is answering, there being no `--socket` on the client.
#
# TWO PHASES, AND WHY THEY ARE NOT ONE
#   **Reading, with both daemons up at once.** They share a configuration
#   directory, neither changes the machine, and the answers must be identical
#   byte for byte.
#
#   **Writing, one daemon at a time.** Each gets its own configuration
#   directory, is asked to write into it, and what it leaves behind is
#   compared. Separate directories because a drop-in written through one daemon
#   would otherwise be read by the other.
#
# WHAT IS DELIBERATELY NOT COMPARED, AND WHAT IT COST TO LEARN
#   Nothing here runs `ncfg apply`, and that is the whole reason the comparison
#   is stable.
#
#   The first version did, and `status --json` then disagreed about
#   `hook_state`: one daemon recorded `link.create: kind is <absent>` and the
#   other `link.up: enabled is false`. It looked like a defect and was
#   deterministic across three runs. It is a race, and it is in both: the drift
#   pass reports on an observation taken **without the apply lock** -- which is
#   deliberate and documented, "a pass that only observes never takes it" -- so
#   while a third process is changing the machine, what the daemon sees is
#   whatever instant it sampled. Measured: the C produced the mid-apply value
#   in four runs of six, the Rust in one of eight. Same behaviour, different
#   odds.
#
#   So `hook_state` is not a thing two daemons can be held to agree on while
#   something else is applying, and the answer is not to filter the field but
#   to stop moving the machine underneath the question. A link's index and MAC
#   are the same kind of value and disappear for the same reason: with no
#   apply, neither daemon creates anything.

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
[ -x "$repo/target/debug/netcfgd" ] || skip "the Rust daemon is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-c-daemon-answers.XXXXXX")
rust_pid=""
c_pid=""
cleanup() {
	[ -n "$rust_pid" ] && kill "$rust_pid" 2>/dev/null || true
	[ -n "$c_pid" ] && kill "$c_pid" 2>/dev/null || true
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

# A document with nothing in it that needs hardware, so that both daemons see
# the same machine: an interface that does not exist, which is a state they can
# both describe without either of them creating anything.
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

# ----------------------------------------------------- reading, both at once

mkdir -p "$work/etc" "$work/run-rust" "$work/run-c"
document > "$work/etc/netcfgd.conf"
export NCFG_CONFIG_DIR="$work/etc"

NCFG_RUN_DIR="$work/run-rust" "$repo/target/debug/netcfgd" --no-apply-on-start \
	> "$work/rust.log" 2>&1 &
rust_pid=$!
NCFG_RUN_DIR="$work/run-c" "$repo/c/netcfgd" --try-the-c-daemon --no-apply-on-start \
	> "$work/c.log" 2>&1 &
c_pid=$!

if ! bound "$work/run-rust/netcfgd.sock"; then
	echo "FAIL the Rust daemon never bound its socket"
	tail -3 "$work/rust.log" | sed 's/^/       /'
	exit 1
fi
if ! bound "$work/run-c/netcfgd.sock"; then
	echo "FAIL the C daemon never bound its socket"
	tail -3 "$work/c.log" | sed 's/^/       /'
	exit 1
fi
echo "ok   both daemons bind a socket and answer"

ask() {
	run_dir="$1"
	shift
	NCFG_RUN_DIR="$run_dir" timeout 30 "$repo/c/ncfg" "$@" 2>&1 || true
}

# Each of these reaches the daemon and each says something: an answer, or a
# refusal with a reason. A verb that produced the same empty string from both
# would be comparing nothing, so the length is checked too.
for verb in \
	"status --json" "show --json" "plan --json" "status" "plan" \
	"explain interface dd0" "explain address dd0 10.9.120.1/24" \
	"wifi status" "wifi scan" "wifi clients" "modem status" \
	"control show" "profile get" "profile list" \
	"confirm" "revert" "reload" \
	"config rm nothing" "wifi forget nothing"
do
	# shellcheck disable=SC2086
	rust_said=$(ask "$work/run-rust" $verb)
	# shellcheck disable=SC2086
	c_said=$(ask "$work/run-c" $verb)
	if [ "${#rust_said}" -lt 10 ]; then
		echo "FAIL \`ncfg $verb\`: the answer is too short to be comparing anything"
		failures=$((failures + 1))
		continue
	fi
	check "\`ncfg $verb\`: both daemons answer alike" "$c_said" "$rust_said"
done

kill "$rust_pid" 2>/dev/null || true
kill "$c_pid" 2>/dev/null || true
rust_pid=""
c_pid=""

# ---------------------------------------------- writing, one daemon at a time

# What each daemon is asked to write, and then what it left behind. Its own
# configuration directory, because a drop-in written through one would
# otherwise be read by the other.
writes() {
	which="$1"
	shift
	mkdir -p "$work/$which/etc/secrets" "$work/$which/run"
	document > "$work/$which/etc/netcfgd.conf"
	NCFG_CONFIG_DIR="$work/$which/etc" NCFG_RUN_DIR="$work/$which/run" \
		"$@" --no-apply-on-start > "$work/$which/daemon.log" 2>&1 &
	pid=$!
	if ! bound "$work/$which/run/netcfgd.sock"; then
		echo "FAIL the $which daemon never bound its socket for the writing pass"
		tail -3 "$work/$which/daemon.log" | sed 's/^/       /'
		failures=$((failures + 1))
		kill "$pid" 2>/dev/null || true
		return 1
	fi
	say() {
		printf '>>> %s\n' "$*"
		NCFG_CONFIG_DIR="$work/$which/etc" NCFG_RUN_DIR="$work/$which/run" \
			timeout 30 "$repo/c/ncfg" "$@" 2>&1 || true
	}
	{
		printf 'device extra0 { kind = "dummy" }\n' | say config put extra
		say config rm extra
		printf 'device extra0 { kind = "dummy" }\n' | say config put extra
		printf 'hunter2hunter2' | say secret set dd-secret
		say wifi add TestNet --open
		say profile save saved
		say profile list
	} > "$work/$which.answers" 2>&1
	kill "$pid" 2>/dev/null || true
	waited=0
	while [ "$waited" -lt 50 ] && kill -0 "$pid" 2>/dev/null; do
		sleep 0.1
		waited=$((waited + 1))
	done
	# The work directory is in every path the daemon prints, and it is a
	# different directory for each of the two. Taken out by name rather than by
	# a pattern over paths, so that a path which differs for any other reason
	# still shows.
	sed "s|$work/$which|<work>|g" "$work/$which.answers" > "$work/$which.said"
	{
		cd "$work/$which/etc" || exit 1
		find . -type f | sort | while read -r file; do
			echo "--- $file"
			cat "$file"
		done
	} > "$work/$which.tree" 2>&1
	return 0
}

if writes rust "$repo/target/debug/netcfgd" &&
	writes c "$repo/c/netcfgd" --try-the-c-daemon
then
	check "the writing verbs answer alike" \
		"$(cat "$work/c.said")" "$(cat "$work/rust.said")"
	check "and leave the same configuration directory behind" \
		"$(cat "$work/c.tree")" "$(cat "$work/rust.tree")"
	# **Not vacuous**, and named rather than counted: two empty trees compare
	# equal, and a count is a number somebody fitted to the output once. Each
	# of these is the file one of the verbs above had to write -- the drop-in
	# from `config put`, the credential from `secret set`, and the profile from
	# `profile save` with the selection drop-in that choosing it leaves.
	for wanted in \
		"--- ./conf.d/extra.conf" \
		"--- ./secrets/dd-secret" \
		"--- ./profile/saved/00-saved.conf" \
		"--- ./conf.d/90-profile.conf"
	do
		check "  and \`${wanted#--- ./}\` is there, so the comparison had something in it" \
			"$(grep -cxF -e "$wanted" "$work/rust.tree" || true)" "1"
	done
	# `wifi add` is the one verb here that cannot succeed in a namespace: there
	# is no radio, and both daemons refuse it. That refusal is still compared
	# above and is still worth comparing -- it names the device it looked for,
	# so the two have to agree about what they found and did not find.
	check "  and the one verb that cannot work here was refused by both" \
		"$(grep -c "is not a radio on this machine" "$work/rust.said" || true)" \
		"$(grep -c "is not a radio on this machine" "$work/c.said" || true)"
fi

if [ "$failures" -eq 0 ]; then
	echo "c_daemon_answers.sh: all checks passed"
else
	echo "c_daemon_answers.sh: $failures check(s) failed"
	exit 1
fi
