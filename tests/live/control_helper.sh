#!/bin/sh
# The privileged half of administrator mode, driven as a real process.
#
#     sh tests/live/control_helper.sh
#
# Decision 0120. `ncfg control helper` is what the red frame is a claim about:
# it runs as root, it is started by an elevator, and it reads commands from a
# pipe held by an unprivileged client. Its parser is unit-tested; what is not
# reachable from a unit test is the *process* -- the ready line, the bound on
# what it will read, and the promise that it goes away when the pipe closes.
#
# Nothing here needs root. The helper writes into a config directory this
# script owns, so the uid it reports is whatever runs it -- and that is the
# point of the ready line being a report rather than an assertion: the client
# is what refuses a uid that is not zero, and it does so on what the helper
# actually said.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "control_helper.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "control_helper.sh: skipping: $1"
	exit 0
}

command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-helper.XXXXXX")
cleanup() {
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
	done
	return 0
}
trap cleanup EXIT INT TERM

mkdir -p "$work/etc"
printf 'interface eth0 {\n\tconfig = "dhcp"\n}\n' > "$work/etc/netcfgd.conf"

helper="$repo/target/debug/ncfg control helper --config-dir $work/etc"
policy="$work/etc/conf.d/00-control.conf"

fail() {
	echo "control_helper.sh: $1" >&2
	exit 1
}

# 1. It announces itself with the uid it actually has, before any command.
#    The client reddens its frame on this line and on nothing else, so a helper
#    that produced no ready line would leave the mode unreachable rather than
#    wrongly available -- which is the safe direction and worth keeping.
first=$(printf '' | $helper | head -1)
case "$first" in
	"ready uid="*) ;;
	*) fail "expected a ready line with a uid, got: $first" ;;
esac
echo "control_helper.sh: announces itself -- $first"

# 2. End of file ends it. This is how the mode is left and how the helper dies
#    when the client is killed, so it is the path that must not need a timeout.
#    `printf ''` above already closed the pipe; if the helper had waited for
#    anything else, this script would have hung there rather than reaching here.
echo "control_helper.sh: end of file ends it"

# 3. The command it exists for.
printf 'set group:netcfgd any root\n' | $helper > "$work/out" 2>&1
grep -q '^ok ' "$work/out" || fail "a valid set was not accepted: $(cat "$work/out")"
grep -q 'observe = "group:netcfgd"' "$policy" || fail "the policy was not written"
echo "control_helper.sh: writes a policy"

# 4. A bound on what it will read, because this is a root process reading a
#    pipe. Over the bound it says so and stops rather than resynchronising:
#    whatever follows an over-length line is the tail of something nobody can
#    parse, and treating that as fresh input is how a parser is fed a command
#    its sender did not write.
before=$(cat "$policy")
python3 -c "print('set ' + 'A' * 5000000)" 2>/dev/null | $helper > "$work/big" 2>&1 || true
grep -q 'may not exceed' "$work/big" || fail "an over-long command was not refused: $(head -2 "$work/big")"
echo "control_helper.sh: refuses an over-long command"

# 5. And a refusal changes nothing. "Returned an error" and "wrote nothing" are
#    different claims, and it is the second that matters when the writer is root.
printf 'set bogus any root\nrm -rf /\nset any\n' | $helper > "$work/bad" 2>&1
grep -q 'is not a principal' "$work/bad" || fail "a bad principal was not named"
grep -q 'unknown command' "$work/bad" || fail "a shell command was not refused"
[ "$(cat "$policy")" = "$before" ] || fail "a refused command changed the policy"
echo "control_helper.sh: refusals write nothing"

echo "control_helper.sh: ok"
