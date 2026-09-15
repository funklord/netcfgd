#!/bin/sh
# Prove a test fails without the fix, against the parent commit rather than
# against a mutation somebody invented.
#
# WHY THIS EXISTS
#   The working order here is fix, then test, then sabotage -- break the fix by
#   hand and check the test goes red. Eight times in the M9 wifi audit the
#   sabotage passed on its first run, which means the test was written from the
#   fix and inherited its blind spots. The sabotage is chosen by the same person
#   who wrote the bug, from the same model of what the code does, so it probes
#   what they already understand.
#
#   The committed tree does not have that problem. It is what the code did
#   before, chosen by nobody. Running the new test against it answers the same
#   question with no invention in it.
#
# WHAT IT DOES
#   Checks out a rev into a throwaway worktree, copies the named test files over
#   it, runs the named test, and requires a failure. Nothing in your working
#   tree is touched, stashed or checked out -- which matters in a tree several
#   sessions share, where a stash is somebody else's work one command away.
#
#     sh tool/prove-red.sh a_connected_event_names_the_network_as_well \
#         -r HEAD~3 backend/netcfgd-supplicant/tests/protocol.rs
#
#     sh tool/prove-red.sh -c 'cargo build && unshare -rn sh tests/live/roam.sh' \
#         roam-restart tests/live/roam.sh
#
#   The files are the ones carrying the *test*. Everything else comes from the
#   rev, so the fix is absent by construction. `-c` replaces the runner, which
#   is what the shell suites need: the best tests in this tree are scripts.
#
# THE LIMIT, WHICH IS NOT SMALL
#   This can only separate the test from the fix where they are in different
#   *files*. A `#[cfg(test)] mod tests` beside the function it checks is copied
#   with the function, so the fix comes along and the test passes -- which this
#   reports as a failure to prove anything, correctly, but it cannot do better.
#   For those, the hand sabotage is still the method.
#
# WHAT A RED MEANS, AND WHAT IT DOES NOT
#   A test that fails an assertion is the answer wanted: the behaviour changed
#   and the test sees it.
#
#   A test that fails to *compile* is a weaker answer and this says so. It
#   happens when the fix added an API the test calls -- the symbol is new, so
#   nothing at the parent rev could have had it. That proves the test is new
#   code and not that any behaviour moved. Where it matters, restate the check
#   in terms the old tree can compile.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

usage() {
	echo "usage: $0 [-r REV] [-c CMD] TESTFILTER FILE..." >&2
	echo "  -r REV      the rev to run against; default HEAD" >&2
	echo "  -c CMD      run this instead of cargo test; TESTFILTER is then a label" >&2
	echo "  TESTFILTER  passed to \`cargo test\`, e.g. a test name" >&2
	echo "  FILE...     the files carrying the test, copied over the rev" >&2
	exit 2
}

rev=HEAD
command=
while [ $# -gt 0 ]; do
	case "$1" in
	-r)
		[ $# -ge 2 ] || usage
		rev=$2
		shift 2
		;;
	-c)
		[ $# -ge 2 ] || usage
		command=$2
		shift 2
		;;
	-*) usage ;;
	*) break ;;
	esac
done
[ $# -ge 2 ] || usage

filter=$1
shift

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

# Every named file has to exist and be inside the repository, because each one
# is about to be copied over a checkout. A path that escapes would copy
# something the rev never had and the run would prove nothing about it.
for file in "$@"; do
	[ -f "$file" ] || { echo "prove-red: $file is not a file" >&2; exit 2; }
	case "$file" in
	/* | ../*) echo "prove-red: $file is not inside the repository" >&2; exit 2 ;;
	esac
done

resolved=$(git rev-parse --verify "$rev^{commit}") ||
	{ echo "prove-red: $rev is not a commit" >&2; exit 2; }

# Named by pid under the repository's own build directory, which `clean`
# already owns. Not /tmp: a worktree is a checkout of this repository and
# belongs beside it.
tree=$repo/target/prove-red.$$
created=

cleanup() {
	status=$?
	set +e
	if [ -n "$created" ]; then
		git worktree remove --force "$tree" 2>/dev/null ||
			{ rm -rf "$tree"; git worktree prune; }
	fi
	exit "$status"
}
trap cleanup EXIT INT TERM

git worktree add --detach --quiet "$tree" "$resolved" ||
	{ echo "prove-red: could not make a worktree at $resolved" >&2; exit 1; }
created=yes

for file in "$@"; do
	mkdir -p "$tree/$(dirname "$file")"
	cp "$file" "$tree/$file"
	echo "prove-red: copied $file over $(git rev-parse --short "$resolved")"
done

log=$tree/prove-red.log
set +e
if [ -n "$command" ]; then
	(cd "$tree" && sh -c "$command") > "$log" 2>&1
else
	(cd "$tree" && cargo test "$filter") > "$log" 2>&1
fi
outcome=$?
set -e

if [ "$outcome" -eq 0 ]; then
	echo
	echo "prove-red: FAILED -- the test PASSES without the fix."
	echo "prove-red:   Whatever it checks, the tree already did at $(git rev-parse --short "$resolved")."
	echo "prove-red:   The test is not holding the change."
	tail -25 "$log" | sed 's/^/  /'
	exit 1
fi

if grep -qE '^error(\[E[0-9]+\])?:' "$log" && ! grep -q '^test result: FAILED' "$log"; then
	echo
	echo "prove-red: red, but by failing to COMPILE rather than by failing a check."
	echo "prove-red:   The fix added something the test calls, so the parent rev has no"
	echo "prove-red:   such symbol. That proves the test is new, not that behaviour moved."
	grep -E '^error(\[E[0-9]+\])?:' "$log" | head -5 | sed 's/^/  /'
	exit 3
fi

echo
echo "prove-red: red at $(git rev-parse --short "$resolved") -- the test fails without the fix."
grep -E '^test result:|^---- .* stdout|panicked at' "$log" | head -10 | sed 's/^/  /'
