#!/bin/sh
# profile.sh -- the profile verbs, against a daemon that is actually running.
#
# WHAT THIS IS FOR
#   The gui's tray lists profiles and switches between them, and it does that
#   over the socket rather than off its own disk -- so what the tray can do is
#   exactly what `profile_list` and `profile_set` do. Neither had ever been
#   spoken to a running daemon. The unit tests drive the loader and the cli
#   with no socket in sight, which is the half that was already covered.
#
# WHAT IT CHECKS, AND WHY EACH ONE
#   That a shipped profile and an operator's own are both listed, and reported
#   as whose they are -- the tray labels them differently and a wrong flag
#   sends somebody to edit a file the next upgrade replaces.
#
#   That switching takes effect *in the document*, not merely in the file: the
#   daemon answers `chosen` from what the loader compiled, so a selection that
#   did not survive the load must not be announced as in force.
#
#   That a name with no directory is refused, and that the refusal says what
#   there is. This is the check that cannot live in the client: only the
#   machine netcfgd runs on knows which directories exist, and a gui checking
#   its own disk would be answering about the wrong host.
#
#   That unsetting goes back to no profile chosen rather than to a profile
#   called "none" -- the distinction 0151 exists to keep, checked where it is
#   easiest to lose.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "profile.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "profile.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

# Short, because a unix socket path is capped at about 108 bytes and the
# daemon binds one inside the run directory.
work=$(mktemp -d /tmp/ncfg-prof.XXXXXX)
ncfg="$repo/target/debug/ncfg"
[ -x "$ncfg" ] || ncfg="$repo/target/debug/netcfgd"
daemon=
failures=0

cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	wait "$daemon" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

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

mkdir -p "$work/etc/conf.d" "$work/etc/profile/office" "$work/run" \
	"$work/factory/profile/offline"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_FACTORY_DIR="$work/factory"

# **The admin tier, opened deliberately.** Switching a profile is a
# configuration write, so the daemon refuses it to anything but root by
# default -- which is correct, and which this test found by being refused.
# Opening it here is what lets the test run as whoever is building; the tier
# itself is checked by `acl.sh`, not by this.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	control {
		admin = "any"
	}
}
device lo {
	mtu = 1500
}
interface lo {
	config = "null"
}
CONF

# The operator's own profile, and the shipped one beside it. `mtu` because it
# is observable in the compiled document without touching the machine -- and
# on the `device`, not the `interface`, since 0155's restructure moved what is
# true of hardware whether or not anything is connected.
cat > "$work/etc/profile/office/10-office.conf" <<'CONF'
override device lo {
	mtu = 9000
}
CONF
cat > "$work/factory/profile/offline/10-offline.conf" <<'CONF'
global {
	networking = "off"
}
CONF

"$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 50 ]; then
		echo "profile.sh: the daemon never bound its socket; log:" >&2
		cat "$work/daemon.log" >&2
		exit 1
	fi
	sleep 0.1
done

# --- listing, through the socket rather than off this disk

listed=$("$ncfg" profile list 2>&1)
contains "the operator's profile is listed as theirs" "$listed" "office  (yours)"
contains "the shipped one is listed as shipped" "$listed" "offline  (shipped)"
check "nothing is chosen to begin with" "$("$ncfg" profile get 2>&1)" "no profile chosen"

# --- switching

"$ncfg" profile set office > "$work/set.log" 2>&1 ||
	{ echo "FAIL could not set"; cat "$work/set.log"; failures=$((failures + 1)); }
check "the daemon reports the profile it compiled" "$("$ncfg" profile get 2>&1)" "office"

# The profile's own drop-in is in force, which is the thing a selection is
# *for*. Reported from the document, so this fails if the profile directory
# was selected but never read.
mtu=$("$ncfg" show 2>/dev/null |
	python3 -c 'import sys,json; print(json.load(sys.stdin)["devices"][0].get("mtu"))' 2>/dev/null ||
	echo "unreadable")
check "the chosen profile's drop-in is in force" "$mtu" "9000"

listed=$("$ncfg" profile list 2>&1)
contains "the chosen one is marked" "$listed" "* office"

# --- a name with no directory

# The cli refuses this before the socket, from the list the daemon gave it, so
# what is checked here is that the two agree about what exists. The daemon
# refuses the same request identically for a client that does not pre-check --
# which is the case the gui is, and is why the check lives there too.
refused=$("$ncfg" profile set nosuch 2>&1 || true)
contains "a name with no directory is refused" "$refused" "no profile called \`nosuch\`"
contains "and the refusal says what there is" "$refused" "office"
check "and the machine is still on the profile it had" "$("$ncfg" profile get 2>&1)" "office"

# --- the shipped profile, which is the one a package can offer

"$ncfg" profile set offline > "$work/off.log" 2>&1 ||
	{ echo "FAIL could not select the shipped profile"; failures=$((failures + 1)); }
off=$("$ncfg" show 2>/dev/null |
	python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["globals"]["networking"], d["interfaces"][0]["enabled"])' 2>/dev/null ||
	echo "unreadable")
check "the shipped profile turns networking off and downs the link" "$off" "off False"

# --- unsetting

"$ncfg" profile unset > "$work/unset.log" 2>&1 ||
	{ echo "FAIL could not unset"; failures=$((failures + 1)); }
# **Not a profile called "none".** The word matters: an absent selection means
# the machine runs its own configuration, and 0151 exists because the two were
# conflated when the feature was described.
check "unsetting goes back to none chosen" "$("$ncfg" profile get 2>&1)" "no profile chosen"
mtu=$("$ncfg" show 2>/dev/null |
	python3 -c 'import sys,json; print(json.load(sys.stdin)["devices"][0].get("mtu"))' 2>/dev/null ||
	echo "unreadable")
check "and the machine's own configuration is back" "$mtu" "1500"

if [ "$failures" -eq 0 ]; then
	echo
	echo "profile.sh: all checks passed"
else
	echo
	echo "profile.sh: $failures check(s) failed"
fi
exit "$failures"
