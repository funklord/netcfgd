#!/bin/sh
# What a configuration netcfgd cannot read does to a machine it has configured.
#
#     sh tests/live/config_unreadable.sh     # needs its own network namespace
#
# WHY THIS EXISTS
#   The write audit (0180) asked what happens when netcfgd cannot write. This
#   is the other half, and it turned out to be the more expensive one: when
#   netcfgd could not *read* its configuration it did not refuse, it compiled
#   an empty document -- and an empty document is a meaningful state. It means
#   nothing on this machine is netcfgd's.
#
#   Measured before the fix, with `/etc/netcfgd/netcfgd.conf` made a symlink to
#   itself:
#
#       $ ncfg apply
#       ok   addr.del read0  addressing: <absent> (was 10.11.0.1/24)
#       $ echo $?
#       0
#
#   The address was taken off the interface, the command reported success, and
#   the cause was a file that could not be read. `Path::is_file` answers
#   `false` for a file it cannot examine, and the loader's gate was that call.
#
# WHAT IT DRIVES
#   A real `ncfg apply` against a real interface, four ways of having a
#   configuration that is there and unreadable, and the one that must still be
#   allowed: not having one at all. The refusals are symlink loops and a
#   directory in place of a file, which need no privilege -- a mode would not
#   do, because root walks through one (10.71).
#
# WHAT IT DELIBERATELY DOES NOT COVER
#   Whether an *empty* configuration should remove what netcfgd configured. It
#   should: the document is what netcfgd owns, and a machine whose config was
#   emptied on purpose is asking for exactly that. The fault was never the
#   tear-down, it was reaching it by guessing.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "config_unreadable.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "config_unreadable.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

# Its own network namespace, refused rather than assumed: this makes an
# interface, and `switch_network.sh` left two on the real machine by being run
# bare. /proc is not remounted by `unshare -rn`, so pid 1's link answers it.
if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
	skip "this makes an interface and must not do it on the machine's own network; run it under \`unshare -rn\`, as the Makefile does"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-unreadable.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_RESOLV_CONF="$work/resolv.conf"
ncfg="$repo/target/debug/ncfg"

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

ip link add read0 type dummy 2>/dev/null || skip "cannot make a dummy interface"

good_config() {
	rm -rf "$work/etc/netcfgd.conf"
	cat > "$work/etc/netcfgd.conf" <<CONF
interface read0 {
	config = "10.11.0.1/24"
}
CONF
}

configured() {
	ip -4 -br addr show read0 | grep -c '10.11.0.1/24' || true
}

# What is on the machine to lose, so everything below is about losing it.
good_config
rc=0
"$ncfg" apply > "$work/apply.log" 2>&1 || rc=$?
check "an apply with a config it can read succeeds" "$rc" "0"
check "and the interface carries what the document asked for" "$(configured)" "1"

# Each of these is a configuration that exists and cannot be read. None of
# them is "this machine configures nothing", and netcfgd must not act as
# though it were.
for situation in loop dangling directory dropins; do
	case $situation in
	loop)
		rm -f "$work/etc/netcfgd.conf"
		ln -s netcfgd.conf "$work/etc/netcfgd.conf"
		what="a config that is a symlink loop"
		;;
	dangling)
		rm -f "$work/etc/netcfgd.conf"
		ln -s "$work/etc/on-a-disk-that-is-not-mounted.conf" "$work/etc/netcfgd.conf"
		what="a config that is a link to nothing"
		;;
	directory)
		rm -f "$work/etc/netcfgd.conf"
		mkdir -p "$work/etc/netcfgd.conf"
		what="a config that is a directory"
		;;
	dropins)
		rm -rf "$work/etc/netcfgd.conf"
		good_config
		ln -s conf.d "$work/etc/conf.d"
		what="a conf.d that is a symlink loop"
		;;
	esac

	rc=0
	"$ncfg" apply > "$work/apply-$situation.log" 2>&1 || rc=$?
	refusal=$(cat "$work/apply-$situation.log")

	check "$what is refused rather than compiled as empty" \
		"$([ "$rc" -ne 0 ] && echo refused || echo accepted)" "refused"
	contains "and the refusal names the path" "$refusal" "$work/etc"
	check "and the interface keeps its address" "$(configured)" "1"

	rm -f "$work/etc/conf.d"
	rm -rf "$work/etc/netcfgd.conf"
done

# **The state that must still be allowed, and the reason this needs saying.**
# The fix could have been "refuse whenever the file is not readable as a
# regular file", which would break every machine that has no netcfgd config at
# all -- an ordinary state that compiles to an empty document. So: an absent
# config still applies, and still means nothing here is netcfgd's, which is
# what takes the address off.
rc=0
"$ncfg" apply > "$work/apply-absent.log" 2>&1 || rc=$?
check "a machine with no configuration at all is not an error" "$rc" "0"
check "and an empty document does take back what netcfgd had configured" \
	"$(configured)" "0"

# And back again, so the tear-down above is netcfgd following the document
# rather than the interface having been lost along the way.
good_config
rc=0
"$ncfg" apply > "$work/apply-again.log" 2>&1 || rc=$?
check "a config it can read again reconfigures the interface" "$rc" "0"
check "and the address is back" "$(configured)" "1"

if [ "$failures" -eq 0 ]; then
	echo "config_unreadable.sh: all checks passed"
else
	echo "config_unreadable.sh: $failures check(s) failed"
	sed 's/^/       /' "$work"/apply*.log >&2
	exit 1
fi
