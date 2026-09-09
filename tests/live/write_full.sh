#!/bin/sh
# What netcfgd says when a write fails after the file is already open.
#
#     sh tests/live/write_full.sh          # needs root and a network namespace
#
# WHY THIS EXISTS
#   Decision 0180 inventoried every write in the shipped crates and made the
#   silent ones audible. It also named what it could not check: a `write_all`
#   that fails *after* a successful `open`. Every unit test beside those
#   writers makes its refusal with a file where a directory has to be, which
#   is refused at the open -- so the second half of every one of those writes
#   was still unexercised, and it is the half a real machine reaches.
#
#   A filesystem that has filled up is how it happens. `/run` is a tmpfs
#   sized from RAM, and netcfgd writes about twenty kinds of file into it.
#   Opening an existing file needs no space at all -- truncating it hands
#   some back -- so the open succeeds, the mode is set, and then the write
#   returns ENOSPC with the operator's script half written.
#
# WHAT IT DRIVES
#   A real `ncfg apply` against a 256 KiB tmpfs, filled with `dd`, and the two
#   writers a shell can reach without a radio, a modem or a VPN:
#
#     * an inline `pre_up` hook, materialised at 0700 into `<run>/hooks/`.
#       This is the write-after-open case exactly: measured, the file is left
#       holding a *prefix* of the operator's script.
#     * the resolver file, whose staging write fails at the create. It is here
#       for the promise `netcfgd-dns`'s `replace` makes in a comment and
#       nothing had ever checked: a full disk must **not** fall back to
#       writing in place, because that truncates a working resolv.conf and
#       then cannot refill it. An unchanged resolver beats an empty one.
#
# WHAT IT DELIBERATELY DOES NOT COVER
#   Which files netcfgd writes -- `tool/write_gate.py` has the inventory --
#   and whether `/run` is `noexec`, which is `hooks.sh`'s question. The tmpfs
#   here is mounted without it on purpose: this script has to be able to watch
#   a hook run, and a fixture that models two hazards at once cannot say which
#   one it caught.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "write_full.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "write_full.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"
[ "$(id -u)" = 0 ] || skip "only root can mount a tmpfs over /run"

# **Its own network namespace, and it refuses to borrow the machine's.** This
# makes a dummy interface, and a script that makes interfaces must not do it
# on the real network -- `switch_network.sh` left two behind on this machine
# by being run bare. pid 1's namespace is the host's and /proc is not
# remounted by `unshare -rn`, so the two links answer the question.
if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
	skip "this makes an interface and must not do it on the machine's own network; run it under \`unshare -rn\`, as the Makefile does"
fi

# The mount namespace is made here rather than asked of the caller, for
# `hooks.sh`'s reason: the Makefile supplies user and network and no mount,
# and a developer runs it bare.
if [ -z "${NCFG_FULL_NS:-}" ]; then
	NCFG_FULL_NS=1
	export NCFG_FULL_NS
	if unshare -m true 2>/dev/null; then
		exec unshare -m -- sh "$0" "$@"
	fi
	skip "no mount namespace, so /run cannot be replaced with a small one"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-full.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/etc"

# Small enough that `dd` fills it in well under a second, large enough for a
# hook, a resolver file and netcfgd's own state to fit before it does.
mount -t tmpfs -o size=256k tmpfs /run || skip "cannot put a tmpfs over /run"
mkdir -p /run/netcfgd

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR=/run/netcfgd
export NCFG_RESOLV_CONF=/run/resolv.conf
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

ip link add full0 type dummy 2>/dev/null || skip "cannot make a dummy interface"

log=$work/transcript
resolver_config() {
	cat > "$work/etc/netcfgd.conf" <<CONF
global { dns { mode = "write_resolv_conf" } }
interface full0 {
	config = "10.9.0.1/24"
	dns { servers = ["$1"] }
}
CONF
}

# ------------------------------------------------------- with room to write

resolver_config 10.9.0.53
printf 'nameserver 203.0.113.1\n' > /run/resolv.conf
rc=0
"$ncfg" apply > "$work/apply1.log" 2>&1 || rc=$?
check "an apply with room to write succeeds" "$rc" "0"
contains "and the resolver holds what the document asked for" \
	"$(cat /run/resolv.conf)" "10.9.0.53"

# ------------------------------------------------------------ and with none

# `dd` with no `count` stops at the first short write, which on a fixed-size
# tmpfs is the whole point and is what bounds it.
dd if=/dev/zero of=/run/filler bs=1k 2>/dev/null || true
free=$(df -k /run | awk 'NR == 2 { print $4 }')
check "the filesystem is full, or nothing below measures anything" "$free" "0"

resolver_config 10.9.0.54
rc=0
"$ncfg" apply > "$work/apply2.log" 2>&1 || rc=$?
refusal=$(cat "$work/apply2.log")

check "an apply that cannot write the resolver fails rather than reporting success" \
	"$([ "$rc" -ne 0 ] && echo yes || echo no)" "yes"
contains "and names the file it could not write" "$refusal" "/run/.resolv.conf.netcfgd"
contains "and gives the kernel's own words for why" "$refusal" "No space left on device"
contains "and says which action it stopped at" "$refusal" "dns.apply"

# **The promise `replace` makes in a comment, and nothing had checked.** A
# full disk deliberately does not fall back to writing in place: that fallback
# exists for a directory netcfgd may not add to, and using it here would
# truncate a working resolver and then fail to refill it. An unchanged
# resolv.conf beats an empty one.
contains "the resolver that was there is untouched, not truncated" \
	"$(cat /run/resolv.conf)" "10.9.0.53"
check "and no staging file is left beside it" \
	"$(find /run -maxdepth 1 -name '.resolv.conf.netcfgd*' | wc -l)" "0"

# ------------------------------------- the write that fails after the open

# A body far larger than the space left, so the failure is the write and not
# the create: the file below already exists, and truncating it hands its
# blocks back before a single byte of this is written.
{
	printf 'interface full0 {\n\tconfig = "10.9.0.1/24"\n\tpre_up {\n'
	printf '\techo ran >> %s\n' "$log"
	i=0
	while [ "$i" -lt 400 ]; do
		printf '\ttrue # padding so the body cannot fit in what is left\n'
		i=$((i + 1))
	done
	printf '\t}\n}\n'
} > "$work/etc/netcfgd.conf"

rm -f "$log"
rc=0
"$ncfg" apply > "$work/apply3.log" 2>&1 || rc=$?
refusal=$(cat "$work/apply3.log")
hook=/run/netcfgd/hooks/full0.pre_up.0

contains "a hook body that cannot be written names the file" "$refusal" "$hook"
contains "and gives the kernel's own words for why" "$refusal" "No space left on device"
check "and the apply fails rather than reporting success" \
	"$([ "$rc" -ne 0 ] && echo yes || echo no)" "yes"

# **This is the case the unit tests cannot reach.** They refuse at the open,
# with a file where a directory has to be; here the open succeeded, the mode
# was set, and the write stopped part way -- so what is on disk is a prefix of
# the operator's script, or nothing at all, and never the script.
check "the file was opened and truncated, so the failure is the write and not the open" \
	"$([ -f "$hook" ] && [ "$(stat -c%s "$hook")" -lt 400 ] && echo yes || echo no)" "yes"
check "and the half-written hook did not run" \
	"$([ -e "$log" ] && echo ran || echo no)" "no"

# ------------------------------------------------------------- the controls

# Everything above would read the same if netcfgd could not write anything at
# all, or if the config were simply wrong. Free the space and require the same
# two writes to go through.
rm -f /run/filler
hook_config() {
	{
		printf 'interface full0 {\n\tconfig = "10.9.0.1/24"\n\tenabled = %s\n' "$1"
		printf '\tpre_up {\n\techo ran >> %s\n' "$log"
		i=0
		while [ "$i" -lt 400 ]; do
			printf '\ttrue # padding so the body cannot fit in what is left\n'
			i=$((i + 1))
		done
		printf '\t}\n}\n'
	} > "$work/etc/netcfgd.conf"
}

# **The link has to go down first, and finding that out is what this control
# is for.** With the space back, the failed apply above had left the interface
# up and addressed, so the next one had nothing to converge and said "nothing
# to do" -- no plan, no hook, and a check that read the absence as a failure.
# A `pre_up` fires when a link comes up, so the control has to put it down.
hook_config false
rc=0
"$ncfg" apply > "$work/apply4a.log" 2>&1 || rc=$?
check "with the space back, taking the link down succeeds" "$rc" "0"

rm -f "$log"
hook_config true
rc=0
"$ncfg" apply > "$work/apply4.log" 2>&1 || rc=$?
check "and bringing it back up succeeds" "$rc" "0"
check "the hook holds the whole body this time" \
	"$([ "$(stat -c%s "$hook")" -gt 400 ] && echo whole || echo short)" "whole"
check "and it ran" "$([ -e "$log" ] && echo ran || echo no)" "ran"

resolver_config 10.9.0.54
rc=0
"$ncfg" apply > "$work/apply5.log" 2>&1 || rc=$?
check "and the resolver takes the server it refused to take when full" \
	"$(grep -c '10.9.0.54' /run/resolv.conf)" "1"

if [ "$failures" -eq 0 ]; then
	echo "write_full.sh: all checks passed"
else
	echo "write_full.sh: $failures check(s) failed"
	sed 's/^/       /' "$work"/apply*.log >&2
	exit 1
fi
