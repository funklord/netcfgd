#!/bin/sh
# The mark netcfgd leaves on a link it created, and what it is for.
#
# WHY THIS FILE EXISTS
#   0135 made addresses and routes survive losing `/run`, because the kernel
#   carries netcfgd's protocol tag on both. A link has no protocol field, so it
#   was the one object kind whose ownership still lived only in the record --
#   and a restart deletes the record. A netcfgd that forgets it created a
#   bridge will never remove that bridge, so a bridge deleted from the config
#   stays on the machine for ever while `ncfg apply` reports success.
#
#   0136 gives every link netcfgd creates an alternative name, `netcfgd:<name>`,
#   which is the kernel-held marker the missing field would have been.
#
# THE HALF THAT MUST NOT MOVE
#   A link netcfgd did not create must survive all of this, so the test puts an
#   unmarked one alongside and checks it is still there at the end. Without it
#   a netcfgd that deleted every virtual link it found would pass every other
#   check in the file.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "altname.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "altname.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
command -v ip >/dev/null 2>&1 || skip "iproute2 is not installed"

work=$(mktemp -d /tmp/ncfg-altname.XXXXXX)
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

start_daemon() {
	"$repo/target/debug/netcfgd" > "$work/$1.log" 2>&1 &
	daemon=$!
	waited=0
	while [ ! -e "$work/run/netcfgd.sock" ]; do
		waited=$((waited + 1))
		if [ "$waited" -gt 60 ]; then
			cat "$work/$1.log" >&2
			echo "altname.sh: the daemon never started" >&2
			exit 1
		fi
		sleep 0.1
	done
	sleep 2
}

stop_daemon() {
	[ -n "$daemon" ] || return 0
	kill "$daemon" 2>/dev/null || true
	wait "$daemon" 2>/dev/null || true
	daemon=
	rm -f "$work/run/netcfgd.sock"
}

ip link add keep0 type dummy 2>/dev/null || skip "cannot create a dummy link"
mkdir -p "$work/etc/conf.d" "$work/run"
export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"

cat > "$work/etc/netcfgd.conf" <<'CONF'
device ncbr0 {
	bridge {
		members = []
	}
}
interface ncbr0 {
	config = "null"
}
CONF

start_daemon d1

# ---------------------------------------------------------------------------
# 1. netcfgd creates the bridge and marks it in the kernel.
check "netcfgd creates the bridge the config asks for" \
	"$(ip link show ncbr0 >/dev/null 2>&1 && echo yes || echo no)" "yes"
check "and marks it with an alternative name" \
	"$(ip -d link show ncbr0 2>/dev/null | grep -c 'altname netcfgd:ncbr0')" "1"
check "and the link it did not create carries no mark" \
	"$(ip -d link show keep0 2>/dev/null | grep -c 'altname netcfgd:')" "0"

# The mark is legible without netcfgd, which is half its value.
check "the mark names the link as netcfgd made it" \
	"$(ip -d link show ncbr0 2>/dev/null | grep -o 'altname netcfgd:[a-z0-9]*' | head -1)" \
	"altname netcfgd:ncbr0"

# ---------------------------------------------------------------------------
# 2. Stop, and take the record away the way a restart does.
stop_daemon
check "stopping the daemon leaves the bridge up" \
	"$(ip link show ncbr0 >/dev/null 2>&1 && echo yes || echo no)" "yes"
rm -f "$work/run/owned.json"
check "the ownership record is gone" \
	"$([ -e "$work/run/owned.json" ] && echo present || echo gone)" "gone"
check "but the mark is not, because it is the kernel's" \
	"$(ip -d link show ncbr0 2>/dev/null | grep -c 'altname netcfgd:ncbr0')" "1"

# ---------------------------------------------------------------------------
# 3. The config stops asking for the bridge. Only a daemon that still knows it
#    made the bridge may take it away.
cat > "$work/etc/netcfgd.conf" <<'CONF'
CONF

start_daemon d2
sleep 1

check "the restarted daemon removes the bridge it created" \
	"$(ip link show ncbr0 >/dev/null 2>&1 && echo present || echo gone)" "gone"
check "and leaves the link that was never its own" \
	"$(ip link show keep0 >/dev/null 2>&1 && echo present || echo gone)" "present"

echo
if [ "$failures" -eq 0 ]; then
	echo "altname.sh: all checks passed"
else
	echo "altname.sh: $failures failed"
	exit 1
fi
