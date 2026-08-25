#!/bin/sh
# Taking a radio over from another manager, which is what displacement means.
#
# WHY THIS FILE EXISTS
#   netcfgd declines a radio while another daemon's supplicant is answering on
#   it -- `dot1x.sh` covers that half, and it is the half that protects a
#   working machine. What nothing covered is the other half: that when the
#   other manager lets go, netcfgd actually takes the radio. A guard that
#   declines and never stops declining is indistinguishable from a daemon that
#   does not work, and "netcfgd stops working if I don't have NetworkManager
#   running" is precisely how that looks from outside.
#
#   It was tried on a real machine and never observed: the handover did not
#   take, and the session ended before it could be retried. So it is done here,
#   where a foreign supplicant can be started and stopped on demand.
#
# WHAT "ANOTHER MANAGER" IS, EXACTLY
#   A supplicant holding the interface's control socket that netcfgd did not
#   start -- which is all netcfgd can see of NetworkManager, and all it needs
#   to see. The test starts one itself rather than requiring NM: what the guard
#   reads is a socket that answers, and a fake answers exactly as a real one
#   does.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "displace.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "displace.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed"
command -v ip >/dev/null 2>&1 || skip "iproute2 is not installed"

work=$(mktemp -d /tmp/ncfg-disp.XXXXXX)
ncfg="$repo/target/debug/ncfg"
[ -x "$ncfg" ] || ncfg="$repo/target/debug/netcfgd"
daemon=
foreign=
failures=0

cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	wait "$daemon" 2>/dev/null || true
	[ -n "$foreign" ] && kill "$foreign" 2>/dev/null
	for pidfile in "$work"/run/supplicant/*.pid; do
		[ -e "$pidfile" ] || continue
		kill "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null || true
	done
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

ip link add radio0 type dummy 2>/dev/null || skip "cannot create a dummy link"
ip link set radio0 up
mkdir -p "$work/sys/radio0/wireless" "$work/etc/conf.d" "$work/run" "$work/ctrl"
cp "$repo/tests/live/fake_supplicant.py" "$work/fake_supplicant"
chmod +x "$work/fake_supplicant"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_SYS_CLASS_NET="$work/sys"
export NCFG_WPA_CTRL_DIR="$work/ctrl"
export NCFG_WPA_SUPPLICANT="$work/fake_supplicant"

# **The other manager, started before netcfgd and not by it.** No pid file
# under netcfgd's run directory, which is exactly what a supplicant belonging
# to something else looks like.
python3 "$repo/tests/live/fake_supplicant.py" "$work/ctrl" radio0 > "$work/foreign.log" 2>&1 &
foreign=$!
waited=0
while [ ! -e "$work/ctrl/radio0" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && skip "the foreign supplicant never bound its socket"
	sleep 0.1
done

# A configuration that says the radio is netcfgd's, so it *wants* to act.
cat > "$work/etc/netcfgd.conf" <<'CONF'
device radio0 {
	wifi { autoconnect = true }
}
interface radio0 {
	config = "null"
}
CONF

"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		cat "$work/daemon.log" >&2
		echo "displace.sh: the daemon never started" >&2
		exit 1
	fi
	sleep 0.1
done

# ---------------------------------------------------------------------------
# 1. While the other manager holds it, netcfgd keeps its hands off.
sleep 2
check "netcfgd starts no supplicant of its own while another holds the radio" \
	"$([ -e "$work/run/supplicant/radio0.pid" ] && echo yes || echo no)" "no"
check "and the other one is untouched" \
	"$(kill -0 "$foreign" 2>/dev/null && echo alive || echo gone)" "alive"
check "and its control socket is still there" \
	"$([ -e "$work/ctrl/radio0" ] && echo yes || echo no)" "yes"

# The refusal names what to stop, which is the whole value of declining rather
# than fighting.
apply=$("$ncfg" apply 2>&1 || true)
contains "and an apply says who is holding it" "$apply" "already running a supplicant"

# ---------------------------------------------------------------------------
# 2. The other manager lets go, and netcfgd takes the radio.
#
# **The half nothing covered.** A guard that declines and never stops declining
# looks exactly like a daemon that does not work, which is how this was
# reported: "netcfgd stops working if I don't have NetworkManager running".
kill "$foreign" 2>/dev/null || true
wait "$foreign" 2>/dev/null || true
foreign=
rm -f "$work/ctrl/radio0"

# Within a tick, and no apply is run here on purpose: the daemon reconciles by
# default, so taking the radio over is something it should do on its own.
waited=0
while [ ! -s "$work/run/supplicant/radio0.pid" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 200 ] && break
	sleep 0.1
done
check "netcfgd starts its own supplicant once the radio is free" \
	"$([ -s "$work/run/supplicant/radio0.pid" ] && echo yes || echo no)" "yes"
started=$(cat "$work/run/supplicant/radio0.pid" 2>/dev/null || echo 0)
check "and it is alive" \
	"$([ -n "$started" ] && [ -e "/proc/$started" ] && echo yes || echo no)" "yes"
check "and it is netcfgd's, by the pid file it was told to write" \
	"$(tr '\0' ' ' < "/proc/$started/cmdline" 2>/dev/null | grep -c "$work/run/supplicant/radio0.pid" || true)" "1"
contains "and the radio is netcfgd's" "$("$ncfg" wifi radios 2>&1)" "netcfgd's"
contains "and scanning works through it" "$("$ncfg" wifi scan radio0 2>&1 || true)" "HomeFiber"

echo
if [ "$failures" -eq 0 ]; then
	echo "displace.sh: all checks passed"
else
	echo "displace.sh: $failures failed"
	exit 1
fi
