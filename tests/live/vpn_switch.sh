#!/bin/sh
# A WireGuard and an OpenVPN tunnel turned off and on by `ncfg tunnel` (0329).
#
#     unshare -rn sh tests/live/vpn_switch.sh
#
# The daemon holds the tunnel's interface with a `switch` block in a drop-in of
# its own, `tunnel-NAME`, and applies that interface before it answers. What is
# checked is what a person turning their VPN off is relying on: the WireGuard
# link goes down and comes back with its address, and the OpenVPN daemon is
# stopped rather than left holding its session behind a down link -- the
# difference `enabled = false` alone did not make (plan/session.c, held_down).
#
# OpenVPN is fake_openvpn.py, found through NCFG_OPENVPN as openvpn.sh finds
# it. WireGuard is the kernel's, in this namespace.
#
# HOW IT STOPS: one daemon, killed by pid in the trap; the fake openvpn by its
# path, which is under this script's mktemp directory; every wait is a count
# of tenths, at most ten seconds.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "vpn_switch.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "vpn_switch.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8) to check the result with"
command -v python3 >/dev/null 2>&1 || skip "no python3 for the fake openvpn"
command -v pkill >/dev/null 2>&1 || skip "no pkill (procps), so this could not clean up after itself"
[ -x "$build/ncfg" ] && [ -x "$build/netcfgd" ] || skip "ncfg and netcfgd are not built"
[ "$(id -u)" = 0 ] || skip "needs root, or unshare -rn"
ip link add ncfg-wg-probe type wireguard 2>/dev/null || skip "this kernel makes no WireGuard link"
ip link del ncfg-wg-probe

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-vpn-switch.XXXXXX")
fake="$work/bin/openvpn"
daemon=
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	pkill -f "$fake" 2>/dev/null || true
	ip link del wg0 2>/dev/null || true
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc/secrets" "$work/run" "$work/bin"
chmod 700 "$work/etc/secrets"
cp "$repo/tests/live/fake_openvpn.py" "$fake"
chmod +x "$fake"
python3 -c 'import base64; print(base64.b64encode(bytes(range(1, 33))).decode())' \
	> "$work/etc/secrets/wg0"
chmod 600 "$work/etc/secrets/wg0"
echo "# netcfgd does not read this file" > "$work/etc/work.ovpn"

cat > "$work/etc/netcfgd.conf" <<CONF
device wg0 {
	wireguard {
		private_key = "@secret:wg0"
		listen_port = 51820
	}
}
interface wg0 {
	config = "10.9.0.2/24"
}
device vpn0 {
	openvpn { config = "$work/etc/work.ovpn" }
}
interface vpn0 { config = "null" }
CONF

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
# `yes` once the condition holds, `no` after ten seconds of it not holding.
within() {
	waited=0
	until sh -c "$1" 2>/dev/null; do
		waited=$((waited + 1))
		if [ "$waited" -gt 100 ]; then
			echo no
			return
		fi
		sleep 0.1
	done
	echo yes
}
wg_up='ip -o link show wg0 | grep -q "[<,]UP[,>]"'
wg_down='ip -o link show wg0 | grep -qv "[<,]UP[,>]"'
wg_addressed='ip -o -4 addr show dev wg0 | grep -q 10.9.0.2/24'
# `openvp[n]`, not the path: these run under `sh -c`, whose own command line
# holds the pattern, and `pgrep -f` would find that shell and call it openvpn.
vpn_running="pgrep -f '$work/bin/openvp[n]' >/dev/null"
vpn_stopped="! pgrep -f '$work/bin/openvp[n]' >/dev/null"
tunnel() {
	NCFG_RUN_DIR="$work/run" "$build/ncfg" tunnel "$@" 2>&1
}

ip link set lo up
env NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run" NCFG_OPENVPN="$fake" \
	FAKE_OPENVPN_LOG="$work/openvpn.log" \
	"$build/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!
check "the daemon comes up and applies" "$(within "[ -e '$work/run/fuzznet.sock' ] && $wg_addressed")" yes
check "  with openvpn started" "$(within "$vpn_running")" yes

said=$(tunnel down wg0)
check "ncfg tunnel down wg0 is answered" "$(echo "$said" | grep -c 'asked for wg0 down')" 1
check "  and the link is down before the answer" "$(sh -c "$wg_down" && echo yes || echo no)" yes
check "  held by a switch in a drop-in of its own" \
	"$(cat "$work/etc/conf.d/tunnel-wg0.conf" 2>/dev/null)" "switch wg0 { up = false }"

said=$(tunnel up wg0)
check "ncfg tunnel up wg0 is answered" "$(echo "$said" | grep -c 'asked for wg0 up')" 1
check "  and the link is up before the answer" "$(sh -c "$wg_up" && echo yes || echo no)" yes
check "  with its address" "$(sh -c "$wg_addressed" && echo yes || echo no)" yes
check "  and the drop-in is gone, the operator's word back" \
	"$([ -e "$work/etc/conf.d/tunnel-wg0.conf" ] && echo present || echo absent)" absent

said=$(tunnel down vpn0)
check "ncfg tunnel down vpn0 is answered" "$(echo "$said" | grep -c 'asked for vpn0 down')" 1
check "  and openvpn is stopped, not left behind a down link" "$(within "$vpn_stopped")" yes

said=$(tunnel up vpn0)
check "ncfg tunnel up vpn0 is answered" "$(echo "$said" | grep -c 'asked for vpn0 up')" 1
check "  and openvpn is started again" "$(within "$vpn_running")" yes

# The operator's own `enabled = false`: removing the drop-in would leave the
# tunnel off having been told on, so `up` holds it up instead.
sed -i 's/config = "10.9.0.2\/24"/config = "10.9.0.2\/24"\n\tenabled = false/' "$work/etc/netcfgd.conf"
NCFG_RUN_DIR="$work/run" "$build/ncfg" reload > /dev/null 2>&1 || true
tunnel up wg0 > /dev/null
check "a tunnel its own block disables is held up when turned on" \
	"$(cat "$work/etc/conf.d/tunnel-wg0.conf" 2>/dev/null)" "switch wg0 { up = true }"
check "  and is up" "$(sh -c "$wg_up" && echo yes || echo no)" yes

check "a device that is not a tunnel is refused by name" \
	"$(tunnel up lo | grep -c 'lo is not a tunnel')" 1

echo
if [ "$failures" -eq 0 ]; then
	echo "vpn_switch.sh: all checks passed"
else
	echo "vpn_switch.sh: $failures check(s) failed"
	sed -n '1,40p' "$work/daemon.log"
	exit 1
fi
