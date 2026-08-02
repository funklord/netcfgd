#!/bin/sh
# A real OpenVPN, told not to install its own routes.
#
#     unshare -rn sh tests/live/tunnel.sh
#
# openvpn.sh checks the lifecycle against a fake daemon that speaks the real
# management protocol. This checks the half a fake cannot: what the *real*
# daemon puts in the environment of the script netcfgd generated, and whether
# what comes back out of it is a route the kernel accepted.
#
# Decision 0047 makes a tunnel's routes netcfgd's and leaves its address with
# the daemon. Decision 0048 says what that costs and how it is done: the daemon
# is started with `--route-noexec` and a `--route-up` script that writes
# `docs/interface-report.md`, and netcfgd installs what the script reported with
# a metric derived from `preference`.
#
# There is no VPN server here and there does not need to be one. Static-key
# point-to-point mode has no handshake, so the tunnel is up as soon as the tun
# device is open -- which is the moment route-up runs. The routes come from the
# config file rather than from a server push, and they reach the script's
# environment by exactly the same road: `--route` and a pushed route are the
# same option list by the time `setenv_routes` sees them.
#
# Not run under NCFG_LIVE, for the reason ap.sh is not: openvpn is a package a
# machine with no VPN has no reason to have, and a missing one is a skip rather
# than a failed suite. To run it against an uninstalled openvpn:
#
#     apt-get download openvpn && dpkg-deb -x openvpn_*.deb /tmp/ovpn
#     PATH=/tmp/ovpn/usr/sbin:$PATH unshare -rn sh tests/live/tunnel.sh

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "tunnel.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "tunnel.sh: skipping: $1"
	exit 0
}

# The same search order netcfgd uses, so a test that found openvpn somewhere
# netcfgd does not look cannot pass while netcfgd reports it missing.
find_openvpn() {
	for dir in /usr/sbin /sbin /usr/local/sbin /usr/bin; do
		if [ -x "$dir/openvpn" ]; then
			echo "$dir/openvpn"
			return 0
		fi
	done
	command -v openvpn 2>/dev/null
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"
openvpn=$(find_openvpn) || skip "openvpn is not installed (apt install openvpn)"
[ -c /dev/net/tun ] || skip "no /dev/net/tun, so no tunnel can be opened"

work=$(mktemp -d /tmp/ncfg-tunnel.XXXXXX)
cleanup() {
	"$repo/target/debug/ncfg" apply > /dev/null 2>&1 || true
	pkill -f "netcfgd-vpn0" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
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

ip link set lo up

# The operator's file, which netcfgd hands over unread (decision 0046). Its
# routes stand in for what a server pushes; openvpn puts both in the same
# option list and the script sees no difference.
#
# BF-CBC is openvpn 2.6's static-key default and OpenSSL 3 has dropped it, so
# the cipher has to be named or the daemon exits before it opens the device.
"$openvpn" --genkey secret "$work/etc/static.key" >/dev/null 2>&1 \
	|| skip "this openvpn will not generate a static key"
cat > "$work/etc/work.ovpn" <<OVPN
dev-type tun
ifconfig 10.8.0.1 10.8.0.2
secret $work/etc/static.key
remote 127.0.0.1
port 1194
nobind
cipher AES-256-CBC
data-ciphers AES-256-GCM:AES-256-CBC
route 10.9.0.0 255.255.255.0
route 10.10.0.0 255.255.0.0 192.168.99.1
ping-exit 60
verb 3
OVPN

# `routes = "default"` is decision 0048's answer to the one thing openvpn will
# not tell a --route-up script: that the server asked for `redirect-gateway`.
# The record recommends writing it in the document instead, so the recommendation
# is checked here rather than asserted there.
cat > "$work/etc/netcfgd.conf" <<CONF
interface vpn0 {
	preference = 700
	routes     = "default"
	openvpn { config = "$work/etc/work.ovpn" }
}
CONF

"$ncfg" apply > "$work/apply.txt" 2>&1 || true

# The tunnel negotiates after the apply returns -- `--daemon` is why the apply
# does not block on it -- so the report arrives later, which is the ordering
# decision 0047 warned about and PPPoE already had.
report="$work/run/reported/vpn0"
waited=0
while [ ! -f "$report" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 100 ] && break
	sleep 0.1
done
check "the real openvpn ran the script netcfgd generated" \
	"$([ -f "$report" ] && echo yes || echo no)" "yes"
if [ ! -f "$report" ]; then
	echo "--- openvpn said:"
	tail -20 "$work/run/openvpn/vpn0.log" 2>/dev/null || true
fi

# The netmask arrives dotted and the report carries a prefix length, which is
# the one conversion the script does. A wrong one here would be a route to
# somewhere else entirely.
check "and reported the route with its mask converted" \
	"$(grep -c '^route=10.9.0.0/24 via 10.8.0.2$' "$report" 2>/dev/null || true)" "1"
# openvpn fills in the gateway even where the config gave none: it becomes the
# tunnel's own endpoint. Where the config *did* give one, that is what comes
# through.
check "and kept the gateway the config named" \
	"$(grep -c '^route=10.10.0.0/16 via 192.168.99.1$' "$report" 2>/dev/null || true)" "1"

# Nothing was installed by openvpn itself, which is what --route-noexec buys.
# Checked before netcfgd's second apply, or the two are indistinguishable.
check "and installed none of them itself" \
	"$(ip -4 route show | grep -c '10\.9\.0\.0/24' || true)" "0"

# The address, which stays with the daemon (decision 0047): openvpn applied it
# and netcfgd neither installs nor removes it.
check "the daemon addressed its own tunnel" \
	"$(ip -4 addr show vpn0 2>/dev/null | grep -c '10\.8\.0\.1' || true)" "1"
check "and the report says nothing about the address" \
	"$(grep -c '^address=' "$report" 2>/dev/null || true)" "0"

# The second apply is the one that installs them, from the report.
"$ncfg" apply > "$work/apply2.txt" 2>&1 || true
check "netcfgd installed the route the daemon negotiated" \
	"$(ip -4 route show 10.9.0.0/24 | grep -c 'dev vpn0' || true)" "1"
# The whole reason for taking them. A metric openvpn chose could not be ranked
# against a wired link's; this one is the number the operator wrote down.
check "with the interface's preference as its metric" \
	"$(ip -4 route show 10.9.0.0/24 | grep -c 'metric 700' || true)" "1"
check "and tagged as netcfgd's, so it can be withdrawn again" \
	"$(ip -4 route show 10.9.0.0/24 | grep -c 'proto 110' || true)" "1"

# The document's own default route down the tunnel: a device route, because a
# tun is point-to-point and needs no gateway -- the same answer a PPPoE session
# gets. This is what an operator writes in place of a `redirect-gateway` the
# daemon will not report, and it is ranked by the same `preference`.
check "a default route written in the document goes down the tunnel" \
	"$(ip -4 route show default | grep -c 'dev vpn0' || true)" "1"
check "with the same preference, so it can be ranked against another uplink" \
	"$(ip -4 route show default | grep -c 'metric 700' || true)" "1"

"$ncfg" plan > "$work/replan.txt" 2>&1 || true
check "and the next plan has nothing to do" \
	"$(grep -cE 'route\.' "$work/replan.txt" || true)" "0"

# Stopping. The report goes with the tunnel: a route netcfgd holds for a tunnel
# that is gone black-holes traffic another interface would have carried, which
# is the same failure a stale modem report causes.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface vpn0 { kind = "dummy"; config = "null" }
CONF
"$ncfg" apply > "$work/stop.txt" 2>&1 || true
# "Names no routes" rather than "the file is gone", because both are correct
# and which one happens is a race netcfgd does not control: netcfgd removes the
# report and openvpn's own --down script may write an empty one afterwards,
# whenever it gets round to exiting. The contract gives gone and empty the same
# meaning on purpose, and this is the assertion that holds either way.
#
# Both were seen on this machine across two runs of this script, which is what
# a race looks like when only one side is asserted.
left=$(grep -c '^route=' "$report" 2>/dev/null || true)
check "the report claims no routes once the tunnel is stopped" "${left:-0}" "0"
check "and the routes with it" \
	"$(ip -4 route show | grep -c '10\.9\.0\.0/24' || true)" "0"

echo
if [ "$failures" -eq 0 ]; then
	echo "tunnel.sh: all checks passed"
else
	echo "tunnel.sh: $failures check(s) failed"
	exit 1
fi
