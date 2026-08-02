#!/bin/sh
# A real PPPoE session, which is the part nobody had.
#
#     sudo sh tests/live/pppoe-session.sh
#
# `ppp.sh` checks what netcfgd hands pppd against a real pppd, and stops where
# an unprivileged machine has to: `/dev/ppp` is root-only and the rp-pppoe
# plugin opens it while options are still being parsed. So nothing had ever
# dialled -- the options file, the generated scripts, the report and the
# delivery were each checked separately and never once end to end.
#
# This dials. There is no DSL line and there does not need to be one: a veth
# pair is an ethernet segment, `pppoe-server` is the access concentrator, and
# what happens between them is a real PPPoE discovery and a real IPCP
# negotiation. The nameservers netcfgd ends up delivering are the ones the
# server pushed, over the wire, in the protocol's own option.
#
# **Needs real root** -- the same bucket as `hwsim.sh` and for the same reason.
# `make live` invokes it either way and an unprivileged run skips, which means
# an unprivileged suite is not evidence about any of this: run the suite as
# root, or run this script with `sudo`. It confines itself to a private
# network *and* mount namespace, so the veths, the ppp interface and pppd's own
# `/etc/ppp/resolv.conf` all disappear with it and the host's network is never
# touched.
#
# It has been run, which is the point of writing it down: a privileged container
# is enough (`docker run --rm --privileged -v "$PWD":/repo:ro debian:trixie`,
# then `apt-get install ppp pppoe iproute2` and this script). The first thing it
# found was that netcfgd could dial and could not hang up.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

if [ "$(id -u)" != "0" ]; then
	echo "pppoe-session.sh: needs real root: /dev/ppp is root-only, and the"
	echo "pppoe-session.sh:   rp-pppoe plugin opens it as it loads."
	echo "pppoe-session.sh:   sudo sh tests/live/pppoe-session.sh"
	exit 0
fi

# Re-exec into private network and mount namespaces. Everything below then
# happens somewhere that can be thrown away: without this, the test would run
# pppd on the machine's own network and let it write the host's
# /etc/ppp/resolv.conf.
if [ -z "${NCFG_PPPOE_NS:-}" ]; then
	NCFG_PPPOE_NS=1
	export NCFG_PPPOE_NS
	exec unshare -mn sh "$0" "$@"
fi

for tool in pppd pppoe-server ip; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "pppoe-session.sh: skipping: no $tool (apt install ppp pppoe)"
		exit 0
	}
done
[ -x "$repo/target/debug/ncfg" ] || {
	echo "pppoe-session.sh: skipping: ncfg is not built"
	exit 0
}
[ -c /dev/ppp ] || {
	echo "pppoe-session.sh: skipping: no /dev/ppp (modprobe ppp_generic)"
	exit 0
}

work=$(mktemp -d /tmp/ncfg-pppoe.XXXXXX)
cleanup() {
	pkill -f 'pppoe-server -I isp0' 2>/dev/null || true
	pkill -f "$work/run/ppp" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc/secrets" "$work/run"

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

# pppd's own directory, emptied for the duration. `usepeerdns` makes pppd write
# /etc/ppp/resolv.conf -- its own file, not the system one, which is the fact
# that made the option safe to turn on -- and this is where that gets proved
# rather than read.
mount -t tmpfs tmpfs /etc/ppp
mkdir -p /etc/ppp

ip link set lo up
ip link add isp0 type veth peer name cpe0
ip link set isp0 up
ip link set cpe0 up

# The access concentrator. `noauth` on this side because what is being tested is
# the session and the pushed configuration, not PAP -- netcfgd sends a username
# and password regardless, and a server that does not ask simply does not use
# them.
cat > "$work/ac.options" <<OPTIONS
noauth
lcp-echo-interval 10
lcp-echo-failure 2
ms-dns 195.190.228.10
ms-dns 195.190.228.20
OPTIONS
# The plugin path is not a detail. `pppoe-server` defaults to
# `/etc/ppp/plugins/rp-pppoe.so`, and Debian ships it at
# `/usr/lib/pppd/<version>/rp-pppoe.so` -- so the default fails, and it fails
# in the *server's* forked pppd where nothing the client can see says why. The
# discovery completes, the client reports "Connect: ppp0 <--> cpe0", and then
# IPCP never starts. Found by reading syslog, which is the only place the
# server's child logs.
plugin=$(ls /usr/lib/pppd/*/rp-pppoe.so 2>/dev/null | head -1)
[ -n "$plugin" ] || {
	echo "pppoe-session.sh: skipping: no rp-pppoe.so (apt install pppoe)"
	exit 0
}
pppoe-server -I isp0 -L 10.99.0.1 -R 10.99.0.100 -N 1 -O "$work/ac.options" \
	-g "$plugin" -k > "$work/ac.log" 2>&1 &
# The concentrator has to be listening before the first PADI, or the client
# spends a discovery timeout getting there. pppd would retry -- `persist` and
# `maxfail 0` are in the options file -- but a test that waits on a retry is a
# test that intermittently waits for a long time.
sleep 1

cat > "$work/etc/netcfgd.conf" <<'CONF'
global { dns { dns_mode = "write_resolv_conf" } }

interface ppp0 {
	routes = "default"
	pppoe {
		parent   = "cpe0"
		username = "alice@isp.example"
		password = "@secret:dsl"
	}
	dns { }
}
CONF
printf '%s' 'dsl-password' > "$work/etc/secrets/dsl"
chmod 600 "$work/etc/secrets/dsl"

"$ncfg" apply > "$work/apply.txt" 2>&1 || true

# The session negotiates after the apply returns, exactly as a tunnel's does --
# `persist` keeps pppd going and the interface arrives when IPCP finishes.
report="$work/run/reported/ppp0"
waited=0
while [ ! -f "$report" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 150 ] && break
	sleep 0.1
done

check "a real pppd dialled a real access concentrator" \
	"$(ip -4 addr show ppp0 2>/dev/null | grep -c 'inet ' || true)" "1"
if [ ! -f "$report" ]; then
	echo "--- pppd said:"; tail -20 "$work/apply.txt" || true
	echo "--- the concentrator said:"; tail -20 "$work/ac.log" || true
fi

# The address is IPCP's and stays with pppd (decision 0047). netcfgd neither
# installs it nor removes it, and the report says nothing about it.
check "the daemon addressed its own link" \
	"$(ip -4 addr show ppp0 2>/dev/null | grep -c '10.99.0.100' || true)" "1"
check "and the report says nothing about the address" \
	"$(grep -c '^address=' "$report" 2>/dev/null || true)" "0"

# The nameservers, which arrived in the protocol rather than in a file. This is
# the whole reason `usepeerdns` is on.
check "the server's nameservers came down the wire" \
	"$(grep -c '^dns=195.190.228.10$' "$report" 2>/dev/null || true)" "1"
check "both of them" \
	"$(grep -c '^dns=195.190.228.20$' "$report" 2>/dev/null || true)" "1"

# And pppd wrote its own resolv.conf rather than the system's, which is the
# claim that kept this option out for years. /etc/ppp is a tmpfs here, so its
# existence is this session's doing.
check "pppd wrote its own resolv.conf, not the system's" \
	"$(grep -c '195.190.228.10' /etc/ppp/resolv.conf 2>/dev/null || true)" "1"
# And the file netcfgd manages carries netcfgd's own header rather than pppd's,
# which is the distinction that matters: both files exist, and only one of them
# is written by the thing that says it writes it.
check "and the one netcfgd manages was written by netcfgd" \
	"$(grep -ci 'generated by pppd' "$NCFG_RESOLV_CONF" 2>/dev/null || true)" "0"

# The second apply is the one that delivers them, from the report, because the
# document gave this interface a `dns` block (decision 0049).
"$ncfg" apply > "$work/apply2.txt" 2>&1 || true
check "netcfgd delivered what the ISP pushed" \
	"$(grep -c '^nameserver 195.190.228.10' "$NCFG_RESOLV_CONF" 2>/dev/null || true)" "1"
check "and the default route the document asked for is up" \
	"$(ip -4 route show default | grep -c 'dev ppp0' || true)" "1"

"$ncfg" plan > "$work/replan.txt" 2>&1 || true
check "and the next plan has nothing to do" \
	"$(grep -cE 'addr\.|route\.|dns\.' "$work/replan.txt" || true)" "0"

# A decoy, for the half of hanging up that is a safety property. It is a copy of
# `sleep` called `pppd`, so anything stopping the session by name -- `pkill
# pppd`, `killall pppd` -- takes it with them. netcfgd finds its own session
# through the pid file pppd wrote for this interface and checks
# /proc/<pid>/cmdline names the options file netcfgd generated, so an operator's
# own pppd is not merely unlikely to be hit but cannot be.
cp "$(command -v sleep)" "$work/pppd"
"$work/pppd" 600 &
decoy=$!

# Hanging up. The document stops asking for the session, netcfgd stops pppd,
# and pppd's ip-down script empties the report on the way out.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global { dns { dns_mode = "write_resolv_conf" } }
interface ppp0 { kind = "dummy"; config = "null" }
CONF
"$ncfg" apply > "$work/stop.txt" 2>&1 || true
waited=0
while ip link show ppp0 >/dev/null 2>&1; do
	waited=$((waited + 1))
	[ "$waited" -gt 100 ] && break
	sleep 0.1
done
check "stopping the session takes the interface with it" \
	"$(ip link show ppp0 >/dev/null 2>&1 && echo yes || echo no)" "no"
check "and the report stops naming the ISP's resolvers" \
	"$(grep -c '^dns=' "$report" 2>/dev/null || true)" "0"
check "while somebody else's pppd is left alone" \
	"$(kill -0 "$decoy" 2>/dev/null && echo alive || echo gone)" "alive"
kill "$decoy" 2>/dev/null || true

echo
if [ "$failures" -eq 0 ]; then
	echo "pppoe-session.sh: all checks passed"
else
	echo "pppoe-session.sh: $failures check(s) failed"
	exit 1
fi
