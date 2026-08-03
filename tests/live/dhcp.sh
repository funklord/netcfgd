#!/bin/sh
# DHCPv4 end to end: a real client, a real server, a real lease.
#
# Nothing in this suite had ever driven a v4 client. That is how netcfgd came to
# invoke `udhcpc` with no `-s` for as long as the fallback existed -- busybox's
# client has no configuration step of its own, so it obtained a lease and did
# nothing with it, on every machine that has busybox and no dhcpcd. Which is most
# Debian machines. Decision 0065.
#
# The server is `busybox udhcpd` on the far end of a veth pair, so this needs no
# package that a build machine would not have if it has busybox at all -- and both
# ends are real: a real protocol exchange, a real lease, and netcfgd's own generated
# script putting the address on the interface.
#
# Runs under `unshare -rn`: the server binds port 67, which a user namespace's root
# may do, and the veth pair is namespace-local.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "dhcp.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "dhcp.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"
command -v busybox >/dev/null 2>&1 || skip "no busybox (which is the client and the server here)"
busybox --list | grep -qx udhcpd || skip "this busybox has no udhcpd applet"
busybox --list | grep -qx udhcpc || skip "this busybox has no udhcpc applet"

work=$(mktemp -d /tmp/ncfg-dhcp.XXXXXX)
server=
cleanup() {
	[ -n "$server" ] && kill "$server" 2>/dev/null
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

# The server side of the wire. netcfgd never touches `srv`.
ip link add cli type veth peer name srv
ip link set srv up
ip addr add 10.44.0.1/24 dev srv

cat > "$work/udhcpd.conf" <<EOF
start 10.44.0.20
end 10.44.0.20
interface srv
option subnet 255.255.255.0
option router 10.44.0.1
option dns 10.44.0.53
option lease 600
lease_file $work/udhcpd.leases
pidfile $work/udhcpd.pid
EOF
: > "$work/udhcpd.leases"
busybox udhcpd -f "$work/udhcpd.conf" > "$work/udhcpd.log" 2>&1 &
server=$!

# netcfgd's side. A static address beside the lease, deliberately: the generated
# script's `deconfig` must remove what *it* added and leave this one alone, where a
# stock udhcpc script flushes the interface and would take it with it.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface cli {
	config = "dhcp 10.44.9.9/24"
}
CONF

# busybox is one binary and Debian ships no `udhcpc` symlink beside it, so the name
# netcfgd looks for first is not there. That is the second half of the defect: the
# fallback was unreachable on the machines most likely to need it.
if ! command -v udhcpc >/dev/null 2>&1; then
	echo "dhcp.sh: no udhcpc in PATH, so the busybox applet is what gets used"
fi

if ! "$ncfg" apply > "$work/apply.log" 2>&1; then
	if grep -q 'Operation not permitted' "$work/apply.log"; then
		skip "no CAP_NET_ADMIN (run under unshare -rn)"
	fi
	echo "dhcp.sh: apply failed" >&2
	cat "$work/apply.log" >&2
	exit 1
fi
contains "the client is started" "$(cat "$work/apply.log")" "backend.start cli"

# The lease arrives asynchronously: udhcpc discovers, selects, and only then runs
# the script. A second is generous on a veth with the server already listening.
waited=0
while ! ip -4 -br addr show cli | grep -q 10.44.0.20; do
	waited=$((waited + 1))
	if [ "$waited" -gt 50 ]; then
		echo "FAIL the lease never reached the interface"
		echo "       udhcpd said:"
		sed 's/^/       /' "$work/udhcpd.log"
		echo "       the script netcfgd generated:"
		sed 's/^/       /' "$work/run/udhcpc/cli.script" 2>/dev/null || true
		failures=$((failures + 1))
		break
	fi
	sleep 0.1
done

addresses=$(ip -4 -br addr show cli)
contains "the lease is on the interface"       "$addresses" "10.44.0.20/24"
contains "and the static address is still there" "$addresses" "10.44.9.9/24"
contains "and the lease's default route is installed" \
	"$(ip -4 route show default dev cli)" "via 10.44.0.1"

# What netcfgd makes of it: the address is the client's, not netcfgd's, exactly as a
# dhcpcd lease is (0004). So it is not tagged, and netcfgd will not remove it.
status=$("$ncfg" status 2>/dev/null | sed -n '/^cli /,/^[^ ]/p')
# `Foreign` on a kernel that reports `IFA_PROTO` and `Unknown` on one older than
# 5.18, where the answer comes from netcfgd's own records and cannot be definite
# (0002). Both mean "not netcfgd's", and neither may be removed -- so what is
# asserted is that it is not `Ours`, which is the property that matters and the one
# that holds on either kernel.
lease_line=$(printf '%s\n' "$status" | grep '10.44.0.20/24' || true)
case "$lease_line" in
*"[Ours]"*)
	echo "FAIL netcfgd claimed the client's lease as its own"
	echo "       actual: $lease_line"
	failures=$((failures + 1))
	;;
*"[Foreign]"* | *"[Unknown]"*) echo "ok   netcfgd reports the lease as somebody else's" ;;
*)
	echo "FAIL netcfgd reports the lease as somebody else's"
	echo "       actual: $lease_line"
	failures=$((failures + 1))
	;;
esac
contains "and its own address as its own"                "$status" "10.44.9.9/24 [Ours]"
contains "a second plan has nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# The MTU and resolv.conf are the two things the script leaves alone, because the
# document owns one and netcfgd's DNS backend owns the other. The server offers no
# MTU here; what is checked is that the interface still has the kernel default
# rather than anything a lease talked it into.
check "the script left the MTU alone" \
	"$(ip link show cli | grep -c 'mtu 1500')" "1"

# Stopping it. `dhcpcd -k` does nothing to a udhcpc, so netcfgd used to leave the
# client running forever with no pid file to find it by.
[ -r "$work/run/udhcpc/cli.pid" ] &&
	echo "ok   the client wrote a pid file where netcfgd told it to" ||
	{
		echo "FAIL the client wrote a pid file where netcfgd told it to"
		failures=$((failures + 1))
	}
pid=$(cat "$work/run/udhcpc/cli.pid" 2>/dev/null || echo 0)

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface cli { config = "10.44.9.9/24" }
CONF
"$ncfg" apply > "$work/apply-stop.log" 2>&1 || {
	cat "$work/apply-stop.log" >&2
	exit 1
}
contains "dropping dhcp stops the client" "$(cat "$work/apply-stop.log")" "backend.stop cli"
waited=0
while kill -0 "$pid" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 30 ] && break
	sleep 0.1
done
if kill -0 "$pid" 2>/dev/null; then
	echo "FAIL and the client is gone"
	echo "       pid $pid is still running"
	failures=$((failures + 1))
else
	echo "ok   and the client is gone"
fi

# And what the client added went with it, while netcfgd's own address stayed. This
# is the check a stock `deconfig` would fail: it flushes the interface.
remaining=$(ip -4 -br addr show cli)
contains "the static address survived the client leaving" "$remaining" "10.44.9.9/24"
case "$remaining" in
*10.44.0.20*)
	echo "FAIL the lease address was left behind"
	echo "       actual: $remaining"
	failures=$((failures + 1))
	;;
*) echo "ok   and the lease address is gone" ;;
esac

echo
if [ "$failures" -eq 0 ]; then
	echo "dhcp.sh: all checks passed"
else
	echo "dhcp.sh: $failures failed"
	exit 1
fi
