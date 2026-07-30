#!/bin/sh
# Ingress shaping against a real kernel.
#
# The kernel cannot queue traffic on the way in -- by the time it can be
# classified it has already arrived -- so shaping it means redirecting it onto
# an `ifb`, where it becomes egress. That is three objects (a device, an
# ingress hook with a redirect filter on it, and a shaper on the ifb) standing
# in for one config key, and every one of them can be present while the path as
# a whole does nothing.
#
# So this checks the path, not the pieces: tc(8) is asked whether the filter
# really points at the ifb, because a redirect to the wrong device is a
# configuration that looks complete and shapes nothing.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "ingress.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "ingress.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

tc=
for candidate in /sbin/tc /usr/sbin/tc; do
	[ -x "$candidate" ] && tc=$candidate && break
done

work=$(mktemp -d /tmp/ncfg-ingress.XXXXXX)
daemon=
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
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

exists() { ip -br link show "$1" >/dev/null 2>&1 && echo yes || echo no; }

write_config() { cat > "$work/etc/netcfgd.conf"; }

apply() {
	if ! "$ncfg" apply > "$work/apply.log" 2>&1; then
		echo "FAIL apply: $1"
		cat "$work/apply.log"
		failures=$((failures + 1))
	fi
}

"$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		if grep -q 'Operation not permitted' "$work/daemon.log" 2>/dev/null; then
			skip "no CAP_NET_ADMIN (run under unshare -rn)"
		fi
		cat "$work/daemon.log" >&2
		echo "ingress.sh: the daemon never started" >&2
		exit 1
	fi
	sleep 0.1
done

write_config <<'CONF'
interface wan0 {
	veth   { peer = "wan0p" }
	config = "10.6.0.1/24"
	qdisc {
		kind              = "cake"
		bandwidth         = "100mbit"
		ingress_bandwidth = "50mbit"
	}
}
CONF

apply "the first apply"
if grep -q 'missing `cls_matchall`' "$work/apply.log" 2>/dev/null; then
	skip "this kernel has no cls_matchall or act_mirred"
fi

# One config key, three objects.
check "the ifb device is created" "$(exists ifb-wan0)" "yes"
check "netcfgd reports the redirect" \
	"$("$ncfg" status 2>/dev/null | grep -c 'ingress redirected to ifb-wan0' || true)" "1"
check "the ifb carries an inbound shaper" \
	"$("$ncfg" status 2>/dev/null | grep -c 'qdisc cake at 50000000 bit/s inbound' || true)" "1"

if [ -n "$tc" ]; then
	# The check this file exists for. Every object above can be present while
	# the filter points somewhere else, or matches only IPv4, and the result
	# is a path that looks configured and shapes nothing.
	check "the hook is attached" \
		"$("$tc" qdisc show dev wan0 ingress | grep -c 'qdisc ingress' || true)" "1"
	check "the filter redirects to the ifb" \
		"$("$tc" filter show dev wan0 ingress | grep -c 'Egress Redirect to device ifb-wan0' || true)" "1"
	check "and it matches every protocol, not just IPv4" \
		"$("$tc" filter show dev wan0 ingress | grep -c 'protocol all' || true)" "2"
	check "cake on the ifb is in ingress mode" \
		"$("$tc" qdisc show dev ifb-wan0 | grep -c ' ingress ' || true)" "1"
fi

# Idempotence: three objects that each have to be recognised as already
# present. Missing any one reinstalls the whole path on every apply.
plan=$("$ncfg" plan 2>&1)
check "a second plan has nothing to do" \
	"$(printf '%s' "$plan" | grep -cE 'ingress\.|qdisc\.|link\.create' || true)" "0"

# Dropping the key takes the whole path away, including the device netcfgd
# created for it.
write_config <<'CONF'
interface wan0 {
	veth   { peer = "wan0p" }
	config = "10.6.0.1/24"
	qdisc {
		kind      = "cake"
		bandwidth = "100mbit"
	}
}
CONF
apply "dropping ingress shaping"
check "the redirect is gone" \
	"$("$ncfg" status 2>/dev/null | grep -c 'ingress redirected' || true)" "0"
check "and the ifb device with it" "$(exists ifb-wan0)" "no"
if [ -n "$tc" ]; then
	check "the ingress hook is gone too" \
		"$("$tc" qdisc show dev wan0 ingress | grep -c 'qdisc ingress' || true)" "0"
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "ingress.sh: all checks passed"
else
	echo "ingress.sh: $failures failed"
	exit 1
fi
