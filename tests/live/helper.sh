#!/bin/sh
# The reference modem helper, end to end into netcfgd.
#
#     unshare -rn sh tests/live/helper.sh
#
# modem.sh checks netcfgd's half of the contract by writing the report itself.
# This checks the other half: the real `helpers/netcfgd-modem-mbim`, driven
# against a fake `mbimcli`, writing a report that netcfgd then reads and
# applies. Between the two the whole path is covered without a modem.
#
# The fake is a fake *modem*, not a fake format -- every line it prints is the
# `g_print` out of libmbim 1.32's `mbimcli_print_ip_config`, spacing included,
# because the helper matches on the spacing. Guessing that format from the
# manual page would be guessing; this is copied from the implementation, which
# is the same standard the hostapd station parser was held to.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "helper.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "helper.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d /tmp/ncfg-helper.XXXXXX)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_RESOLV_CONF="$work/resolv.conf"
export MBIMCLI="$repo/tests/live/fake_mbimcli.sh"
export FAKE_MBIMCLI_LOG="$work/mbimcli.log"
ncfg="$repo/target/debug/ncfg"
helper="$repo/helpers/netcfgd-modem-mbim"

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

[ -x "$helper" ] || skip "the helper is not executable"

ip link add wwan0 type dummy
cat > "$work/etc/netcfgd.conf" <<'CONF'
global { dns { dns_mode = "write_resolv_conf" } }

interface wwan0 {
	kind   = "dummy"
	config = "modem"
}
CONF

# ------------------------------------------------------------------ connect

# A failure here is a failure, not a skip. `skip` is for an environment that
# cannot run the test -- no ip(8), no built binary -- and the helper refusing to
# connect against a fake that always succeeds is the test finding something.
# Written as a skip first, and breaking the parser proved it: every downstream
# check went unreached and the suite reported no failures at all.
if ! sh "$helper" connect -d /dev/cdc-wdm0 -i wwan0 -a internet > "$work/connect.txt" 2>&1; then
	echo "FAIL the helper could not connect against a fake that always succeeds"
	sed 's/^/       /' "$work/connect.txt"
	failures=$((failures + 1))
fi

check "the helper connected with the apn it was given" \
	"$(grep -c -- '--connect=access-string=internet' "$FAKE_MBIMCLI_LOG" || true)" "1"
# Through the proxy, without which each invocation opens and closes the control
# device -- and closing it drops the session on a good many modems, so the
# connect would succeed and the query would come back empty.
check "and through the proxy, so the session survives the second command" \
	"$(grep -c -- '--device-open-proxy' "$FAKE_MBIMCLI_LOG" || true)" "2"

check "and wrote a report where the contract says" \
	"$([ -f "$work/run/modem/wwan0" ] && echo yes || echo no)" "yes"
# Both families, from libmbim's own output format. The v4 and v6 sections use
# the same labels, which is exactly the thing a hand-written parser gets wrong.
check "with both families' addresses" \
	"$(sed -n 's/^address=//p' "$work/run/modem/wwan0" | tr '\n' ' ')" \
	"10.64.1.23/30 2001:db8::2/64 "
check "both gateways" \
	"$(sed -n 's/^gateway=//p' "$work/run/modem/wwan0" | tr '\n' ' ')" \
	"10.64.1.24 2001:db8::1 "
check "and every nameserver" \
	"$(sed -n 's/^dns=//p' "$work/run/modem/wwan0" | tr '\n' ' ')" \
	"8.8.8.8 8.8.4.4 2001:4860:4860::8888 "
# Reported although netcfgd ignores it, because the contract promises unknown
# keys are skipped -- so the helper needs no change the day netcfgd uses it.
check "and the mtu, which netcfgd does not use yet" \
	"$(sed -n 's/^mtu=//p' "$work/run/modem/wwan0")" "1428"

# --------------------------------------------- and netcfgd acts on all of it

"$ncfg" apply > "$work/apply.txt" 2>&1 || true
check "netcfgd installed the address the helper reported" \
	"$(ip -4 addr show wwan0 | grep -c '10.64.1.23/30' || true)" "1"
check "the default route" \
	"$(ip -4 route show default | grep -c 'via 10.64.1.24 dev wwan0' || true)" "1"
check "and the nameserver" \
	"$(grep -c '^nameserver 8.8.8.8' "$work/resolv.conf" 2>/dev/null || true)" "1"

# --------------------------------------------------------------- disconnect

sh "$helper" disconnect -d /dev/cdc-wdm0 -i wwan0 > /dev/null 2>&1 || true
check "disconnecting empties the report rather than removing it" \
	"$([ -f "$work/run/modem/wwan0" ] && echo yes || echo no)" "yes"
check "and it names no addresses" \
	"$(grep -c '^address=' "$work/run/modem/wwan0" || true)" "0"

"$ncfg" apply > "$work/down.txt" 2>&1 || true
check "so netcfgd takes the address back off" \
	"$(ip -4 addr show wwan0 | grep -c '10.64.1.23/30' || true)" "0"
check "and the route with it" \
	"$(ip -4 route show default | grep -c 'dev wwan0' || true)" "0"

sh "$helper" stop -i wwan0
check "stopping removes the report entirely" \
	"$([ -f "$work/run/modem/wwan0" ] && echo yes || echo no)" "no"

# ------------------------------------------------------------- the refusals

# A bearer that connects and gets no address is not a bearer. Writing an empty
# report would tell netcfgd the modem is down when it is up and misconfigured,
# which sends somebody to look at the wrong thing.
FAKE_MBIMCLI_NO_ADDRESS=1 sh "$helper" connect -d /dev/cdc-wdm0 -i wwan0 -a internet \
	> "$work/noaddr.txt" 2>&1 && result=0 || result=$?
check "a connection that yields no address fails rather than reporting nothing" \
	"$result" "1"
check "and says so" \
	"$(grep -c 'gave no address' "$work/noaddr.txt" || true)" "1"
check "and leaves no report behind" \
	"$([ -f "$work/run/modem/wwan0" ] && echo yes || echo no)" "no"

FAKE_MBIMCLI_CONNECT_FAILS=1 sh "$helper" connect -d /dev/cdc-wdm0 -i wwan0 -a internet \
	> "$work/nocon.txt" 2>&1 && result=0 || result=$?
check "a refused connection is a failure" "$result" "1"
check "naming the interface and the apn" \
	"$(grep -c 'could not connect wwan0 via internet' "$work/nocon.txt" || true)" "1"

echo
if [ "$failures" -eq 0 ]; then
	echo "helper.sh: all checks passed"
else
	echo "helper.sh: $failures check(s) failed"
	exit 1
fi
