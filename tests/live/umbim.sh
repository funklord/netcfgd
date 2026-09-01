#!/bin/sh
# The umbim modem helper, against a fake `umbim`.
#
#     sh tests/live/umbim.sh
#
# No root and no hardware. What is faked is the modem, not the contract: the
# helper writes a real interface report to a real directory and the assertions
# read it the way netcfgd would.
#
# ## THE CASE THIS EXISTS FOR
#
# `umbim` is stateful across invocations in a way `mbimcli` is not, and the
# sequence is OpenWrt's rather than ours. A helper that sent the right commands
# in the wrong order, or dropped `-n`, would work against a forgiving fake and
# fail on a modem -- so the order is asserted here rather than assumed.
set -eu

repo=$(cd "$(dirname "$0")/../.." && pwd)
helper="$repo/helper/netcfgd-modem-umbim"

work=$(mktemp -d)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM

export NCFG_RUN_DIR="$work/run"
export UMBIM="$repo/tests/live/fake_umbim.sh"
export FAKE_UMBIM_LOG="$work/umbim.log"

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
	case $2 in
	*"$3"*) echo "ok   $1" ;;
	*) echo "FAIL $1"; echo "       expected to contain: $3"; echo "       actual: $2"
	   failures=$((failures + 1)) ;;
	esac
}

report="$NCFG_RUN_DIR/reported/wwan0"

# 1. A connect, end to end into a report netcfgd could read.
: > "$FAKE_UMBIM_LOG"
sh "$helper" connect -d /dev/cdc-wdm0 -i wwan0 -a internet > "$work/connect.txt" 2>&1 || {
	echo "FAIL the helper could not connect against a fake that always succeeds"
	sed 's/^/       /' "$work/connect.txt"
	failures=$((failures + 1))
}

check "the report is where the contract says" \
	"$([ -f "$report" ] && echo yes || echo no)" "yes"
check "a v4 address with no prefix is given one" \
	"$(sed -n 's/^address=\(10\..*\)$/\1/p' "$report")" "10.64.1.23/32"
check "a v6 address that came with a prefix keeps it" \
	"$(sed -n 's/^address=\(2001:db8.*\)$/\1/p' "$report")" "2001:db8::2/64"
check "the gateway is reported" \
	"$(sed -n 's/^gateway=//p' "$report" | tr '\n' ' ')" "10.64.1.24 "
check "both nameservers are reported" \
	"$(grep -c '^dns=' "$report")" "2"

# 2. **The case this file exists for.** The sequence is OpenWrt's, in order,
#    and every setup call carries -n.
check "caps comes first" "$(sed -n '1p' "$FAKE_UMBIM_LOG" | grep -o 'caps')" "caps"
# The command is the word after `-d <device>`, which is where umbim's own
# argument order puts it. Taking the last word instead gives `internet` for
# `connect internet` -- which this assertion did on its first run, and reported
# as the helper skipping a step it had not skipped.
check "and the order is the one OpenWrt uses" \
	"$(awk '{for (i = 1; i <= NF; i++) if ($i == "-d") { print $(i + 2); break }}' \
	   "$FAKE_UMBIM_LOG" | tr '\n' ' ')" \
	"caps pinstate subscriber registration attach connect config "
check "every setup call carries -n" \
	"$(grep -c -- '-n ' "$FAKE_UMBIM_LOG")" "7"
check "and each carries a transaction id" \
	"$(grep -c -- '-t ' "$FAKE_UMBIM_LOG")" "7"
check "which is not reused inside the sequence" \
	"$(sed -n 's/.*-t \([0-9]*\).*/\1/p' "$FAKE_UMBIM_LOG" | sort -u | wc -l)" "7"

# 3. A bearer that connects and gets no address is a failure, not an empty
#    report. An empty one would tell netcfgd the modem is down when it is up
#    and misconfigured.
FAKE_UMBIM_NO_ADDRESS=1 sh "$helper" connect -d /dev/cdc-wdm0 -i wwan0 -a internet \
	> "$work/noaddr.txt" 2>&1 && {
	echo "FAIL a bearer with no address should be a failure"
	failures=$((failures + 1))
}
contains "and says the network gave no address" "$(cat "$work/noaddr.txt")" "gave no address"

# 4. A refused connect names the interface and the APN, so the message says
#    which bearer on which machine.
FAKE_UMBIM_CONNECT_FAILS=1 sh "$helper" connect -d /dev/cdc-wdm0 -i wwan0 -a internet \
	> "$work/nocon.txt" 2>&1 && {
	echo "FAIL a refused connect should be a failure"
	failures=$((failures + 1))
}
contains "naming the interface and the apn" "$(cat "$work/nocon.txt")" \
	"could not connect wwan0 via internet"

# 5. The APN netcfgd published, taken from the file rather than a flag (0152).
mkdir -p "$NCFG_RUN_DIR/modem"
printf 'sim=esim\napn=from.document\n' > "$NCFG_RUN_DIR/modem/wwan0"
: > "$FAKE_UMBIM_LOG"
sh "$helper" connect -d /dev/cdc-wdm0 -i wwan0 > /dev/null 2>&1 || true
contains "the apn is taken from the file netcfgd published" \
	"$(cat "$FAKE_UMBIM_LOG")" "connect from.document"

: > "$FAKE_UMBIM_LOG"
sh "$helper" connect -d /dev/cdc-wdm0 -i wwan0 -a on.the.flag > "$work/over.txt" 2>&1 || true
contains "an explicit apn still wins" "$(cat "$FAKE_UMBIM_LOG")" "connect on.the.flag"
contains "and the disagreement is called out" "$(cat "$work/over.txt")" "overrides"
rm -f "$NCFG_RUN_DIR/modem/wwan0"

# 6. Disconnect empties the report rather than deleting it, and drops -n --
#    the session is being finished rather than handed on.
: > "$FAKE_UMBIM_LOG"
sh "$helper" disconnect -d /dev/cdc-wdm0 -i wwan0 > /dev/null 2>&1 || true
check "the report survives a disconnect" \
	"$([ -f "$report" ] && echo yes || echo no)" "yes"
check "and carries no address" "$(grep -c '^address=' "$report" || true)" "0"
check "the disconnect drops -n" "$(grep -c -- '-n ' "$FAKE_UMBIM_LOG")" "0"

echo
if [ "$failures" -eq 0 ]; then
	echo "umbim.sh: all checks passed"
else
	echo "umbim.sh: $failures failed"
	exit 1
fi
