#!/bin/sh
# The modem reporting contract, from the side a helper writes.
#
#     unshare -rn sh tests/live/modem.sh
#
# Decisions 0044 and 0045 put modem support in a helper that netcfgd does not
# start, supervise or speak to: it writes a file, netcfgd reads it. The whole
# interface is `docs/modem-report.md`.
#
# So this test *is* a helper, in the sense that matters. It writes the file the
# way the document tells somebody to write it -- a shell script wrapped around
# what the modem said, which is exactly what a `umbim` or `mbimcli` helper is --
# and then asks netcfgd what it saw. If this script has to do anything the
# document does not describe, the document is wrong.
#
# There is no modem here and there does not need to be one. netcfgd's half of
# the contract is reading a file, and that is the half being checked.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "modem.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "modem.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d /tmp/ncfg-modem.XXXXXX)
cleanup() { rm -rf "$work"; }
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

# A stand-in for the modem's interface. netcfgd does not care what kind of
# device it is -- the report is keyed on the name, and a real one would be a
# `wwan0` from `cdc_mbim`.
ip link add wwan0 type dummy
ip link set wwan0 up
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface wwan0 {
	kind   = "dummy"
	config = "null"
}
CONF

# The directory the contract names. A helper creates it; netcfgd does not,
# because netcfgd is not the one reporting.
mkdir -p "$work/run/modem"

report() {
	# Atomically, as the document tells a helper to: netcfgd may read at any
	# moment and a half-written file is a file it will believe.
	cat > "$work/run/modem/.wwan0.tmp"
	mv "$work/run/modem/.wwan0.tmp" "$work/run/modem/wwan0"
}

seen() {
	"$ncfg" status --json 2>/dev/null | python3 -c '
import json,sys
observed = json.load(sys.stdin)
found = [m for m in observed.get("modems", []) if m["interface"] == "wwan0"]
if not found:
    print("no report")
else:
    m = found[0]
    print(" ".join(m["addresses"] + m["gateways"] + m["nameservers"]) or "empty")
'
}

# ------------------------------------------------ nothing reported, no modem

check "a machine with no helper running reports no modem" "$(seen)" "no report"

# ------------------------------------------------- the documented example

# Verbatim from docs/modem-report.md. If this stops matching the document, one
# of the two is wrong and it is not the document.
report <<'EOF'
# wwan0, connected 2026-07-31T14:02:11Z via three.co.uk
address=10.64.1.23/30
gateway=10.64.1.24
dns=8.8.8.8
dns=2001:4860:4860::8888
EOF
check "the documented example is read as the document describes" "$(seen)" \
	"10.64.1.23/30 10.64.1.24 8.8.8.8 2001:4860:4860::8888"

# The text output says it was *reported*, not applied, which is the true state:
# netcfgd has no addressing source for this yet. An operator who could not tell
# those apart would have no way to know which half was broken.
"$ncfg" status > "$work/status.txt" 2>&1 || true
check "and the text output does not claim it was applied" \
	"$(grep -c 'reported by a modem helper, not applied' "$work/status.txt" || true)" "3"
# Really not applied: the interface has no address on it.
check "the interface really does not carry the address" \
	"$(ip -4 addr show wwan0 | grep -c '10.64.1.23' || true)" "0"

# ------------------------------------- a helper that knows more than netcfgd

# The contract promises unknown keys are ignored, so a helper can report things
# a later netcfgd will use without waiting for it. A reader that refused here
# would break every helper the day it learned a new field.
report <<'EOF'
operator=three.co.uk
mtu=1428
signal=-71
address=10.64.1.23/30
EOF
check "a helper may report more than netcfgd understands" "$(seen)" "10.64.1.23/30"

# --------------------------------------------------- the bearer going down

# Truncated rather than removed, which is what the document asks a running
# helper to do: it distinguishes "connected to nothing" from "nobody is
# watching this modem".
report < /dev/null
check "an empty report is a bearer that is down, and says so" "$(seen)" "empty"

rm -f "$work/run/modem/wwan0"
check "and a removed report is nobody watching" "$(seen)" "no report"

echo
if [ "$failures" -eq 0 ]; then
	echo "modem.sh: all checks passed"
else
	echo "modem.sh: $failures check(s) failed"
	exit 1
fi
