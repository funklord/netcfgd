#!/bin/sh
# The interface reporting contract, from the side a writer writes.
#
#     unshare -rn sh tests/live/report.sh
#
# Decisions 0044 and 0045 put modem support in a helper that netcfgd does not
# start, supervise or speak to: it writes a file, netcfgd reads it. Decision
# 0047 takes the modem's name off that contract, because a tunnel daemon
# reports through it too. The whole interface is `docs/interface-report.md`.
#
# So this test *is* a writer, in the sense that matters. It writes the file the
# way the document tells somebody to write it -- a shell script wrapped around
# what the far end said, which is exactly what a `umbim` or `mbimcli` helper is
# -- and then asks netcfgd what it saw. If this script has to do anything the
# document does not describe, the document is wrong.
#
# There is no modem here and there does not need to be one. netcfgd's half of
# the contract is reading a file, and that is the half being checked.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "report.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "report.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d /tmp/ncfg-report.XXXXXX)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
# Somewhere other than the real one, so a suite run on a workstation does
# not rewrite the resolver of the machine running it.
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

# A stand-in for the modem's interface. netcfgd does not care what kind of
# device it is -- the report is keyed on the name, and a real one would be a
# `wwan0` from `cdc_mbim`.
ip link add wwan0 type dummy
ip link set wwan0 up
write_config() {
	cat > "$work/etc/netcfgd.conf" <<CONF
${2:-}
interface wwan0 {
	kind   = "dummy"
	config = "$1"
}
CONF
}
write_config null

# The directory the contract names. A writer creates it; netcfgd does not,
# because netcfgd is not the one reporting.
mkdir -p "$work/run/reported"

report() {
	# Atomically, as the document tells a writer to: netcfgd may read at any
	# moment and a half-written file is a file it will believe.
	cat > "$work/run/reported/.wwan0.tmp"
	mv "$work/run/reported/.wwan0.tmp" "$work/run/reported/wwan0"
}

seen() {
	"$ncfg" status --json 2>/dev/null | python3 -c '
import json,sys
observed = json.load(sys.stdin)
found = [m for m in observed.get("reports", []) if m["interface"] == "wwan0"]
if not found:
    print("no report")
else:
    m = found[0]
    print(" ".join(m["addresses"] + m["gateways"] + m["nameservers"]) or "empty")
'
}

# ----------------------------------------------------- nothing reported yet

check "a machine with nothing reporting shows no report" "$(seen)" "no report"

# ------------------------------------------------- the documented example

# Verbatim from docs/interface-report.md. If this stops matching the document, one
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
	"$(grep -c 'reported, not applied' "$work/status.txt" || true)" "3"
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

rm -f "$work/run/reported/wwan0"
check "and a removed report is nobody watching" "$(seen)" "no report"

# ------------------------------------ and now the source that consumes it

# `config = "reported"` is the document saying where this interface's addresses
# come from. The helper still does not install anything -- netcfgd does, from
# what the helper reported, with its own tag. That is the whole point of the
# split: one writer.
# A host that manages its resolver, so the reported nameservers have somewhere
# to go. Without this netcfgd manages no DNS and a modem appearing is not a
# reason for it to start.
write_config reported 'global { dns { dns_mode = "write_resolv_conf" } }'
report <<'EOF'
address=10.64.1.23/30
gateway=10.64.1.24
dns=8.8.8.8
EOF
"$ncfg" apply > "$work/apply.txt" 2>&1 || true
check "netcfgd installs the address the helper reported" \
	"$(ip -4 addr show wwan0 | grep -c '10.64.1.23/30' || true)" "1"
# Tagged as netcfgd's, which is what lets it be withdrawn again. An address
# nobody owns is one netcfgd will never remove (decision 0002).
check "and tags it as its own" \
	"$("$ncfg" status --json | python3 -c '
import json,sys
o = json.load(sys.stdin)
print([a["ownership"] for a in o["addresses"]
       if a["interface"] == "wwan0" and a["address"] == "10.64.1.23/30"][0])')" "ours"

# The gateway, which is the half that makes the address useful. A cellular
# next hop is routinely outside every address the bearer was given -- a /30 or
# a /32 with the gateway elsewhere is the ordinary shape -- so this only works
# because the route is onlink, and a real kernel is the only thing that can say
# so. Without it the kernel answers ENETUNREACH and the apply fails.
check "and installs the default route the helper reported" \
	"$(ip -4 route show default | grep -c 'via 10.64.1.24 dev wwan0' || true)" "1"

# And the resolver. Decision 0006 rule 4 says a source contributes nameservers
# and they merge; until the modem there was no source that contributed any, so
# this is the first thing to exercise it. The mode is not chosen -- every scope
# in one delivery has to agree about it, so the only value that is not an error
# is the one the host already uses.
check "and delivers the nameserver the helper reported" \
	"$(grep -c '^nameserver 8.8.8.8' "$work/resolv.conf" 2>/dev/null || true)" "1"

# Converged: a second apply does nothing, which is the check that the source
# is not adding an address the teardown then removes on every reconcile.
"$ncfg" plan > "$work/replan.txt" 2>&1 || true
check "and the next plan has nothing to do" \
	"$(grep -cE 'addr\.|route\.|dns\.' "$work/replan.txt" || true)" "0"

# The bearer drops. The helper truncates its report, as the contract asks, and
# the address goes -- rule 7 for this source. Unlike a lease there is no client
# holding it and no backend to restart, so it is netcfgd's to withdraw.
report < /dev/null
"$ncfg" apply > "$work/down.txt" 2>&1 || true
check "and withdraws it when the bearer goes down" \
	"$(ip -4 addr show wwan0 | grep -c '10.64.1.23/30' || true)" "0"
# The route too, and this is the one that matters more: a default route down a
# modem that is gone black-holes traffic another interface would have carried.
check "and takes the default route with it" \
	"$(ip -4 route show default | grep -c 'dev wwan0' || true)" "0"

# ----------------------------------- the neighbouring case this refactor fixed

# Not about modems, and here because this is where a redirected resolv.conf is
# already set up. `dns = "9.9.9.9"` on an interface compiles to a policy whose
# mode is `none` -- the line says nothing about delivery -- and the executor
# used to drop such a scope while the plan happily reported applying it. An
# operator wrote a nameserver down and netcfgd silently ignored it.
#
# Only a delivery can catch this. A check on the plan sees the server either
# way, because the plan carried it all along.
report < /dev/null
cat > "$work/etc/netcfgd.conf" <<'CONF'
global { dns { dns_mode = "write_resolv_conf" } }
interface wwan0 {
	kind   = "dummy"
	config = "10.9.9.1/24"
	dns    = "9.9.9.9"
}
CONF
"$ncfg" apply > "$work/plaindns.txt" 2>&1 || true
check "a nameserver written on an interface reaches the resolver" \
	"$(grep -c '^nameserver 9.9.9.9' "$work/resolv.conf" 2>/dev/null || true)" "1"

echo
if [ "$failures" -eq 0 ]; then
	echo "report.sh: all checks passed"
else
	echo "report.sh: $failures check(s) failed"
	exit 1
fi
