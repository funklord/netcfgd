#!/bin/sh
# The captive portal check, against a real HTTP server on a real socket.
#
# A portal gives a machine an address, a gateway and a resolver, then answers
# every request with its own login page: everything looks configured and
# nothing works. netcfgd fetches the URL the *operator* named -- it has none of
# its own, which is 0061's decision and 0095's -- and runs the interface's
# `on portal { }` hook when something other than the expected answer arrives.
#
# The server here is a few lines of python rather than a fake protocol: HTTP is
# what netcfgd speaks to it, so the only thing worth faking is the network
# being hostile, which is done by answering a redirect instead of a 204.
#
# Needs a running netcfgd: a probe is not a plan action -- it is a question, and
# an action that ran on every apply would mean no plan ever converged -- so no
# `ncfg apply` can exercise it.
#
# Runs under `unshare -rn`: it makes a dummy interface and serves on loopback.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "portal.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "portal.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

work=$(mktemp -d /tmp/ncfg-portal.XXXXXX)
daemon=
server=
cleanup() {
	for pid in $daemon $server; do
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"

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

log=$work/transcript
: > "$log"
ip link set lo up

# Answers 204 or a redirect, whichever the file says. A real portal answers the
# second: it intercepts the request and points at its login page.
cat > "$work/server.py" <<'PY'
import http.server, sys, os
mode_file = sys.argv[2]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        mode = open(mode_file).read().strip()
        if mode == "clear":
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(302)
            self.send_header("Location", "http://login.example/portal")
            self.end_headers()
    def log_message(self, *args):
        print(" ".join(str(a) for a in args), flush=True)
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

echo clear > "$work/mode"
python3 "$work/server.py" 8731 "$work/mode" > "$work/server.log" 2>&1 &
server=$!
waited=0
while ! python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',8731))==0 else 1)" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 50 ] && skip "the test server never started"
	sleep 0.1
done

# The device names the URL; the interface carries the hook. `portal0` is a
# dummy that gets an address, which is the transition the probe fires on.
cat > "$work/etc/netcfgd.conf" <<CONF
device portal0 {
	wifi { portal_check = "http://127.0.0.1:8731/generate_204" }
}
interface portal0 {
	kind   = "dummy"
	config = "10.3.3.1/24"
	# `report`, so taking the address away below stays taken away long enough
	# for the daemon to observe the interface bare. Under `reconcile` it puts
	# the address back within the same pass, so the machine never looks
	# unaddressed and the transition the probe fires on never happens -- which
	# is true of the real thing too and is worth knowing.
	on_drift = "report"
	on portal {
	echo "portal iface=\$NCFG_IFACE url=\$NCFG_URL reason=\$NCFG_REASON" >> $log
	}
}
CONF

"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ] && [ "$waited" -lt 50 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
[ -e "$work/run/netcfgd.sock" ] || { cat "$work/daemon.log" >&2; exit 1; }

waited=0
while ! ip -br addr show portal0 2>/dev/null | grep -q 10.3.3.1; do
	waited=$((waited + 1))
	[ "$waited" -gt 60 ] && break
	sleep 0.1
done
sleep 2

runs() {
	grep -c '^portal ' "$log" 2>/dev/null || true
}

check "the interface was addressed" \
	"$(ip -br addr show portal0 2>/dev/null | grep -c 10.3.3.1 || true)" 1
check "and the server was asked" \
	"$([ -s "$work/server.log" ] && echo yes || echo no)" "yes"
# A clear network runs nothing. A hook that fired on every successful join is a
# hook nobody keeps.
check "a network that answers what was asked runs no hook" "$(runs)" 0

# Now make the network hostile and take the interface down and up again, which
# is the transition the probe fires on.
echo portal > "$work/mode"
ip addr del 10.3.3.1/24 dev portal0
sleep 2
"$repo/target/debug/ncfg" apply > /dev/null 2>&1 || true
waited=0
while [ "$(runs)" = "0" ] && [ "$waited" -lt 60 ]; do
	waited=$((waited + 1))
	sleep 0.1
done

check "a network that answers with something else runs the hook" "$(runs)" 1
check "and the script is told which interface" \
	"$(grep -c 'iface=portal0' "$log" || true)" 1
check "and which url was fetched" \
	"$(grep -c 'url=http://127.0.0.1:8731/generate_204' "$log" || true)" 1
check "and what the network said instead" \
	"$(grep -c 'got 302' "$log" || true)" 1

# A network where nothing answers is not a portal. A portal is a thing that
# *replies*; calling a dead network one sends the operator to a login page that
# is not there, which is worse than saying nothing.
kill "$server" 2>/dev/null || true
wait "$server" 2>/dev/null || true
server=
before=$(runs)
ip addr del 10.3.3.1/24 dev portal0
sleep 2
"$repo/target/debug/ncfg" apply > /dev/null 2>&1 || true
sleep 3
check "a network where nothing answers does not run the portal hook" "$(runs)" "$before"
# And it said so rather than going quiet, so an operator reading the log knows
# the check happened and could not be completed.
check "and says it could not be checked" \
	"$(grep -c 'could not be checked' "$work/daemon.log" || true)" 1

if [ "$failures" -eq 0 ]; then
	echo "portal.sh: all checks passed"
else
	echo "portal.sh: $failures check(s) failed"
	exit 1
fi
