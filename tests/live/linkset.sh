#!/bin/sh
# A linkset against a real kernel and a running daemon.
#
# WHY THIS FILE EXISTS
#   The choosing is a pure function and is tested as one; the acting is a
#   planner fixture and is tested as one. What neither can show is the thing an
#   operator cares about: **that exactly one of these links has a default route
#   in the kernel, and that it is the one that works**. That is a join between
#   the document, the observation, the probe machinery and the executor, and
#   every fault this milestone has produced was in a join.
#
#   The case it is built around is the one metrics cannot handle on their own.
#   A link with no carrier loses its routes to the kernel anyway -- they go out
#   of the table when the link goes down -- so ranking by metric is enough for a
#   cable somebody unplugged. A link that is up, has carrier, and reaches
#   nothing looks identical to a working one from the routing table, and it
#   keeps its better metric while doing so. The probe is what tells them apart,
#   and a linkset is what makes the answer act on more than one link at a time.
#
# WHAT IT NEEDS
#   A running netcfgd, because a probe is not a plan action: it is a question
#   the daemon asks on a timer. Two dummy interfaces, so nothing real is
#   touched. It runs under `unshare -rn` like the rest of the suite.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "linkset.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "linkset.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-linkset.XXXXXX")
daemon=
cleanup() {
	if [ -n "$daemon" ]; then
		kill "$daemon" 2>/dev/null || true
		wait "$daemon" 2>/dev/null || true
	fi
	# Retried, for the reason drift.sh records: a signalled daemon writes on
	# its way out, so one `rm -rf` races the process just asked to stop, and a
	# trap that exits non-zero fails a run whose every check passed.
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
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

# Two probes whose answers this script controls by rewriting them. A file
# rather than a flag, because the daemon runs the command and re-reads nothing
# else -- and the whole point is to change the answer under a running daemon
# without touching its configuration.
cat > "$work/probe-a" <<'PROBE'
#!/bin/sh
exit 1
PROBE
cat > "$work/probe-b" <<'PROBE'
#!/bin/sh
exit 0
PROBE
chmod +x "$work/probe-a" "$work/probe-b"

# `seta0` has the better metric and is the one that does not work. `setb0` is
# worse-ranked and does. Without the set, the kernel would use `seta0`: it has
# carrier -- a dummy always does -- and the better metric.
#
# `interval` and the counts are as short as the model allows, because this
# script waits for them in real time.
cat > "$work/etc/netcfgd.conf" <<CONF
device seta0 { kind = "dummy" }
device setb0 { kind = "dummy" }

interface seta0 {
	config     = "10.10.1.2/24"
	routes     = "default via 10.10.1.1"
	preference = 100
	probe {
		command    = "$work/probe-a"
		interval   = 1
		timeout    = 2
		down_after = 1
		up_after   = 1
	}
}

interface setb0 {
	config     = "10.10.2.2/24"
	routes     = "default via 10.10.2.1"
	preference = 700
	probe {
		command    = "$work/probe-b"
		interval   = 1
		timeout    = 2
		down_after = 1
		up_after   = 1
	}
}

linkset "uplink" {
	members = ["seta0", "setb0"]
}
CONF

"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ] && [ "$waited" -lt 50 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
[ -e "$work/run/netcfgd.sock" ] || {
	cat "$work/daemon.log" >&2
	echo "linkset.sh: the daemon never bound its socket" >&2
	exit 1
}

# Both probes have to have run and the daemon to have re-planned on the answer.
# Bounded: fifteen seconds, then the checks run and say what they found.
defaults_on() {
	ip -4 route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' |
		sort | tr '\n' ' '
}
waited=0
while [ "$waited" -lt 150 ]; do
	[ "$(defaults_on)" = "setb0 " ] && break
	waited=$((waited + 1))
	sleep 0.1
done

# **The check this file exists for.** One default route, on the link that
# answers -- not two at different metrics, and not the better-ranked one that
# reaches nothing.
check "exactly one member carries a default route" "$(defaults_on)" "setb0 "

# And the daemon's own published record says the same thing, naming the member
# it is using and why the other one lost. A failover nobody can explain is one
# nobody trusts.
#
# **The daemon's file rather than `ncfg status`, deliberately.** A probe verdict
# has exactly one producer: the daemon runs the command on a timer and stamps
# the answer onto its observation. A client that observes for itself -- which
# `ncfg status` does when it can read the kernel -- sees `reachable: null` on
# every link and so works out a different winner. That divergence is older than
# linksets and wider than them (`ncfg plan` has it too); what a set does is make
# it visible. Asserting against the daemon's record is asserting against the
# thing that decided.
record=$(cat "$work/run/observed.json" 2>/dev/null || true)
printf '%s\n' "$record" > "$work/record.json"
check "the daemon's record names the member the set is using" \
	"$(printf '%s\n' "$record" | python3 -c "
import json, sys
try:
	seen = json.load(sys.stdin)
except ValueError:
	print('no record'); raise SystemExit
sets = seen.get('linksets', [])
print(next((one.get('active') for one in sets if one.get('name') == 'uplink'), 'no uplink'))
")" "setb0"
check "and why the other one is not carrying anything" \
	"$(printf '%s\n' "$record" | python3 -c "
import json, sys
try:
	seen = json.load(sys.stdin)
except ValueError:
	print('no record'); raise SystemExit
sets = seen.get('linksets', [])
uplink = next((one for one in sets if one.get('name') == 'uplink'), {})
print(next((m.get('ineligible') for m in uplink.get('members', []) if m.get('name') == 'seta0'), 'no member'))
")" "probe"

# Now the failing link starts working. Nothing about the configuration changes;
# the set is asked again because the observation changed, which is the whole
# behaviour being claimed.
cat > "$work/probe-a" <<'PROBE'
#!/bin/sh
exit 0
PROBE
chmod +x "$work/probe-a"

waited=0
while [ "$waited" -lt 150 ]; do
	[ "$(defaults_on)" = "seta0 " ] && break
	waited=$((waited + 1))
	sleep 0.1
done
check "the better member takes over when it starts working" "$(defaults_on)" "seta0 "

if [ "$failures" -ne 0 ]; then
	echo "linkset.sh: $failures check(s) failed" >&2
	echo "--- the daemon's record was:" >&2
	cat "$work/record.json" >&2
	tail -20 "$work/daemon.log" >&2
	exit 1
fi
echo "linkset.sh: all checks passed"
