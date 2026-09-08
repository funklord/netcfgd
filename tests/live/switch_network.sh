#!/bin/sh
# What follows a station moving from one wifi network to another.
#
# WHY THIS EXISTS
#   Switching networks is wpa_supplicant's decision -- netcfgd hands it every
#   network the document holds and it associates with whichever is in range --
#   and everything that has to follow is netcfgd's: the route metric the new
#   network carries, and the resolver the new lease offers. Both were reasoned
#   about and neither was tested.
#
#   `roam.sh` is the *same* network under a different access point and says so
#   in its first line. `wifi.sh` has two networks and asserts their settings,
#   not what happens when the association moves between them. So the whole
#   consequence of a switch was uncovered, on a tree where every uncovered path
#   this week has turned out to hold a fault.
#
# WHAT IT DRIVES
#   A real netcfgd against `fake_supplicant.py`, which grew a `JOIN <ssid>`
#   command for this: the one thing this repository cannot produce on demand is
#   a radio with two networks in range. What is not faked is netcfgd -- the
#   observation reads `STATUS` over the control socket exactly as it does
#   against a real supplicant, and `network_for` matches the SSID to the
#   document the same way.
#
# WHICH CHECKS THE SWITCH ACTUALLY GATES, measured rather than assumed
#   Sabotaged by making `JOIN` emit the event without moving the station: only
#   *"netcfgd follows the station onto the other network"* went red. The two
#   resolver checks after it passed anyway, because the report is written by
#   this script and netcfgd delivers whatever is in it regardless of which
#   network it believes it is on.
#
#   They are kept, and named for what they do prove: that a second lease
#   *replaces* the first network's nameserver rather than accumulating beside
#   it, which is the failure an operator would see as "it still resolves
#   against the cafe". But the association is what one check covers, and saying
#   so is the difference between a suite and a suite that reads well.
#
# WHAT IT DELIBERATELY DOES NOT COVER, so the name does not overclaim:
#   * That the DHCP client notices the change and re-leases. That is dhcpcd's
#     own behaviour, driven by the access point it logs, and `dhcpcd.sh`
#     exercises the client against a real server. Here the *report* is written
#     the way the hook writes it, which is the contract in
#     doc/interface-report.md and the only thing netcfgd reads.
#   * Which network wpa_supplicant picks. That is its choice among what it was
#     given; `wifi.sh` checks that the ranking netcfgd derives reaches it.
#   * The route metric the new network carries. `network { metric = N }` sets
#     both the join order and the routes' metric while associated, and the
#     second half needs a lease with a default route in it -- which is
#     `dhcpcd.sh`'s fixture, not this one. The two networks here carry
#     different metrics anyway, so the document is ready for that check when
#     somebody joins the two fixtures.
#
# Runs under `unshare -rn`: it makes a dummy interface.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "switch_network.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "switch_network.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-switch.XXXXXX")
daemon=
fake=
cleanup() {
	for pid in $daemon $fake; do
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
	# Retried, for the reason roam.sh records: a signalled daemon writes on its
	# way out and a single rm races it, failing a run whose checks all passed.
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
}
trap cleanup EXIT INT TERM

mkdir -p "$work/etc" "$work/run" "$work/ctrl" "$work/sys/wlan0/wireless" "$work/runroot"
cp "$repo/tests/live/fake_supplicant.py" "$work/fake_supplicant"
chmod +x "$work/fake_supplicant"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_RESOLV_CONF="$work/resolv.conf"
export NCFG_WPA_CTRL_DIR="$work/ctrl"
export NCFG_SYS_CLASS_NET="$work/sys"
# netcfgd starts this as its supplicant, so the backend is recorded and
# observed the way a real one is -- which is what the association pass needs.
# The fake parses netcfgd's own argv (`-i`, `-C`, `-P`, `-B`), which is what
# that parser is for.
export NCFG_WPA_SUPPLICANT="$work/fake_supplicant"
# Isolated from the host's NetworkManager state, for the reason enterprise.sh
# gives: netcfgd refuses a radio another manager claims, and on a developer
# machine those files exist for real interfaces.
export NCFG_RUN_ROOT="$work/runroot"
printf 'nameserver 203.0.113.1\n' > "$work/resolv.conf"

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

ip link add wlan0 type dummy 2>/dev/null || skip "cannot make a dummy interface"
ip link set wlan0 up 2>/dev/null || true

# Two networks the fake advertises, with metrics that differ so the switch is
# visible in something netcfgd owns. Lower wins, and it is a route metric.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global { dns { mode = "write_resolv_conf" } }

network "HomeFiber" {
	wifi { psk = "@secret:HomeFiber" }
	metric = 100
}

network "Cafe" {
	wifi { open = true }
	metric = 400
}

# Both blocks, which is what `ncfg wifi activate` writes and what a radio
# needs: `device` is policy about the hardware, `interface` is what makes the
# link netcfgd's to configure. Without the first, nothing plans a supplicant.
device wlan0 {
	wifi { autoconnect = true }
}

interface wlan0 {
	config = "dhcp"
	dns { }
}
CONF
mkdir -p "$work/etc/secrets"
printf 'hunter2hunter2' > "$work/etc/secrets/HomeFiber"
chmod 0600 "$work/etc/secrets/HomeFiber"

"$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ] && [ "$waited" -lt 50 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
[ -e "$work/run/netcfgd.sock" ] || { cat "$work/daemon.log" >&2; exit 1; }

ncfg="$repo/target/debug/ncfg"

# roam.sh's sender, unchanged: a datagram client needs an address of its own,
# in a directory of its own because the whole path has to fit a unix socket's
# 108 bytes. Two copies of this is one more than there should be; the other one
# carries the reasoning and they are in step deliberately.
send_event() {
	if [ ! -S "$work/ctrl/wlan0" ]; then
		echo "FAIL the control socket was there to be sent: $1"
		failures=$((failures + 1))
		return 1
	fi
	python3 - "$work/ctrl/wlan0" "$1" <<'PYSEND'
import socket, sys, os, tempfile
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
staging = tempfile.mkdtemp()
local = os.path.join(staging, "c")
try:
	sock.bind(local)
	sock.sendto(sys.argv[2].encode(), sys.argv[1])
finally:
	sock.close()
	os.unlink(local)
	os.rmdir(staging)
PYSEND
}

# What netcfgd thinks it is associated to, read back through its own
# observation rather than from the fake -- the fake is what is being driven,
# and asserting on it would prove only that the fixture works.
associated() {
	"$ncfg" status --json 2>/dev/null |
		python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print(""); raise SystemExit
for link in d.get("links", []):
    if link.get("name") == "wlan0":
        print(link.get("network") or "")
        raise SystemExit
print("")' 2>/dev/null || true
}

# Bounded wait: the observation is refreshed on a tick, not synchronously with
# the event, so a bare read races it. Every check below reads through this.
settle_to() {
	waited=0
	while [ "$waited" -lt 60 ]; do
		[ "$(associated)" = "$1" ] && return 0
		waited=$((waited + 1))
		sleep 0.1
	done
	return 1
}

# The apply starts the supplicant, which is what puts the backend in the
# observation at all -- an association is only read for a backend netcfgd knows
# is running.
timeout 60 "$ncfg" apply >/dev/null 2>&1 || true

waited=0
while [ ! -S "$work/ctrl/wlan0" ] && [ "$waited" -lt 60 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
if [ ! -S "$work/ctrl/wlan0" ]; then
	echo "--- ncfg plan:"; timeout 30 "$ncfg" plan 2>&1 | head -10
	echo "--- daemon:"; tail -10 "$work/daemon.log" 2>/dev/null
	echo "--- ctrl dir:"; ls -la "$work/ctrl" 2>&1
	skip "netcfgd never started the fake supplicant"
fi

settle_to HomeFiber || true
check "netcfgd sees the network the station is on" "$(associated)" "HomeFiber"

# The report, written the way the DHCP hook writes it. This is the contract in
# doc/interface-report.md and the only thing netcfgd reads for a lease's
# nameservers -- the client that produces it is dhcpcd.sh's business.
report() {
	mkdir -p "$work/run/reported"
	{
		printf '# wlan0, from a lease. Written by the test.\n'
		printf 'dns=%s\n' "$1"
	} > "$work/run/reported/.wlan0.tmp"
	mv "$work/run/reported/.wlan0.tmp" "$work/run/reported/wlan0"
}

resolver_has() {
	grep -c "^nameserver $1\$" "$work/resolv.conf" 2>/dev/null || true
}

report 10.1.0.53
timeout 60 "$ncfg" apply >/dev/null 2>&1 || true
check "the first network's nameserver reaches the resolver" \
	"$(resolver_has 10.1.0.53)" "1"
check "and what was there before it is gone, because netcfgd owns that file" \
	"$(resolver_has 203.0.113.1)" "0"

# **The switch.** `JOIN` moves the fake, which from netcfgd's side is exactly
# what a real supplicant does when the first network goes out of range: STATUS
# reports the new SSID and a CTRL-EVENT-CONNECTED arrives.
send_event "JOIN Cafe"

settle_to Cafe || true
check "netcfgd follows the station onto the other network" "$(associated)" "Cafe"

# The lease the new network hands out. A different resolver, which is the whole
# reason a switch has to be followed: keeping the old one is a machine that
# resolves against a network it is no longer on.
report 10.2.0.53
timeout 60 "$ncfg" apply >/dev/null 2>&1 || true
check "the new network's nameserver reaches the resolver" \
	"$(resolver_has 10.2.0.53)" "1"
check "and the old network's is gone rather than left beside it" \
	"$(resolver_has 10.1.0.53)" "0"

echo
if [ "$failures" -eq 0 ]; then
	echo "switch_network.sh: all checks passed"
else
	echo "switch_network.sh: $failures check(s) failed"
	sed 's/^/       /' "$work/daemon.log" 2>/dev/null | tail -20 >&2
	exit 1
fi
