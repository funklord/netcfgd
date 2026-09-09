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
	# **The supplicant netcfgd started, which is nobody's child here.** It is
	# launched with `-B`, so it daemonises away from this shell, and killing
	# netcfgd deliberately does not take it -- that is what `KillMode=process`
	# means on a real machine (0134, 0142) and the fixture reproduces it
	# faithfully. Faithfully enough to leak: four of these were alive, one per
	# run, before this existed.
	#
	# By the pid file netcfgd wrote, which is how netcfgd finds it too, and
	# never by name -- `pgrep -x python3` on a shared pid namespace is a sweep
	# across the whole machine.
	if [ -r "$work/run/supplicant/wlan0.pid" ]; then
		supplicant=$(cat "$work/run/supplicant/wlan0.pid" 2>/dev/null || true)
		case "$supplicant" in
		[0-9]*)
			# Confirmed to be this run's before it is signalled: a pid file
			# outlives the process it names and pids are recycled.
			if grep -qa "$work" "/proc/$supplicant/cmdline" 2>/dev/null; then
				kill "$supplicant" 2>/dev/null || true
			fi
			;;
		esac
	fi
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

# **Refused outside a network namespace of its own, rather than trusted to be
# in one.** The header says `unshare -rn` and the Makefile supplies it, and
# neither of those stops somebody running the script directly -- which makes
# `wlan0` and `wlan0p` on the real machine, puts a DHCP server on them, and
# leaves both behind when a check fails before the cleanup. Measured, by doing
# it: two veths survived on the host, and the next run skipped with "cannot
# make a veth pair" because the names were taken.
#
# pid 1's namespace is the host's, and `/proc` is not remounted by `unshare
# -rn`, so comparing the two links answers this without anything being
# created first.
if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
	skip "this makes interfaces and must not do it on the machine's own network; run it under \`unshare -rn\`, as the Makefile does"
fi

# **A veth rather than a dummy**, so the metric section below can put a real
# DHCP server on the far end. For everything above it behaves as a dummy did:
# what makes netcfgd treat it as a radio is `NCFG_SYS_CLASS_NET`, not its kind.
ip link add wlan0 type veth peer name wlan0p 2>/dev/null ||
	skip "cannot make a veth pair"
ip link set wlan0 up 2>/dev/null || true
ip link set wlan0p up 2>/dev/null || true
ip addr add 10.44.0.1/24 dev wlan0p 2>/dev/null || true

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
	# `null` to begin with: the metric section below turns this into `dhcp`
	# once the association is observed, because that is when netcfgd has a
	# metric to give the client. The checks above need no lease.
	config = "null"
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

# ------------------------------------------- the route metric the network sets

# **`network { metric = N }` is documented to do two things and this is the
# second.** `netcfgd_model::wifi`: *"Lower wins, and it is a route metric -- the
# same number and the same scale as an interface's `preference` ... While the
# radio is associated to this network, its interface's routes take this metric
# instead of the interface's own."* The join-order half is asserted by
# `wifi.sh`; this is the half nothing drove, and it needs a real lease with a
# default route in it because on a `config = "dhcp"` radio -- which is what
# `ncfg wifi activate` writes -- the lease's route *is* the interface's route.
#
# The fixture is `dhcpcd.sh`'s: busybox udhcpd on the far end of the veth,
# offering a router. Skipped rather than failed where there is no server, the
# way that script does, because the machine is what is missing and not the code.
if command -v busybox >/dev/null 2>&1 && busybox --list | grep -qx udhcpd &&
	command -v dhcpcd >/dev/null 2>&1; then
	: > "$work/udhcpd.leases"
	cat > "$work/udhcpd.conf" <<CONF
start 10.44.0.20
end 10.44.0.20
interface wlan0p
option subnet 255.255.255.0
option router 10.44.0.1
option dns 10.44.0.53
option lease 600
lease_file $work/udhcpd.leases
pidfile $work/udhcpd.pid
CONF
	busybox udhcpd -f "$work/udhcpd.conf" > "$work/udhcpd.log" 2>&1 &
	server=$!

	# The metric on the lease's default route, which is what an operator sees
	# and what decides whether this radio beats the wired link.
	lease_metric() {
		ip -4 route show default dev wlan0 2>/dev/null |
			sed -n 's/.*metric \([0-9]*\).*/\1/p' | head -1
	}

	# Back onto the first network: the section above left the station on Cafe,
	# and this half is about the metric each network carries, so it has to
	# start from a known one.
	send_event "JOIN HomeFiber"
	settle_to HomeFiber || true

	# **The client is started after the association is known, deliberately.**
	# netcfgd reads the metric when it starts the client and passes it as
	# `-m`, so a first apply that starts the supplicant and the client
	# together has no association observed yet and nothing to read. Bringing
	# `dhcp` in on a second apply is what a real machine does anyway: the
	# radio associates before a lease is asked for.
	sed -i 's/config = "null"/config = "dhcp"/' "$work/etc/netcfgd.conf"
	timeout 60 "$ncfg" apply >/dev/null 2>&1 || true
	waited=0
	while [ -z "$(lease_metric)" ] && [ "$waited" -lt 200 ]; do
		waited=$((waited + 1))
		sleep 0.1
	done

	check "the lease's default route arrives while on the first network" \
		"$([ -n "$(lease_metric)" ] && echo yes || echo no)" "yes"
	# HomeFiber carries `metric = 100`, so that is what its routes take.
	check "and takes the metric that network carries" "$(lease_metric)" "100"

	# Move to the network whose metric is 400 and let netcfgd reconcile.
	send_event "JOIN Cafe"
	settle_to Cafe || true
	timeout 60 "$ncfg" apply >/dev/null 2>&1 || true
	sleep 1
	timeout 60 "$ncfg" apply >/dev/null 2>&1 || true

	# **This is the half that does not work, pinned rather than wished for.**
	# The metric is read when netcfgd *starts* the client and passed as `-m`;
	# a station moving to a network with a different metric does not re-drive
	# a client that is already running, so the lease's route keeps the metric
	# of the network it was obtained on. Cafe carries 400 and this is still
	# 100.
	#
	# Closing it is a decision rather than an oversight, and it is the
	# copyright holder's. Restarting the client applies the new metric and
	# drops the lease for as long as the exchange takes -- on a laptop moving
	# between networks that is the moment least able to afford it. Rewriting
	# the route in place avoids that and means netcfgd editing a route the
	# DHCP client owns, which is the thing constraint 1 exists to stop.
	# `ObservedBackend::started_with` is the empty slot either answer would
	# fill, and `Op::BackendStart` carries no metric to compare against.
	#
	# Asserted at the value it actually has, so that closing the gap turns
	# this red and says so, rather than leaving a wish in a comment nobody
	# reruns.
	# **Waited for, because the restart is the mechanism.** netcfgd stops the
	# client and starts it again with the new `-m`, so the route goes away and
	# comes back -- through a fresh DHCP exchange and dhcpcd's ARP probe, which
	# is seconds rather than milliseconds. Reading once here caught the gap
	# between the two and reported no route at all.
	waited=0
	while [ "$(lease_metric)" != "400" ] && [ "$waited" -lt 300 ]; do
		timeout 60 "$ncfg" apply >/dev/null 2>&1 || true
		waited=$((waited + 1))
		sleep 0.1
	done

	check "and the metric follows the station onto the other network" \
		"$(lease_metric)" "400"

	kill "$server" 2>/dev/null || true
	wait "$server" 2>/dev/null || true
	# The client netcfgd started, which KillMode=process would leave on a real
	# machine and nothing here would otherwise reap.
	timeout 30 dhcpcd -4 -k wlan0 >/dev/null 2>&1 || true
else
	echo "note the route metric section needs busybox udhcpd and dhcpcd; skipped"
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "switch_network.sh: all checks passed"
else
	echo "switch_network.sh: $failures check(s) failed"
	sed 's/^/       /' "$work/daemon.log" 2>/dev/null | tail -20 >&2
	exit 1
fi
