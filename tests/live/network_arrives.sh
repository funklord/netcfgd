#!/bin/sh
# A wifi network added to a running daemon: does the radio get it?
#
#     unshare -rn sh tests/live/network_arrives.sh
#
# ## Why this exists
#
# This is project.md 10.307's own shape, which `config_arrives.sh` deliberately
# does not have. That script proves a written file reaches the machine, on
# dummy links and ordinary keys. What 10.307 actually held was a `network`
# block written into `conf.d/` while the daemon ran, where the work lands on a
# radio and on a supplicant netcfgd started -- two more layers, either of which
# could swallow it, and neither of which any test drove.
#
# **It calls `apply` nowhere.** `switch_network.sh` shares this fixture and
# drives it with `ncfg apply` at every step, which is the right shape for what
# that script asks and the wrong one for this: the question here is whether the
# daemon does it *unasked*.
#
# ## What is faked and what is not
#
# `fake_supplicant.py`, as five other scripts use it -- netcfgd starts it,
# parses its own argv, and speaks the real control protocol to it. What is not
# faked is netcfgd: the reload, the plan, the supplicant configuration and the
# observation are the real ones.
#
# The fake advertises three networks and `JOIN <ssid>` is how a test says the
# station moved, which needs two access points and a radio otherwise. So the
# network this script adds is one the fake already advertises: what is under
# test is whether netcfgd hands it over, not whether a fixture can invent a
# radio.
#
# ## What it would take to get this wrong, which is the check that matters
#
# A daemon that reloads the document, plans correctly, and never reaches the
# supplicant would pass every check in `config_arrives.sh` and leave a machine
# that does not join the network somebody just added. That is the failure
# 10.307 looked like from the operator's chair, and **one check here sees it**
# -- which one is measured below rather than claimed, because the obvious
# candidate turned out not to.
set -eu

name=network_arrives.sh
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"

daemon_flags=
if "$build/netcfgd" --help 2>&1 | grep -q -- '--try-the-c-daemon'; then
	daemon_flags=--try-the-c-daemon
fi

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "$name: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "$name: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$build/netcfgd" ] || skip "netcfgd is not built"
[ -x "$build/ncfg" ] || skip "ncfg is not built"

# switch_network.sh's guard, and for its measured reason: the header says
# `unshare -rn` and the Makefile supplies it, and neither stops somebody
# running this directly -- which makes `wlan0` on the real machine and leaves
# it behind when a check fails before the cleanup.
if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
	skip "this makes interfaces and must not do it on the machine's own network; run it under \`unshare -rn\`, as the Makefile does"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-netarrive.XXXXXX")
daemon=
cleanup() {
	if [ -n "$daemon" ]; then
		kill "$daemon" 2>/dev/null || true
		wait "$daemon" 2>/dev/null || true
	fi
	# **The supplicant netcfgd started is nobody's child here**, launched with
	# `-B` so it daemonises away from this shell, and killing netcfgd
	# deliberately does not take it -- `KillMode=process` (0134, 0142). By the
	# pid file netcfgd wrote, confirmed to be this run's before it is
	# signalled, and never by name: a pattern kill on a shared pid namespace is
	# a sweep across the whole machine. switch_network.sh's, and it is there
	# because four of these were alive, one per run, before it existed.
	if [ -r "$work/run/supplicant/wlan0.pid" ]; then
		supplicant=$(cat "$work/run/supplicant/wlan0.pid" 2>/dev/null || true)
		case "$supplicant" in
		[0-9]*)
			if grep -qa "$work" "/proc/$supplicant/cmdline" 2>/dev/null; then
				kill "$supplicant" 2>/dev/null || true
			fi
			;;
		esac
	fi
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
}
trap cleanup EXIT INT TERM

mkdir -p "$work/etc/conf.d" "$work/etc/secrets" "$work/run" "$work/ctrl" \
	"$work/sys/wlan0/wireless" "$work/runroot"
cp "$repo/tests/live/fake_supplicant.py" "$work/fake_supplicant"
chmod +x "$work/fake_supplicant"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_RESOLV_CONF="$work/resolv.conf"
export NCFG_WPA_CTRL_DIR="$work/ctrl"
export NCFG_SYS_CLASS_NET="$work/sys"
export NCFG_WPA_SUPPLICANT="$work/fake_supplicant"
export NCFG_RUN_ROOT="$work/runroot"
printf 'nameserver 203.0.113.1\n' > "$work/resolv.conf"

failures=0
checks=0
check() {
	checks=$((checks + 1))
	if [ "$2" = "$3" ]; then
		printf 'ok   %s\n' "$1"
	else
		printf 'FAIL %s\n' "$1"
		printf '       expected: %s\n' "$3"
		printf '       actual:   %s\n' "$2"
		failures=$((failures + 1))
	fi
}

awaits() {
	i=0
	while [ "$i" -lt 150 ]; do
		if eval "$1" >/dev/null 2>&1; then
			return 0
		fi
		i=$((i + 1))
		sleep 0.1
	done
	return 1
}

ncfg="$build/ncfg"

# What netcfgd believes the station is on, read through its own observation
# rather than from the fake: asserting on the fake would prove the fixture
# works. switch_network.sh's, unchanged.
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

# roam.sh's and switch_network.sh's sender: a datagram client needs an address
# of its own, in a directory of its own, because the whole path has to fit a
# unix socket's 108 bytes.
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

# The fake prints every command it was sent, secrets stripped, and netcfgd
# inherits its stdout -- so what the supplicant was told is in the daemon's own
# log. That is the observable this script turns on: a `network` block that
# never becomes a `SET_NETWORK` is a block the radio never heard of.
#
# **The SSID goes over as hex, which this got wrong first.** netcfgd sends
# `SET_NETWORK 0 ssid 486f6d654669626572`, not a quoted string -- which is what
# a real supplicant takes, because an SSID is 32 arbitrary bytes and quoting
# them is the problem hex exists to avoid. A grep for the quoted form matches
# nothing and reads exactly like a network that never reached the radio.
hexed() {
	printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'
}

told_about() {
	grep -c "ssid $(hexed "$1")" "$work/daemon.log" 2>/dev/null || true
}

ip link add wlan0 type veth peer name wlan0p 2>/dev/null ||
	skip "cannot make a veth pair"
ip link set wlan0 up 2>/dev/null || true
ip link set wlan0p up 2>/dev/null || true

# ------------------------------------------------- one network, and a daemon

cat > "$work/etc/netcfgd.conf" <<'CONF'
global { dns { mode = "write_resolv_conf" } }

network "HomeFiber" {
	wifi { psk = "@secret:HomeFiber" }
	metric = 100
}

device wlan0 {
	wifi { autoconnect = true }
}

interface wlan0 {
	config = "null"
	dns { }
}
CONF
printf 'hunter2hunter2' > "$work/etc/secrets/HomeFiber"
chmod 0600 "$work/etc/secrets/HomeFiber"

# **No `--no-apply-on-start`**, which is what every other script using this
# fixture passes. The daemon has to do this by itself or there is nothing here
# to measure.
"$build/netcfgd" $daemon_flags > "$work/daemon.log" 2>&1 &
daemon=$!
awaits '[ -e "$work/run/netcfgd.sock" ]' ||
	{ cat "$work/daemon.log" >&2; skip "the daemon never bound its socket"; }
awaits '[ -S "$work/ctrl/wlan0" ]' || {
	echo "--- daemon:"; tail -15 "$work/daemon.log"
	skip "netcfgd never started the fake supplicant"
}

awaits '[ "$(associated)" = HomeFiber ]' || true
check "the daemon joined the one network it was started with, unasked" \
	"$(associated)" "HomeFiber"
# At least once rather than exactly once: netcfgd re-sends the set on a pass
# that rebuilds the supplicant's configuration, and how many times it does that
# is not what this script is about.
check "and told the supplicant about it" \
	"$([ "$(told_about HomeFiber)" -ge 1 ] && echo yes || echo no)" yes
check "and knows nothing of a network nobody has configured" \
	"$(told_about Cafe)" 0

# ------------------------------------- a network arrives while it is running
#
# **The write 10.307 made.** A drop-in under `conf.d/`, which is what
# `ncfg wifi add` and every GUI dialog produce, naming a network the radio has
# never been given.

cat > "$work/etc/conf.d/60-cafe.conf" <<'CONF'
network "Cafe" {
	wifi { open = true }
	metric = 400
}
CONF

awaits '[ "$(told_about Cafe)" -ge 1 ]' || true
check "a network added while the daemon runs reaches the supplicant, with no apply" \
	"$([ "$(told_about Cafe)" -ge 1 ] && echo yes || echo no)" yes

# And it did not lose the one it already had, which is the other way a reload
# can be wrong: a supplicant reconfigured from scratch drops the association.
check "and the station is still on the network it was on" \
	"$(associated)" "HomeFiber"

# --------------------------------------------------- and the station moves
#
# `JOIN` is how this fixture says the station left one network for another, and
# netcfgd sees the same `CTRL-EVENT-CONNECTED` a real supplicant sends.
#
# **WHICH OF THESE TWO CHECKS GATES THE ARRIVAL, MEASURED RATHER THAN
# ASSUMED.** Sabotaged by watching `/etc` and not `conf.d/` -- the exact failure
# the daemon's own log made look likely -- only *"a network added while the
# daemon runs reaches the supplicant"* went red. The check below passed with
# the network never having reached the radio at all, because `associated()`
# reads what netcfgd observed from `STATUS`, and the fake reports whatever
# station it was told to be on whether or not anybody configured it.
#
# So this one is kept for what it does prove -- that netcfgd follows a station
# that moves, through its own observation -- and named for it. The arrival is
# gated by the `told_about` check above, and by nothing here.

send_event "JOIN Cafe"
awaits '[ "$(associated)" = Cafe ]' || true
check "and netcfgd sees the station on the network it moved to" \
	"$(associated)" "Cafe"

# ---------------------------------------------------------------- and quiet

check "and it never warned that the machine does not match" \
	"$(grep -c 'does not match its configuration' "$work/daemon.log" || true)" 0
check "nor that the configuration stopped compiling" \
	"$(grep -c 'does not compile' "$work/daemon.log" || true)" 0

if [ "$failures" -eq 0 ]; then
	echo "$name: $checks check(s), all passed"
else
	echo "$name: $failures of $checks check(s) failed"
	echo "--- the daemon's log ---"
	tail -30 "$work/daemon.log"
	exit 1
fi
