#!/bin/sh
# The wireless journey a person actually takes, end to end, with nothing
# configured to begin with. Run by `make live` inside `unshare -rn`.
#
# WHY THIS FILE EXISTS
#   Every wifi fault found in M8 was found by hand, on a laptop, after being
#   shipped -- while the suite stayed green. Each was the same shape: a
#   configuration written, a plan that was correct, and nothing that ran it.
#
#     * a supplicant that needed a `network` block before it would start, and
#       a scan that needed the supplicant, so neither could ever happen first;
#     * a `device` block that planned nothing, because the planner walks
#       interfaces and nothing had written an `interface` block;
#     * `ncfg wifi add` writing a network onto a machine with no radio
#       activated, which compiles and joins nothing;
#     * a daemon that never applied a configuration change at all.
#
#   Not one was visible to a unit test, because a unit test asserts the
#   artifact -- the file, the request, the plan -- and every one of these was a
#   correct artifact that changed nothing about the machine. So this asserts
#   the machine: is there a supplicant running, does a scan return, did the
#   network reach it.
#
# HOW IT HAS A RADIO WITHOUT A RADIO
#   Three fakes, and each replaces something a namespace cannot provide:
#
#     * a dummy link called `radio0`;
#     * `NCFG_SYS_CLASS_NET`, so `/sys/class/net/radio0/wireless` exists and
#       netcfgd's own predicate calls it a radio;
#     * `NCFG_WPA_SUPPLICANT`, so the supplicant netcfgd *starts* is
#       `fake_supplicant.py` rather than a real one that would find nothing.
#
#   The third is the one that was missing. `nm.sh` fakes a radio and a control
#   socket, but the *test* starts the fake -- so the step that had actually
#   broken, netcfgd deciding to start a supplicant and starting it, was the one
#   step no test performed.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "wifi_journey.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "wifi_journey.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed"
command -v ip >/dev/null 2>&1 || skip "iproute2 is not installed"

# Short, because a unix socket path has to fit in SUN_LEN.
work=$(mktemp -d /tmp/ncfg-journey.XXXXXX)
ncfg="$repo/target/debug/ncfg"
[ -x "$ncfg" ] || ncfg="$repo/target/debug/netcfgd"
daemon=
failures=0

cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	wait "$daemon" 2>/dev/null || true
	# Whatever netcfgd started, by the pid it recorded -- not by name, so a
	# supplicant belonging to something else on the machine is never touched.
	for pidfile in "$work"/run/supplicant/*.pid; do
		[ -e "$pidfile" ] || continue
		kill "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null || true
	done
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

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
	case "$2" in
	*"$3"*) echo "ok   $1" ;;
	*)
		echo "FAIL $1"
		echo "       expected to contain: $3"
		echo "       actual:              $2"
		failures=$((failures + 1))
		;;
	esac
}

# A radio, without a radio.
ip link add radio0 type dummy 2>/dev/null || skip "cannot create a dummy link"
ip link set radio0 up
mkdir -p "$work/sys/radio0/wireless" "$work/etc/conf.d" "$work/run" "$work/ctrl"

# Executable, because netcfgd runs it as a program. The shebang is the file's.
cp "$repo/tests/live/fake_supplicant.py" "$work/fake_supplicant"
chmod +x "$work/fake_supplicant"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_SYS_CLASS_NET="$work/sys"
export NCFG_WPA_CTRL_DIR="$work/ctrl"
# **Isolated from the host's NetworkManager state.** netcfgd refuses to start a
# supplicant on an interface another manager claims, and it learns that from the
# files NM leaves under `/run/NetworkManager/devices/<ifindex>`. On a developer
# machine those exist for real interfaces -- including `lo`, index 1 -- so
# without this a test would read the host's NM and be refused for reasons that
# have nothing to do with what it is testing. `displace.sh` points this at a
# tree it populates on purpose; everything else points it at an empty one.
mkdir -p "$work/runroot"
export NCFG_RUN_ROOT="$work/runroot"
export NCFG_WPA_SUPPLICANT="$work/fake_supplicant"

# Nothing configured. This is the state a fresh install is in, and the state
# every fault above was found in.
: > "$work/etc/netcfgd.conf"

"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		cat "$work/daemon.log" >&2
		echo "wifi_journey.sh: the daemon never started" >&2
		exit 1
	fi
	sleep 0.1
done

# ---------------------------------------------------------------------------
# 1. A radio nobody has activated is offered, and says so.
contains "a radio nobody activated is listed" "$("$ncfg" wifi radios 2>&1)" "radio0"
contains "and says it is not netcfgd's yet" "$("$ncfg" wifi radios 2>&1)" "not activated"

# The fault this whole file is about: scanning needs a supplicant, and there is
# none. What matters is that the refusal says *why netcfgd* has not started one
# rather than asking whether somebody else has.
contains "and a scan explains which configuration is missing" \
	"$("$ncfg" wifi scan radio0 2>&1 || true)" "no \`wifi\` policy"

# ---------------------------------------------------------------------------
# 2. Activating writes both blocks and starts the supplicant.
"$ncfg" wifi activate radio0 > "$work/activate.log" 2>&1 ||
	{ cat "$work/activate.log" >&2; echo "wifi_journey.sh: activate failed" >&2; exit 1; }

# Both blocks, because a `device` block alone plans nothing: the planner walks
# interfaces, so a radio with no `interface` block is never visited.
config="$work/etc/conf.d/radio-radio0.conf"
check "activation wrote a drop-in" "$([ -e "$config" ] && echo yes || echo no)" "yes"
contains "with the device block" "$(cat "$config" 2>/dev/null)" "device radio0 {"
contains "and the interface block, without which nothing is planned" \
	"$(cat "$config" 2>/dev/null)" "interface radio0 {"

# The assertion the unit tests could not make: a supplicant is *running*.
pidfile="$work/run/supplicant/radio0.pid"
waited=0
while [ ! -s "$pidfile" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 60 ] && break
	sleep 0.1
done
check "netcfgd started a supplicant" "$([ -s "$pidfile" ] && echo yes || echo no)" "yes"
started=$(cat "$pidfile" 2>/dev/null || echo 0)
check "and it is alive" \
	"$([ -n "$started" ] && [ -e "/proc/$started" ] && echo yes || echo no)" "yes"
check "and its control socket is there" \
	"$([ -e "$work/ctrl/radio0" ] && echo yes || echo no)" "yes"
contains "and netcfgd now calls the radio its own" "$("$ncfg" wifi radios 2>&1)" "netcfgd's"

# ---------------------------------------------------------------------------
# 3. Scanning works, which is what the radio was activated for.
scan=$("$ncfg" wifi scan radio0 2>&1 || true)
contains "a scan returns access points" "$scan" "HomeFiber"
contains "and reports the open one too" "$scan" "Cafe"

# ---------------------------------------------------------------------------
# 4. Adding a network, and it reaching the supplicant.
printf 'hunter2hunter2\n' | "$ncfg" wifi add HomeFiber > "$work/add.log" 2>&1 ||
	{ cat "$work/add.log" >&2; echo "wifi_journey.sh: add failed" >&2; exit 1; }

check "the network block was written" \
	"$([ -e "$work/etc/conf.d/wifi-HomeFiber.conf" ] && echo yes || echo no)" "yes"
secret="$work/etc/secrets/HomeFiber"
check "and the credential, at 0600" \
	"$(stat -c '%a' "$secret" 2>/dev/null || echo missing)" "600"
check "and the passphrase is not in the configuration" \
	"$(grep -rc hunter2hunter2 "$work/etc/conf.d" 2>/dev/null | grep -v ':0$' | wc -l)" "0"

# The join, which is what the whole journey was for: netcfgd hands the network
# to the supplicant. The fake logs every command it is sent.
"$ncfg" wifi connect HomeFiber > "$work/connect.log" 2>&1 || true
waited=0
while ! grep -q SELECT_NETWORK "$work/daemon.log" 2>/dev/null &&
	! grep -q SELECT_NETWORK "$work/fake.log" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 30 ] && break
	sleep 0.1
done
contains "joining reached the supplicant" \
	"$(cat "$work/connect.log" 2>&1)" "joining"

# ---------------------------------------------------------------------------
# 5. The same journey in one command, from nothing.
#
# **The case the section above cannot cover**, and the one the operator hit:
# there, the radio was handed over explicitly first, so by the time a network
# was added it was already netcfgd's. Here nothing is, and `ncfg wifi add`
# alone has to notice -- write the radio's blocks, hand it over, and leave a
# supplicant running. Checked by removing the activation from `wifi add`: with
# it gone, the section above still passes and this one does not.
# A clean boundary rather than a wipe under a running daemon. Removing the
# files while it watches means racing its reload, and the first version of this
# section did exactly that: `wifi add` asked a daemon still holding the old
# document, was told the radio was already netcfgd's, correctly did nothing,
# and the test reported the wrong fault. Stopping first makes the precondition
# a fact rather than a hope.
kill "$daemon" 2>/dev/null || true
wait "$daemon" 2>/dev/null || true
daemon=
[ -s "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null || true
rm -rf "$work/etc/conf.d" "$work/etc/secrets" "$work/run" "$work/ctrl"
mkdir -p "$work/etc/conf.d" "$work/run" "$work/ctrl"
: > "$work/etc/netcfgd.conf"

"$repo/target/debug/netcfgd" > "$work/daemon2.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		cat "$work/daemon2.log" >&2
		echo "wifi_journey.sh: the second daemon never started" >&2
		exit 1
	fi
	sleep 0.1
done
contains "a fresh machine has the radio back to nobody's" \
	"$("$ncfg" wifi radios 2>&1)" "not activated"

printf 'hunter2hunter2\n' | "$ncfg" wifi add HomeFiber > "$work/add2.log" 2>&1 ||
	{ cat "$work/add2.log" >&2; echo "wifi_journey.sh: the one-command add failed" >&2; exit 1; }

contains "one command says which radio it took" "$(cat "$work/add2.log")" "radio0"
check "and wrote the radio's blocks itself" \
	"$([ -e "$config" ] && echo yes || echo no)" "yes"
contains "including the interface block" "$(cat "$config" 2>/dev/null)" "interface radio0 {"

waited=0
while [ ! -s "$pidfile" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 60 ] && break
	sleep 0.1
done
revived=$(cat "$pidfile" 2>/dev/null || echo 0)
check "and left a supplicant running, from one command" \
	"$([ -n "$revived" ] && [ -e "/proc/$revived" ] && echo yes || echo no)" "yes"
contains "so a scan works straight away" "$("$ncfg" wifi scan radio0 2>&1 || true)" "HomeFiber"

echo
if [ "$failures" -eq 0 ]; then
	echo "wifi_journey.sh: all checks passed"
else
	echo "wifi_journey.sh: $failures failed"
	exit 1
fi
