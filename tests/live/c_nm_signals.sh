#!/bin/sh
# The shim's signals, watched on the bus, with something forced to happen.
#
#     unshare -rn sh tests/live/c_nm_signals.sh
#
# ## Why this exists rather than a unit test
#
# `bus_test` drives both detectors directly and sabotages each to watch it fail,
# so "did it notice" is already answered. What a unit test cannot answer is
# whether the answer reaches a client: `nmc_emit_path` and `nmc_emit_numbers`
# build and send messages, and nothing short of a bus observes that.
#
# ## The control, which is the whole point
#
# **A quiet bus is what a converged machine looks like and also what a broken
# emitter looks like**, and this adapter has twice been quiet for the wrong
# reason. So this does not watch and hope. It appends a drop-in declaring a
# device netcfgd has never seen, which the daemon picks up on its own, and then
# requires `DeviceAdded` to appear. A run where nothing is forced proves
# nothing; a run where something is forced and nothing arrives is a failure.
#
# The first-sight silence is checked too, and in the right order: the monitor is
# attached before the shim starts, so the startup ticks are observed rather than
# assumed, and a shim announcing every device it found at startup fails here.
#
# ## What it does to the machine
#
# Nothing. A private bus, a private netcfgd with its own config and run
# directories, dummy links in the namespace `unshare -rn` gave it, and the shim
# with `--session` so the name is claimed there and never on the system bus.
set -eu

name=c_nm_signals.sh
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"
shim="$repo/adapter/netcfgd-nm/c/netcfgd-nm"

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
command -v dbus-daemon >/dev/null 2>&1 || skip "dbus-daemon is not installed"
command -v dbus-monitor >/dev/null 2>&1 || skip "dbus-monitor is not installed"
[ -x "$build/netcfgd" ] || skip "netcfgd is not built"
[ -x "$shim" ] || skip "the C shim is not built (make -C adapter/netcfgd-nm/c)"
ip link add probe-ns type dummy 2>/dev/null || skip "no namespace to make links in"
ip link del probe-ns 2>/dev/null || true

# Short, because a unix socket path has to fit in sun_path.
work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-sig.XXXXXX")
daemon=
bus=
shim_pid=
monitor=
cleanup() {
	# Each by its own pid, recorded when it was started. Nothing here matches
	# a pattern: a `pkill` for any of these three names on a developer's
	# machine reaches the NetworkManager running it.
	[ -n "$monitor" ] && kill "$monitor" 2>/dev/null
	[ -n "$shim_pid" ] && kill "$shim_pid" 2>/dev/null
	[ -n "$bus" ] && kill "$bus" 2>/dev/null
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
	return 0
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc/conf.d" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
# A network namespace is not a mount namespace, so without this the DNS backend
# writes the resolver configuration of the machine running the test.
export NCFG_RESOLV_CONF="$work/resolv.conf"

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

# Twenty seconds in tenths, returning as soon as the condition holds. The bound
# is the assertion: a signal nobody is waiting on is not a signal. Twenty rather
# than ten because a tick is two hundred milliseconds and the daemon's reload
# has to land first.
awaits() {
	i=0
	while [ "$i" -lt 200 ]; do
		if eval "$1" >/dev/null 2>&1; then
			return 0
		fi
		i=$((i + 1))
		sleep 0.1
	done
	return 1
}

saw() {
	grep -c "member=$1" "$work/monitor.log" 2>/dev/null || true
}

# ------------------------------------------------------ the running machine

cat > "$work/etc/netcfgd.conf" <<'CONF'
device sig0 {
	kind = "dummy"
}
interface sig0 {
	config = "10.30.0.1/24"
}
CONF

"$build/netcfgd" $daemon_flags > "$work/daemon.log" 2>&1 &
daemon=$!
awaits '[ -e "$work/run/netcfgd.sock" ]' || {
	echo "$name: the daemon never bound its socket" >&2
	cat "$work/daemon.log" >&2
	exit 1
}

# nm.sh's spelling, and the pid comes from the daemon itself: it forks, so `$!`
# would be the shell that forked and the cleanup would kill nothing.
eval "$(dbus-daemon --session --print-address=1 --print-pid=1 --fork | {
	read -r address
	read -r pid
	echo "address='$address'; bus=$pid"
})"
[ -n "${address:-}" ] || skip "the private bus printed no address"
export DBUS_SESSION_BUS_ADDRESS="$address"

# ------------------------------------------------ attached BEFORE the shim
#
# The order is the test. Attached afterwards, the startup ticks would already
# have gone by and "nothing at startup" would be a claim about a window nobody
# watched.
dbus-monitor --session "type='signal'" > "$work/monitor.log" 2>&1 &
monitor=$!
awaits '[ -f "$work/monitor.log" ]' || true

"$shim" --session > "$work/shim.log" 2>&1 &
shim_pid=$!
awaits 'dbus-send --session --print-reply --dest=org.freedesktop.NetworkManager \
	/org/freedesktop/NetworkManager org.freedesktop.DBus.Properties.Get \
	string:org.freedesktop.NetworkManager string:Version' || {
	echo "$name: the shim never answered on the private bus" >&2
	cat "$work/shim.log" >&2
	exit 1
}

# Four ticks' worth, so the round-robin has been all the way round and every
# set has been seen at least twice.
sleep 3
check "nothing is announced for what was already there at startup" \
	"$(saw DeviceAdded)" 0
check "nor is anything announced as having gone" \
	"$(saw DeviceRemoved)" 0

# -------------------------------------------------------------- the control
#
# A dummy link added in this namespace, and nothing else. **Not a configuration
# change, which is what the first version of this did and got wrong**: removing a
# drop-in stops netcfgd managing a device and does not make the link go away, so
# the device was still reported, still served, and the shim was right to keep
# announcing nothing. The check was the thing at fault.
#
# A link arriving and leaving is also what the signal is FOR -- a client wants to
# know a cable went in, not that somebody edited a file.

ip link add probe1 type dummy
awaits '[ "$(saw DeviceAdded)" -gt 0 ]' || true
check "a device that arrives is announced to the bus" \
	"$([ "$(saw DeviceAdded)" -gt 0 ] && echo yes || echo no)" yes
# The path matters as much as the member: a client subscribes per object, and a
# `DeviceAdded` carrying the manager's own path would be unusable.
# Asked as a yes rather than as two counts, because two counts that are both
# zero agree -- so a bus with nothing on it would satisfy a comparison written
# the obvious way.
check "and it carries a device path rather than the manager's" \
	"$(seen=$(saw DeviceAdded)
	   paths=$(grep -A4 'member=DeviceAdded' "$work/monitor.log" |
	       grep -c '/org/freedesktop/NetworkManager/Devices/')
	   [ "$seen" -gt 0 ] && [ "$paths" -eq "$seen" ] && echo yes || echo no)" yes
# **The signal libnm actually reads, which is a different one.** `DeviceAdded` is
# read as a hint about an object a client is expected to know already; what tells
# it the object EXISTS is the object manager's `InterfacesAdded`. A shim emitting
# only the first leaves a device no libnm client can see, which is what
# `tests/live/nm.sh` reported as nmcli listing one device out of six.
check "and the object manager says the object exists" \
	"$([ "$(saw InterfacesAdded)" -gt 0 ] && echo yes || echo no)" yes
check "on /org/freedesktop, which is where NM puts its object manager" \
	"$(seen=$(saw InterfacesAdded)
	   there=$(grep 'member=InterfacesAdded' "$work/monitor.log" |
	       grep -c 'path=/org/freedesktop;')
	   [ "$seen" -gt 0 ] && [ "$there" -eq "$seen" ] && echo yes || echo no)" yes
check "it is emitted on the manager, which is where NM emits it" \
	"$(seen=$(saw DeviceAdded)
	   there=$(grep 'member=DeviceAdded' "$work/monitor.log" |
	       grep -c 'path=/org/freedesktop/NetworkManager;')
	   [ "$seen" -gt 0 ] && [ "$there" -eq "$seen" ] && echo yes || echo no)" yes

# ------------------------------------------------------------- the removal
#
# The same link taken away. netcfgd stops reporting it, the store marks the slot
# absent and keeps its number -- a client holding that path must be told the
# device is gone rather than handed whoever comes next.

ip link del probe1
awaits '[ "$(saw DeviceRemoved)" -gt 0 ]' || true
check "a device that goes is announced too" \
	"$([ "$(saw DeviceRemoved)" -gt 0 ] && echo yes || echo no)" yes
check "and the object manager says it has gone" \
	"$([ "$(saw InterfacesRemoved)" -gt 0 ] && echo yes || echo no)" yes
check "and that one is on the manager as well" \
	"$(seen=$(saw DeviceRemoved)
	   there=$(grep 'member=DeviceRemoved' "$work/monitor.log" |
	       grep -c 'path=/org/freedesktop/NetworkManager;')
	   [ "$seen" -gt 0 ] && [ "$there" -eq "$seen" ] && echo yes || echo no)" yes

if [ "$failures" -ne 0 ]; then
	echo "--- signals seen:" >&2
	grep -o 'member=[A-Za-z]*' "$work/monitor.log" | sort | uniq -c >&2
	echo "--- Devices now:" >&2
	dbus-send --session --print-reply --dest=org.freedesktop.NetworkManager \
		/org/freedesktop/NetworkManager org.freedesktop.DBus.Properties.Get \
		string:org.freedesktop.NetworkManager string:Devices >&2 2>&1 || true
fi

printf '\n%s: %d check(s)\n' "$name" "$checks"
if [ "$failures" -eq 0 ]; then
	printf '%s: all checks passed\n' "$name"
else
	printf '%s: %d check(s) failed\n' "$name" "$failures"
fi
exit "$failures"
