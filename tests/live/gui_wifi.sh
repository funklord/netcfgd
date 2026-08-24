#!/bin/sh
# The GUI's wifi view against a real daemon, driven by its own buttons.
#
# WHY THIS FILE EXISTS
#   "The buttons don't work properly" is a report nothing in this repository
#   could have answered. The probes under `gui/tests/` are widget logic with no
#   daemon: they check that a state produces a rendering, given the state.
#   Whether the state ever arrives -- whether `scan` fills the table, whether
#   `activate radio` leaves a supplicant running -- is a join between the view,
#   the C client, the socket and the daemon, and every fault this milestone was
#   in a join.
#
#   `wifi_journey.sh` does the same for the command line. This is the other
#   client, and it is the one the report was about.
#
# WHAT IT NEEDS, AND WHAT IT SKIPS FOR
#   Qt, which most machines running `make live` will not have. A skip here is
#   honest: the GUI is behind a build profile in packaging too, so a machine
#   without Qt is one that never builds it.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	# Unlike the other live scripts, NCFG_LIVE does *not* make this fatal: Qt
	# is a real dependency a machine may reasonably not have, where python3
	# and iproute2 are not. A suite that refused to run without Qt would make
	# the GUI's absence break the daemon's tests.
	echo "gui_wifi.sh: skipping: $1"
	exit 0
}

command -v qmake6 >/dev/null 2>&1 || skip "qmake6 is not installed (apt install qt6-base-dev)"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed"
command -v ip >/dev/null 2>&1 || skip "iproute2 is not installed"

# The C client the view links. Built here rather than assumed, because a live
# run does not otherwise build it.
make -C "$repo/client" >/dev/null 2>&1 || skip "the C client will not build"

# Found rather than listed, the way `gui/Makefile` finds the headless probes,
# so a fourth needs no edit here. Each gets its own build directory: two qmake
# projects in one directory overwrite each other's Makefile.
probes=$(ls "$repo"/gui/tests/live/*.pro 2>/dev/null || true)
[ -n "$probes" ] || skip "no probes found under gui/tests/live"

for project in $probes; do
	name=$(basename "$project" .pro)
	build="$repo/gui/tests/live/build/$name"
	mkdir -p "$build"
	(cd "$build" && qmake6 "$project" >/dev/null && make >/dev/null 2>&1) ||
		skip "$name will not build (is qt6-base-dev complete?)"
	[ -x "$build/$name" ] || skip "$name did not build"
done

# Short, because a unix socket path has to fit in SUN_LEN.
work=$(mktemp -d /tmp/ncfg-guiw.XXXXXX)
daemon=

cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	wait "$daemon" 2>/dev/null || true
	for pidfile in "$work"/run/supplicant/*.pid; do
		[ -e "$pidfile" ] || continue
		kill "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null || true
	done
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

ip link add radio0 type dummy 2>/dev/null || skip "cannot create a dummy link"
ip link set radio0 up
mkdir -p "$work/sys/radio0/wireless" "$work/etc/conf.d" "$work/run" "$work/ctrl"
cp "$repo/tests/live/fake_supplicant.py" "$work/fake_supplicant"
chmod +x "$work/fake_supplicant"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_SYS_CLASS_NET="$work/sys"
export NCFG_WPA_CTRL_DIR="$work/ctrl"
export NCFG_WPA_SUPPLICANT="$work/fake_supplicant"
export QT_QPA_PLATFORM=offscreen
# Where `contention.rs` looks for the files other managers leave. Pointed at
# the fixture so a probe can invent a NetworkManager without one being
# installed -- and, more to the point, without one being *running*, which on a
# developer's machine it usually is.
export NCFG_RUN_ROOT="$work/runroot"
mkdir -p "$work/runroot"
# The index, because every daemon in `contention.rs` keys its state by ifindex
# rather than by name: an interface can be renamed and the index cannot.
# From `ip`, not from /sys: inside `unshare -rn` the /sys/class/net tree still
# shows the *parent* namespace's links unless /sys is remounted, so the dummy
# created a moment ago is not there. That is the same reason the fake sysfs
# override exists at all, and it is worth knowing before writing any test that
# expects to find a namespaced interface under /sys.
NCFG_TEST_RADIO_INDEX=$(ip -o link show radio0 | cut -d: -f1 | tr -d ' ')
export NCFG_TEST_RADIO_INDEX

# Nothing configured, which is the state the report came from.
: > "$work/etc/netcfgd.conf"

"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		cat "$work/daemon.log" >&2
		echo "gui_wifi.sh: the daemon never started" >&2
		exit 1
	fi
	sleep 0.1
done

failed=0
for project in $probes; do
	name=$(basename "$project" .pro)
	"$repo/gui/tests/live/build/$name/$name" || failed=1
done
if [ "$failed" -ne 0 ]; then
	echo "gui_wifi.sh: the daemon those probes were talking to said:" >&2
	tail -8 "$work/daemon.log" >&2
	exit 1
fi
