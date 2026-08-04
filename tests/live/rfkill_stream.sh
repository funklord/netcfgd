#!/bin/sh
# The `/dev/rfkill` event stream: a flipped switch wakes the daemon.
#
# 0062 made netcfgd report a blocked radio, read out of `/sys` during an
# observation. This is what makes the report prompt: an observation runs on a
# netlink event or on the loop's five-second backstop, and a kill switch
# produces neither reliably -- blocking a radio usually takes the interface
# down and shows up on netlink, but *unblocking* one produces nothing at all
# until something else happens.
#
# **The device is a fifo, not the real one.** Writing to `/dev/rfkill` blocks
# or unblocks every radio on the machine, and a test that did that would take
# the wifi off the desk it is running on. rfkill is not namespaced either, so
# `unshare -rn` is no protection. What is real here is the record format --
# eight bytes the kernel's own header defines, and the bytes below were
# captured from a real `/dev/rfkill` -- and the daemon's reaction to them.
# `tests/live/rfkill.sh` reads the real device, read-only, for the other half.
#
# Runs under `unshare -rn` for the dummy interface, not for the device.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "rfkill_stream.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "rfkill_stream.sh: skipping: $1"
	exit 0
}

command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"

work=$(mktemp -d /tmp/ncfg-rfk.XXXXXX)
daemon=
feeder=
cleanup() {
	for pid in $daemon $feeder; do
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_RFKILL_DEV="$work/rfkill"

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

mkfifo "$work/rfkill"

# The interface exists and is already what the document asks for, so the daemon
# has nothing to do and every reconcile is a no-op. What is being counted is
# whether it looked at all.
cat > "$work/etc/netcfgd.conf" <<'CONF'
interface quiet0 { kind = "dummy" }
CONF

# Holds the write end open so the daemon's read blocks rather than seeing EOF,
# and writes a record when told. The bytes are a real kernel's: index, type,
# op, soft, hard -- little-endian index, then four bytes.
python3 - "$work/rfkill" "$work/feed" <<'PY' &
import os, sys, time
device, trigger = sys.argv[1], sys.argv[2]
# Blocks until the daemon opens the read end, which is what makes this a
# reliable "the daemon is watching" signal for the shell below.
fd = os.open(device, os.O_WRONLY)
open(trigger + ".open", "w").close()
seen = 0
while True:
    if os.path.exists(trigger):
        want = int(open(trigger).read().strip() or 0)
        while seen < want:
            # idx=0, type=1 (WLAN), op=2 (CHANGE), soft=1, hard=0.
            os.write(fd, bytes([0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00]))
            seen += 1
    time.sleep(0.05)
PY
feeder=$!

"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ] && [ "$waited" -lt 50 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
[ -e "$work/run/netcfgd.sock" ] || { cat "$work/daemon.log" >&2; exit 1; }

waited=0
while [ ! -e "$work/feed.open" ] && [ "$waited" -lt 60 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
check "the daemon opened the rfkill device" \
	"$([ -e "$work/feed.open" ] && echo yes || echo no)" "yes"

# What the daemon writes on every observation, as the thing to count. The
# observed file is rewritten each time it looks, so its modification time is
# the answer to "did an event make it look again".
observed=$work/run/observed.json
waited=0
while [ ! -e "$observed" ] && [ "$waited" -lt 50 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
check "and wrote an observation to start with" \
	"$([ -e "$observed" ] && echo yes || echo no)" "yes"

# Settle, so the startup burst is over and the next change is the switch.
sleep 1
before=$(stat -c %Y.%y "$observed" 2>/dev/null || echo none)

# Flip it. One record, well inside the five-second backstop -- so if the
# observation moves, it moved because of the event and not because of the tick.
echo 1 > "$work/feed"
sleep 1
after=$(stat -c %Y.%y "$observed" 2>/dev/null || echo none)

if [ "$before" != "$after" ]; then
	echo "ok   a record on the device makes the daemon look again"
else
	echo "FAIL a record on the device makes the daemon look again"
	echo "       observation unchanged: $before"
	failures=$((failures + 1))
fi

if [ "$failures" -eq 0 ]; then
	echo "rfkill_stream.sh: all checks passed"
else
	echo "rfkill_stream.sh: $failures check(s) failed"
	exit 1
fi
