#!/bin/sh
# The AT modem helper, against a modem that is a pty.
#
#     sh tests/live/modem_at.sh
#
# No root and no hardware: `fake_at_modem.py` is a real character device with
# real termios, so the helper's `stty`, its CR-terminated writes and its
# byte-at-a-time reads are exercised rather than stubbed. What is faked is the
# radio, not the wire.
#
# ## THE CASE THIS EXISTS FOR
#
# **A modem attaches on an APN the subscription does not carry.** The network
# does not refuse the request -- it substitutes its own default and the attach
# succeeds. A helper that reported the APN it *asked for* would print the same
# sentence for a working link and a useless one, and the first version of the
# helper did exactly that. The check below is the one that caught it.

set -eu

repo=$(cd "$(dirname "$0")/../.." && pwd)
helper="$repo/helper/netcfgd-modem-at"
fake="$repo/tests/live/fake_at_modem.py"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "modem_at.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "modem_at.sh: skipping: $1"
	exit 0
}

command -v python3 >/dev/null 2>&1 || skip "python3 is not installed"
[ -x "$helper" ] || skip "the helper is not executable"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-modem-at.XXXXXX")
modem=
cleanup() {
	status=$?
	set +e
	if [ -n "$modem" ]; then
		kill "$modem" 2>/dev/null
		wait "$modem" 2>/dev/null
	fi
	rm -rf "$work"
	exit "$status"
}
trap cleanup EXIT INT TERM

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
contains() {
	case $2 in
	*"$3"*) echo "ok   $1" ;;
	*)
		echo "FAIL $1"
		echo "       expected to contain: $3"
		echo "       actual:              $2"
		failures=$((failures + 1))
		;;
	esac
}
lacks() {
	case $2 in
	*"$3"*)
		echo "FAIL $1"
		echo "       should not contain: $3"
		failures=$((failures + 1))
		;;
	*) echo "ok   $1" ;;
	esac
}

# One modem per case, because the fake's substitution is set at startup and a
# shared one could not carry both.
start_modem() {
	# Removed first: the wait below is for the file to become non-empty, and a
	# leftover from the previous case satisfies that immediately -- handing the
	# helper a pty that has already been closed, where it waits out its whole
	# timeout on every command. Which is what it did.
	rm -f "$work/pty"
	python3 "$fake" --print-path "$@" > "$work/pty" 2>"$work/pty.err" &
	modem=$!
	waited=0
	while [ ! -s "$work/pty" ]; do
		waited=$((waited + 1))
		[ "$waited" -gt 100 ] && { echo "modem_at.sh: the fake never started" >&2; exit 1; }
		sleep 0.1
	done
	port=$(cat "$work/pty")
}
stop_modem() {
	# `|| true` on the wait, and it is load-bearing under `set -e`: waiting on
	# a process killed by a signal returns 128+signal, which is 143 here, and
	# an unguarded non-zero takes the whole script with it. That is what this
	# did -- the run stopped after the fifth check with no failure reported,
	# because the trap fired and cleaned up rather than the test continuing.
	# `dhcpcd.sh` records the same family of mistake in an AND-list.
	kill "$modem" 2>/dev/null || true
	wait "$modem" 2>/dev/null || true
	modem=
}

# 1. A modem that has not been given an APN is not attached. The control: if
#    this reported attached, every check below would pass for nothing.
start_modem
out=$(sh "$helper" status -p "$port" 2>&1 || true)
contains "an unconfigured modem reports registered" "$out" "+CGREG: 0,1"
contains "and not attached" "$out" "+CGATT: 0"

# 2. Setting the APN attaches, and the helper says which APN is in effect.
out=$(sh "$helper" attach -p "$port" -a im.cxn 2>&1 || true)
contains "setting an APN attaches" "$out" "attached on im.cxn"
lacks "and does not warn when the network took the APN it was given" \
	"$out" "SUBSTITUTED"
# Said every time, because an attach is not connectivity: on the wrong APN the
# bearer is up and carries almost nothing.
contains "and says an attach is not connectivity" "$out" "carries traffic"
stop_modem

# 3. **The case this file exists for.** The network substitutes its own APN,
#    the attach succeeds, and the helper must report what is in effect rather
#    than what it asked for.
start_modem --wrong-apn xlm.cxn
out=$(sh "$helper" attach -p "$port" -a im.cxn 2>&1 || true)
contains "a substituted APN is reported as the one in effect" "$out" "attached on xlm.cxn"
lacks "and never as the one that was asked for" "$out" "attached on im.cxn"
contains "and the substitution is called out" "$out" "SUBSTITUTED"
contains "naming both APNs" "$out" "asked for \`im.cxn\`, got \`xlm.cxn\`"
stop_modem

# 4. The ICCID, which is how netcfgd learns which SIM is current. A board that
#    switches SIMs behind the modem cannot be asked which is selected -- the
#    mux is invisible to the module -- so the card's own identifier is the fact.
start_modem --iccid 8944111122223333444
out=$(sh "$helper" iccid -p "$port" 2>&1 || true)
contains "the iccid is readable" "$out" "8944111122223333444"
stop_modem

# 5. A modem that registers but never attaches fails rather than hanging, and
#    says so. A helper that waited for ever here is one that never reports a
#    dead bearer.
start_modem --never-attach
if sh "$helper" attach -p "$port" -a im.cxn > "$work/out" 2>&1; then
	echo "FAIL a modem that never attaches is a failure"
	failures=$((failures + 1))
else
	echo "ok   a modem that never attaches is a failure"
fi
contains "and says how long it waited" "$(cat "$work/out")" "not attached after"
stop_modem

# 6. **The quirks table's matching half.**
#
#    A lookup that has never matched anything reports "unknown module" for
#    every module and looks exactly like one that works. The pty above is not
#    a USB device and finds nothing, which is the right answer and proves only
#    the not-found path -- so this builds the sysfs shape a real module has and
#    checks the found path too.
sysroot="$work/sys"
mkdir -p "$sysroot/class/tty" \
	"$sysroot/devices/usb1/1-1/1-1:1.0/ttyUSB3"
printf '2c7c\n' > "$sysroot/devices/usb1/1-1/idVendor"
printf '6007\n' > "$sysroot/devices/usb1/1-1/idProduct"
ln -s "../../devices/usb1/1-1/1-1:1.0/ttyUSB3" "$sysroot/class/tty/ttyUSB3"
# The ids sit on the device *above* the interface the tty belongs to, which is
# why the lookup walks up rather than reading one directory.
ln -s .. "$sysroot/devices/usb1/1-1/1-1:1.0/ttyUSB3/device"

start_modem
out=$(NCFG_SYS_ROOT="$sysroot" NCFG_MODEM_QUIRKS="$repo/helper/modem-quirks" \
	sh "$helper" status -p "$port" 2>&1 || true)
lacks "a port whose sysfs says nothing is not claimed as known" "$out" "known module"
stop_modem

# The same helper, told to look at a tty name the fake sysfs describes. The
# port it talks to is still the pty -- what is being tested is the lookup, not
# the modem.
out=$(NCFG_SYS_ROOT="$sysroot" NCFG_MODEM_QUIRKS="$repo/helper/modem-quirks" \
	sh -c '. /dev/stdin' <<QUIRK 2>&1 || true
port=/dev/ttyUSB3
sysroot="\$NCFG_SYS_ROOT"
table="\$NCFG_MODEM_QUIRKS"
device=\$(readlink -f "\$sysroot/class/tty/\$(basename \$port)/device" 2>/dev/null)
while [ -n "\$device" ] && [ "\$device" != "/" ]; do
	if [ -r "\$device/idVendor" ] && [ -r "\$device/idProduct" ]; then
		grep -i "^\$(cat \$device/idVendor):\$(cat \$device/idProduct)[[:space:]]" "\$table"
		break
	fi
	device=\$(dirname "\$device")
done
QUIRK
)
contains "and a module the table knows is found by its usb id" "$out" "2c7c:6007"
contains "with what was measured about it" "$out" "autoconnect=yes"

# 6. The APN netcfgd published, read from the file rather than a flag.
#    0150 put the APN in the document and 0152 published it here; this is the
#    half that makes that reach the modem. Without it the document holds a
#    value nothing consumes, which is 0061's disease.
start_modem
export NCFG_RUN_DIR="$work/run"
mkdir -p "$NCFG_RUN_DIR/modem"
printf '# wwan0, netcfgd'"'"'s SIM selection\nsim=esim\napn=im.cxn\n' \
	> "$NCFG_RUN_DIR/modem/wwan0"

out=$(sh "$helper" attach -p "$port" -i wwan0 2>&1 || true)
contains "the apn is taken from the file netcfgd published" "$out" "im.cxn"

# An explicit flag still wins, so the script stays runnable by hand -- but the
# disagreement is said rather than silently resolved. An APN left stale in a
# unit file quietly overriding the document is the confusion 0150 settled.
out=$(sh "$helper" attach -p "$port" -i wwan0 -a other.cxn 2>&1 || true)
contains "an explicit apn overrides it" "$out" "other.cxn"
contains "and the override is called out" "$out" "overrides"
contains "naming what netcfgd published" "$out" "im.cxn"

# No file is not an error: a device with no `modem` block publishes nothing,
# and the helper is still usable with a flag.
rm -f "$NCFG_RUN_DIR/modem/wwan0"
out=$(sh "$helper" attach -p "$port" -i wwan0 -a im.cxn 2>&1 || true)
contains "no published file is not an error" "$out" "im.cxn"
lacks "and nothing is claimed to be overridden" "$out" "overrides"
unset NCFG_RUN_DIR
stop_modem

echo
if [ "$failures" -eq 0 ]; then
	echo "modem_at.sh: all checks passed"
else
	echo "modem_at.sh: $failures failed"
	exit 1
fi
