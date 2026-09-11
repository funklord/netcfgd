#!/bin/sh
# The gpiod SIM-select hook, against an expander that is a Python script.
#
#     sh tests/live/sim_select.sh
#
# No root, no board and no GPIO. What is faked is the expander --
# `fake_gpiod.py` models the two behaviours the hook depends on and would be
# wrong without -- and what runs is the hook itself: its backgrounding, its
# bounded wait, its kill, its check after the release, and its trap.
#
# ## WHAT THIS CANNOT TELL YOU
#
# **It does not prove the hook works on a board.** Polarity, line names and the
# chip label are that board's, and a pca953x that behaved differently from the
# fake would not be caught here. Said plainly because the alternative is a
# green tick somebody reads as hardware coverage.
#
# What it does prove is everything that is not the hardware: that the hook
# returns rather than hanging on a `gpioset` that holds its line, that it
# drives the right line to the right value for each source, that it pulses
# reset and puts it back, that it notices a release that did not latch, and
# that a kill mid-reset does not leave the modem in reset for ever. Every one
# of those is a defect somebody would otherwise find on the board.

set -eu

repo=$(cd "$(dirname "$0")/../.." && pwd)
hook="$repo/packaging/hook/sim-select-gpiod.example"
fake="$repo/tests/live/fake_gpiod.py"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "sim_select.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "sim_select.sh: skipping: $1"
	exit 0
}

command -v python3 >/dev/null 2>&1 || skip "python3 is not installed"
[ -f "$hook" ] || skip "the hook example is not there"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-sim-select.XXXXXX")
cleanup() {
	status=$?
	set +e
	# Anything the hook left behind. It backgrounds `gpioset`, and a run that
	# died between the spawn and the kill would otherwise leave one sleeping
	# for two minutes in the test's own process group.
	pkill -f "$work/bin/gpioset" 2>/dev/null
	rm -rf "$work"
	exit "$status"
}
trap cleanup EXIT INT TERM

mkdir -p "$work/bin" "$work/run/modem" "$work/gpio" "$work/sys"
ln -s "$fake" "$work/bin/gpioset"
ln -s "$fake" "$work/bin/gpioinfo"
PATH="$work/bin:$PATH"
export PATH
export FAKE_GPIO_DIR="$work/gpio"

failures=0
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
equals() {
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1"
		echo "       expected: $3"
		echo "       actual:   $2"
		failures=$((failures + 1))
	fi
}

# The hook reads `<sysroot>/class/net/<iface>` to decide the modem came back.
# Pointed at a directory this test owns rather than at the machine's own, so a
# run here says nothing about whatever interfaces happen to exist -- and so
# both answers can be exercised, which is what `NCFG_SYS_ROOT` is for.
mkdir -p "$work/sys/class/net/wwan0"
publish() {
	printf 'sim=%s\napn=im.cxn\n' "$1" > "$work/run/modem/wwan0"
}
run_hook() {
	rm -f "$work/gpio/log"
	env NCFG_RUN_DIR="$work/run" NCFG_IFACE=wwan0 \
		GPIO_CHIP=gpiochip0 ENUM_WAIT=2 RESET_PULSE=1 \
		NCFG_SYS_ROOT="$work/sys" \
		sh "$hook" 2>&1 || echo "EXIT=$?"
}
log() { cat "$work/gpio/log" 2>/dev/null | tr '\n' ';'; }
line_state() { cut -d' ' -f1 "$work/gpio/CELL_SIM_SEL#_3V3" 2>/dev/null; }

# 1. **That the hook returns promptly, timed rather than assumed.**
#
#    This check used to be `contains "selecting socket"` under a name about not
#    hanging, and it was a lie: with `gpioset` called in the foreground the
#    hook blocked on every line and the check still passed, because the phrase
#    it looked for is printed *before* the block. It only came out because the
#    sabotage pass ran that exact mutation.
#
#    A hook that blocks on `gpioset` holds netcfgd's reconcile until the sixty
#    second hook timeout kills it, on every bring-up. That is a duration, so
#    the check is a duration. The real work here is one reset pulse plus a few
#    tenths: ten seconds is far above it and far below a hook that is hanging.
publish socket
started=$(date +%s)
out=$(run_hook)
elapsed=$(( $(date +%s) - started ))
if [ "$elapsed" -lt 10 ]; then
	echo "ok   the hook returns promptly rather than blocking on a held line"
else
	echo "FAIL the hook returns promptly rather than blocking on a held line"
	echo "       took ${elapsed}s, which is a hook that is waiting for gpioset"
	failures=$((failures + 1))
fi
contains "and selects the source it was told" "$out" "selecting socket"
lacks "and does not fail" "$out" "EXIT="
equals "the select line is driven to the socket value" "$(line_state)" "0"

# 2. The other source drives the other value. Two sources rather than one,
#    because a hook that drove a constant would pass every check above.
publish esim
out=$(run_hook)
contains "the other source is selected" "$out" "selecting esim"
equals "and drives the other value" "$(line_state)" "1"
# The reset takes the module's interface away with the USB device, so the hook
# waits for it before returning -- netcfgd brings the interface up when the
# hook returns, and returning early hands it one that is not there.
contains "and waits for the interface to come back" "$out" "wwan0 is back after"

# **The other answer, which must not be a failure.** A modem that does not
# re-enumerate is a runtime fact the probe is about to establish anyway, and
# refusing here would abort the bring-up -- which never reaches the probe, so
# netcfgd would never learn to try the next source. A unit that cannot fall
# back is a unit somebody has to physically visit.
mv "$work/sys/class/net/wwan0" "$work/sys/class/net/gone"
out=$(run_hook)
contains "an interface that does not come back is said" "$out" "did not come back in 2s"
contains "and why the hook carries on anyway" "$out" "so the probe can fail"
lacks "and it is not a failure" "$out" "EXIT="
mv "$work/sys/class/net/gone" "$work/sys/class/net/wwan0"

# 3. **The reset is pulsed and put back.** A hook that asserted reset and
#    returned would leave the modem held in reset for ever, because the latch
#    keeps the line after the request is released.
recorded=$(log)
contains "reset is asserted" "$recorded" "set M2_RST_3V3=1"
contains "and released again" "$recorded" "set M2_RST_3V3=0"
equals "and the line ends up running, not in reset" \
	"$(cut -d' ' -f1 "$work/gpio/M2_RST_3V3")" "0"

# 4. **The line is held after the setter is killed.** This is the behaviour the
#    whole set-then-release approach rests on, so it is asserted rather than
#    assumed: every `set` above is followed by a `release` that latched.
contains "releasing the line latches rather than floating it" "$recorded" "release CELL_SIM_SEL#_3V3 -> latched"

# 5. **A kernel that restored the direction on release would be caught.** No
#    board here does that; the hook checks because everything downstream would
#    silently be about the wrong SIM if one did, and a check nothing exercises
#    is a check nobody knows is broken.
#
#    The shim is written to its own path and then moved over the symlink.
#    Writing straight to `$work/bin/gpioset` would follow the link and
#    overwrite `fake_gpiod.py` in the source tree, which is exactly what it did
#    the first time this was run.
cat > "$work/shim" <<'SHIM'
#!/bin/sh
exec python3 "$FAKE_GPIOD" --as gpioset --restore-on-release "$@"
SHIM
chmod +x "$work/shim"
FAKE_GPIOD=$fake
export FAKE_GPIOD
rm -f "$work/bin/gpioset"
mv "$work/shim" "$work/bin/gpioset"
publish socket
out=$(run_hook)
contains "a line that does not stay driven is refused" "$out" "did not stay driven"
contains "and the hook fails rather than carrying on" "$out" "EXIT=1"
rm -f "$work/bin/gpioset"
ln -s "$fake" "$work/bin/gpioset"

# 6. A source the hook has no value for is fatal, and says which. The
#    alternative is bringing the interface up on whichever source the mux was
#    left on, which looks like the fallback working.
publish spare
out=$(run_hook)
contains "an unknown source is refused" "$out" "no idea how to select \`spare\`"
contains "naming what to set" "$out" "VALUE_spare"
contains "and fails" "$out" "EXIT=1"

# 7. Nothing published is not an error: a device with no `modem` block never
#    gets a file, and a hook that guessed a default there is the failure 0152
#    keeps netcfgd itself away from.
rm -f "$work/run/modem/wwan0"
out=$(run_hook)
equals "no published selection does nothing at all" "$out" ""

# 8. A `modem` block naming an APN and no source is an ordinary configuration:
#    configure the APN, leave the SIM alone.
printf 'apn=im.cxn\n' > "$work/run/modem/wwan0"
out=$(run_hook)
equals "a published apn with no source does nothing either" "$out" ""

# 9. **A hook killed mid-reset releases the modem.** netcfgd sends SIGTERM at
#    the hook timeout, and without the trap the latch would hold the module in
#    reset until somebody power-cycled the board. Killed during the pulse,
#    which is where the window is.
publish socket
rm -f "$work/gpio/log"
env NCFG_RUN_DIR="$work/run" NCFG_IFACE=wwan0 GPIO_CHIP=gpiochip0 \
	ENUM_WAIT=2 RESET_PULSE=8 sh "$hook" > "$work/killed" 2>&1 &
victim=$!
# Long enough to be inside the pulse, short enough to be well before its end.
sleep 3
kill -TERM "$victim" 2>/dev/null || true
wait "$victim" 2>/dev/null || true
contains "a hook killed mid-reset says it is releasing" "$(cat "$work/killed")" "releasing the modem from reset"
equals "and the modem is left running rather than held in reset" \
	"$(cut -d' ' -f1 "$work/gpio/M2_RST_3V3")" "0"

echo
if [ "$failures" -eq 0 ]; then
	echo "sim_select.sh: all checks passed"
else
	echo "sim_select.sh: $failures failed"
	exit 1
fi
