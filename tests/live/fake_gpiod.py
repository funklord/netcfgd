#!/usr/bin/env python3
"""Stand-ins for `gpioset` and `gpioinfo`, modelling what a pca953x does.

`tests/live/sim_select.sh` puts a directory holding two symlinks to this on
`PATH` and runs the hook. What is faked is the expander; the hook's own logic
-- backgrounding, waiting, killing, checking, the trap -- is the real thing.

THE TWO BEHAVIOURS THAT MATTER, AND WHY THEY ARE MODELLED RATHER THAN STUBBED

  - **`gpioset` holds the line until it is killed.** That is libgpiod v2, and
    it is the whole reason the hook backgrounds it. A stub that exited
    immediately would let a hook calling `gpioset` plainly pass here and then
    hang for sixty seconds on hardware, which is the defect this exists to
    catch.

  - **Releasing a line does not return the pin to an input.** The direction
    register and the output latch both keep their values, which is what makes
    set-then-release work at all -- and what makes a crash leave the mux
    driven. So the recorded state survives the process exiting.

`--restore-on-release` models the opposite kernel, where releasing a line does
return it to an input. No board here behaves that way; the hook checks for it
because everything downstream would silently be about the wrong SIM if one
ever did, and this is how that check is checked.

State lives in $FAKE_GPIO_DIR, one file per line holding `<value> <direction>`,
plus an append-only `log` of every request -- which is what the test reads to
assert the sequence rather than only the final state.
"""

import argparse
import os
import pathlib
import signal
import sys
import time

STATE = pathlib.Path(os.environ.get("FAKE_GPIO_DIR", "/tmp/fake-gpio"))
# The lines this board has, by name, as `gpio-line-names` would give them.
LINES = os.environ.get("FAKE_GPIO_LINES", "CELL_SIM_SEL#_3V3,M2_RST_3V3,MCU_BOOT0").split(",")


def path_of(name):
	return STATE / name.replace("/", "_")


def record(name, value=None, direction=None, consumer=None):
	held, shape, owner = read(name)
	if value is not None:
		held = value
	if direction is not None:
		shape = direction
	if consumer is not None:
		owner = consumer
	path_of(name).write_text(f"{held} {shape} {owner}")


def read(name):
	path = path_of(name)
	if not path.exists():
		return "0", "input", "-"
	fields = path.read_text().strip().split()
	while len(fields) < 3:
		fields.append("-")
	return fields[0], fields[1], fields[2]


def log(line):
	with (STATE / "log").open("a", encoding="utf-8") as handle:
		handle.write(line + "\n")


def do_info(argv):
	parser = argparse.ArgumentParser()
	parser.add_argument("-c", "--chip", default="")
	parser.parse_args(argv)
	for index, name in enumerate(LINES):
		value, direction, owner = read(name)
		# `consumer=` appears only while the line is requested, which is what
		# separates "somebody holds this now" from "somebody left it an
		# output". The hook waits on the first and checks the second.
		held = f' consumer="{owner}"' if owner != "-" else ""
		print(f'\tline {index:3}: "{name}" {direction} active-high{held} value={value}')
	return 0


def do_set(argv):
	parser = argparse.ArgumentParser()
	parser.add_argument("-c", "--chip", default="")
	parser.add_argument("--restore-on-release", action="store_true")
	parser.add_argument("assignments", nargs="+")
	args = parser.parse_args(argv)

	held = []
	for assignment in args.assignments:
		name, _, value = assignment.partition("=")
		record(name, value=value, direction="output", consumer="gpioset")
		log(f"set {name}={value}")
		held.append(name)

	def release(_signum, _frame):
		for name in held:
			# The consumer goes on release either way -- the request is what
			# it names. What differs is whether the direction survives it.
			if args.restore_on_release:
				record(name, direction="input", consumer="-")
				log(f"release {name} -> input")
			else:
				record(name, consumer="-")
				log(f"release {name} -> latched")
		sys.exit(0)

	signal.signal(signal.SIGTERM, release)
	signal.signal(signal.SIGINT, release)
	# Held until killed, which is what v2 does and what the hook must survive.
	#
	# Not forever, and the number is chosen from both sides. A correct hook
	# kills this within a fraction of a second, so anything above a second is
	# past what it waits for. The cap matters for the *incorrect* hook: with it
	# at two minutes, a hook calling `gpioset` in the foreground made the whole
	# suite exceed its own timeout and get killed, which is a failure nobody
	# can read. Fifteen seconds is long enough never to expire under a correct
	# hook and short enough that a blocking one is reported as a failed check
	# with a duration attached.
	time.sleep(15)
	release(None, None)
	return 0


def main():
	STATE.mkdir(parents=True, exist_ok=True)
	# Dispatch on argv[0], so the two symlinks behave as the two tools -- and
	# on an explicit `--as` for the case that cannot: a wrapper that runs this
	# through the interpreter gets `fake_gpiod.py` as argv[0] whatever it is
	# called, which had one test silently exercising neither tool.
	argv = sys.argv[1:]
	called = pathlib.Path(sys.argv[0]).name
	if argv[:1] == ["--as"]:
		called, argv = argv[1], argv[2:]
	if called.endswith("gpioinfo"):
		return do_info(argv)
	if called.endswith("gpioset"):
		return do_set(argv)
	print(f"fake_gpiod: called as `{called}`, which is neither tool", file=sys.stderr)
	return 2


if __name__ == "__main__":
	sys.exit(main())
