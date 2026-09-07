#!/usr/bin/env python3
"""A backgrounded process in a live script is killed by pid, never by job spec.

`kill %1` needs job control, and job control is off in a non-interactive
shell. So it does nothing, returns without complaint, and looks exactly like
cleaning up -- the daemon it was meant to stop is reparented to init and
outlives the run. Four netcfgd daemons were found that way on 2026-09-07,
aged 25 to 70 minutes, one per probe written with `kill %1` in its cleanup.
Every one of them also ran under `timeout`, which bounds the foreground
command and not what it backgrounded.

Nothing in `tests/live/` has ever had the bug: every script there captures
`$!` and traps on it. This gate exists because the suite gains scripts often
and the mistake is invisible in review -- `kill %1` reads as correct, and a
leak shows up an hour later as somebody else's confusing failure.

**A gate over an empty population reports success exactly as loudly as one
that checked something**, so this refuses to pass when it finds no scripts,
and prints the counts it inspected rather than a bare "ok".
"""

import re
import sys
from pathlib import Path

LIVE = Path(__file__).resolve().parent.parent / "tests" / "live"

# `kill %1`, `wait %2`, `kill -9 %1` -- a job spec anywhere in an argument.
JOB_SPEC = re.compile(r"\b(kill|wait)\b[^\n#]*\s%\d+")

# Long-running things a script backgrounds and must be able to stop again.
# Named rather than "anything with &", because a script legitimately
# backgrounds short-lived helpers it never reaps -- a sleep, a one-shot writer
# -- and flagging those would make this a gate people add exceptions to.
DAEMONS = ("netcfgd", "wpa_supplicant", "hostapd", "dhcpcd", "dhclient", "openvpn", "pppd", "dnsmasq")


def main() -> int:
	if not LIVE.is_dir():
		print(f"probe-gate: {LIVE} is not there", file=sys.stderr)
		return 1
	scripts = sorted(LIVE.glob("*.sh"))
	if not scripts:
		print("probe-gate: no scripts found, so this checked nothing", file=sys.stderr)
		return 1

	failures = 0
	backgrounding = 0

	for script in scripts:
		text = script.read_text()
		for number, line in enumerate(text.splitlines(), start=1):
			if line.lstrip().startswith("#"):
				continue
			if JOB_SPEC.search(line):
				print(f"probe-gate: {script.name}:{number}: kills by job spec")
				print("probe-gate:   job control is off in a non-interactive shell, so this")
				print("probe-gate:   does nothing. Capture the pid: p=$! ; kill \"$p\"")
				failures += 1

		# The property underneath: a script that starts a daemon in the
		# background has to hold its pid. Heuristic, and it says so -- what it
		# cannot see is whether the pid captured is the right one.
		starts = [
			line
			for line in text.splitlines()
			if line.rstrip().endswith("&")
			and not line.lstrip().startswith("#")
			and any(daemon in line for daemon in DAEMONS)
		]
		if starts:
			backgrounding += 1
			if "$!" not in text:
				print(f"probe-gate: {script.name} backgrounds a daemon and never reads $!")
				print("probe-gate:   so nothing in it can stop what it started")
				failures += 1

	if failures:
		print(f"probe-gate: {failures} problem(s)", file=sys.stderr)
		return 1
	print(
		f"probe-gate: {len(scripts)} live script(s), "
		f"{backgrounding} of them background a daemon, none kills by job spec"
	)
	return 0


if __name__ == "__main__":
	sys.exit(main())
