#!/usr/bin/env python3
"""Every manager `netcfgd_select.sh` names is one it can actually act on.

The switcher keeps four facts about each network daemon -- its name in the
`managers` list, the units that start it, the runtime claim it leaves and the
children it abandons -- and three of those live in `case` arms. A manager
added to the list and to two of the three arms is not an error in shell: the
`case` falls through, the function prints nothing, and the daemon is silently
never stood down. It reads exactly like a manager that has nothing to clean
up, which is a real state several of them are in.

So this asserts the shape rather than the behaviour, which is what can be
checked without root and without systemd:

  * every manager in `managers` has an arm in `unit_of`, or it is a name that
    does nothing;
  * `claims_of` and `children_of` account for every manager, either with an
    arm or through the `*)` default -- so the two that genuinely have nothing
    are a decision rather than an omission;
  * `none` unmasks every unit any manager can mask, or removing the package
    leaves something masked with nothing able to undo it;
  * the daemons netcfgd delegates to are never named as units to stand down.

That last one is the one with teeth. netcfgd *runs* wpa_supplicant, dhcpcd,
hostapd, pppd, openvpn, udhcpc, odhcp6c and resolvconf; masking any of those
services is defensible for the first two, whose services are a rival
instance, and standing down the rest would break netcfgd rather than its
competition.
"""

import re
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "packaging" / "netcfgd_select.sh"

# Programs netcfgd starts itself. A unit named for one of these would be
# netcfgd disabling its own tools. wpa_supplicant and dhcpcd are deliberately
# absent: their *services* are a rival instance another manager drives, while
# the binaries are netcfgd's to run, and the script tells them apart by the
# marker in the process's own argv.
DELEGATED = ("hostapd", "pppd", "openvpn", "udhcpc", "odhcp6c", "resolvconf", "dnsmasq", "unbound")


def body(text: str, function: str) -> str:
	"""One shell function's body, from its `() {` to the `}` in column zero.

    Scoped deliberately. The first version of the `unmask_all` check below
    searched from the function's opening brace with a non-greedy `.*?` and no
    end anchor, so it ran past the closing brace and matched an identical
    loop in the main case block further down -- it passed with the function
    sabotaged to walk a hard-coded pair. Caught by sabotaging it and checking
    the edit had landed, rather than by reading the regex again.
    """
	match = re.search(rf"^{function}\(\) \{{\n(.*?)^\}}", text, re.MULTILINE | re.DOTALL)
	return match.group(1) if match else ""


def arms(text: str, function: str) -> set[str]:
	"""The case labels inside one shell function."""
	found: set[str] = set()
	for line in body(text, function).splitlines():
		label = re.match(r"\s*([A-Za-z0-9_ |*]+?)\)", line)
		if label:
			for name in label.group(1).split("|"):
				found.add(name.strip())
	return found


def main() -> int:
	if not SCRIPT.is_file():
		print(f"select-gate: {SCRIPT} is missing", file=sys.stderr)
		return 1
	text = SCRIPT.read_text()

	listed = re.search(r"^managers='([^']+)'", text, re.MULTILINE)
	if not listed:
		print("select-gate: could not find the managers list", file=sys.stderr)
		return 1
	managers = listed.group(1).split()
	if not managers:
		# An empty list would make every check below pass over nothing, which
		# is the vacuous pass this file exists inside a project that hunts.
		print("select-gate: the managers list is empty", file=sys.stderr)
		return 1

	failures = 0

	units = arms(text, "unit_of")
	for manager in managers:
		if manager not in units:
			print(f"select-gate: {manager} is in `managers` and has no unit_of arm,")
			print("select-gate:   so selecting anything else silently leaves it running")
			failures += 1

	for function in ("claims_of", "children_of"):
		covered = arms(text, function)
		if "*" not in covered:
			print(f"select-gate: {function} has no default arm, so a manager")
			print("select-gate:   missing from it is a shell error rather than a decision")
			failures += 1

	# Everything `unit_of` can name has to be reachable by `unmask_all`, which
	# walks the same list -- so the check is that `none` uses that list rather
	# than a second copy of it.
	if "for manager in $managers" not in body(text, "unmask_all"):
		print("select-gate: unmask_all does not walk `managers`, so `none` can")
		print("select-gate:   leave masked whatever the second list forgot")
		failures += 1

	for tool in DELEGATED:
		if re.search(rf"^\t[a-z]+\) echo .*\b{tool}\.service", text, re.MULTILINE):
			print(f"select-gate: {tool}.service is named as a unit to stand down,")
			print("select-gate:   and netcfgd runs that program itself")
			failures += 1

	# The rename rung. Diverting a binary is the one thing here that outlives
	# the package, so what may be diverted is checked harder than what may be
	# masked.
	listed = re.search(r"^divertible='([^']*)'", text, re.MULTILINE)
	divertible = listed.group(1).split() if listed else []
	paths = arms(text, "divertible_path")
	for program in divertible:
		if program not in paths:
			print(f"select-gate: {program} is divertible and has no path,")
			print("select-gate:   so the rename would silently do nothing")
			failures += 1
		# **The check with teeth.** netcfgd runs these; renaming one would
		# disable netcfgd rather than a competitor, and it would survive the
		# package being reinstalled.
		if program in DELEGATED or program in ("wpa_supplicant", "dhcpcd", "NetworkManager"):
			print(f"select-gate: {program} may not be diverted -- netcfgd runs it,")
			print("select-gate:   or a desktop applet depends on its package")
			failures += 1

	# A diversion that nothing removes is a machine nobody can put back.
	if divertible and "undivert" not in body(text, "unmask_all") + text.split("none)")[-1]:
		print("select-gate: nothing undiverts on `none`, so a renamed binary")
		print("select-gate:   would outlive the package that renamed it")
		failures += 1

	if failures:
		print(f"select-gate: {failures} problem(s)", file=sys.stderr)
		return 1
	# Say what was inspected, not merely that it passed: a gate over an empty
	# divertible list would report success in exactly these words.
	print(
		f"select-gate: {len(managers)} manager(s), each with a unit; "
		f"{len(divertible)} divertible, none of them netcfgd's own; "
		"`none` unmasks and undiverts"
	)
	return 0


if __name__ == "__main__":
	sys.exit(main())
