#!/usr/bin/env python3
"""Every manager `netcfgd_select.sh` names is one it can actually act on.

**And nothing that is merely a tool is treated as a manager.** That
distinction is the one this gate exists for now: `wpa_supplicant.service`
sat in the `managers` list once, so every selection masked it -- including
the one that selects NetworkManager, which cannot scan without it. netcfgd
never wants the service (it spawns the binary with its own marker), so
nothing in this tree would have noticed at runtime, and a real machine ended
with no daemon able to use its radio.

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

# Where this project's own units live. The switcher has to be able to stand
# down everything netcfgd installs, and until this gate compared the two it
# could only compare the script against itself.
UNITS = Path(__file__).resolve().parent.parent / "packaging" / "systemd"

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

	# **What `stand_aside` masks has to be something `none` can unmask.**
	# `unmask_all` walks `$managers $radios $tools` and nothing else, so an
	# entry in `revived_over_dbus` that is not in one of those could be masked
	# by a selection and never put back -- the machine-with-everything-masked
	# outcome 0145 records, arrived at from the one list added to fix a
	# different fault.
	#
	# Read from the script rather than hard-coded, so adding an entry is what
	# makes this fail. A missing list is a failure and not a skip: this gate
	# has already been caught passing over something it never read.
	revived = re.search(r"^revived_over_dbus='([^']*)'", text, re.MULTILINE)
	if not revived:
		print("select-gate: could not find the revived_over_dbus list, so what")
		print("select-gate:   stand_aside masks is unchecked")
		failures += 1
	else:
		recoverable = set()
		for name in ("radios", "tools"):
			found_list = re.search(rf"^{name}='([^']+)'", text, re.MULTILINE)
			if found_list:
				recoverable.update(found_list.group(1).split())
		for entry in revived.group(1).split():
			if entry not in recoverable:
				print(f"select-gate: {entry} is masked by stand_aside and is in")
				print("select-gate:   neither `radios` nor `tools`, so `none` never")
				print("select-gate:   unmasks it and nothing can put the machine back")
				failures += 1
			# A manager is masked by `stand_down` already and reached by
			# `unmask_all` that way; naming it here too would mask it twice and
			# read as though `stand_aside` handled managers, which it must not.
			if entry in managers:
				print(f"select-gate: {entry} is in `managers` and in")
				print("select-gate:   `revived_over_dbus` -- a manager is stood down,")
				print("select-gate:   not stood aside, and the two paths differ")
				failures += 1

	# **The regression that broke a machine, refused statically.**
	# `wpa_supplicant.service` in `managers` means every selection masks it,
	# including the one that selects NetworkManager -- which cannot scan
	# without it. netcfgd never wants the service, so nothing here would have
	# noticed at runtime. A radio or a tool is not a manager.
	for entry in ("supplicant", "iwd", "dhcpcd", "modemmanager", "resolved"):
		if entry in managers:
			print(f"select-gate: {entry} is in `managers`, so every selection masks it")
			print("select-gate:   it is a radio or a tool a manager drives, not a rival")
			failures += 1

	# Everything a manager declares needing has to be a radio or a tool this
	# script knows how to start.
	known = set(
		(re.search(r"^radios='([^']*)'", text, re.MULTILINE) or [None, ""]).__getitem__(1).split()
	) | set(
		(re.search(r"^tools='([^']*)'", text, re.MULTILINE) or [None, ""]).__getitem__(1).split()
	)
	for line in body(text, "needs_of").splitlines():
		wanted = re.match(r"\s*[a-z|]+\) echo '([^']*)'", line)
		if not wanted:
			continue
		for service in wanted.group(1).split():
			if service not in known:
				print(f"select-gate: needs_of names {service}, which is not a radio or a tool")
				failures += 1

	for manager in managers:
		if manager not in units:
			print(f"select-gate: {manager} is in `managers` and has no unit_of arm,")
			print("select-gate:   so selecting anything else silently leaves it running")
			failures += 1

	# **Every unit this project ships has to be named in `unit_of`**, and this
	# is the check that was missing rather than wrong. The rest of this gate
	# compares the script's lists against each other, so a unit the script has
	# simply never heard of is consistent with all of them.
	#
	# `netcfgd-nm.service` was that unit for as long as it existed. It serves
	# NetworkManager's bus name, so it carries `Conflicts=NetworkManager.service`
	# and `Requires=netcfgd.service` -- which makes it, from the switcher's
	# point of view, a second copy of the netcfgd manager wearing another
	# name. `unit_of netcfgd` listed only `netcfgd.service`, so selecting
	# NetworkManager stood the daemon down and left its shim enabled: the next
	# boot pulled the shim in from multi-user.target, its `Conflicts=` stopped
	# the NetworkManager that had just been selected, and its `Requires=`
	# asked for a daemon the same run had masked. Three units in
	# `multi-user.target.wants`, each conflicting with another, and which one
	# survived a boot was a race -- reported, accurately, as wifi that worked
	# occasionally.
	#
	# Read from the directory rather than from a list here, so that adding a
	# unit to the package is what makes this fail. A list would be a fourth
	# thing to keep in step, which is the failure the whole gate is about.
	if not UNITS.is_dir():
		print(f"select-gate: {UNITS} is not a directory, so this gate would")
		print("select-gate:   compare the script against no units at all")
		failures += 1
	else:
		# The unit names `unit_of` echoes, taken from its body rather than
		# from its case labels -- the labels are manager names, and it is the
		# echoed units that decide what gets stood down.
		#
		# **Comments stripped first, and the first version of this did not.**
		# The arm that fixed `netcfgd-nm.service` carries a paragraph naming
		# the unit and the bug, so `netcfgd-nm.service` appeared in the body
		# whether or not any arm echoed it -- and the check passed with the
		# arm sabotaged back to its broken form. Caught by running that
		# sabotage and confirming the edit had landed, which is the only way
		# this shape of vacuous pass is ever visible. Same failure
		# `sandbox_gate.strip_shell_comments` records: a check satisfied by
		# the prose that explains it.
		code = "\n".join(
			line for line in body(text, "unit_of").splitlines()
			if not line.lstrip().startswith("#")
		)
		named = set(re.findall(r"[A-Za-z0-9_.@-]+\.service", code))
		shipped = sorted(path.name for path in UNITS.glob("*.service"))
		if not shipped:
			print(f"select-gate: no units found in {UNITS}, so the comparison")
			print("select-gate:   below cannot fail -- has the layout changed?")
			failures += 1
		for unit in shipped:
			if unit not in named:
				print(f"select-gate: {unit} is installed by this project and no")
				print("select-gate:   unit_of arm names it, so no selection can stand")
				print("select-gate:   it down -- it survives every switch and fights")
				print("select-gate:   whichever manager was chosen")
				failures += 1

	# **`dhcpcd` may not appear in `children_of`, ever.** That sweep decides
	# ownership from the `/run/netcfgd/` marker in a process's argv, and dhcpcd
	# calls `setproctitle`: its command line becomes `dhcpcd: eth0 [ip4]`, with
	# the marker gone and, in the BOOTP proxy, the interface gone too. A test
	# that cannot answer does not abstain -- `is_netcfgds` returns false, which
	# reads as "somebody else's", which had `netcfgd_select.sh netcfgd`
	# proposing to kill the client netcfgd had just started.
	#
	# It is stopped by `stop_netcfgd_dhcpcd` instead, from netcfgd's own
	# bookkeeping under `/run/netcfgd/dhcpcd/` and with `dhcpcd -4 -k`, which
	# takes the privilege-separated children with it where a signal to the pid
	# does not. `tests/live/select.sh` proves that end to end; this refuses the
	# regression without needing root or a namespace.
	# Comments stripped, for the third time in this file: the arm that removed
	# dhcpcd carries a paragraph explaining why, and scanning the raw body found
	# the word there and failed on correct code. A check satisfied -- or broken
	# -- by the prose that explains it is the shape this tree keeps meeting.
	# **The programs echoed, not the case labels.** `children_of` has a
	# `dhcpcd) echo \'\' ;;` arm, which is a legitimate statement that dhcpcd
	# has no children of its own -- matching that read as the fault and failed
	# on correct code. What matters is whether any arm *names dhcpcd as a
	# program to sweep*, which is the echoed value.
	#
	# Comments stripped as well, for the third time in this file: the arm that
	# removed dhcpcd carries a paragraph explaining why, and the word is in it.
	# A check broken -- or satisfied -- by the prose that explains it is the
	# shape this tree keeps meeting.
	code = "\n".join(
		line
		for line in body(text, "children_of").splitlines()
		if not line.lstrip().startswith("#")
	)
	swept = " ".join(re.findall(r"echo\s+\'([^\']*)\'", code))
	if "dhcpcd" in swept.split():
		print("select-gate: `dhcpcd` is in children_of, so the argv sweep will")
		print("select-gate:   classify it -- and it cannot be classified, because")
		print("select-gate:   setproctitle has destroyed the marker. Stop it with")
		print("select-gate:   stop_netcfgd_dhcpcd instead")
		failures += 1
	if "stop_netcfgd_dhcpcd" not in text:
		print("select-gate: nothing stops the dhcpcd netcfgd started, so it")
		print("select-gate:   survives every switch and keeps the lease")
		failures += 1

	for function in ("claims_of", "children_of"):
		covered = arms(text, function)
		if "*" not in covered:
			print(f"select-gate: {function} has no default arm, so a manager")
			print("select-gate:   missing from it is a shell error rather than a decision")
			failures += 1

	# **`none` has to reach every list, not only the managers.** A machine
	# masked by the version that conflated managers with the tools they drive
	# still has `wpa_supplicant.service` masked, and `none` is the recovery --
	# so it walks the radios and tools too, whether or not the current code
	# would ever mask them. Checked against the lists rather than a literal
	# loop, so rewriting the loop does not silently drop one.
	unmasking = body(text, "unmask_all")
	for name in ("managers", "radios", "tools"):
		if f"${name}" not in unmasking:
			print(f"select-gate: unmask_all does not walk `{name}`, so `none` cannot")
			print("select-gate:   recover a machine where one of them was masked")
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
