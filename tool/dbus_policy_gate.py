#!/usr/bin/env python3
"""Every D-Bus interface the shim serves must be named in its bus policy.

The two lists are kept in step by memory otherwise, which is the failure this
tree keeps finding -- `install` against `uninstall`, an init script's paths
against what gets installed, five documents against a field that never existed.
This is the same shape with a worse failure mode.

**A missing interface here is silent.** The system bus denies method calls by
default and each service allows its own, so an interface the shim implements
and the policy does not mention is a client method call refused at run time --
not at build time, not by any test that drives the shim over a private bus, and
only on a machine where NetworkManager's own package is absent. That is exactly
the configuration the shim exists for and the one nobody reaches by accident,
so it would be found by an operator with no network rather than by CI.

The reverse is checked too, and matters less but is not nothing: a policy that
grants sends on an interface the shim does not implement is inviting calls that
can only fail, and it is usually the residue of an interface that was removed.

Static: it reads two files and runs anywhere, like `uninstall_gate.py`.
"""

import re
import sys
import pathlib
import xml.parsers.expat

SHIM = pathlib.Path("adapter/netcfgd-nm/src")
POLICY = pathlib.Path("packaging/dbus/netcfgd-nm.conf")

# The three every D-Bus service answers. They are in the policy and are not in
# the shim's source as string literals, because the library implements them.
STANDARD = {
	"org.freedesktop.DBus.Introspectable",
	"org.freedesktop.DBus.Properties",
	"org.freedesktop.DBus.ObjectManager",
}

INTERFACE = re.compile(r'"(org\.freedesktop\.NetworkManager(?:\.[A-Za-z0-9_]+)*)"')


def served():
	"""Interfaces the shim's source names."""
	found = set()
	for path in sorted(SHIM.rglob("*.rs")):
		found.update(INTERFACE.findall(path.read_text()))
	return found


def granted():
	"""Interfaces the policy allows sends on."""
	text = POLICY.read_text()
	return set(re.findall(r'send_interface="([^"]+)"', text))


def well_formed():
	"""The policy has to parse, and the way it stops parsing is not obvious.

	XML forbids `--` inside a comment, and this project writes `--` where prose
	would use an em dash -- so the natural comment style produces a file
	dbus-daemon refuses *in its entirety*, which means no policy at all rather
	than a broken line. That is a whole bus name nobody can own, discovered
	when the shim will not start.

	It happened while this file was being written, which is why the check is
	here rather than in somebody's habits.
	"""
	try:
		xml.parsers.expat.ParserCreate().Parse(POLICY.read_bytes(), True)
	except xml.parsers.expat.ExpatError as error:
		print(f"dbus-policy: {POLICY} is not well-formed XML: {error}")
		line = str(error).split("line ")[-1].split(",")[0] if "line " in str(error) else None
		if line and line.isdigit():
			text = POLICY.read_text().splitlines()
			index = int(line) - 1
			if 0 <= index < len(text):
				print(f"dbus-policy:   {line}: {text[index].strip()}")
				if "--" in text[index]:
					print("dbus-policy:   a comment cannot contain `--`. Rewrite the")
					print("dbus-policy:   prose; dbus-daemon refuses the whole file.")
		print("dbus-policy:   dbus-daemon would refuse the file entirely, so the")
		print("dbus-policy:   bus name would belong to nobody.")
		return False
	return True


def main():
	if not SHIM.is_dir():
		print(f"dbus-policy: {SHIM} is missing, so this would check nothing")
		return 1
	if not POLICY.is_file():
		print(f"dbus-policy: {POLICY} is missing")
		return 1
	if not well_formed():
		return 1

	code = served()
	policy = granted() - STANDARD

	# A run that matched nothing reports success exactly as loudly as a real
	# pass. If the extraction breaks -- a rename, a different quoting style --
	# both sets go empty and every comparison below succeeds, so the emptiness
	# is the thing to refuse.
	if not code:
		print(f"dbus-policy: no interfaces found in {SHIM}, so the comparison is vacuous")
		return 1
	if not policy:
		print(f"dbus-policy: no send_interface rules found in {POLICY}, likewise")
		return 1

	fail = 0
	for name in sorted(code - policy):
		print(f"dbus-policy: the shim serves {name} and the policy does not grant it")
		print("dbus-policy:   a client calling it is denied, but only where")
		print("dbus-policy:   NetworkManager's own policy file is absent")
		fail = 1
	for name in sorted(policy - code):
		print(f"dbus-policy: the policy grants {name} and the shim does not serve it")
		fail = 1

	if not fail:
		print(f"dbus-policy: {len(code)} interfaces, all granted")
	return fail


if __name__ == "__main__":
	sys.exit(main())
