#!/usr/bin/env python3
"""The udev rules and the quirks table say the same thing about every module.

`helper/modem-quirks` is the source: it carries the USB id, which helper drives
a module, and which tty index answers AT. `packaging/udev/71-netcfgd-modem.rules`
names the same ids and the same index, in a syntax udev reads.

**Two files carrying one fact is how a quirk somebody reads stops being the
quirk that runs.** The table is what a person consults when a module misbehaves;
the rules file is what actually decides which device node appears. A module
added to one and not the other produces either a port with no stable name, or a
name pointing at whatever port that index happens to be on a module the table
never described.

WHAT THIS CHECKS

  - every `helper=at` row with an `at=` index has exactly one rule, and the
    rule's vid, pid and interface number match the row;
  - every rule corresponds to such a row, so a rule cannot outlive the row that
    justified it;
  - the interface number is two digits, which is what udev's
    `ID_USB_INTERFACE_NUM` holds -- `at=3` in the table is `"03"` here, and
    `"3"` matches nothing at all while looking correct.

WHAT IT DOES NOT CHECK

It does not run udev and cannot tell you the rule fires. That needs the module.
What it can do is make the rule wrong in a way a person could not have noticed
by reading either file alone, which is the failure that has actually happened
to tables in this repository.
"""

import re
import sys

TABLE = "helper/modem-quirks"
RULES = "packaging/udev/71-netcfgd-modem.rules"


def table_rows(path):
	"""`{vid:pid: {key: value}}` for every data row, comments dropped."""
	rows = {}
	with open(path, encoding="utf-8") as handle:
		for number, line in enumerate(handle, 1):
			line = line.strip()
			if not line or line.startswith("#"):
				continue
			fields = line.split()
			identifier = fields[0]
			if not re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{4}", identifier):
				sys.exit(f"modem-rules: {path}:{number}: `{identifier}` is not a usb id")
			values = {}
			for field in fields[1:]:
				key, _, value = field.partition("=")
				values[key] = value
			rows[identifier] = (number, values)
	return rows


def rules_entries(path):
	"""`{vid:pid: (line number, interface number)}` for every SUBSYSTEM line."""
	entries = {}
	with open(path, encoding="utf-8") as handle:
		for number, line in enumerate(handle, 1):
			if not line.startswith("SUBSYSTEM=="):
				continue
			vendor = re.search(r'ATTRS\{idVendor\}=="([^"]*)"', line)
			product = re.search(r'ATTRS\{idProduct\}=="([^"]*)"', line)
			interface = re.search(r'ENV\{ID_USB_INTERFACE_NUM\}=="([^"]*)"', line)
			if not (vendor and product and interface):
				sys.exit(
					f"modem-rules: {path}:{number}: a rule must match idVendor, "
					"idProduct and ID_USB_INTERFACE_NUM"
				)
			entries[f"{vendor.group(1)}:{product.group(1)}"] = (
				number,
				interface.group(1),
			)
	return entries


def main():
	rows = table_rows(TABLE)
	entries = rules_entries(RULES)

	# The rows that earn a rule: an AT helper needs a tty, and a row with no
	# `at=` index has not said which one.
	wanted = {
		identifier: values
		for identifier, (_, values) in rows.items()
		if values.get("helper") == "at" and "at" in values
	}

	# **A gate over an empty list reports success exactly as loudly as a real
	# pass.** If the table ever stops parsing, this is what says so.
	if not wanted:
		sys.exit(f"modem-rules: no `helper=at` row with an `at=` index in {TABLE}")

	failures = []
	for identifier, values in wanted.items():
		if identifier not in entries:
			failures.append(
				f"{identifier} is `helper=at at={values['at']}` in {TABLE} "
				f"and has no rule in {RULES}"
			)
			continue
		number, interface = entries[identifier]
		expected = f"{int(values['at']):02d}"
		if interface != expected:
			failures.append(
				f"{RULES}:{number}: {identifier} matches interface "
				f"`{interface}`, and {TABLE} says `at={values['at']}` "
				f"(which is `{expected}` here)"
			)

	for identifier, (number, _) in entries.items():
		if identifier not in wanted:
			failures.append(
				f"{RULES}:{number}: {identifier} has a rule and no "
				f"`helper=at` row with an `at=` index in {TABLE}"
			)

	for failure in failures:
		print(f"modem-rules: {failure}", file=sys.stderr)
	if failures:
		return 1

	print(f"modem-rules: {len(wanted)} AT module(s), table and udev rules agree")
	return 0


if __name__ == "__main__":
	sys.exit(main())
