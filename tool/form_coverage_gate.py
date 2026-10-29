#!/usr/bin/env python3
"""Every member of a block a GUI form saves must be one the client reads.

WHAT THIS ENFORCES
  Four GUI dialogs -- device, interface, network, access point -- load a block
  through the C client and save it whole, with `replace`. What the dialog has
  no field for, the client must name in `unmodelled` so the dialog can refuse;
  what the client never reads, it cannot name, and Save deletes it.

  That is not hypothetical. project.md 10.606: the network and access point
  dialogs had no such guard at all, and the interface reader's list had not
  gained `dhcp_server`, so a DHCP server, an access point's `width` and
  `steering`, and a network's pinned `bssid` and routes were each deleted by
  pressing Save. Every one was a member added to the model after its reader
  was written, and nothing told the reader.

  So this reads the members each block's `ncfg_field_t` table declares in
  `c/src/model/document.c`, and requires each one's JSON key to appear as a
  string literal in that block's reader in `client/ncfg_client.c` -- read into
  a field, or listed as unmodelled -- unless `tool/form-unread-keys.txt` names
  it with a reason.

WHAT IT DOES NOT CATCH
  **Nesting.** Only a block's own members: a key added inside `probe` or
  `steering` is not seen. Where the reader names a whole sub-block as
  unmodelled that is complete; where it reads a sub-block field by field, a
  new field there can still be dropped.

  **Reading is not carrying.** A literal in the reader is a member the code
  looks at, not proof that the dialog writes it back. The dialog tests do
  that; this catches the class where nobody looked at all.

WHAT A FAILURE LOOKS LIKE
  The block, the key, and the reader that never mentions it. The answer is to
  read it into a field the dialog writes, to add it to that reader's
  unmodelled list, or -- for a member nobody writes, such as provenance -- to
  waive it with the reason.
"""

import pathlib
import re
import sys

MODEL = pathlib.Path("c/src/model/document.c")
CLIENT = pathlib.Path("client/ncfg_client.c")
WAIVED = pathlib.Path("tool/form-unread-keys.txt")

# Each saved block, the reader its dialog loads it through, and the helpers
# that reader hands members to. Written out rather than derived, because a
# helper is found by its call and a call does not say which keys it reads.
FORMS = {
	"device_fields": ("ncfg_client_device_config", ["read_qdisc", "read_kind"]),
	"interface_fields": ("ncfg_client_interface_config", []),
	"network_fields": ("ncfg_client_saved_networks", ["network_unmodelled"]),
	"access_point_fields": ("ncfg_client_access_points", ["editable_stations"]),
}


def without_comments(text):
	"""The code alone. A key discussed in prose is not a key read."""
	text = re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group(0)), text, flags=re.S)
	return re.sub(r"//[^\n]*", "", text)


def table_keys(source, table):
	"""The JSON keys one field table declares, in order."""
	start = re.search(r"static const ncfg_field_t " + re.escape(table) + r"\[\]", source)
	if not start:
		return None
	end = source.index("};", start.end())
	return re.findall(r'\.name\s*=\s*"([a-z0-9_]+)"', source[start.end():end])


def function_body(source, name):
	"""One function's text, from its definition to the closing brace in column 0."""
	start = re.search(r"^(?:static\s+)?[a-z_][\w\s\*]*\b" + re.escape(name) + r"\(", source,
	    flags=re.M)
	if not start:
		return None
	opening = source.find("\n{", start.end())
	closing = source.find("\n}", opening)
	if opening < 0 or closing < 0:
		return None
	return source[start.start():closing]


def waivers():
	"""Keys a reader is allowed not to mention, each with its reason."""
	reasons = {}
	if not WAIVED.exists():
		sys.exit(f"{WAIVED}: missing, so no key may be waived")
	for number, line in enumerate(WAIVED.read_text(encoding="utf-8").splitlines(), 1):
		line = line.split("#", 1)[0].strip()
		if not line:
			continue
		parts = line.split(None, 1)
		if len(parts) != 2:
			sys.exit(f"{WAIVED}:{number}: a waiver is a `table.key` and a reason")
		reasons[parts[0]] = parts[1]
	return reasons


def main():
	for path in (MODEL, CLIENT):
		if not path.exists():
			sys.exit(f"{path}: missing, so this gate would check nothing")
	model = without_comments(MODEL.read_text(encoding="utf-8"))
	client = without_comments(CLIENT.read_text(encoding="utf-8"))
	waived = waivers()

	faults = []
	checked = 0
	unread = set()
	for table, (reader, helpers) in FORMS.items():
		keys = table_keys(model, table)
		if not keys:
			faults.append(f"{table}: no field table of that name, so nothing was checked")
			continue
		bodies = []
		for function in [reader] + helpers:
			body = function_body(client, function)
			if body is None:
				faults.append(f"{function}: not found in {CLIENT}, so {table} was not checked")
				continue
			bodies.append(body)
		literals = set(re.findall(r'"([a-z0-9_]+)"', "\n".join(bodies)))
		for key in keys:
			checked += 1
			if key in literals:
				continue
			name = f"{table}.{key}"
			unread.add(name)
			if name not in waived:
				faults.append(
					f"{name}: a member the document holds, and {reader} neither reads it nor"
					" names it unmodelled -- the dialog's Save would delete it"
				)

	# Held to the tree in both directions, so a waiver cannot outlive its key.
	for name in sorted(waived):
		table, _, key = name.partition(".")
		keys = table_keys(model, table) if table in FORMS else None
		if not keys or key not in keys:
			faults.append(f"{name}: waived, and no longer a member of a form's block")
		elif name not in unread:
			faults.append(f"{name}: waived, and its reader now mentions it -- drop the waiver")

	# A control: the instrument must see a missing key, or its silence means
	# nothing. The interface reader with `dhcp_server` -- the key 10.606 found
	# missing -- taken out again must no longer clear it.
	body = function_body(client, "ncfg_client_interface_config") or ""
	stripped = set(re.findall(r'"([a-z0-9_]+)"', body.replace('"dhcp_server"', '""')))
	if '"dhcp_server"' not in body or "dhcp_server" in stripped:
		faults.append("control: the interface reader without dhcp_server still clears it,"
		    " so this gate cannot see a missing key")

	if faults:
		print("form_coverage_gate: FAILED")
		for fault in faults:
			print(f"  {fault}")
		return 1
	print(
		f"form_coverage_gate: {checked} member(s) of {len(FORMS)} saved block(s), "
		f"{checked - len(unread)} their readers mention, {len(waived)} waived with a reason"
	)
	return 0


if __name__ == "__main__":
	sys.exit(main())
