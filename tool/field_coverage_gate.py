#!/usr/bin/env python3
"""Every field the document can hold must be one the renderer reads.

**The key gate cannot see this class, and both instances of it cost a save.**
`key_coverage_gate.py` starts from the configuration language: the keys the
lowering's `strcmp` arms accept, each of which the renderer must write. That is
blind by construction to a field *no key can express* -- and the two defects
this project has shipped in the renderer were both of exactly that kind. An
ingress shaper was neither rendered nor refused, and `declared` was a member
the language has no word for, so no key-side instrument could ask about either.

So this starts from the DOCUMENT instead:

  * the fields, read out of the `ncfg_field_t` tables in `c/src/model/
	document.c`, which are the document's own member list and what drives its
	writer, its reader and its comparison;
  * what the renderer touches, read out of `c/src/compile/render*.c`.

A member the renderer's code never mentions cannot be written or refused by it,
so it fails the build unless `tool/renderer-unread-fields.txt` names it with a
reason.

**A list is satisfied by its count, which is how this gate was wrong first.**
Hooks are refused wholesale -- `render_link.c` tests `interface->hook_count`
and refuses "hooks" -- and the list member itself is never named. Reading the
count is enough to refuse, so a field's `count_offset` companion counts as a
read; without that, five fields were reported that are correctly handled.

**What this gate is and is not evidence of, stated because the difference
matters.** Its ALARM is sound: code that never mentions a member cannot write
or refuse it. Its CLEAR is weak, in two measured ways.

Reading a member is not writing it, so a member read only to compute something
else passes. And the read is matched by member NAME -- `x->mode` does not say
what `x` is, and nothing short of a parser can -- so two types sharing a member
name mask each other: 39 of the 197 distinct names are used by more than one
type, which puts 102 of the 260 entries' clears within reach of a sibling.
`mode` and `id` are six types each.

The consequence for the job this gate is actually for -- a field added to the
model and not wired into the renderer -- is that a NEW field hides if its name
collides with one of those 39 and is visible otherwise. That is a hole, stated
rather than closed, because closing it needs a C parser and the gate is worth
having meanwhile. What covers the rest is the round trip over the mutation
corpus and the key gate; this is a third instrument aimed at the one class
neither can see, not a replacement for either.

Found `schema_version` counted by an equality the renderer could not satisfy,
which made every document from an older schema minor unsaveable.
"""

import pathlib
import re
import sys

MODEL = pathlib.Path("c/src/model/document.c")
RENDERER = [
	pathlib.Path("c/src/compile/render.c"),
	pathlib.Path("c/src/compile/render_link.c"),
	pathlib.Path("c/src/compile/render_device.c"),
	pathlib.Path("c/src/compile/render_private.h"),
]
WAIVED = pathlib.Path("tool/renderer-unread-fields.txt")


def without_comments(text):
	"""The code alone. A member discussed in prose is not a member read."""
	text = re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group(0)), text, flags=re.S)
	return re.sub(r"//[^\n]*", "", text)


def model_fields():
	"""Every field table entry, as (table, key, type, member, count member)."""
	if not MODEL.exists():
		sys.exit(f"{MODEL}: missing, so this gate would check nothing")
	source = without_comments(MODEL.read_text(encoding="utf-8"))
	tables = [
		(m.start(), m.group(1))
		for m in re.finditer(r"static const ncfg_field_t ([a-z0-9_]+)\[\]", source)
	]
	def table_at(pos):
		name = "?"
		for start, table in tables:
			if start <= pos:
				name = table
			else:
				break
		return name
	entries = list(re.finditer(r'\.name\s*=\s*"([a-z0-9_]+)"', source))
	fields, unparsed = [], []
	for index, entry in enumerate(entries):
		end = entries[index + 1].start() if index + 1 < len(entries) else len(source)
		chunk = source[entry.end():end]
		offset = re.search(
			r"\.offset\s*=\s*offsetof\(\s*([a-z0-9_]+)\s*,\s*([a-z0-9_]+)\s*\)", chunk
		)
		count = re.search(
			r"\.count_offset\s*=\s*offsetof\(\s*[a-z0-9_]+\s*,\s*([a-z0-9_]+)\s*\)", chunk
		)
		if not offset:
			unparsed.append(f"{table_at(entry.start())}.{entry.group(1)}")
			continue
		fields.append(
			(
				table_at(entry.start()),
				entry.group(1),
				offset.group(1),
				offset.group(2),
				count.group(1) if count else None,
			)
		)
	return fields, unparsed


def renderer_source():
	"""The renderer's code, comments removed."""
	parts = []
	for path in RENDERER:
		if not path.exists():
			sys.exit(f"{path}: missing, so this gate would check nothing")
		parts.append(without_comments(path.read_text(encoding="utf-8")))
	return "\n".join(parts)


def waivers():
	"""Members the renderer is allowed not to read, each with its reason."""
	reasons = {}
	if not WAIVED.exists():
		sys.exit(f"{WAIVED}: missing, so no field may be waived")
	for number, line in enumerate(WAIVED.read_text(encoding="utf-8").splitlines(), 1):
		line = line.split("#", 1)[0].strip()
		if not line:
			continue
		parts = line.split(None, 1)
		if len(parts) != 2:
			sys.exit(f"{WAIVED}:{number}: a waiver is a `type.member` and a reason")
		reasons[parts[0]] = parts[1]
	return reasons


def main():
	fields, unparsed = model_fields()
	code = renderer_source()
	waived = waivers()
	if not fields or not code:
		sys.exit("field_coverage_gate: read no fields or no renderer, so checked nothing")

	def reads(member):
		return bool(re.search(r"(->|\.)" + re.escape(member) + r"\b", code))

	faults = []
	# An entry this cannot parse is not an entry this has cleared.
	for name in unparsed:
		faults.append(f"{name}: no `.offset = offsetof(...)` this gate can read")

	unread = {}
	for table, key, ctype, member, count in fields:
		if reads(member) or (count and reads(count)):
			continue
		unread[f"{ctype}.{member}"] = f"{table}.{key}"

	for name in sorted(unread):
		if name not in waived:
			faults.append(
				f"{name}: in the document as {unread[name]}, and the renderer"
				" neither writes nor refuses it"
			)

	# Held to the tree in both directions, so the list cannot quietly become
	# one of fields nobody has looked at since.
	known = {f"{ctype}.{member}" for _, _, ctype, member, _ in fields}
	for name in sorted(waived):
		if name not in known:
			faults.append(f"{name}: waived, and no longer a field the document holds")
		elif name not in unread:
			faults.append(f"{name}: waived, and the renderer now reads it -- drop the waiver")

	if faults:
		print("field_coverage_gate: FAILED")
		for fault in faults:
			print(f"  {fault}")
		return 1

	print(
		f"field_coverage_gate: {len(fields)} field(s) the document holds, "
		f"{len(fields) - len(unread)} the renderer reads, "
		f"{len(waived)} waived with a reason"
	)
	return 0


if __name__ == "__main__":
	sys.exit(main())
