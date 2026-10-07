#!/usr/bin/env python3
"""Every `Op` the planner can name is emitted by the planner and run by the
executor, or is named here as one that is not.

**This gate exists because three of them were neither, and nothing said so.**
Measured when the plan vocabulary was swept for the first time: of 48 `Op`
variants, `WifiAssociate`, `WifiDisassociate` and `WifiSetRegdom` appeared in
exactly one place in the whole tree -- `netcfgd-plan/tests/frozen.rs`, which
pins their serialisation. Nothing emitted them and nothing executed them, so
each was a word in the plan's vocabulary with no behaviour at either end, and
each had been frozen into the schema on the way past.

They are not the same kind of leftover, which is why the waiver file takes a
reason rather than a list of names:

  * the two association ops are a superseded generation. Association is
    imperative and transient rather than desired state, so the daemon drives
    it straight at the supplicant with `SELECT_NETWORK`;
  * `WifiSetRegdom` is the unwired half of an inertness the example file
    documents in as many words -- "the radio's is kept in the document and
    reaches nothing". The op is what would carry it;
  * `CommitConfirm` is never planned because the daemon owns the commit
    window; `confirm.rs` has its own machinery and the executor's arm for it
    is deliberately defensive.

TWO DIRECTIONS, AND THE SECOND IS WORSE. A variant that is defined and never
emitted is dead weight. A variant that *is* emitted and has no executor arm is
a plan step that always fails -- the executor's catch-all returns
`"<name> is not implemented in this build"` -- so a reconcile would refuse
every time that op was planned. Nothing is in that state today and this is what
keeps it so.

WHY A GREP IS EXACT HERE, WHICH IT USUALLY IS NOT. Rust makes you name a
variant's path to construct it, and in this tree the two uses are spelled
differently: `netcfgd-plan/src/lib.rs` writes `Op::X { .. }` only to build one
-- it holds 109 such occurrences and not a single match arm -- while `impl Op`
in `action.rs` matches on `Self::X`. So "appears in lib.rs" means "is
constructed there", and that is a property of the file rather than of the
query.

**That property is checked rather than assumed**, because it is exactly the
kind of thing that stops being true without anybody noticing: a `match op` added
to the planner would make every arm read as a construction, and this gate would
go quiet in the same words it uses for a pass. An `Op::` occurrence that looks
like a pattern fails the run and says so.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ACTION = ROOT / "crates/netcfgd-plan/src/action.rs"
PLANNER = [ROOT / "crates/netcfgd-plan/src/lib.rs", ROOT / "crates/netcfgd-plan/src/net.rs"]
EXECUTOR = ROOT / "crates/netcfgd-apply/src/kernel.rs"
WAIVED = ROOT / "tool/op-unemitted.txt"


def code(path):
	"""A file's text with line comments removed.

	`action.rs` refers to `Op::NatReplace` in a doc comment, which is prose and
	not a use -- and a gate that counted it would report a variant as handled
	because somebody mentioned it.
	"""
	lines = []
	for line in path.read_text().splitlines():
		stripped = line.lstrip()
		if stripped.startswith("//"):
			continue
		lines.append(line)
	return "\n".join(lines)


def variants():
	"""The plan's vocabulary, from the enum that defines it."""
	text = code(ACTION)
	block = re.search(r"^pub enum Op \{(.*?)^\}", text, re.M | re.S)
	if not block:
		return []
	return [m.group(1) for m in re.finditer(r"^\t([A-Z]\w*)(\s*\{|\(|,)", block.group(1), re.M)]


def used(paths):
	"""Which variants each file names, and any occurrence that is a pattern."""
	found = set()
	patterns = []
	for path in paths:
		text = code(path)
		for match in re.finditer(r"Op::([A-Z]\w*)", text):
			found.add(match.group(1))
		for match in re.finditer(r"^.*Op::[A-Z]\w*[^;]*?=>.*$", text, re.M):
			patterns.append((path, match.group(0).strip()))
	return found, patterns


def waived():
	"""Names acknowledged as unemitted, each with a reason after a space."""
	if not WAIVED.exists():
		return {}
	out = {}
	for line in WAIVED.read_text().splitlines():
		line = line.strip()
		if not line or line.startswith("#"):
			continue
		name, _, reason = line.partition(" ")
		out[name] = reason.strip()
	return out


def main():
	names = variants()
	# A run that extracted nothing would find nothing unwired and report
	# success in exactly the words of a real pass.
	if len(names) < 40:
		print(f"op: only {len(names)} variants found in {ACTION.name}; the extraction is broken")
		return 1

	emitted, planner_patterns = used(PLANNER)
	if planner_patterns:
		for path, line in planner_patterns[:3]:
			print(f"op: {path.name} matches on an op rather than only building one:")
			print(f"op:   {line}")
		print("op: this gate reads `Op::X` in the planner as a construction, which that")
		print("op:   spelling breaks -- so its result is not trustworthy until it is gone")
		return 1

	executed, _ = used([EXECUTOR])
	known = waived()

	fail = 0
	for name in names:
		if name in emitted and name not in executed:
			print(f"op: `{name}` is planned and has no arm in {EXECUTOR.name}, so every")
			print("op:   plan carrying it fails with \"not implemented in this build\"")
			fail = 1
		if name not in emitted and name not in known:
			print(f"op: `{name}` is in the plan vocabulary and the planner never builds one")
			fail = 1
	if fail:
		print(f"op:   wire it, remove it, or name it in {WAIVED.name} with the reason")

	# The reverse checks, which are what keep the file from becoming a list
	# nobody has read since it was written.
	for name, reason in sorted(known.items()):
		if name not in names:
			print(f"op: {WAIVED.name} names `{name}`, which is not an op any more")
			fail = 1
		elif name in emitted:
			print(f"op: {WAIVED.name} says `{name}` is never planned, and the planner builds one")
			fail = 1
		elif not reason:
			print(f"op: {WAIVED.name} names `{name}` with no reason")
			fail = 1

	if not fail:
		print(
			f"op: {len(names)} variants, {len(names) - len(known)} planned and executed, "
			f"{len(known)} acknowledged unplanned"
		)
	return fail


if __name__ == "__main__":
	sys.exit(main())
