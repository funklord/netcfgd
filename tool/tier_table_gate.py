"""`doc/socket-protocol.md`'s tier table against the C's `tier_table[]`.

Section 4 of that document tells an implementer who may ask for what. It said
twenty-three requests while `tier_of` classified thirty-two, and had done for
long enough that nobody remembers: the five listings, `radio_set`, and the
three that write a profile or a probe were simply absent. The prose bullets
under the table were right about every one of them, which is what made the
table easy to read past -- including by whoever added `hook_list` to it two
days ago and did not notice it was short by nine.

Section 2 of that document names three things that hold it honest: the frozen
witness, the round-trip test and the member table. **None of them can see a
tier.** The witness pins bytes, the round trip pins shapes, and the member
table pins members; who may send a request is nowhere in any of them, which is
why the only check was somebody reading two files side by side.

WHAT THIS CHECKS

Every request the build classifies appears in the table under the tier it is
given, and the table names nothing that is not a request. A verb added to the
protocol without a row, or moved between tiers without the document moving
with it, fails here.

WHICH `tier_of` IT READS, AND WHY THAT CHANGED

**The C's**, since 0276. This read `crates/netcfgd-daemon/src/authorize.rs`
until then, which was right when the Rust was what answered a socket and
wrong from the day it stopped: a gate about who may ask had its authority in
a program nobody runs. The same fault as `dbus_policy_gate.py` parsing the
retired shim, and `linkage` reading a binary nobody installs (project.md
10.506).

The switch was measured rather than assumed. Both tables were read on
2026-10-22 -- the Rust's `tier_of` arms through this file's own reader, the
C's `tier_table[]` through the new one -- and they agreed on all thirty-two,
so nothing about the verdict moved. That is the only kind of re-pointing worth
making silently; a disagreement would have been a finding rather than a
cleanup.

**The C's table is designated rather than ordered**, which is what makes it
readable here: `[NCFG_PROTO_REQ_HELLO] = NCFG_TIER_OBSERVE` names both halves
on one line. The enum member becomes a wire name through `request_names[]`,
which is indexed by the same enum -- and because that is an ordering
assumption, the reader checks it against a second derivation (the member's own
suffix, lowercased) and refuses when the two disagree.
"""

import pathlib
import re
import sys

DOC = pathlib.Path("doc/socket-protocol.md")
ENUM = pathlib.Path("c/include/ncfg/proto.h")
NAMES = pathlib.Path("c/src/proto/request.c")
AUTHORIZE = pathlib.Path("c/src/daemon/authorize.c")
FROZEN = pathlib.Path("crates/netcfgd-proto/tests/frozen.rs")


def wire_names():
	"""Enum member to wire name, by two derivations that have to agree.

	`request_names[]` is indexed by `ncfg_proto_request_kind_t`, so zipping
	the enum's members with the table's strings is the mapping -- and it is an
	assumption about order. The member's own suffix, lowercased, is a second
	and independent derivation of the same thing, so the two are compared and
	a disagreement is refused rather than resolved. `word_table_gate.py`
	already holds the table to one word per enum value; this is the other half
	of that sentence.
	"""
	enum = re.search(
		r"typedef enum \{(.*?)\} ncfg_proto_request_kind_t;", ENUM.read_text(), re.S
	)
	table = re.search(
		r"request_names\[NCFG_PROTO_REQ_COUNT\]\s*=\s*\{(.*?)\};",
		NAMES.read_text(),
		re.S,
	)
	if not enum or not table:
		print("tier-gate: the request enum or its name table is not where this")
		print("tier-gate:   expects it, so the mapping would be empty")
		return {}
	members = [
		m
		for m in re.findall(r"(NCFG_PROTO_REQ_\w+)", enum.group(1))
		if m != "NCFG_PROTO_REQ_COUNT"
	]
	names = re.findall(r'"([^"]+)"', table.group(1))
	if len(members) != len(names):
		print(f"tier-gate: {len(members)} enum member(s) and {len(names)} name(s):")
		print("tier-gate:   the table is not indexed by the enum any more")
		return {}
	out = {}
	for member, name in zip(members, names):
		if member[len("NCFG_PROTO_REQ_") :].lower() != name:
			print(f"tier-gate: {member} is `{name}` in the table and the two")
			print("tier-gate:   derivations of its wire name disagree")
			return {}
		out[member] = name
	return out


def classified():
	"""Wire name to tier, read from the C's `tier_table[]`."""
	table = re.search(
		r"tier_table\[NCFG_PROTO_REQ_COUNT\]\s*=\s*\{(.*?)\n\};",
		AUTHORIZE.read_text(),
		re.S,
	)
	if not table:
		return {}
	names = wire_names()
	out = {}
	for member, tier in re.findall(
		r"\[(NCFG_PROTO_REQ_\w+)\]\s*=\s*NCFG_TIER_(\w+)", table.group(1)
	):
		if member in names:
			out[names[member]] = tier.lower()
	return out


def tabled():
	"""Wire name to tier, read from the document's table."""
	out = {}
	for line in DOC.read_text().splitlines():
		row = re.match(r"^\|\s*`(observe|wifi|admin)`\s*\|(.*)\|\s*$", line)
		if not row:
			continue
		for name in re.findall(r"`([a-z_]+)`", row.group(2)):
			out[name] = row.group(1)
	return out


def main():
	if not DOC.is_file() or not AUTHORIZE.is_file():
		print("tier-gate: the document or the C authorize module is missing")
		return 1
	code = classified()
	doc = tabled()
	# A gate over an empty reading passes as loudly as a real one.
	if len(code) < 20 or len(doc) < 20:
		print(f"tier-gate: read {len(code)} from the code and {len(doc)} from the table;")
		print("tier-gate:   one of the two extractions is broken")
		return 1

	faults = 0
	for name, tier in sorted(code.items()):
		if name not in doc:
			print(f"tier-gate: `{name}` is {tier} in the C and absent from the table")
			faults += 1
		elif doc[name] != tier:
			print(f"tier-gate: `{name}` is {tier} in the C and {doc[name]} in the table")
			faults += 1
	for name in sorted(doc):
		if name not in code:
			print(f"tier-gate: the table names `{name}`, which is not a request")
			faults += 1
	if faults:
		print("tier-gate:   section 4 tells an implementer who may ask for what")
		return 1
	print(f"tier-gate: {len(code)} request(s), each in the table under the tier it has")
	return 0


if __name__ == "__main__":
	sys.exit(main())
