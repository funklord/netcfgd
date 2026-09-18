"""`doc/socket-protocol.md`'s tier table against `authorize.rs`.

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

Every request in `tier_of` appears in the table under the tier `tier_of` gives
it, and the table names nothing that is not a request. A verb added to the
protocol without a row, or moved between tiers without the document moving
with it, fails here.
"""

import pathlib
import re
import sys

DOC = pathlib.Path("doc/socket-protocol.md")
AUTHORIZE = pathlib.Path("crates/netcfgd-daemon/src/authorize.rs")
FROZEN = pathlib.Path("crates/netcfgd-proto/tests/frozen.rs")


def wire_names():
	"""Variant name to wire name, read from the witness's own table."""
	text = FROZEN.read_text()
	pairs = re.findall(
		r"(?:Self|Request)::(\w+)(?:\s*\{\s*\.\.\s*\})?\s*=>\s*\"([a-z_]+)\"", text
	)
	return dict(pairs)


def classified():
	"""Wire name to tier, read from `tier_of`'s arms."""
	text = AUTHORIZE.read_text()
	start = text.find("pub(crate) fn tier_of")
	body = text[start : text.find("\n}\n", start)]
	names = wire_names()
	out = {}
	pending = []
	for line in body.splitlines():
		for variant in re.findall(r"Request::(\w+)", line):
			if variant in names:
				pending.append(names[variant])
		tier = re.search(r"=>\s*Tier::(\w+)", line)
		if tier and pending:
			for name in pending:
				out[name] = tier.group(1).lower()
			pending = []
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
		print("tier-gate: the document or authorize.rs is missing")
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
			print(f"tier-gate: `{name}` is {tier} in authorize.rs and absent from the table")
			faults += 1
		elif doc[name] != tier:
			print(f"tier-gate: `{name}` is {tier} in authorize.rs and {doc[name]} in the table")
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
