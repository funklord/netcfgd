#!/usr/bin/env python3
"""Every config key the compiler accepts must be classified.

Decision 0127 makes netcfgd the only writer of /etc/netcfgd, so config text
arrives from clients that are not root. `c/src/daemon/privilege.c` decides
what a caller may send, and it is only as good as its coverage: a key the
compiler accepts and the classification has never heard of is treated as
ordinary, which is the safe-by-default direction that is wrong here.

So this ties three things together:

  * the keys the lowering accepts, read out of its `strcmp(key, "...")` arms
    by `key_coverage_gate.py`'s reader -- imported rather than copied, so the
    two gates cannot disagree about what the language is;
  * `privileged[]` in `privilege.c`, the ones that grant more than
    configuring a network;
  * `tool/privilege-ordinary.txt`, where every other key is acknowledged by
    name.

A key in none of them fails the build. That is the `tier_of` construction --
"a request added without a tier fails to compile" -- reproduced for a language
whose keys are strings and cannot be an enum to be exhaustive over.

**It read the Rust until 0317, and so it never held the C.** `privilege.c`
said as much: "that gate reads the Rust, so what keeps *this* copy honest is
`authorize_test.c`", which pins the table entry for entry -- a check that the
table did not lose a row, and not one that a key added to the C's lowering
was ever looked at. Retiring the Rust deleted the gate; this is it pointed at
the C, where the question was always meant to be asked.

WHAT THIS DOES NOT PROMISE, stated because a gate quoted for more than it
checks is worse than none. It matches on the key *name*, while the
classification is keyed on (block, key) because `config` is an addressing list
in one block and a path to an .ovpn file in another. So this proves nothing is
unclassified; it does not prove each classification is right for every block
the key appears in. The block-sensitive half is `authorize_test.c`'s.
"""

import pathlib
import re
import sys

from key_coverage_gate import language_keys

PRIVILEGE = pathlib.Path("c/src/daemon/privilege.c")
ORDINARY = pathlib.Path("tool/privilege-ordinary.txt")

# Fewer keys than this and the extraction is broken rather than the language
# small: the lowering accepted 182 when this was written.
KEY_FLOOR = 150


def privileged():
	"""Key names in `privileged[]`, from its `{ "block", "key", ... }` rows."""
	text = PRIVILEGE.read_text(encoding="utf-8")
	start = text.find("} privileged[] = {")
	if start < 0:
		return set()
	body = text[start:text.find("};", start)]
	return {key for _, key in re.findall(r'\{\s*"([a-z0-9_]+)"\s*,\s*"([a-z0-9_]+)"', body)}


def ordinary():
	if not ORDINARY.is_file():
		return set()
	out = set()
	for line in ORDINARY.read_text(encoding="utf-8").splitlines():
		line = line.split("#", 1)[0].strip()
		if line:
			out.add(line)
	return out


def main():
	keys = set(language_keys())
	# A run that extracted nothing would find nothing unclassified and report
	# success in the same words as a real pass.
	if len(keys) < KEY_FLOOR:
		print(f"privilege: only {len(keys)} keys found in the lowering; the extraction is broken")
		return 1
	held = privileged()
	if len(held) < 10:
		print(f"privilege: only {len(held)} privileged keys read from {PRIVILEGE}; "
		      f"the extraction is broken")
		return 1

	listed = ordinary()
	missing = sorted(keys - held - listed)
	stale = sorted(listed - keys - held)

	fail = 0
	for key in missing:
		print(f"privilege: `{key}` is accepted by the compiler and classified nowhere")
		fail = 1
	if missing:
		print(f"privilege:   add it to privileged[] in {PRIVILEGE} if it grants more")
		print(f"privilege:   than configuring a network, or to {ORDINARY} if it does not")
	for key in stale:
		print(f"privilege: `{key}` is acknowledged in {ORDINARY} and the compiler")
		print("privilege:   no longer accepts it")
		fail = 1

	if not fail:
		print(f"privilege: {len(keys)} keys, {len(held & keys)} privileged, all classified")
	return fail


if __name__ == "__main__":
	sys.exit(main())
