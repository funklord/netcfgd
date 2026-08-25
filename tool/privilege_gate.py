#!/usr/bin/env python3
"""Every config key the compiler accepts must be classified.

Decision 0127 makes netcfgd the only writer of /etc/netcfgd, so config text
arrives from clients that are not root. `netcfgd-compile`'s `privilege` module
decides what a caller may send, and it is only as good as its coverage: a key
the compiler accepts and the classification has never heard of is treated as
ordinary, which is the safe-by-default direction that is wrong here.

So this ties three things together:

  * the keys `lower.rs` accepts, read out of its own `unknown X key`
    diagnostics, which is the compiler describing itself;
  * `PRIVILEGED` in `privilege.rs`, the ones that grant more than configuring
    a network;
  * `tool/privilege-ordinary.txt`, where every other key is acknowledged by
    name.

A key in none of them fails the build. That is the `tier_of` construction --
"a request added without a tier fails to compile" -- reproduced for a language
whose keys are strings and cannot be an enum to be exhaustive over.

WHAT THIS DOES NOT PROMISE, stated because a gate quoted for more than it
checks is worse than none. It matches on the key *name*, while the
classification is keyed on (block, key) because `config` is an addressing list
in one block and a path to an .ovpn file in another. So this proves nothing is
unclassified; it does not prove each classification is right for every block
the key appears in. The block-sensitive half is tested in `privilege.rs`,
where `config_is_privileged_in_openvpn_and_ordinary_in_an_interface` pins the
case that motivated it.
"""

import re
import sys
import pathlib

LOWER = pathlib.Path("crates/netcfgd-compile/src/lower.rs")
PRIVILEGE = pathlib.Path("crates/netcfgd-compile/src/privilege.rs")
ORDINARY = pathlib.Path("tool/privilege-ordinary.txt")


def accepted():
	"""Keys the compiler matches, from every `match ....key.as_str()`."""
	lines = LOWER.read_text().splitlines()
	found, index = set(), 0
	while index < len(lines):
		if "match" in lines[index] and ".key.as_str()" in lines[index]:
			depth = index
			while depth < len(lines) and depth < index + 200:
				arm = re.match(r'\s*((?:"[a-z0-9_]+"\s*\|\s*)*"[a-z0-9_]+")\s*=>', lines[depth])
				if arm:
					found.update(re.findall(r'"([a-z0-9_]+)"', arm.group(1)))
				if re.search(r"unknown .+ key", lines[depth]):
					break
				depth += 1
			index = depth
		index += 1
	return found


def privileged():
	"""Key names in the PRIVILEGED table."""
	text = PRIVILEGE.read_text()
	block = text.split("const PRIVILEGED", 1)
	if len(block) < 2:
		return set()
	body = block[1].split("];", 1)[0]
	return {key for _, key in re.findall(r'\(\s*"([a-z0-9_]+)"\s*,\s*"([a-z0-9_]+)"', body)}


def ordinary():
	if not ORDINARY.is_file():
		return set()
	out = set()
	for line in ORDINARY.read_text().splitlines():
		line = line.split("#", 1)[0].strip()
		if line:
			out.add(line)
	return out


def main():
	keys = accepted()
	# A run that extracted nothing would find nothing unclassified and report
	# success in the same words as a real pass.
	if len(keys) < 50:
		print(f"privilege: only {len(keys)} keys found in {LOWER}; the extraction is broken")
		return 1

	known = privileged() | ordinary()
	missing = sorted(keys - known)
	stale = sorted(ordinary() - keys - privileged())

	fail = 0
	for key in missing:
		print(f"privilege: `{key}` is accepted by the compiler and classified nowhere")
		fail = 1
	if missing:
		print("privilege:   add it to PRIVILEGED in privilege.rs if it grants more")
		print(f"privilege:   than configuring a network, or to {ORDINARY} if it does not")
	for key in stale:
		print(f"privilege: `{key}` is acknowledged in {ORDINARY} and the compiler")
		print("privilege:   no longer accepts it")
		fail = 1

	if not fail:
		print(f"privilege: {len(keys)} keys, {len(privileged() & keys)} privileged, all classified")
	return fail


if __name__ == "__main__":
	sys.exit(main())
