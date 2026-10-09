#!/usr/bin/env python3
"""Every renderer word table has one word per value of the enum it indexes.

**What a short table does.** The renderer keeps the CONFIGURATION LANGUAGE's
spellings in tables of its own, indexed by the model's enum, because the two
sides spell several values differently -- `wire_guard` against `wireguard`,
`wpa2_wpa3` against `wpa2+wpa3` -- and `render.c`'s header records that
reaching for the model's name function instead has shipped a silently missing
feature twice. The tables are therefore deliberate duplication and the
duplication has to be held to the thing it duplicates.

Add a value to one of those enums without adding its word and
`ncfg_render_word` returns NULL for it, `ncfg_render_word_or_gap` turns that
into `?`, and the renderer writes `powersave = "?"` -- measured -- while
reporting success with no refusals. `ncfg profile save` then writes the
profile, fails its own proof because `?` is not a word the language reads,
rolls the whole thing back and tells the operator it is a fault in the snapshot
worth reporting. Honest, and a build-time check is cheaper than that
conversation.

**The round trip cannot cover it**, which is why this exists as a gate rather
than a test. A round trip only exercises values some document in a corpus sets,
and the value that has just been added to an enum is precisely the one no
corpus sets yet.

The table-to-enum mapping is `tool/renderer-word-tables.txt`, held in both
directions: a table with no entry fails, and an entry naming a table or an enum
that does not exist fails. A new table therefore cannot be added without
saying what it indexes.
"""

import pathlib
import re
import sys

HEADER = pathlib.Path("c/include/ncfg/document.h")
RENDERER = [
	pathlib.Path("c/src/compile/render.c"),
	pathlib.Path("c/src/compile/render_link.c"),
	pathlib.Path("c/src/compile/render_device.c"),
]
MAP = pathlib.Path("tool/renderer-word-tables.txt")


def without_comments(text):
	text = re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group(0)), text, flags=re.S)
	return re.sub(r"//[^\n]*", "", text)


def enum_sizes():
	"""Each `ncfg_*_t` enum in the public model header, and how many values."""
	if not HEADER.exists():
		sys.exit(f"{HEADER}: missing, so this gate would check nothing")
	source = without_comments(HEADER.read_text(encoding="utf-8"))
	sizes = {}
	for match in re.finditer(
		r"typedef enum\s*\{(.*?)\}\s*(ncfg_[a-z0-9_]+_t)\s*;", source, flags=re.S
	):
		names = re.findall(r"\b(NCFG_[A-Z0-9_]+)\b", match.group(1))
		sizes[match.group(2)] = len(names)
	return sizes


def word_tables():
	"""Each renderer word table, and how many words it holds."""
	tables = {}
	for path in RENDERER:
		if not path.exists():
			sys.exit(f"{path}: missing, so this gate would check nothing")
		source = without_comments(path.read_text(encoding="utf-8"))
		# Scope is defined by USE, not by name: a table indexed by an enum is one
		# handed to `ncfg_render_word`. A name-keyed scan both missed `prefixes`,
		# which is enum-indexed and not called `*_words`, and picked up two
		# function-local `keys[]` lists that are parallel to a values array rather
		# than indexed by anything -- and those two share a name, so a name-keyed
		# table could not have spoken about either.
		indexed = set(re.findall(r"ncfg_render_word\(\s*([a-z0-9_]+)\s*,", source))
		for match in re.finditer(
			r"static const char \*const ([a-z0-9_]+)\[\]\s*=\s*\{(.*?)\}\s*;",
			source,
			flags=re.S,
		):
			if match.group(1) not in indexed:
				continue
			words = re.findall(r'"(?:[^"\\]|\\.)*"', match.group(2))
			tables[match.group(1)] = (len(words), f"{path}")
	return tables


def mapping():
	"""Which enum each table indexes, with the reason the pairing is right."""
	pairs = {}
	if not MAP.exists():
		sys.exit(f"{MAP}: missing, so no table could be checked")
	for number, line in enumerate(MAP.read_text(encoding="utf-8").splitlines(), 1):
		line = line.split("#", 1)[0].strip()
		if not line:
			continue
		parts = line.split(None, 1)
		if len(parts) != 2:
			sys.exit(f"{MAP}:{number}: an entry is a table and the enum it indexes")
		pairs[parts[0]] = parts[1].split(None, 1)[0]
	return pairs


def main():
	sizes = enum_sizes()
	tables = word_tables()
	pairs = mapping()
	if not sizes or not tables:
		sys.exit("word_table_gate: read no enums or no tables, so checked nothing")

	faults = []
	for table in sorted(tables):
		count, where = tables[table]
		if table not in pairs:
			faults.append(
				f"{table}: a word table in {where} that says no enum it indexes"
				f" -- add it to {MAP}"
			)
			continue
		enum = pairs[table]
		if enum not in sizes:
			faults.append(f"{table}: mapped to {enum}, which {HEADER} does not declare")
			continue
		if count != sizes[enum]:
			faults.append(
				f"{table}: {count} word(s) for {enum}'s {sizes[enum]} value(s)"
				f" -- the renderer would write `?` for the rest"
			)

	for table in sorted(pairs):
		if table not in tables:
			faults.append(f"{table}: mapped, and no longer a word table -- drop the entry")

	if faults:
		print("word_table_gate: FAILED")
		for fault in faults:
			print(f"  {fault}")
		return 1

	print(
		f"word_table_gate: {len(tables)} word table(s), each with one word per value of"
		f" the enum it indexes, across {len(sizes)} enum(s)"
	)
	return 0


if __name__ == "__main__":
	sys.exit(main())
