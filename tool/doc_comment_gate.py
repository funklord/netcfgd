"""A doc comment written twice on one line.

`crates/netcfgd-compile/src/lower.rs` carries two lines of the shape

    /// The `band` key, checked here rather than at render time./// The `band`
    key, checked here rather than at render time.

-- one sentence, the marker in the middle, from an edit that pasted over
itself. Harmless to the compiler and to every test; wrong only to the next
person who reads it, which is how it survived.

WHAT THIS DOES NOT SEE, AND THE REASON IT DOES NOT TRY

The other shape found the same day is a doc comment attached to the wrong
item -- `expand_ingress_shapers`' paragraph above `fn declares`,
`address_ownership`'s rationale above `tagged_origin`, and the mode-0600 rule
in `netcfgd-secret` sitting above `first_line` with `check_mode` left
undocumented and unguarded. Those cannot be found mechanically: Rust lets doc
blocks and attributes interleave, and every interleaved pair in this tree that
a first version of this gate flagged was legitimate. A gate that cries wolf
teaches people to ignore red, which costs more than the gate is worth -- this
file's own `rss` target says so in as many words. Those were found by reading,
which is the only way.

So this covers exactly the half that needs no judgement: a line that opens as a
doc comment and then starts another one against the text, with no space and no
backtick before it. A `///` quoted in prose or sitting inside a base64 string
is not that, and both appear in this tree.
"""

import pathlib
import re
import sys

ROOTS = ["crates", "backend", "adapter"]
# A line that opens as a doc comment and then starts another against the text.
# The lookbehind is what keeps a `///` quoted in prose out, and the anchor is
# what keeps a base64 string of slashes out -- both are in this tree.
DOUBLED = re.compile(r"^\s*///.*[^\s`]///")


def main():
	files = [
		path
		for root in ROOTS
		for path in pathlib.Path(root).rglob("*.rs")
		if "target" not in path.parts
	]
	if len(files) < 50:
		print(f"doc-gate: only {len(files)} file(s) found; the paths are wrong")
		return 1

	faults = 0
	for path in files:
		lines = path.read_text().splitlines()
		for number, line in enumerate(lines, 1):
			if DOUBLED.search(line):
				print(f"doc-gate: {path}:{number}: one line carries two doc comments")
				print("doc-gate:   an edit pasted over itself; say it once")
				faults += 1
	if faults:
		return 1
	print(f"doc-gate: {len(files)} rust file(s): no doc comment written twice on one line")
	return 0


if __name__ == "__main__":
	sys.exit(main())
