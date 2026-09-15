#!/usr/bin/env python3
"""A record that quotes the tree must quote something the tree still says.

**Three decision records in the M9 wifi audit were found asserting things the
code contradicts** -- 0231 on how the NetworkManager adapter is built, 0235 on
why the daemon uses threads rather than an event loop, and 0234 on which
watchers have a backstop. The last was made false by the round immediately
before it, by the same campaign, and stood for a week.

Prose does not compile, so nothing noticed. This closes the part of that which
can be closed mechanically: a quotation. A record that wants to quote the tree
marks the block with the file it came from, and this checks the text is still
there.

    ```quote from=crates/netcfgd-daemon/src/lib.rs
    An observation runs on a netlink event or on the loop's five-second
    backstop
    ```

Whitespace is collapsed on both sides and comment markers are stripped from the
source, so a quotation may be re-wrapped and may cross `///` lines. What is
compared is the words.

Emphasis and code marks are dropped from both sides, so a record need not carry
the `**` and `*` of the doc comment it is quoting.

WHAT THIS DOES NOT PROMISE, said plainly because a gate quoted for more than it
checks is worse than none:

  * **It catches quotations, not paraphrases.** 0234 said "`roam` and `rfkill`
    have no backstop" in its own words, citing nothing. No gate can check that
    sentence; what caught it was reading the code while writing the next
    record, which is a practice and not a tool.
  * It proves the words still exist somewhere in the named file. It does not
    prove they still mean what the record says they mean.
  * A record that marks nothing is checked for nothing. The marker is opt-in,
    so this raises the floor for quotations that use it and leaves the rest
    where they were.
"""

import re
import sys
import pathlib

ROOTS = [pathlib.Path("doc/decision"), pathlib.Path(".")]
DOCS = sorted(pathlib.Path("doc/decision").glob("*.md")) + [pathlib.Path("project.md")]

FENCE = re.compile(r"^```quote\s+from=(\S+)\s*$")
COMMENT = re.compile(r"^\s*(///|//!|//|#+|\*)\s?")


#: Emphasis and code marks, dropped from both sides before comparing. Doc
#: comments in this tree are markdown -- **this** and *that* and `the_other` --
#: and a record quoting one should not have to reproduce the marks to prove it
#: read the words. Found by this gate refusing 0241's own quotation, which is
#: the check being capable of a negative before anything depended on it.
MARKUP = str.maketrans("", "", "*`")


def words(text):
	"""The text as one whitespace-collapsed string, without emphasis marks."""
	return " ".join(text.translate(MARKUP).split())


def source_of(path):
	"""A file's words, with comment markers and line continuations removed.

	Stripped so a quotation may be taken from a doc comment and compared to
	what it says rather than to how it is marked up; collapsed so it may be
	re-wrapped to a different width in the record.
	"""
	out = []
	for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
		line = COMMENT.sub("", line)
		out.append(line.rstrip().removesuffix("\\"))
	return words(" ".join(out))


def quotes(doc):
	"""Every marked quotation in one document, as (line, path, text)."""
	lines = doc.read_text(encoding="utf-8", errors="replace").splitlines()
	index = 0
	while index < len(lines):
		opened = FENCE.match(lines[index])
		if not opened:
			index += 1
			continue
		start, body = index, []
		index += 1
		while index < len(lines) and not lines[index].startswith("```"):
			body.append(lines[index])
			index += 1
		yield start + 1, opened.group(1), words(" ".join(body))
		index += 1


def main():
	if not pathlib.Path("doc/decision").is_dir():
		print("cited-quote: doc/decision is missing; the extraction is broken")
		return 1
	present = [doc for doc in DOCS if doc.is_file()]
	if not present:
		print("cited-quote: no documents to read; the extraction is broken")
		return 1

	cached = {}
	checked = fail = 0
	for doc in present:
		for line, named, text in quotes(doc):
			checked += 1
			source = pathlib.Path(named)
			if not source.is_file():
				print(f"cited-quote: {doc}:{line}: quotes `{named}`, which is not a file")
				fail = 1
				continue
			if not text:
				print(f"cited-quote: {doc}:{line}: an empty quotation proves nothing")
				fail = 1
				continue
			if source not in cached:
				cached[source] = source_of(source)
			if text not in cached[source]:
				print(f"cited-quote: {doc}:{line}: {named} no longer says this")
				print(f"cited-quote:   quoted: {text[:110]}")
				fail = 1

	if not fail:
		print(
			f"cited-quote: {checked} marked quotation(s) across {len(present)} document(s), "
			"each still in the file it names"
		)
	return fail


if __name__ == "__main__":
	sys.exit(main())
