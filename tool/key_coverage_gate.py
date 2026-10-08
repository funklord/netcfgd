#!/usr/bin/env python3
"""Every key the configuration language accepts must be one the renderer writes.

**This gate exists because `require_lease` was found by accident.** The
renderer had nine fields to write for a `probe` block and wrote eight. The one
it missed was the only one whose default is `true`: every other key there is
written when it differs from a fallback, and a boolean that is on by default
needs the opposite test. So a profile saved from a machine whose `wwan0` probe
set `require_lease = false` came back requiring a lease -- the probe's
precondition inverted, silently, with `ncfg profile save` reporting success.

Nothing was positioned to catch it. The round-trip corpora each compile a
document and ask whether it renders back, so they find a dropped key only if
some document in them happens to set it; `doc/netcfgd.conf.example` did, which
is why it surfaced at all, and the three other corpora did not. The agree gate
compares the two implementations, and both had the same hole. A field the
renderer writes nothing for is invisible to every instrument that starts from a
document.

So this starts from the LANGUAGE instead:

  * the keys, read out of the `strcmp(key, "...")` arms in `c/src/compile/
	lower_*.c`, which is where a config file's keys are actually accepted;
  * what the renderer writes, read out of the string literals in
	`c/src/compile/render*.c`.

A key in the first and not the second fails the build, unless it is named in
`tool/renderer-unwritten-keys.txt` with a reason.

**Comments are stripped before the renderer is read, and the reason is not the
obvious one.** Only string literals are read, so a comment that merely
discusses a key was never going to cover it -- with the stripping disabled and
the `require_lease` write deleted, the gate still fires, and the paragraph
above `render_probe` discusses that key at length. What stripping actually
buys is a literal scan that stays synchronised: an apostrophe or a quote in
prose pairs with the next one and everything after it is read inside-out.
Measured, with stripping off: 173 extra words, among them `ists`, `ound`,
`riting` and `sked` -- `exists`, `found`, `writing` and `asked` with their
beginnings eaten, which is what a scan reading prose as a literal looks like.
None of the 173 is a key today, so this guards a coincidence that has not
happened rather than one that has; it is cheap and the alternative is a scan
whose correctness depends on how many quotes the comments happen to contain.

WHAT THIS DOES NOT PROMISE. It asks whether the renderer MENTIONS a key, not
whether it writes it correctly, under the right condition, with the right
value, or at the right nesting. A key emitted into the wrong block passes here.
It also cannot see a key the language accepts somewhere other than a
`strcmp(key, ...)` arm -- a modifier parsed positionally, a word inside a
phrase -- so it is a tripwire on the one failure that recurs (an arm added with
no renderer write), not a proof of coverage. The round-trip corpora remain what
establishes that a document comes back; this establishes that a key cannot
arrive with nobody having thought about rendering it.
"""

import re
import sys
import pathlib

LOWER = sorted(pathlib.Path("c/src/compile").glob("lower_*.c"))
RENDER = sorted(pathlib.Path("c/src/compile").glob("render*.c"))
WAIVED = pathlib.Path("tool/renderer-unwritten-keys.txt")


def strip_comments(text):
	"""Remove C comments and leave string literals alone.

	A regex cannot do this: `/*` inside a string literal is not a comment, and
	a quote inside a comment is not a string. So walk it once.
	"""
	out = []
	i, n = 0, len(text)
	while i < n:
		c = text[i]
		if c == '"':
			out.append(c)
			i += 1
			while i < n and text[i] != '"':
				if text[i] == "\\":
					out.append(text[i])
					i += 1
				if i < n:
					out.append(text[i])
					i += 1
			if i < n:
				out.append('"')
				i += 1
		elif c == "'" and i + 1 < n:
			out.append(c)
			i += 1
			while i < n and text[i] != "'":
				if text[i] == "\\":
					out.append(text[i])
					i += 1
				if i < n:
					out.append(text[i])
					i += 1
			if i < n:
				out.append("'")
				i += 1
		elif text.startswith("/*", i):
			i = text.find("*/", i + 2)
			i = n if i < 0 else i + 2
			out.append(" ")
		elif text.startswith("//", i):
			i = text.find("\n", i)
			i = n if i < 0 else i
			out.append(" ")
		else:
			out.append(c)
			i += 1
	return "".join(out)


def language_keys():
	"""Every key an arm of the lowering accepts, and where it is accepted."""
	keys = {}
	for path in LOWER:
		function = "?"
		for line in path.read_text(encoding="utf-8").splitlines():
			match = re.match(r"(?:static\s+)?\w[\w \t*]*\b(\w+)\s*\(", line)
			if match and not line[:1].isspace():
				function = match.group(1)
			for key in re.findall(r'strcmp\(key, "([^"]+)"\)', line):
				keys.setdefault(key, set()).add(f"{path.name}:{function}")
	return keys


def rendered_words():
	"""Every word appearing in a string literal in the renderer.

	Deliberately loose. A key reaches the output three ways -- inline in a
	format string, as the key argument of `ncfg_render_list_emit`, or as a
	bare literal passed to a helper or sat in a table -- and enumerating the
	helpers is a list that rots. What they share is that the key is spelled
	somewhere as a literal.
	"""
	words = set()
	for path in RENDER:
		text = strip_comments(path.read_text(encoding="utf-8"))
		for literal in re.findall(r'"((?:[^"\\]|\\.)*)"', text):
			# Replace each escape with a space before splitting into words. A
			# `\t` otherwise fuses with the name after it, so `"\t\teap = "`
			# yields `teap` and never `eap` -- which made the first run of this
			# gate report 60 keys unwritten, every one of them written.
			words.update(re.findall(r"[a-z][a-z0-9_]*", re.sub(r"\\.", " ", literal)))
	return words


def waivers():
	"""Keys the renderer is allowed not to write, each with its reason."""
	reasons = {}
	if not WAIVED.exists():
		sys.exit(f"{WAIVED}: missing, so no key may be waived")
	for number, line in enumerate(WAIVED.read_text(encoding="utf-8").splitlines(), 1):
		line = line.split("#", 1)[0].strip()
		if not line:
			continue
		parts = line.split(None, 1)
		if len(parts) != 2:
			sys.exit(f"{WAIVED}:{number}: a waiver is a key and a reason")
		reasons[parts[0]] = parts[1]
	return reasons


def main():
	keys = language_keys()
	written = rendered_words()
	waived = waivers()
	if not keys or not written:
		sys.exit("key_coverage_gate: read no keys or no renderer, so checked nothing")

	unwritten = {k: v for k, v in keys.items() if k not in written}
	faults = []

	for key in sorted(unwritten):
		if key not in waived:
			where = " ".join(sorted(unwritten[key]))
			faults.append(f"{key}: accepted at {where}, and the renderer writes no such key")

	# The waiver list is held to the tree in both directions, so that it cannot
	# quietly become a list of keys nobody has looked at since.
	for key in sorted(waived):
		if key not in keys:
			faults.append(f"{key}: waived, and no longer a key the lowering accepts")
		elif key in written:
			faults.append(f"{key}: waived, and the renderer now writes it -- drop the waiver")

	if faults:
		print("key_coverage_gate: FAILED")
		for fault in faults:
			print(f"  {fault}")
		return 1

	print(
		f"key_coverage_gate: {len(keys)} keys accepted by the lowering, "
		f"{len(keys) - len(unwritten)} written by the renderer, "
		f"{len(waived)} waived with a reason"
	)
	return 0


if __name__ == "__main__":
	sys.exit(main())
