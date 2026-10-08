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

**Comments and character literals are both blanked before the renderer is
read, and what that buys is the opposite of the obvious guess.** The guess is
that a comment discussing a key would cover it and cause a false pass. It would
not -- only string literals are read, and with the blanking disabled and the
`require_lease` write deleted this gate still fires, although the paragraph
above `render_probe` discusses that key at length.

What the blanking actually prevents is a desynchronised scan, and the damage
runs the other way -- towards false FAILURES, which is the direction a reader
would act on. An apostrophe in prose (`renderer's`, `parser's`) pairs with the
next real quote, so the literal after it is read inside-out and every literal
following it shifts. Measured, three configurations of this one function:

    comments and chars blanked    the gate as it stands
    comments kept, chars blanked  50 written keys LOST, among them `command`,
                                  `autoneg`, `interval` and `duplex`
    nothing blanked               0 keys lost, and 6 word fragments gained --
                                  `ists`, `ound`, `riting`, `sked`

**Read the third row before trusting a scan by sampling it.** Losing no keys
looks like the healthy answer and is not: the fragments are `exists`, `found`,
`writing` and `asked` with their beginnings eaten, so the scan is reading prose
as a literal there, and it comes out even only because two desynchronisations
happen to cancel. A character literal is the other half -- this renderer's job
is quoting, so it holds ten `'\"'`, and one of them hid `"@secret:keyring:"` at
`render.c:268` from a scan that had that literal directly in front of it.

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
			# Blanked, not kept. A character literal never holds a key, and this
			# renderer's job is quoting, so it contains ten `'\"'` -- each of
			# which pairs with the next real quote and reads everything after it
			# inside-out. That is what hid `@secret:keyring:` at render.c:268
			# from a scan that had the literal in front of it.
			i += 1
			while i < n and text[i] != "'":
				i += 2 if text[i] == "\\" else 1
			i += 1
			out.append(" ")
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
			# Both spellings. Several lowerings hold the assignment rather than
			# having pulled its key into a local, and the first version of this
			# read only the local form -- so `owner`, `apn`, `agent`, `allow`,
			# `deny`, `requires` and fourteen others were outside the
			# denominator entirely, and `tun`'s `group` was being credited to a
			# vxlan's alias of `remote`. A count inherits its detector.
			for key in re.findall(r'strcmp\((?:[a-z_]+(?:->|\.))?key, "([^"]+)"\)', line):
				keys.setdefault(key, set()).add(f"{path.name}:{function}")
	return keys


def written_keys():
	"""Every key the renderer is seen to write, in the shapes it writes them.

	The first version of this asked only whether a key's name appeared in any
	string literal, which is too loose in the one direction that matters: it
	passes a key on the strength of a sentence. Two did. `prefix` was counted as
	written because two REFUSAL messages mention a prefix, and `user` because
	`render.c` spells a principal `"user:%s"`. Both verdicts happened to be
	right -- each is an alias the renderer legitimately does not write -- so the
	gate was correct by luck, and a real gap with either spelling would have
	gone straight through.

	So match the two shapes an emission actually takes, and nothing else:

	  (a) an assignment inside a format string, `"\\tmtu = %lld\\n"`, which is
	      how most keys go out;
	  (b) a literal that is nothing but the key, which covers the bare-argument
	      and table forms -- `render_toggle(body, "autoneg", ...)`,
	      `ncfg_render_list_emit(body, "\\t", "routes", ...)`, and the
	      `{ "interval", 30 }` rows a `"%s = %lld"` format reads its name from.

	A refusal sentence satisfies neither, and neither does `"user:%s"`.
	"""
	written = set()
	for path in RENDER:
		text = strip_comments(path.read_text(encoding="utf-8"))
		for literal in re.findall(r'"((?:[^"\\]|\\.)*)"', text):
			# An escape becomes a break rather than vanishing, so that `\\t\\teap`
			# yields `eap` and not `teap` -- the fault that made the first run of
			# this gate report 60 written keys as missing.
			plain = re.sub(r"\\[tn]", "\n", literal)
			written.update(re.findall(r"(?:^|\n|\s)([a-z][a-z0-9_]*) =", plain))
			bare = plain.strip("\n ")
			if re.fullmatch(r"[a-z][a-z0-9_]*", bare):
				written.add(bare)
	return written


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
	written = written_keys()
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
