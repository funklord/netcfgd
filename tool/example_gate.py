#!/usr/bin/env python3
"""Every block in `netcfgd.conf.example` compiles.

The file calls itself "every feature, with the syntax to use it", the postinst
points an operator at it as the thing to read on a machine with no network, and
until this gate existed **nothing checked a word of it**. The Makefile installs
it and removes it; that is all.

Two faults had already been found in it by reading, both in one session: it had
no `probe` block at all while shipping a `probe` feature with a script, and it
told the reader to write `mac_policy = "random"`, which the compiler rejects
with "one of permanent, per_network, per_connection".

WHAT THIS INSPECTS, AND WHAT IT DOES NOT

Every commented top-level block is uncommented and compiled on its own. That
catches the fault that costs a reader the most -- copying a block that cannot
work -- and it pins the ones that currently do.

**It does not read prose.** The `mac_policy = "random"` above was in a
sentence, not a block, and this gate would have passed the file carrying it.
Saying so here rather than letting the gate's name imply otherwise: a check
that is trusted for more than it does is worse than no check, because the next
person stops reading the file by hand.

TWO BLOCKS ARE EXPECTED NOT TO COMPILE ALONE, and they are named rather than
skipped by pattern, so that a third joining them is a failure:

  - `override interface` needs the block it overrides.
  - one `interface eth0` carries a per-interface `dns` scope with routing
	domains, which needs the `global` block whose `dns_mode` can express them;
	alone it compiles against the default mode `none` and is refused.
  - the `linkset` names the links it chooses between, and a member that
	resolves to nothing is refused on purpose -- an `uplink` naming an
	interface this configuration does not describe answers "disconnected" for
	ever with nothing saying why.

Both are correct as documentation and meaningless in isolation. A gate that
silently tolerated "anything that does not compile" would tolerate the next
real error too.
"""

import os
import re
import subprocess
import sys
import tempfile

EXAMPLE = "doc/netcfgd.conf.example"
NCFG = "./target/debug/ncfg"

# Where the compiler decides what a top-level block is. The list is read from
# it rather than written here, for the reason the planner's `FIRED_PHASES`
# gives: a second copy is a thing that goes stale, and this one would go stale
# in the direction of passing.
LOWER = "crates/netcfgd-compile/src/lower.rs"

# The blocks that cannot stand alone, by the line they start on and their first
# line. Both are checked, so moving one without updating this is a failure
# rather than a silent pass.
EXPECTED_INCOMPLETE = {
	"override interface eth0 {",
	'interface eth0 {\n\tconfig = "dhcp"\n\tdns {',
	'linkset "uplink" {',
}


def blocks(text):
	"""Every commented top-level block, uncommented, with its starting line."""
	found, current, depth, start = [], [], 0, 0
	for number, line in enumerate(text.split("\n"), 1):
		if not line.startswith("#"):
			continue
		body = line[1:]
		if depth == 0 and body.strip().endswith("{"):
			current, depth, start = [body], body.count("{") - body.count("}"), number
			continue
		if depth > 0:
			current.append(body)
			depth += body.count("{") - body.count("}")
			if depth == 0:
				found.append((start, "\n".join(current)))
				current = []
	return found


def compiles(text):
	"""`ncfg plan` on this block alone. Returns the first diagnostic, or None.

	A diagnostic is `file:line:column:`, which is what the compiler prints and
	what a warning does not. Warnings are expected here -- most of these blocks
	describe hardware the machine running the gate does not have.
	"""
	with tempfile.TemporaryDirectory() as directory:
		with open(os.path.join(directory, "netcfgd.conf"), "w") as handle:
			handle.write(text + "\n")
		result = subprocess.run(
			[NCFG, "plan"],
			env=dict(
				os.environ,
				NCFG_CONFIG_DIR=directory,
				NCFG_RUN_DIR=os.path.join(directory, "run"),
			),
			capture_output=True,
			text=True,
			timeout=60,
			check=False,
		)
		output = result.stdout + result.stderr
		for line in output.split("\n"):
			if re.match(r"^ncfg: .*:\d+:\d+:", line):
				return line.split(": ", 1)[1]
	return None


def block_heads():
	"""Every top-level block head the compiler accepts, read from `lower.rs`.

	The arms of the `match block.head.as_str()` that walks the merged document.
	Nested heads -- `wifi`, `bridge`, `probe` and the rest -- are not this
	question: they cannot be written on their own, and the gate above compiles
	the blocks that contain them.
	"""
	text = open(LOWER).read()
	start = text.find("for block in &merged.blocks {")
	if start < 0:
		return []
	body = text[start : text.find("\n\t}\n", start)]
	return re.findall(r'^\t\t\t"([a-z_]+)"', body, re.MULTILINE)


def check_every_block_is_documented():
	"""Every block the language accepts is written down in the example.

	**`bluetooth` was in the language from 0149 and in this file never.** The
	file calls itself "every feature, with the syntax to use it" and the
	postinst points an operator at it as the thing to read on a machine with no
	network -- and a block that is missing entirely is invisible to the gate
	above, which only compiles what is there. A feature nobody can find is not
	far from a feature nobody has.

	Returns 0 when every head appears, 1 when one does not.
	"""
	heads = block_heads()
	if len(heads) < 6:
		print(
			f"example-gate: only {len(heads)} block head(s) read from {LOWER};"
			" the extraction is broken, which looks exactly like a pass",
			file=sys.stderr,
		)
		return 1

	text = open(EXAMPLE).read()
	missing = [
		head
		for head in heads
		if not re.search(rf"^#(override )?{head}[ \t{{]", text, re.MULTILINE)
	]
	for head in missing:
		print(
			f"example-gate: the language has a `{head}` block and {EXAMPLE} has none",
			file=sys.stderr,
		)
		print(
			"example-gate:   the file calls itself every feature with the syntax to"
			" use it",
			file=sys.stderr,
		)
	if missing:
		return 1
	print(f"example-gate: {len(heads)} block head(s) in the language, all documented")
	return 0


def main():
	if not os.path.exists(NCFG):
		print("example-gate: ncfg is not built", file=sys.stderr)
		return 1
	found = blocks(open(EXAMPLE).read())
	if len(found) < 50:
		# The extractor silently finding nothing is the failure mode this gate
		# shares with every other: a pass over an empty list reports success
		# exactly as loudly as a real one.
		print(
			f"example-gate: only {len(found)} blocks found in {EXAMPLE};"
			" the extractor is broken, not the file",
			file=sys.stderr,
		)
		return 1

	failures, allowed = [], set()
	for start, text in found:
		expected = any(text.startswith(prefix) for prefix in EXPECTED_INCOMPLETE)
		problem = compiles(text)
		if problem and expected:
			allowed.add(text.split("\n")[0])
		elif problem:
			failures.append((start, text.split("\n")[0], problem))
		elif expected:
			failures.append(
				(start, text.split("\n")[0], "compiles alone now; take it off the list")
			)

	for start, first, problem in failures:
		print(f"example-gate: {EXAMPLE}:{start}: {first}", file=sys.stderr)
		print(f"example-gate:   {problem}", file=sys.stderr)
	if failures:
		print(f"example-gate: {len(failures)} block(s) do not compile", file=sys.stderr)
		return 1
	print(
		f"example-gate: {len(found)} blocks in {EXAMPLE} compile"
		f" ({len(allowed)} known-incomplete, named)"
	)
	return check_every_block_is_documented()


if __name__ == "__main__":
	sys.exit(main())
