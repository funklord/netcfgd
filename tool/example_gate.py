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

# The blocks that cannot stand alone, by the line they start on and their first
# line. Both are checked, so moving one without updating this is a failure
# rather than a silent pass.
EXPECTED_INCOMPLETE = {
	"override interface eth0 {",
	'interface eth0 {\n\tconfig = "dhcp"\n\tdns {',
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
	return 0


if __name__ == "__main__":
	sys.exit(main())
