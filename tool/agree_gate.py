#!/usr/bin/env python3
"""The two programs compile the same configuration to the same document.

0263 says a module of the C port is a candidate to replace its Rust half "only
once it passes the Rust's own tests for the same behaviour", and that the
comparison "needs the modules to exist first". They do. This is the first
mechanical comparison of the two programs on the same input, and it is
deliberately the narrowest one that means something.

WHAT IS COMPARED, AND WHY IT IS `show`

`ncfg show --json` is the whole pure path: a configuration directory in, a
canonical document out. Nothing in it reads the kernel, so two runs a moment
apart are answering the same question -- which is not true of `plan`, `status`
or `explain`, every one of which observes the machine and would differ for
honest reasons. Comparing those needs a machine held still, which is what the
live scripts are for.

**The documents are compared as values, not as bytes.** The Rust prints this
one indented and the C prints it compact; `plan.h` records that convention and
says the two "differ by whitespace and by nothing else". This is what checks
the second half of that sentence.

WHAT A REFUSAL IS COMPARED ON

A configuration that does not compile has to be refused by both, at the same
file, line and column. The *text* after that is deliberately not compared: the
C joins a diagnostic's help onto one line and the Rust prints it as a `help:`
continuation, which is a rendering difference recorded in 0263 rather than a
disagreement about the configuration.

WHY IT FAILS RATHER THAN SKIPS

A gate that skips when a binary is missing reports success exactly as loudly as
one that compared anything. Both programs are built by `make` and by `make
c-test`, so an absent one is a broken tree rather than a machine this cannot
run on. The corpus is counted for the same reason.
"""

import json
import os
import subprocess
import sys
import tempfile

RUST = "./target/release/ncfg"
RUST_FALLBACK = "./target/debug/ncfg"
C = "./c/ncfg"

# Configuration directories in this tree, and whether they are expected to
# compile. Named rather than found by a pattern: a corpus that grows by glob is
# one nobody notices going empty.
CORPUS = [
	("tests/determinism", True),
	("tests/footprint/etc", True),
	("packaging/profile/offline", True),
	("tests/agree/refused", False),
]


def run(program, config_dir):
	"""`show --json` over one directory. Returns (status, stdout, stderr)."""
	with tempfile.TemporaryDirectory() as run_dir:
		result = subprocess.run(
			[program, "show", "--json", "--config-dir", config_dir,
			 "--run-dir", run_dir],
			capture_output=True,
			text=True,
			timeout=120,
			check=False,
		)
	return result.returncode, result.stdout, result.stderr


def location(text):
	"""The `file:line:column` a diagnostic names, or None.

	The first such line only: a compile reports every diagnostic it found, and
	what is being compared here is where the two programs stopped agreeing with
	the operator -- not how many things they had to say about it.
	"""
	for line in text.split("\n"):
		if not line.startswith("ncfg: "):
			continue
		parts = line[len("ncfg: "):].split(":")
		if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
			return ":".join(parts[:3])
	return None


def compare(rust, c, config_dir, expected_to_compile):
	"""Returns a sentence where they disagree, or None."""
	rust_status, rust_out, rust_err = run(rust, config_dir)
	c_status, c_out, c_err = run(c, config_dir)

	if (rust_status == 0) != (c_status == 0):
		return (f"{config_dir}: one program compiled it and the other did not "
			f"(rust {rust_status}, c {c_status}): "
			f"{(rust_err or c_err).strip().splitlines()[:1]}")
	if rust_status != 0:
		if expected_to_compile:
			return (f"{config_dir}: neither program compiled a directory that "
				f"should: {rust_err.strip().splitlines()[:1]}")
		here, there = location(rust_err), location(c_err)
		if here is None or there is None:
			return (f"{config_dir}: a refusal named no position "
				f"(rust {here}, c {there})")
		if here != there:
			return f"{config_dir}: refused at {here} by one and {there} by the other"
		return None
	if not expected_to_compile:
		return f"{config_dir}: expected not to compile, and both programs compiled it"
	try:
		first, second = json.loads(rust_out), json.loads(c_out)
	except json.JSONDecodeError as error:
		return f"{config_dir}: one of the two did not print a document: {error}"
	if first != second:
		return f"{config_dir}: the two documents differ"
	return None


def main():
	rust = RUST if os.path.exists(RUST) else RUST_FALLBACK
	missing = [name for name in (rust, C) if not os.path.exists(name)]
	if missing:
		print(f"agree-gate: not built: {', '.join(missing)}", file=sys.stderr)
		return 1
	present = [(d, ok) for d, ok in CORPUS if os.path.isdir(d)]
	if len(present) < len(CORPUS):
		gone = [d for d, _ in CORPUS if not os.path.isdir(d)]
		print(f"agree-gate: no such configuration directory: {', '.join(gone)}",
		      file=sys.stderr)
		return 1

	failures = []
	for config_dir, expected in present:
		problem = compare(rust, C, config_dir, expected)
		if problem:
			failures.append(problem)
	if failures:
		for problem in failures:
			print(f"agree-gate: {problem}", file=sys.stderr)
		return 1
	compiling = sum(1 for _, ok in present if ok)
	print(f"agree-gate: {len(present)} configuration(s), {compiling} compiled by both "
	      "programs to the same document and the rest refused at the same position")
	return 0


if __name__ == "__main__":
	sys.exit(main())
