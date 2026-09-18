#!/usr/bin/env python3
"""No test disarms the process the other tests are in, or orphans a child.

Rust runs the tests of one binary as threads in one process, which makes two
ordinary-looking lines everybody else's problem. Both of these shipped, and
neither failure said anything about the cause:

  * **A test that sheds privilege.** Where `shed` reaches `Fully` there is an
    unprivileged id to become, and POSIX makes credentials a property of the
    process -- glibc broadcasts the change to every thread, so the whole binary
    is uid 65534 from that moment. What was seen: an intermittent
    `chmod: PermissionDenied` in a test about file modes, and a `kill` of a
    root-owned child returning `EPERM`, which left `wait` blocked on a
    `sleep 30`. Thirty seconds on every run of that crate's tests.

  * **A test that spawns a shell which forks.** `sh -c 'sleep 30'` runs the
    sleep as a grandchild, so killing the child kills the shell and leaves the
    sleep reparented to init -- holding the test binary's stderr, which
    `cargo test` reads until every writer is gone. Thirty seconds again, after
    the last assertion, for a test that had already passed.

The remedies are one line each: put the shed in its own integration binary,
which is a process of its own, and spawn with `process_group(0)` so the group
can be signalled. Neither is visible in a failure, which is why this is a gate
and not a test. Decision 0262.

WHAT THIS DOES NOT SEE

Production code, which is where `terminate_group` and its reasoning already
live, and shells spawned by the shell test suites under `tests/`. It reads only
Rust, and only the test halves of it.
"""

import pathlib
import re
import sys

CRATES = pathlib.Path("crates")

# A shell whose command may fork, which is every `sh -c`.
SHELL = re.compile(r'Command::new\("sh"\)')
GROUPED = re.compile(r"\.process_group\(")
# The call that disarms the process, not the word in a comment or a doc link.
# `\b` and the parentheses together: `super::shed()` is the form that matters
# and a `[`shed`]` in a doc comment has no parentheses to match. Written the
# other way round first -- a lookbehind forbidding `:` -- which excluded the
# one spelling this exists to catch, and the sabotage said so.
SHED = re.compile(r"\bshed\(\)")


def test_region(text):
	"""Everything from the first `#[cfg(test)]` to the end of the file.

	Crude, and true of this tree: tests live at the bottom of the file they
	test. A crate that grows a `#[cfg(test)]` helper in the middle would have
	its production code read as test code, which errs towards checking too
	much rather than too little.
	"""
	at = text.find("#[cfg(test)]")
	return "" if at < 0 else text[at:]


def main():
	unit = sorted(CRATES.glob("*/src/**/*.rs"))
	integration = sorted(CRATES.glob("*/tests/*.rs"))
	if len(unit) < 20:
		print(f"disarm-gate: only {len(unit)} source file(s) found; the paths are wrong")
		return 1

	shells = 0
	faults = 0
	for path in unit + integration:
		text = path.read_text()
		region = text if path.parts[2] == "tests" else test_region(text)
		if not region:
			continue

		# A shed in an integration test is the point of this gate, so only the
		# unit half is checked for it.
		if path.parts[2] != "tests":
			for number, line in enumerate(region.splitlines(), 1):
				if SHED.search(line):
					print(f"disarm-gate: {path}: a unit test calls shed()")
					print("disarm-gate:   it disarms every other test in the binary;")
					print("disarm-gate:   put it in tests/, which is a process of its own")
					faults += 1

		for block in region.split("Command::new"):
			if not block.startswith('("sh")'):
				continue
			# **Only a shell the test means to outlive.** `.output()` and
			# `.status()` wait for the shell, which waits for its own child, so
			# nothing can be left behind. `.spawn()` keeps a handle and kills
			# it later, which is where the grandchild survives.
			end = min(
				(block.find(call) for call in (".spawn(", ".output(", ".status(") if block.find(call) >= 0),
				default=len(block),
			)
			if ".spawn(" not in block[: end + 8]:
				continue
			shells += 1
			if not GROUPED.search(block[:end]):
				print(f"disarm-gate: {path}: a test spawns `sh` with no process group")
				print("disarm-gate:   `sh -c` forks, so the work is a grandchild and")
				print("disarm-gate:   killing the child leaves it holding stderr;")
				print("disarm-gate:   add `.process_group(0)` and kill the group")
				faults += 1

	if not shells:
		print("disarm-gate: no `sh` spawned in any test; the extraction is broken")
		return 1
	if faults:
		return 1
	print(
		f"disarm-gate: {len(unit) + len(integration)} file(s) checked, "
		f"{shells} test shell(s), each in a group of its own"
	)
	return 0


if __name__ == "__main__":
	sys.exit(main())
