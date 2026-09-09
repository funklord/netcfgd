#!/usr/bin/env python3
"""Every file netcfgd writes either reports its failure or is named here.

**The question this answers is "what happens when the write fails", asked of
all of them at once.** netcfgd writes configuration into `/etc`, a resolver
file, and about twenty kinds of runtime file under `/run/netcfgd`: a
supplicant's config, a dhcpcd hook, pid files, generated scripts, reports,
and the digests it keeps of its own past. Three faults in one week were a
write that could not happen and nobody being told -- a grant that was inert
under `ProtectSystem=full` (0176), a hook that could not be executed because
`/run` is `noexec` (0178), and a stop that could not signal (0179) -- and in
every one of them netcfgd reported success.

A write whose `Result` is dropped is the same fault with no sandbox needed.
It is not always wrong: netcfgd keeps records whose loss must not fail an
apply, because a device that was configured correctly is not made wrong by a
digest that could not be written. What is wrong is doing it *silently*, and
what is worse is doing it by accident -- `let _ =` reads the same either way,
which is how four of them sat in the tree unnoticed.

So this reads every write in the shipped crates and requires each one to be

* propagated, with `?` or by being the function's own value, or
* handled where it stands -- a `match`, an `if let Err`, a `let ... else`,
	or an `.is_err()` the caller acts on, or
* listed in `tool/write-best-effort.txt`, with a reason, which is where a
	deliberate discard says what it costs.

**Removals are exempt by rule rather than by listing.** `remove_file` and
`remove_dir_all` are asked for a state -- the file is not there -- and the
error case is usually that it already was not. Requiring 40 entries saying so
would bury the four that matter.

WHAT THIS DOES NOT PROMISE, since a gate quoted for more than it checks is
worse than none. It reads the shape of the call, not what the caller does
with the error afterwards: a propagated failure that its caller then swallows
would pass here. It says nothing about the *quality* of a message -- whether
it names the path, or carries the kernel's own words -- which is asserted by
the unit tests beside each writer and by `tests/live/sandbox_writes.sh`. And
it cannot see writes done through a helper it does not recognise, which is
why the recogniser is a list of the standard-library calls and not a guess.
"""

import re
import pathlib
import sys

# The crates that ship. Test-only helpers are not held to this: a leaked
# temporary directory is not an operator's problem.
ROOTS = ("crates", "backend", "helper", "adapter")
SKIP = ("netcfgd-testdir",)

WRITE = re.compile(
	r"fs::write\(|File::create\(|\.open\(|fs::rename\(|fs::create_dir_all\(|"
	r"fs::create_dir\(|::symlink\(|fs::set_permissions\(|fs::copy\(|"
	r"\.write_all\(|\.sync_all\("
)
REMOVE = re.compile(r"fs::remove_file\(|fs::remove_dir")
DISCARD = re.compile(r"let _ =|\.ok\(\);|unwrap_or_default\(\)")
ALLOWED = pathlib.Path("tool/write-best-effort.txt")


def statement(lines, index, limit):
	"""The call's whole statement, which may be wrapped over several lines."""
	out = []
	for i in range(index, min(index + 14, limit)):
		out.append(lines[i].strip())
		if lines[i].rstrip().endswith(";") or lines[i].rstrip().endswith("{"):
			break
	return " ".join(out)


def sites():
	"""Every write in the shipped crates, with the function it sits in."""
	for root in ROOTS:
		for path in sorted(pathlib.Path(root).glob("**/*.rs")):
			name = str(path)
			if "/tests/" in name or any(skip in name for skip in SKIP):
				continue
			lines = path.read_text().split("\n")
			# Unit tests live at the bottom of the file they test, and are
			# not held to this: a test that cannot write is a test failing.
			end = len(lines)
			for i, line in enumerate(lines):
				if line.strip().startswith("#[cfg(test)]"):
					end = i
					break
			function = "?"
			for i, line in enumerate(lines[:end]):
				found = re.match(r"\s*(pub(\(\w+\))? )?(async )?fn (\w+)", line)
				if found:
					function = found.group(4)
				stripped = line.strip()
				if stripped.startswith("//") or REMOVE.search(line):
					continue
				if WRITE.search(line):
					yield name, function, i + 1, statement(lines, i, end), lines[i]


def discarded(text, line):
	"""Whether the error goes nowhere. The `let _ =` may open the statement."""
	return bool(DISCARD.search(line) or DISCARD.search(text.split(";")[0]))


def main():
	if not ALLOWED.is_file():
		print(f"write_gate: {ALLOWED} is missing", file=sys.stderr)
		return 1
	allowed = set()
	for line in ALLOWED.read_text().split("\n"):
		line = line.split("#")[0].strip()
		if line:
			allowed.add(line.split(" -- ")[0].strip())

	silent, named = [], set()
	for path, function, number, text, line in sites():
		if discarded(text, line):
			key = f"{path}::{function}"
			named.add(key)
			if key not in allowed:
				silent.append((path, number, function, line.strip()))

	stale = sorted(allowed - named)
	if silent:
		print("write_gate: a write whose failure nothing reports:", file=sys.stderr)
		for path, number, function, line in silent:
			print(f"  {path}:{number}  in `{function}`", file=sys.stderr)
			print(f"      {line[:100]}", file=sys.stderr)
		print(
			"\n  Report it, propagate it, or add it to tool/write-best-effort.txt\n"
			"  with what its loss costs. Decision 0180.",
			file=sys.stderr,
		)
	if stale:
		print(
			"write_gate: listed as best-effort but no longer discarded:",
			file=sys.stderr,
		)
		for key in stale:
			print(f"  {key}", file=sys.stderr)
		print(
			"\n  Take it out of tool/write-best-effort.txt: an allowance nothing\n"
			"  uses is an allowance nobody rechecks.",
			file=sys.stderr,
		)
	if silent or stale:
		return 1
	print(f"write_gate: OK ({len(named)} best-effort writes, all accounted for)")
	return 0


if __name__ == "__main__":
	sys.exit(main())
