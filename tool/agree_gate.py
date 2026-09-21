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
file, line and column, saying the same thing. The C joins a diagnostic's help
onto one line where the Rust prints it as a `help:` continuation -- 0263
records that -- so the Rust's first line is a *prefix* of the C's, and that is
the comparison. It is deliberately strict: a message reworded in one program is
a message that has to be reworded in the other, and finding that out here is
better than finding it out from somebody who moved between the two.

One case has no position in either program, and it is in the corpus for that:
an include naming a file which is not there is refused by the loader, before
anything is parsed. What is compared there is that both refused and neither
invented a line.

WHAT ELSE IS COMPARED: WRITING A CONFIGURATION BACK

`ncfg profile save` is the other pure path, and a longer one: it compiles what
is on disk, renders it back to configuration text, writes the profile, folds
the previous selection into `conf.d` and selects the new one. Nothing in that
reads the kernel either, so the two programs can be handed identical
directories and asked to produce identical ones -- which is a comparison of the
renderer, the profile writer and the fold at once, and the renderer has no
other differential.

The text each prints is compared too, with the scratch directory's path taken
out of it. That is where a configuration neither can write back shows up: the
determinism fixture states a `qdisc`, which neither renderer can put into
configuration text, so both refuse it in the same words and write nothing.

AND THE THREE VERBS THAT WRITE

`config put`, `secret set` and `control set` each take something from a caller
and put it in the configuration directory, and none of them reads the kernel
either. They are run against one corpus entry rather than all of them -- what
they write barely depends on what was there, and a gate that is slow is a gate
somebody runs less often.

`wifi add` is **deliberately not among them**, and the reason is worth writing
down: it activates a radio, so what it writes depends on which radios this
machine has. Both programs read the same machine and agreed when this was
tried by hand, but a check whose fixture is the developer's laptop is one that
fails for a reason nobody can reproduce.

The text each prints is compared with its whitespace collapsed. The C joins a
diagnostic onto the sentence that introduces it and the Rust puts it on the
next line; that is the same rendering divergence as above, and collapsing is
what lets the *words* be compared without pinning the line breaks.

WHY IT FAILS RATHER THAN SKIPS

A gate that skips when a binary is missing reports success exactly as loudly as
one that compared anything. Both programs are built by `make` and by `make
c-test`, so an absent one is a broken tree rather than a machine this cannot
run on. The corpus is counted for the same reason.
"""

import json
import os
import shutil
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
	("tests/agree/wrong-block", False),
	("tests/agree/unknown-key", False),
	("tests/agree/bad-value", False),
	("tests/agree/defined-twice", False),
	("tests/agree/unclosed", False),
	("tests/agree/override-alone", False),
	("tests/agree/include-missing", False),
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


def first_diagnostic(text):
	"""The first `ncfg: ` line, and the `file:line:column` in it if there is one.

	The first only: a compile reports every diagnostic it found, and what is
	being compared is where the two programs stopped agreeing with the operator
	-- not how many things they then had to say about it.

	A refusal with no position is a real answer rather than a parse failure
	here: an include that names a file which is not there is refused by the
	*loader*, before anything has been parsed, so there is no line to point at
	in either program.
	"""
	for line in text.split("\n"):
		if not line.startswith("ncfg: "):
			continue
		body = line[len("ncfg: "):]
		parts = body.split(":")
		where = None
		if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
			where = ":".join(parts[:3])
		return body, where
	return None, None


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
		rust_said, here = first_diagnostic(rust_err)
		c_said, there = first_diagnostic(c_err)
		if rust_said is None or c_said is None:
			return (f"{config_dir}: a refusal said nothing that begins `ncfg: ` "
				f"(rust {rust_said!r}, c {c_said!r})")
		if (here is None) != (there is None):
			# **No fixture reaches this arm**, and that is the fact it exists to
			# watch: today every input in the corpus makes both programs name a
			# position or neither. Removing it therefore turns nothing red,
			# which is said here rather than left for somebody to discover by
			# aiming a sabotage at it.
			return (f"{config_dir}: one program named a position and the other "
				f"did not (rust {here}, c {there})")
		if here is None:
			# Both refused before parsing. Agreeing about *that* is the whole
			# of what can be compared, and it is worth comparing: a program
			# that read a missing include as an empty file would compile a
			# configuration the other one refuses.
			return None
		if here != there:
			return f"{config_dir}: refused at {here} by one and {there} by the other"
		if not c_said.startswith(rust_said):
			# **The C's line is the Rust's plus the help.** 0263 records that
			# divergence: the C joins a diagnostic's help onto one line and the
			# Rust prints it as a `help:` continuation. So the Rust's sentence
			# is a prefix of the C's, and a reworded message in one program is
			# a message that has to be reworded in the other -- which is a
			# decision to take rather than a difference to discover later.
			return (f"{config_dir}: the two refusals do not say the same thing\n"
				f"    rust: {rust_said}\n    c   : {c_said}")
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


# One corpus entry, three verbs, and what each is given on standard input.
# Named rather than generated: a list a person reads is a list a person can
# argue with.
WRITE_CORPUS = "tests/footprint/etc"
WRITE_VERBS = [
	("config put", ["config", "put", "lab"],
	 "device lo {\n\tmanaged = false\n}\n"),
	("config put, refused", ["config", "put", "lab"],
	 "interface lo {\n\tmanaged = false\n}\n"),
	("secret set", ["secret", "set", "lab"], "hunter2\n"),
	("control set", ["control", "set", "--observe", "any"], ""),
]


# One place the two programs are known to differ, with both sides written out.
#
# `profile save`'s snapshot is the only configuration file the Rust writes with
# `fs::write` rather than through its own `write_atomically(.., 0o644)`, so it
# lands with the process umask -- 0664 under this tree's 0002 -- and without the
# temporary-and-rename every other file in that module gets. The C writes 0644
# atomically like everything else. Recorded rather than fixed: the Rust is what
# this port is being compared against, and a defect in it is a finding rather
# than an edit (project.md 10.221).
#
# Written as an exact pair so that it stops being an exception the moment
# either side changes: a Rust that starts writing 0644 makes the two equal and
# never reaches here, and a C that stops writing 0644 fails.
KNOWN_MODE_DIVERGENCE = {
	("profile/agree/00-saved.conf", 0o664, 0o644),
}


def known_divergence(name, rust_mode, c_mode):
	"""Whether this is the one difference that is written down."""
	return (name, rust_mode, c_mode) in KNOWN_MODE_DIVERGENCE


def words(text):
	"""The text with its whitespace collapsed, for `WRITE_VERBS`' reason."""
	return " ".join(text.split())


def tree(root):
	"""Every file under `root`, as {relative path: (permissions, bytes)}.

	**The permissions are compared as well as the contents**, and that is not
	tidiness: `ncfg secret set` writes a credential and the mode is the whole
	of what keeps it from being world-readable. A comparison of contents alone
	passes a program that wrote the right passphrase into the wrong file.
	"""
	found = {}
	for directory, _, names in os.walk(root):
		for name in names:
			path = os.path.join(directory, name)
			with open(path, "rb") as handle:
				found[os.path.relpath(path, root)] = (
					os.stat(path).st_mode & 0o777, handle.read())
	return found


def saved(program, config_dir, work):
	"""`profile save` over a copy of `config_dir`. Returns (said, tree).

	The copy is what makes this comparable: the command writes into the
	configuration directory, so the two programs each get one of their own and
	what is compared is what they made of the same starting point.
	"""
	copy = os.path.join(work, "etc")
	run_dir = os.path.join(work, "run")
	shutil.copytree(config_dir, copy)
	os.makedirs(run_dir, exist_ok=True)
	result = subprocess.run(
		[program, "profile", "save", "agree", "--config-dir", copy,
		 "--run-dir", run_dir],
		capture_output=True,
		text=True,
		timeout=120,
		check=False,
	)
	# The scratch path is in the output -- "wrote <copy>/profile/agree/..." --
	# and it differs between the two runs by construction.
	said = (result.stdout + result.stderr).replace(copy, "<config>")
	said = said.replace(run_dir, "<run>")
	return said, tree(copy)


def wrote(program, config_dir, verb, stdin, work):
	"""One writing verb over a copy of `config_dir`. Returns (said, tree)."""
	copy = os.path.join(work, "etc")
	run_dir = os.path.join(work, "run")
	shutil.copytree(config_dir, copy)
	os.makedirs(run_dir, exist_ok=True)
	result = subprocess.run(
		[program] + verb + ["--config-dir", copy, "--run-dir", run_dir],
		input=stdin,
		capture_output=True,
		text=True,
		timeout=120,
		check=False,
	)
	# Both scratch paths, because a message can name either -- "nothing is
	# listening on <run>/netcfgd.sock, so this was written directly" names the
	# run directory, and the two programs are given different ones on purpose.
	said = (result.stdout + result.stderr).replace(copy, "<config>")
	said = said.replace(run_dir, "<run>")
	return words(said), tree(copy)


def compare_writes(rust, c):
	"""Returns a sentence where a writing verb differs, or None."""
	for name, verb, stdin in WRITE_VERBS:
		with tempfile.TemporaryDirectory() as work:
			rust_said, rust_tree = wrote(rust, WRITE_CORPUS, verb, stdin,
						     os.path.join(work, "rust"))
			c_said, c_tree = wrote(c, WRITE_CORPUS, verb, stdin,
					       os.path.join(work, "c"))
		if rust_said != c_said:
			return (f"`ncfg {name}` said different things\n"
				f"    rust: {rust_said[:160]}\n    c   : {c_said[:160]}")
		if set(rust_tree) != set(c_tree):
			only_rust = sorted(set(rust_tree) - set(c_tree))
			only_c = sorted(set(c_tree) - set(rust_tree))
			return (f"`ncfg {name}` wrote different files "
				f"(only rust: {only_rust}, only c: {only_c})")
		for leaf in sorted(rust_tree):
			rust_mode, rust_bytes = rust_tree[leaf]
			c_mode, c_bytes = c_tree[leaf]
			if rust_mode != c_mode and not known_divergence(leaf, rust_mode, c_mode):
				return (f"`ncfg {name}` wrote {leaf} with mode "
					f"{rust_mode:04o} and {c_mode:04o}")
			if rust_bytes != c_bytes:
				return f"`ncfg {name}` wrote a different {leaf}"
	return None


def compare_save(rust, c, config_dir):
	"""Returns a sentence where the two write-backs differ, or None."""
	with tempfile.TemporaryDirectory() as work:
		rust_said, rust_tree = saved(rust, config_dir, os.path.join(work, "rust"))
		c_said, c_tree = saved(c, config_dir, os.path.join(work, "c"))
	if rust_said != c_said:
		return (f"{config_dir}: `profile save` said different things\n"
			f"    rust: {rust_said.strip()[:160]}\n"
			f"    c   : {c_said.strip()[:160]}")
	if set(rust_tree) != set(c_tree):
		only_rust = sorted(set(rust_tree) - set(c_tree))
		only_c = sorted(set(c_tree) - set(rust_tree))
		return (f"{config_dir}: `profile save` wrote different files "
			f"(only rust: {only_rust}, only c: {only_c})")
	for name in sorted(rust_tree):
		rust_mode, rust_bytes = rust_tree[name]
		c_mode, c_bytes = c_tree[name]
		if rust_mode != c_mode and not known_divergence(name, rust_mode, c_mode):
			return (f"{config_dir}: `profile save` wrote {name} with mode "
				f"{rust_mode:04o} and {c_mode:04o}")
		if rust_bytes != c_bytes:
			return f"{config_dir}: `profile save` wrote a different {name}"
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
			continue
		if expected:
			problem = compare_save(rust, C, config_dir)
			if problem:
				failures.append(problem)
	problem = compare_writes(rust, C)
	if problem:
		failures.append(problem)
	if failures:
		for problem in failures:
			print(f"agree-gate: {problem}", file=sys.stderr)
		return 1
	compiling = sum(1 for _, ok in present if ok)
	print(f"agree-gate: {len(present)} configuration(s), {compiling} compiled by both "
	      f"programs to the same document and written back as the same profile, "
	      f"{len(present) - compiling} refused by both in the same words, and "
	      f"{len(WRITE_VERBS)} writing verb(s) that left the same directory behind")
	return 0


if __name__ == "__main__":
	sys.exit(main())
