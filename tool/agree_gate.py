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

AND THE VERBS THAT WRITE

`config put`, `secret set`, `control set`, `profile set`, `wifi forget` and the
`rm` of each take something from a caller and put it in -- or take it out of --
the configuration directory, and none of them reads the kernel either.

**Several run as pairs**, because undoing is the half that goes wrong: a `rm`
that leaves a file behind, or takes one more than it was asked for, shows up
only when the directory is compared after both halves have run.

`wifi add` is **deliberately not among them**, and the reason is worth writing
down: it activates a radio, so what it writes depends on which radios this
machine has. Both programs read the same machine and agreed when this was
tried by hand, but a check whose fixture is the developer's laptop is one that
fails for a reason nobody can reproduce.

The text each prints is compared with its whitespace collapsed. The C joins a
diagnostic onto the sentence that introduces it and the Rust puts it on the
next line; that is the same rendering divergence as above, and collapsing is
what lets the *words* be compared without pinning the line breaks.

AND WHERE THEY ARE TOLD TO LOOK

`--help` promises that each directory is "the flag, or the variable, or the
default", and a precedence that differs between the two programs is the
quietest divergence available: nothing refuses, and a machine is configured
from a directory nobody meant. Those cases set the variables and compare what
comes back.

AND THE DAEMON'S ARGUMENT HANDLING

The other program has a surface too -- `--help`, `--version`, an option nobody
defined, an option with no value -- and it is compared the same way. **Every
case there prints or refuses and exits**: a case that started a daemon would be
this gate running a network manager on whatever machine invoked it. Each is
given `--no-apply-on-start` and a scratch directory pair as well, so that a
mistake in that list observes and changes nothing.

AND THE VERBS THAT ONLY READ

`--help`, `--version`, `control show`, `profile get` and `profile list` print
and change nothing, so they are compared as text and as an exit status. The
help is the one a person actually depends on: it is the contract somebody reads
before they type, and it is maintained by hand on the C side.

Most of that list is **argument handling** -- a verb with no subcommand, a flag
nobody defined, a name that cannot be one, a count that is not a number. It is
a wide surface, an easy one for two implementations to drift on, and none of it
needs a machine. Each runs against a copy of a configuration directory, because
a mistake here -- a verb that writes where this expected it to print -- must not
reach the tree.

TWO CASES WHERE THE TEXT IS *REQUIRED* TO DIFFER

`ncfg reset` diverges in three ways that 0263 records with its reasons -- the C
says `would remove` before and `removed` after where the Rust prints the whole
list under `removed` and *then* runs the loop that removes, and its note says
"the next reconcile or apply" where the Rust says "the next apply", and it
refuses a positional argument where the Rust's dispatch drops one -- so
`ncfg reset office --yes` empties the whole configuration there. Those cases
are marked, and the gate then insists the two **do** differ. So a divergence
that gets closed is a gate that goes red asking for its own exception to be
deleted, which is the opposite of what an allow-list does.

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
	("tests/agree/network", True),
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


# What is asked of a copy of a configuration directory, and in what order.
# Named rather than generated: a list a person reads is a list a person can
# argue with.
#
# **Several are pairs, because undoing is the half that goes wrong.** A `rm`
# that leaves a file behind, or takes one more than it was asked for, shows up
# only when the directory is compared after both halves have run.
# Invocations that print and change nothing, with whether the two programs are
# *required* to differ. Most are argument handling: which flags are accepted,
# what a missing one says, and what a verb does with a word it did not expect.
# That is a wide surface and an easy one for two implementations to drift on,
# and none of it needs a machine.
#
# They are still run against a copy, because a mistake here -- a verb that
# writes where this expected it to print -- must not reach the tree.
READ_CASES = [
	(["--help"], False),
	(["--version"], False),
	(["control", "show"], False),
	(["profile", "get"], False),
	(["profile", "list"], False),
	([], False),
	(["nonsense"], False),
	(["--nonsense"], False),
	(["-h"], False),
	(["explain"], False),
	(["explain", "interface"], False),
	(["explain", "nonsense", "eth0"], False),
	(["wifi"], False),
	(["wifi", "connect"], False),
	(["profile"], False),
	(["profile", "set"], False),
	(["profile", "set", "../x"], False),
	(["config"], False),
	(["config", "put"], False),
	(["config", "rm"], False),
	(["control"], False),
	(["secret"], False),
	(["secret", "set"], False),
	(["wait-online", "notanumber"], False),
	(["show", "--json", "--nonsense"], False),
	(["--config-dir"], False),
	# 0263: the Rust's dispatch drops every positional at `reset`, so
	# `ncfg reset office --yes` empties the whole configuration. This port
	# refuses the argument instead.
	(["reset", "extra"], True),
]

# What the reading cases are pointed at. A copy of it is made per case.
READ_CORPUS = "tests/footprint/etc"

# Where the two programs are told to look **through the environment** rather
# than through a flag.
#
# `--help` promises this in as many words -- "default /etc/netcfgd, or
# $NCFG_CONFIG_DIR" -- and a precedence that differs between the two is the
# quietest kind of divergence there is: nothing refuses, and a machine is
# configured from a directory the operator did not mean. So the cases are the
# three answers in order -- the flag, then the variable, then the default --
# and one where the variable names a directory that is not there.
#
# `<config>` is replaced with the copy this case runs against, and `<missing>`
# with a path inside the scratch tree that does not exist. A case that lists a
# flag as well is the one testing that the flag wins.
# Each case names the directory it is given a copy of, because *which* one
# matters here: a case whose answer is the same from the flag's directory and
# from the variable's proves nothing about which was read.
# `tests/agree/selected` names a profile, so `profile get` prints `office` from
# it and `no profile chosen` from anywhere else.
ENV_CASES = [
	(["profile", "get"], {"NCFG_CONFIG_DIR": "<config>"}, "tests/agree/selected"),
	(["profile", "get"], {"NCFG_CONFIG_DIR": "<missing>"}, "tests/agree/selected"),
	(["control", "show"], {"NCFG_CONFIG_DIR": "<config>"}, "tests/footprint/etc"),
	# The flag against a variable pointing somewhere else: the flag wins, and
	# the two directories answer differently, so this fails if it does not.
	(["profile", "get", "--config-dir", "<config>"],
	 {"NCFG_CONFIG_DIR": "<missing>"}, "tests/agree/selected"),
	(["profile", "list"],
	 {"NCFG_FACTORY_DIR": "<config>", "NCFG_CONFIG_DIR": "<missing>"}, "packaging"),
]

# The daemon's own argument handling.
#
# **Every one of these prints or refuses and exits**, and that is a rule rather
# than an observation: a case that *started* a daemon would be this gate
# running a network manager on whatever machine it was invoked on. Two things
# hold it. Each case is an invocation that cannot reach the loop -- `--help`,
# `--version`, an option nobody defined, an option with no value -- and every
# one is given `--no-apply-on-start` and a scratch directory pair anyway, so
# that a mistake here observes and watches and changes nothing.
DAEMON_CASES = [
	["--help"],
	["--version"],
	["--nonsense"],
	["extra"],
	["--config-dir"],
]
# The one place the two daemons' own output is allowed to differ, written as
# the exact lines each side produces so that it expires by failing.
#
# `--try-the-c-daemon` is the C port's alone and must stay that way: the Rust
# daemon runs when it is started, and this one refuses unless somebody at the
# keyboard says they are watching (project.md 10.232). A Rust that grew the
# flag would be a Rust that had acquired the C's refusal, which should not
# happen quietly -- and a C that lost it would leave this gate carrying an
# exception for a divergence that has gone.
#
# **Whole lines, not fragments, and that is not fussiness.** The first version
# of this recorded the substring `--try-the-c-daemon`, and a sabotage that
# renamed the flag to `--try-the-c-daemon-x` passed: the fragment was still
# *in* the line, so the exception swallowed a flag nobody had recorded. An
# exception that matches more than what it was written for is how a gate comes
# to approve its own drift.
DAEMON_DIFFERENCES = {
	"--help": [
		# `--supported` is the C port's alone for the same kind of reason and a
		# different one: it is the completeness ledger `doc/c-transition.md`
		# section 5 asks for, and what it answers is "what does *this port* not
		# do yet". A Rust that grew one would be answering a question nobody is
		# asking of it. project.md 10.247.
		("c", "  --supported            what this build carries out, as JSON lines, asked"),
		("c", "                         of the code that decides rather than listed"),
		("c", "  --try-the-c-daemon     run the loop anyway. This build refuses by"),
		("c", "                         default and prints why; read that first, and"),
		("c", "                         have something watching the machine when you"),
		("c", "                         use this -- tests/live/c_daemon_tryout.sh is"),
		("c", "                         what it was written for"),
	],
}


def daemon_without_exceptions(verb, rust_text, c_text):
	"""The two texts with the recorded divergence taken out, or a sentence.

	Answers `(rust, c, None)` when every recorded line is exactly where it
	should be, and `(None, None, why)` when one has gone -- which is how an
	exception stops outliving the thing it is about.
	"""
	recorded = DAEMON_DIFFERENCES.get(verb, [])
	if not recorded:
		return (rust_text, c_text, None)
	for which, line in recorded:
		said = rust_text if which == "rust" else c_text
		if line not in said.splitlines():
			return (None, None,
				f"`netcfgd {verb}`: the {which} program no longer has the line "
				f"{line!r}. project.md 10.232 records that divergence; if it has "
				"been closed, the exception in this gate can go")
	# Each recorded line is dropped once, from the side that owns it, so a
	# second copy of one -- or any line nobody recorded -- still has to match.
	def trimmed(text, which):
		lines = text.splitlines(True)
		for owner, line in recorded:
			if owner != which:
				continue
			for at, existing in enumerate(lines):
				if existing.rstrip("\n") == line:
					del lines[at]
					break
		return "".join(lines)

	return (trimmed(rust_text, "rust"), trimmed(c_text, "c"), None)


DAEMON_RUST = "./target/release/netcfgd"
DAEMON_RUST_FALLBACK = "./target/debug/netcfgd"
DAEMON_C = "./c/netcfgd"

WRITE_CASES = [
	("config put", "tests/footprint/etc", [
		(["config", "put", "lab"], "device lo {\n\tmanaged = false\n}\n"),
	]),
	("config put, refused", "tests/footprint/etc", [
		(["config", "put", "lab"], "interface lo {\n\tmanaged = false\n}\n"),
	]),
	("config put and rm", "tests/footprint/etc", [
		(["config", "put", "lab"], "device lo {\n\tmanaged = false\n}\n"),
		(["config", "rm", "lab"], ""),
	]),
	("secret set", "tests/footprint/etc", [
		(["secret", "set", "lab"], "hunter2\n"),
	]),
	("secret set and rm", "tests/footprint/etc", [
		(["secret", "set", "lab"], "hunter2\n"),
		(["secret", "rm", "lab"], ""),
	]),
	("control set", "tests/footprint/etc", [
		(["control", "set", "--observe", "any"], ""),
	]),
	("wifi forget", "tests/agree/network", [
		(["secret", "set", "lab"], "hunter2\n"),
		(["wifi", "forget", "Lab"], ""),
	]),
	("profile save, unset and set", "tests/footprint/etc", [
		(["profile", "save", "agree"], ""),
		(["profile", "unset"], ""),
		(["profile", "set", "agree"], ""),
	]),
]

# The places 0263 records the two saying different things on purpose, spelled
# as the words each program has to still be using.
#
# **Each divergence is pinned separately** rather than as "these two differ
# somehow": `reset` has three of them, and a marker that only asked for one
# difference would go on passing while two of the three were quietly converged.
# A fragment that stops appearing is a gate that goes red naming which
# exception can go.
REQUIRED_DIFFERENCES = {
	"reset, dry run": [
		("rust", "The next apply would remove"),
		("c", "The next reconcile or apply would remove"),
	],
	"reset": [
		("rust", "The next apply would remove"),
		("c", "The next reconcile or apply would remove"),
		# The Rust prints the whole list under `removed` before the loop that
		# removes; this port says `would remove` first and `removed` as each
		# file actually goes.
		("c", "would remove <config>/netcfgd.conf"),
	],
	"reset extra": [
		("rust", "would remove <config>/netcfgd.conf"),
		("c", "takes no arguments and got"),
	],
}


def missing_difference(name, rust_said, c_said):
	"""Which recorded divergence has stopped being one, or None."""
	for which, fragment in REQUIRED_DIFFERENCES.get(name, []):
		said = rust_said if which == "rust" else c_said
		if fragment not in said:
			return (f"`ncfg {name}`: the {which} program no longer says "
				f"{fragment!r}. 0263 records that divergence; if it has been "
				"closed, the exception in this gate can go")
	return None

WRITE_CASES += [
	("reset, dry run", "tests/footprint/etc", [
		(["reset"], ""),
	]),
	("reset", "tests/footprint/etc", [
		(["reset", "--yes"], ""),
	]),
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
	"""The text with its whitespace collapsed, for `WRITE_CASES`' reason."""
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


def wrote(program, config_dir, steps, work):
	"""One sequence of writing verbs over a copy. Returns (said, tree)."""
	copy = os.path.join(work, "etc")
	run_dir = os.path.join(work, "run")
	shutil.copytree(config_dir, copy)
	os.makedirs(run_dir, exist_ok=True)
	said = ""
	for verb, stdin in steps:
		result = subprocess.run(
			[program] + verb + ["--config-dir", copy, "--run-dir", run_dir],
			input=stdin,
			capture_output=True,
			text=True,
			timeout=120,
			check=False,
		)
		said += result.stdout + result.stderr
	# Both scratch paths, because a message can name either -- "nothing is
	# listening on <run>/netcfgd.sock, so this was written directly" names the
	# run directory, and the two programs are given different ones on purpose.
	said = said.replace(copy, "<config>").replace(run_dir, "<run>")
	return words(said), tree(copy)


def compare_writes(rust, c):
	"""Returns a sentence where a writing verb differs, or None."""
	for name, config_dir, steps in WRITE_CASES:
		with tempfile.TemporaryDirectory() as work:
			rust_said, rust_tree = wrote(rust, config_dir, steps,
						     os.path.join(work, "rust"))
			c_said, c_tree = wrote(c, config_dir, steps,
					       os.path.join(work, "c"))
		if name in REQUIRED_DIFFERENCES:
			gone = missing_difference(name, rust_said, c_said)
			if gone:
				return gone
		elif rust_said != c_said:
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


def compare_reads(rust, c):
	"""Returns a sentence where a verb that only reads differs, or None."""
	for verb, must_differ in READ_CASES:
		with tempfile.TemporaryDirectory() as work:
			copy = os.path.join(work, "etc")
			run_dir = os.path.join(work, "run")
			shutil.copytree(READ_CORPUS, copy)
			os.makedirs(run_dir, exist_ok=True)
			said = []
			for program in (rust, c):
				result = subprocess.run(
					[program] + verb + ["--config-dir", copy,
							    "--run-dir", run_dir],
					capture_output=True,
					text=True,
					timeout=120,
					check=False,
				)
				text = (result.stdout + result.stderr)
				text = text.replace(copy, "<config>").replace(run_dir, "<run>")
				said.append((result.returncode, text))
		spelled = " ".join(verb) or "(no verb)"
		if must_differ:
			gone = missing_difference(spelled, said[0][1], said[1][1])
			if gone:
				return gone
		elif said[0] != said[1]:
			return (f"`ncfg {spelled}` differs\n"
				f"    rust: {said[0][1].strip()[:160]}\n"
				f"    c   : {said[1][1].strip()[:160]}")
	return None


def compare_env(rust, c):
	"""Returns a sentence where reading the environment differs, or None."""
	for verb, environment, corpus in ENV_CASES:
		with tempfile.TemporaryDirectory() as work:
			copy = os.path.join(work, "etc")
			run_dir = os.path.join(work, "run")
			missing = os.path.join(work, "nowhere")
			shutil.copytree(corpus, copy)
			os.makedirs(run_dir, exist_ok=True)
			filled = {key: value.replace("<config>", copy).replace("<missing>", missing)
				  for key, value in environment.items()}
			argv = [word.replace("<config>", copy).replace("<missing>", missing)
				for word in verb]
			said = []
			for program in (rust, c):
				result = subprocess.run(
					[program] + argv + ["--run-dir", run_dir],
					env=dict(os.environ, **filled),
					capture_output=True,
					text=True,
					timeout=120,
					check=False,
				)
				text = (result.stdout + result.stderr)
				text = text.replace(copy, "<config>").replace(missing, "<missing>")
				said.append((result.returncode, text.replace(run_dir, "<run>")))
		if said[0] != said[1]:
			spelled = " ".join(verb)
			named = " ".join(f"{key}={value}" for key, value in sorted(environment.items()))
			return (f"`{named} ncfg {spelled}` differs\n"
				f"    rust: {said[0][1].strip()[:160]}\n"
				f"    c   : {said[1][1].strip()[:160]}")
	return None


def compare_daemon(rust, c):
	"""Returns a sentence where the daemon's argument handling differs."""
	for verb in DAEMON_CASES:
		with tempfile.TemporaryDirectory() as work:
			config_dir = os.path.join(work, "etc")
			run_dir = os.path.join(work, "run")
			os.makedirs(config_dir)
			os.makedirs(run_dir)
			said = []
			for program in (rust, c):
				result = subprocess.run(
					[program, "--no-apply-on-start",
					 "--config-dir", config_dir, "--run-dir", run_dir] + verb,
					capture_output=True,
					text=True,
					timeout=30,
					check=False,
				)
				text = (result.stdout + result.stderr)
				said.append((result.returncode,
					     text.replace(config_dir, "<config>").replace(run_dir, "<run>")))
		rust_text, c_text, why = daemon_without_exceptions(
			" ".join(verb), said[0][1], said[1][1])
		if why:
			return why
		if said[0][0] != said[1][0] or rust_text != c_text:
			return (f"`netcfgd {' '.join(verb)}` differs\n"
				f"    rust: {said[0][1].strip()[:160]}\n"
				f"    c   : {said[1][1].strip()[:160]}")
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
	daemon_rust = (DAEMON_RUST if os.path.exists(DAEMON_RUST)
		       else DAEMON_RUST_FALLBACK)
	missing = [name for name in (rust, C, daemon_rust, DAEMON_C)
		   if not os.path.exists(name)]
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
	problem = compare_reads(rust, C)
	if problem:
		failures.append(problem)
	problem = compare_env(rust, C)
	if problem:
		failures.append(problem)
	problem = compare_daemon(daemon_rust, DAEMON_C)
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
	      f"{len(WRITE_CASES)} sequence(s) of writing verbs that left the same "
	      f"directory behind, {len(READ_CASES)} invocation(s) that only read, "
	      f"{len(ENV_CASES)} that are told where to look through the environment, "
	      f"and {len(DAEMON_CASES)} of the daemon's own")
	return 0


if __name__ == "__main__":
	sys.exit(main())
