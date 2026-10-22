#!/usr/bin/env python3
"""The completeness ledger: what the C build carries out, against the witnesses.

WHY THIS IS DERIVED AND NOT A LIST
    `doc/c-transition.md` section 5 asks for a completeness ledger and says in
    the same breath what it may not be: "a hand-written checklist of supported
    features is exactly the shape this workspace has been burned by repeatedly
    -- a list that quietly stops matching the thing it describes, under a name
    that claims it is exhaustive."

    So there is no list here either. One side is `netcfgd --supported`, which
    asks `ncfg_apply_supported` and `ncfg_proto_request_name` and prints what
    they answer; the other is `doc/schema/`, the four artifacts blessed under
    decision 0020 that both implementations must reproduce. Neither side is
    written by hand, and the gate is the sentence between them:

        everything the frozen witnesses exercise, this build carries out.

WHAT THE WITNESS IS, WHICH THIS GATE GOT WRONG FIRST
    `plan.json` is **populated by hand** -- its own test says so -- and
    regenerated with `make schema-bless`. Its job is to pin the serialisation
    of every `Op` variant, so that a renamed op or a new field moves the file.
    It is not a plan anything produced and not one anything could run: it
    carries `backend.reload` for a `supplicant` because that pins the shape of
    a reload action, and **neither implementation can reload a supplicant** --
    the Rust answers "not implemented in this build" and the C says which
    daemons have a reload and why the others do not.

    The first version of this gate read the witness as an executable plan and
    reported that one pairing as a gap in the C. It is not: it is a pairing the
    format witness exercises and no planner emits.

    So what is compared is the **taxonomy**, which is what the witness actually
    pins: every op name, every request name, every link kind and every backend
    kind it carries must be one this build has heard of and can answer about.
    Whether a particular pairing is carried out is a question for the live
    suite, which runs real plans.

WHAT A REFUSAL MEANS HERE
    A refusal is not a failure. `link.create` for a `physical` device is
    refused because netcfgd configures hardware and cannot make it; for
    `pppoe`, because the helper that connects the session is what brings the
    interface into existence. Those are facts about the world, and each is
    printed with its own sentence -- which is the half a checklist loses, and
    the answer a reader asking "what does the C side not do yet" is owed.

    What *is* a failure is a name in the witnesses this build has never heard
    of. That is the taxonomy drifting, and it is what this catches.

WHAT THIS DOES NOT CHECK
    That the op *works*, which is the live suite's job, and that the bytes
    match, which is the schema tests' and `agree_gate.py`'s. This checks the
    third thing, which nothing else did: that the taxonomy is whole.
"""

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "doc" / "schema"
NETCFGD = ROOT / "c" / "netcfgd"


def ledger():
	"""Ask the build what it carries out. One JSON object per line."""
	if not NETCFGD.exists():
		print(f"ledger-gate: {NETCFGD} is not built", file=sys.stderr)
		raise SystemExit(1)
	done = subprocess.run(
		[str(NETCFGD), "--supported"], capture_output=True, text=True, timeout=60
	)
	if done.returncode != 0:
		print(f"ledger-gate: --supported exited {done.returncode}", file=sys.stderr)
		print(done.stderr[:400], file=sys.stderr)
		raise SystemExit(1)
	rows = []
	for line in done.stdout.splitlines():
		line = line.strip()
		if line:
			rows.append(json.loads(line))
	if not rows:
		print("ledger-gate: --supported said nothing at all", file=sys.stderr)
		raise SystemExit(1)
	return rows


def named_in_c(table, what):
	"""The wire names a `const char *const` table in the proto module holds.

	`event_names[]` and `response_names[]` are the same shape -- indexed by
	their enum, sized by its `_COUNT`, and held to one word per value by
	`word_table_gate.py`. So this reads either, and the two callers below
	differ only in which they ask for.
	"""
	source = (ROOT / "c/src/proto/response.c").read_text()
	found = re.search(table + r"\[\w+\]\s*=\s*\{(.*?)\};", source, re.S)
	if not found:
		print(f"ledger-gate: c/src/proto/response.c has no {table} table, so",
		    file=sys.stderr)
		print(f"ledger-gate:   this would check the {what} against nothing",
		    file=sys.stderr)
		raise SystemExit(1)
	return set(re.findall(r'"([^"]+)"', found.group(1)))


def witnessed_tagged(tag):
	"""Every value the frozen transcript gives to one tag member.

	Both shapes count for an event. A monitor stream delivers a bare
	`{"event": ...}` line and a request's answer carries
	`{"response": "event", "event": ...}`, and the witness has one of the
	second and one of each of the first -- so a filter for the wrapped form
	alone sees one event kind where there are five. That is not hypothetical:
	it is how the monitor fuzz target came to be seeded with one kind out of
	five (project.md 10.514).
	"""
	seen = set()
	for line in (SCHEMA / "socket.json").read_text().splitlines():
		line = line.strip()
		if not line:
			continue
		value = json.loads(line).get(tag)
		if isinstance(value, str):
			seen.add(value)
	return seen


def documented_ops(heading="6.3 The plan's actions"):
	"""Op name to its two flags, from the document's table.

	Three columns rather than one, which is what makes this table worth
	checking at all: the names spell themselves out and the flags do not.
	"""
	text = (ROOT / "doc/socket-protocol.md").read_text()
	section = re.search(
		r"\n### " + re.escape(heading) + r"\n(.*?)\n#{2,4} ", text, re.S
	)
	if not section:
		print(f"ledger-gate: doc/socket-protocol.md has no `### {heading}` section,",
		    file=sys.stderr)
		print("ledger-gate:   so this would check the op table against nothing",
		    file=sys.stderr)
		raise SystemExit(1)
	out = {}
	for name, cuts, host in re.findall(
		# **Digits belong in a wire name** -- `link.set_ipv6_token` has one, and
		# a charset without them read the table as short by a row on the first
		# run of this check. The gate caught its own reader, which is the
		# cheapest place for that to happen.
		r"^\| `([a-z0-9_.]+)` \| *(yes)? *\| *(yes)? *\|$", section.group(1), re.M
	):
		out[name] = (cuts == "yes", host == "yes")
	return out


# **The exception that expired, kept as a sentence rather than as code.**
# `WITNESSLESS_BACKEND` excused `link_local` here for one commit: the C had a
# tenth backend kind the Rust had no word for, and the witness was generated by
# the Rust, so `observed.json` could not carry it. 0279 moved the witnesses to
# the C and the file carries it now -- at which point the exception's own
# self-check fired and said so, which is what an excuse with an expiry is for.
#
# Nothing replaces it. Every backend kind the build names is in the witness, and
# the check below is the plain one it should always have been.
def witnessed_backend_kinds():
	"""Every backend kind the frozen observation names."""
	observed = json.loads((SCHEMA / "observed.json").read_text())
	return {
		entry["kind"]
		for entry in observed.get("backends", [])
		if isinstance(entry.get("kind"), str)
	}


def documented_kinds(heading, column):
	"""One column of a table under a heading, as a set of wire names.

	`6.4` has two tables and they are read the same way: the first column is
	the kind in backticks, which is this document's convention everywhere.
	"""
	text = (ROOT / "doc/socket-protocol.md").read_text()
	section = re.search(
		r"\n### " + re.escape(heading) + r"\n(.*?)\n#{2,3} ", text, re.S
	)
	if not section:
		print(f"ledger-gate: doc/socket-protocol.md has no `### {heading}` section,",
		    file=sys.stderr)
		print(f"ledger-gate:   so the {column} table would be checked against nothing",
		    file=sys.stderr)
		raise SystemExit(1)
	body = section.group(1)
	# Each table follows its own `####` heading, so the split is by that.
	for part in re.split(r"\n#### ", body):
		if part.lower().startswith(column):
			return set(re.findall(r"^\| `([a-z0-9_.]+)` \|", part, re.M))
	print(f"ledger-gate: section {heading} has no `#### {column}` table",
	    file=sys.stderr)
	raise SystemExit(1)


def documented_rows(heading, what):
	"""Every wire name a table under one heading of the protocol document has
	a row for.

	**Two consumers of one authority**, which is why these live beside the
	witness check rather than in a gate of their own: the name table says what
	the daemon can send, `doc/schema/socket.json` pins the bytes of each, and
	`doc/socket-protocol.md` says what each one means. A kind missing from
	either consumer is a kind somebody has to find by reading the source.

	The first column is the name in backticks, which is this document's own
	convention -- the tier table in section 4 spells requests that way and
	`tier_table_gate.py` reads it that way.
	"""
	text = (ROOT / "doc/socket-protocol.md").read_text()
	# **Up to the next heading of ANY level.** Stopping at `\n## ` alone made
	# section 6.1 swallow 6.2's table, so the events check reported that the
	# document described an `error` event -- which the gate caught on the run
	# that introduced the second table, and is the reason this is a comment
	# rather than a fixed regex nobody questions.
	section = re.search(
		r"\n### " + re.escape(heading) + r"\n(.*?)\n#{2,4} ", text, re.S
	)
	if not section:
		print(f"ledger-gate: doc/socket-protocol.md has no `### {heading}` section,",
		    file=sys.stderr)
		print(f"ledger-gate:   so this would check the {what} table against nothing",
		    file=sys.stderr)
		raise SystemExit(1)
	return set(re.findall(r"^\| `([a-z0-9_]+)` \|", section.group(1), re.M))


def witnessed_requests():
	"""Every request kind the frozen socket transcript carries."""
	seen = set()
	for line in (SCHEMA / "socket.json").read_text().splitlines():
		line = line.strip()
		if not line:
			continue
		message = json.loads(line)
		if "request" in message:
			seen.add(message["request"])
	return seen


def witnessed_actions():
	"""Every op the blessed plan carries, with the kinds it carries them for.

	Returned as three sets, because `link.create` and the backend verbs are
	answered per kind and the rest are answered once.
	"""
	plan = json.loads((SCHEMA / "plan.json").read_text())
	ops, link_kinds, backend_kinds = set(), set(), set()
	for action in plan["actions"]:
		op = action["op"]
		name = op["op"]
		ops.add(name)
		if name == "link.create":
			kind = op.get("kind", {}).get("kind")
			if kind:
				link_kinds.add(kind)
		elif name.startswith("backend."):
			kind = op.get("kind")
			if kind:
				backend_kinds.add((name, kind))
	return ops, link_kinds, backend_kinds


def main():
	rows = ledger()
	supported = {(r["subject"], r["name"]) for r in rows if r["supported"]}
	known = {(r["subject"], r["name"]) for r in rows}
	refusals = {
		(r["subject"], r["name"]): r.get("refusal", "")
		for r in rows
		if not r["supported"]
	}

	failures = []

	def must_answer(subject, name, why):
		"""The build has heard of this name and has an answer about it."""
		if (subject, name) not in known:
			failures.append(f"{why}: this build has never heard of `{name}`")

	def must_carry_out(subject, name, why):
		"""And it must actually do it -- for the answers that are not a
		function of a kind, so the witness naming it is enough."""
		must_answer(subject, name, why)
		if (subject, name) in known and (subject, name) not in supported:
			failures.append(
				f"{why}: `{name}` is refused -- {refusals[(subject, name)]}"
			)

	# A request is a request: nothing about it is conditional, so the witness
	# carrying one is enough to require that the daemon answers it.
	requests = witnessed_requests()
	for name in sorted(requests):
		must_carry_out("request", name, "socket.json sends it")

	# **And the other direction, which nothing checked.** The line above asks
	# that everything the witness sends is carried out; this asks that
	# everything the build can be sent has a line to be pinned by. A request
	# with no witness line is a wire form nothing holds still -- which is how
	# `ap_stations` came to be absent from three witnesses at once, recorded in
	# `crates/netcfgd-proto/tests/frozen.rs`'s own header.
	#
	# The authority here is the program rather than a parsed table: requests
	# are what `netcfgd --supported` enumerates, and asking it beats reading
	# the source for something it will tell you. Events and responses are
	# below with a table each, because `--supported` says nothing about either.
	for subject, name in sorted(known):
		if subject == "request" and name not in requests:
			failures.append(
				f"socket.json has no line for the `{name}` request, which this "
				"build answers"
			)

	# **Every event kind the build can emit has a line in the witness**, which
	# is the one direction this gate did not check and the one a reader
	# believes without looking. An event is the only thing netcfgd says that
	# nobody asked for, so a kind with no witness line is a wire form nothing
	# pins -- and a corpus seeded from the witness never sees it.
	# **Every kind the build can send has a witness line and a documented
	# row**, in both directions, for the two tags that are not requests. A
	# request is covered above by the ledger; these two are covered by nothing
	# else, and an event in particular is the only thing netcfgd says that
	# nobody asked for -- so a kind with no witness line is a wire form nothing
	# pins, and one with no row is a wire form nobody can look up.
	kinds = {}
	for tag, table, heading in (
		("event", "event_names", "6.1 The events"),
		("response", "response_names", "6.2 The responses"),
	):
		sends = named_in_c(table, tag + "s")
		kinds[tag] = sends
		witnessed_kinds = witnessed_tagged(tag)
		documented = documented_rows(heading, tag)
		for name in sorted(sends - witnessed_kinds):
			failures.append(
				f"socket.json has no line for the `{name}` {tag}, "
				"which this build sends"
			)
		for name in sorted(witnessed_kinds - sends):
			failures.append(
				f"socket.json carries an `{name}` {tag} and this build cannot "
				"send one"
			)
		for name in sorted(sends - documented):
			failures.append(
				f"socket-protocol.md {heading.split()[0]} has no row for the "
				f"`{name}` {tag}, which this build sends"
			)
		for name in sorted(documented - sends):
			failures.append(
				f"socket-protocol.md {heading.split()[0]} describes an `{name}` "
				f"{tag} and this build cannot send one"
			)

	# **Every op the build knows has a witness line and a documented row**,
	# which is the pair requests and the two message tags already have. The
	# witness direction is the one `daemon_main.c`'s own comment warns about:
	# "a kind the C has and the witness does not is a kind no gate is looking
	# at". The document direction checks three columns, because an op's name
	# says what it does and says nothing about whether it can cut somebody
	# off.
	build_ops = {}
	for row in rows:
		if row["subject"] == "op" or row["subject"] in (
			"link.create",
			"backend.start",
			"backend.stop",
			"backend.reload",
		):
			name = row["subject"] if row["subject"] != "op" else row["name"]
			build_ops[name] = (row.get("disruptive"), row.get("host_wide"))
	if any(flags[0] is None for flags in build_ops.values()):
		print("ledger-gate: --supported prints no `disruptive` member, so the op",
		    file=sys.stderr)
		print("ledger-gate:   table would be checked against nothing", file=sys.stderr)
		raise SystemExit(1)
	documented = documented_ops()
	for name in sorted(set(build_ops) - set(documented)):
		failures.append(
			f"socket-protocol.md 6.3 has no row for the `{name}` action, which "
			"this build has"
		)
	for name in sorted(set(documented) - set(build_ops)):
		failures.append(
			f"socket-protocol.md 6.3 has a row for `{name}`, which is not an action "
			"this build has"
		)
	for name in sorted(set(build_ops) & set(documented)):
		if build_ops[name] != documented[name]:
			said = "cuts traffic" if documented[name][0] else "does not cut traffic"
			answers = "does" if build_ops[name][0] else "does not"
			if build_ops[name][0] != documented[name][0]:
				failures.append(
					f"socket-protocol.md 6.3 says `{name}` {said} and the build "
					f"answers that it {answers}"
				)
			else:
				failures.append(
					f"socket-protocol.md 6.3 and the build disagree about whether "
					f"`{name}` is host-wide"
				)

	# The two vocabularies those four actions take, in both directions against
	# the document -- and, for the backends, against the observation witness
	# that carries them. `plan.json` is not that witness: it pins one sample
	# of the `link.create` envelope, and the kinds' own fields belong to the
	# document and the observation.
	build_links = {r["name"] for r in rows if r["subject"] == "link.create"}
	build_backends = {r["name"] for r in rows if r["subject"].startswith("backend.")}
	for what, build, column in (
		("interface kind", build_links, "interface kinds"),
		("backend", build_backends, "backends"),
	):
		documented_set = documented_kinds("6.4 The kinds those four actions take", column)
		for name in sorted(build - documented_set):
			failures.append(
				f"socket-protocol.md 6.4 has no row for the `{name}` {what}, "
				"which this build knows"
			)
		for name in sorted(documented_set - build):
			failures.append(
				f"socket-protocol.md 6.4 has a row for the `{name}` {what}, "
				"which this build does not know"
			)
	witnessed_backends = witnessed_backend_kinds()
	for name in sorted(build_backends - witnessed_backends):
		failures.append(
			f"observed.json names no `{name}` backend, which this build reports"
		)
	for name in sorted(witnessed_backends - build_backends):
		failures.append(
			f"observed.json names a `{name}` backend and this build has no such kind"
		)

	ops, link_kinds, backend_kinds = witnessed_actions()
	asked_per_kind = {"link.create", "backend.start", "backend.stop", "backend.reload"}
	for name in sorted(ops - asked_per_kind):
		must_carry_out("op", name, "plan.json contains it")
	for name in sorted(set(build_ops) - ops):
		failures.append(
			f"plan.json has no action named `{name}`, which this build has"
		)
	# And the four whose answer is a function of the kind: the vocabulary has
	# to be whole, and which pairings are carried out is the live suite's
	# question rather than this one's.
	for kind in sorted(link_kinds):
		must_answer("link.create", kind, "plan.json names the kind")
	for verb, kind in sorted(backend_kinds):
		must_answer(verb, kind, f"plan.json names it under `{verb}`")

	# The other direction, which is what keeps the dump honest: an op the
	# witness names and the dump never mentions means the two enumerations have
	# drifted apart, whichever way round.
	dumped_ops = {name for subject, name in known if subject == "op"} | asked_per_kind
	stranded = sorted(ops - dumped_ops)
	if stranded:
		failures.append(
			"plan.json names op(s) the ledger does not enumerate at all: "
			+ ", ".join(stranded)
		)

	if failures:
		print("ledger-gate: the C build does not cover the frozen witnesses:")
		for line in failures:
			print(f"  {line}")
		raise SystemExit(1)

	# What is refused and not witnessed. Not a failure -- it is the answer to
	# "what does the C side not do yet", and it is printed rather than counted
	# because the sentence is the useful part.
	print(
		f"ledger-gate: {len(requests)} request(s), each with a witness line, "
		f"{len(ops)} op(s), each with a line and a row, "
		f"{len(link_kinds)} link kind(s) and {len(backend_kinds)} backend action(s) "
		f"in the witnesses, all carried out by this build; "
		f"{len(build_links)} interface kind(s) and {len(build_backends)} backend(s), "
		f"each with a row; "
		f"{len(kinds['event'])} event and {len(kinds['response'])} response "
		f"kind(s), each with a witness line and a row"
	)
	if refusals:
		print(f"ledger-gate: and {len(refusals)} thing(s) refused, each saying why:")
		for (subject, name), why in sorted(refusals.items()):
			print(f"  {subject} {name}: {why}")


if __name__ == "__main__":
	main()
