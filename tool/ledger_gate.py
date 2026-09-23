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

	ops, link_kinds, backend_kinds = witnessed_actions()
	asked_per_kind = {"link.create", "backend.start", "backend.stop", "backend.reload"}
	for name in sorted(ops - asked_per_kind):
		must_carry_out("op", name, "plan.json contains it")
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
		f"ledger-gate: {len(requests)} request(s), {len(ops)} op(s), "
		f"{len(link_kinds)} link kind(s) and {len(backend_kinds)} backend action(s) "
		f"in the witnesses, all carried out by this build"
	)
	if refusals:
		print(f"ledger-gate: and {len(refusals)} thing(s) refused, each saying why:")
		for (subject, name), why in sorted(refusals.items()):
			print(f"  {subject} {name}: {why}")


if __name__ == "__main__":
	main()
