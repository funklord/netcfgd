# 0130: A radio gets a supplicant before it has anything to join

Status: accepted
Date: 2026-08-21
Milestone: M8, found in use rather than in a test

Reverses a stated property of the planner: a managed radio with no `network`
block used to get no supplicant, and `crates/netcfgd-plan/tests/fixtures.rs`
asserted it by name.

## Context

The rule read well. A supplicant handed nothing is a process running for no
reason, and it makes `ncfg status` report a backend nothing asked for. Both
those sentences are true.

They are also only half the question, because **scanning needs a supplicant
too**. netcfgd drives `wpa_supplicant` over its per-interface control socket,
and that socket exists only while a supplicant has that interface. So the rule
closed a loop:

- no supplicant without a `network` block,
- no scan without a supplicant,
- no `network` block without a scan to find the network.

A machine whose wifi already worked went on working. A machine starting from
nothing could not start, and the only way out was to hand-write a `network`
block for a network you could not yet look at -- with the SSID typed from
memory.

## Why nobody noticed

**NetworkManager was running.** NM adds the interface to the system
`wpa_supplicant`, which creates `/run/wpa_supplicant/<iface>`, so netcfgd
scanned perfectly well through a supplicant it had not started, did not manage,
and had no opinion about. Every scan in normal use was borrowing NM's work.

It surfaced the first time somebody stopped NM -- which is the thing this
project exists to make possible ([0125](0125-displacing-networkmanager-is-a-runtime-switch.md))
-- and found that scanning stopped with it. The report was "I stopped NM and
after that I couldn't scan any networks", and the machine it came from had a
config directory holding exactly one drop-in: a `global { control { .. } }`
block written by `ncfg control set`. No `device` block, no `network` block, and
therefore no supplicant netcfgd would ever start.

**This is the second bootstrap deadlock of the same shape.** The first was
`ncfg control set` refusing to run because no configuration existed, on an
install that deliberately ships none. Both are a first step that requires its
own result.

## Decision

**A declared, managed radio gets a supplicant whether or not the document has
anything to join.** The condition is the `device` block alone.

The declaration is what carries it. An operator who wrote `wifi { }` for a
radio has said netcfgd manages that radio, and managing a radio includes being
able to see what is in range. A supplicant holding no networks is what 0015
already builds on purpose -- it starts empty and is given networks afterwards
-- so "running for no reason" was never quite the right description: it is
running because somebody said this radio is netcfgd's.

**Both predicates moved together, and that is not incidental.** The planner
decides to start a supplicant and `supplicant_wanted` decides whether a running
one is wanted; they are deliberately the same test, and its own comment warns
that disagreeing "makes netcfgd start a supplicant and kill it on the next
reconcile, forever". Changing one would have produced exactly that flapping,
which the idempotence gate exists to catch.

## What this does not decide

**Whether an undeclared radio should get one.** The machine that produced the
report has no `device` block at all, so this decision does not fix it on its
own -- it fixes the state one step later, where somebody has declared the radio
and has not yet joined anything. Making netcfgd claim a wireless interface
nobody's configuration mentions is a larger question: it is netcfgd taking
ownership of hardware by default, which is what displacing NetworkManager
implies and is not a thing to start doing as a side effect of a bug report.
It belongs to the copyright holder.

**Whether scanning should need a supplicant at all.**
[0016](0016-which-half-of-a-supplicant-could-ever-be-ours.md) already records
scanning as the one part of a supplicant that could be netcfgd's --
`NL80211_CMD_TRIGGER_SCAN` and parsing the results, marked low difficulty. That
would make a scan an observation like every other one netcfgd makes over
netlink, needing no process and no ownership, and it would dissolve this
question rather than answer it. It is also a real piece of work: the security
flags a scan reports come from parsing RSN and WPA information elements, which
is where `secured`, `enterprise` and the fast-transition flag all come from
today, free, from the supplicant.

## Consequences

**A supplicant appears on a declared radio earlier than it used to**, and
`ncfg status` reports it. That is the visible cost and it is the intended one:
the backend is running because the document declared the radio.

**The scan failure explains itself now.** The control socket's own message --
"no control socket at ...: is wpa_supplicant running?" -- is true, unhelpful,
and points at the wrong program. The question is not whether somebody started a
supplicant, it is why netcfgd did not, and only the document knows. A radio
with no `wifi` policy is now told so, with the block to add; one marked
`managed = false` is told that instead.
