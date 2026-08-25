# 0092: a client is told what it may do

Status: accepted
Date: 2026-08-04
Milestone: M8, the gap [0088](0088-consent-is-a-tick-per-refusal-never-a-switch.md) recorded

## Context

`gui/project.md` section 4 lists two things a client must show rather than
infer. The first — which machine this is — has been on screen since the first
commit. The second was not possible:

> **which tier the operator holds** — a connection with `observe` should not
> offer an apply button that will be refused.

There was no way to ask. The daemon works out which tier a request needs and
whether the peer satisfies it, per request, and says so only by refusing one. So
the only way for a client to learn what it may do was to try it — which means a
window offers an apply button and the first thing that happens when somebody
presses it is a no.

## Decision

**`hello` reports the tiers this connection satisfies.**

Not "the highest tier". 0013's tiers are three separate group memberships, not a
ladder: a machine may grant `admin` to a group somebody is in and `wifi` to one
they are not. Reporting a maximum, or filling in everything below it, would tell
an operator they can do something they cannot.

`hello` because it is the request every client makes first and the one somebody
with no permissions can still make — it is `Tier::Observe`, which the desktop
case opens to anybody. Peer-specific, not machine-specific: two connections from
different users get different answers, which is the whole point of asking.

Constraint 6 is satisfied on its own terms rather than by appeal to the GUI: the
daemon already computes this for every request, and an operator running `ncfg`
has the same question. What this adds is a way to ask it once instead of
learning it by being refused.

Additive — `tiers` defaults to empty when absent. A **minor** bump.

## What "could not tell" means

A daemon older than this field answers nothing, and the C layer reports that as
*success with nothing granted* rather than as failure. The caller decides, and
the window's choice is stated in its own code: **an unanswered handshake leaves
the button enabled.**

That is the safe direction here and it is worth saying why, because the instinct
runs the other way. Being refused produces a sentence naming the tier that was
needed and what to change (0013), which this client already shows. A greyed-out
button produces silence. Guessing "not allowed" against a daemon that would have
answered would make the client useless on it, and would do so quietly.

## The gates

**The answer agrees with the refusal.** `granted` is checked against `check`
itself, for every tier and for two peers — one request per tier, taken through
the same authorisation a real request goes through. Two answers to "may I" is
exactly what this decision would otherwise create: a list that said more would
put a button on a screen that fails when pressed, and one that said less would
hide something the operator is allowed to do.

**The tiers are not a ladder**, with a policy where the middle one is out of
reach and the one "above" it is not. Breaking `granted` to stop at the first
tier it cannot satisfy turns that red; breaking it to grant everything turns
both red.

**In the witness**, `["observe","admin"]` — deliberately not a prefix, so a
sample holding one could not pin a shape that happens to look like a ladder.

**In `client/`**, three cases: a daemon that names tiers, one that names none,
and one that refuses. The middle is the one worth having — it is a real daemon,
one version behind.

**Against a real daemon**, both ways round, with the same user and the same
binary: with `admin = "root"` an unprivileged connection is told `["observe"]`,
`reload` is refused naming `admin`, and the window's Apply button is disabled
with that sentence in its tooltip; with `admin = "any"` the same user is told
`["observe","admin"]` and the button is enabled. The policy is the only thing
that changed.

## What this does not do

It does not hide the *plan* or the *devices* tab from a connection holding only
`observe`, and should not: reading is what `observe` is for. What it stops is
offering an action that cannot succeed.

It is asked once, at startup, because peer credentials are fixed when the socket
is opened. A client that re-asked would be implying they might change.
