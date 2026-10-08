# 0271: the one-way rule governs adapters, not netcfgd's own scopes

Status: accepted
Date: 2026-09-29
Milestone: M10; the network-wide scope

Decided by the copyright holder. Interprets constraint 6 rather than changing
it: the rule is unaltered and its force against adapters is unaltered with it.

## What this decides

**Constraint 6 governs adapters.** A change justified solely by NetworkManager's
needs, or RESTCONF's, or any other northbound model's, is still refused, and a
concept an adapter wants must still independently be something a local operator
would want in their own config file.

**netcfgd's network-wide scope is not an adapter and is not subject to it.**

## Why it needed deciding at all

The holder has set local and network-wide configuration as two first-class use
cases, both to be met in full (project.md 10.346). A site-scoped concept fails
constraint 6's test by construction: *"this WLAN spans forty access points"* is
not something a single-machine operator wants in their file, and no amount of
design will make it so.

So the literal reading refuses the site model **on principle, while quoting the
rules correctly**. That is the dangerous kind of contradiction -- not an
oversight anybody would notice and route around, but a rule that blocks a
sanctioned feature and can cite itself for doing it. It was recorded as needing
a ruling rather than resolved by whoever noticed, which is
`working-practice.md`'s instruction where a document and an intention
disagree.

## The test, which is whose model a concept comes from

An adapter is **somebody else's design pressing inward**. Constraint 6 exists so
that pressure cannot reshape netcfgd's model, config language or socket API --
and 9.2 of `netcfgd-design.md` is where the discipline is argued.

Local and network-wide are both **netcfgd's own** use cases. Neither is a
projection of another system's model, so neither is what the rule was written
against.

**This is a boundary, not a loophole**, and the distinction is the whole of the
decision's value. A concept does not escape the one-way rule by being described
as network-wide. It escapes only by being netcfgd's own. An adapter that wants a
site concept is an adapter wanting a concept and answers to constraint 6 exactly
as before -- and an adapter is not made into a scope by being given a site's
vocabulary.

## What it does not license

**It does not weaken the rule against adapters**, which is its whole remaining
job and the reason the wording above is narrow.

**It does not settle where the local/network boundary runs.** Which options are
local-only, which network-wide and which meaningful in both is a per-key
judgement across the language, and 10.346 names it as the bulk of the design.
This decision makes that work permissible; it does not do any of it.

**It does not touch constraint 2.** A machine that never joins a network-wide
deployment must still show no site machinery at all -- the filesystem reflects
use, not capability, and that is what keeps the single-machine case whole.

## Where this is written

Constraint 6 in `project.md` section 1 carries the ruling inline, because that
is where a reader meets the rule and forms the wrong reading. This record
carries the reasoning. 10.346 previously said the question was the holder's to
answer and now says it was answered, rather than leaving a reader to find the
open version and believe it.
