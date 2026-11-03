# 0312: the control vocabulary is one fuzznet procedure, and a remote change carries its window

Status: accepted
Date: 2026-11-03
Milestone: fuzznet integration (project.md 10.688 to 10.692), and 0311's fleet
Builds on: [0311](0311-fuzznet-is-the-store-and-the-estate-is-the-fleet.md), [0309](0309-one-protocol-the-local-socket-is-fuzznets-too.md), 0128's remote tiers

## The question

0311 puts everything internal on fuzznet's protocols and makes the fleet the
estate, an authenticated operator managing every node. 10.688 to 10.692 carried
one verb, `status`, as a fuzznet procedure, paged, with a client on each side.
The control socket has some forty more. Do they each become a procedure, or
does one procedure carry the vocabulary?

## The decision

**One procedure, `ask`, carries a control-socket request**: the same JSON line
the socket reads, as the procedure's arguments after a page offset,
`call ask FROM REQUEST` (fuzznet's sec 853). The daemon answers it the way the
socket does, with the same functions and in the same order:

1. the line parsed by the socket's own reader (`proto.h`);
2. judged by `ncfg_authz_permitted`, the one place netcfgd decides who may do
   what. A caller on this machine is judged by the `control` tiers on the peer
   fuzznet read, as on the socket (10.683). An operator of the estate is judged
   by the node's `remote` block, 0128's tiers, which is the per-node, granular
   configuration the holder asked for (10.685);
3. answered by `ncfg_main_answer`, the socket's dispatcher, on the loop's
   thread.

The answer is the socket's JSON, paged as `status` is (`ok TOTAL FROM COUNT
DIGEST`, 10.689), because fuzznet caps an answer this side does not choose.

**Rejected: a procedure per verb.** That is forty names to keep in step with
the socket's vocabulary, each with its own argument grammar. It is a second
vocabulary, which 0263 spends its length refusing. `status` stays, because two
clients and a test already use it, and it is the one read worth having without
JSON on the caller's side.

## What a page may repeat

**Every answer is made at FROM 0 and kept**, for that caller, until it has
been read to the end or a minute has passed. Later pages are cut from the
copy, so a `plan` is computed once rather than once a page. Where no copy
stands behind a later page, **only a read is made again**: an `observe`-tier
request (`ncfg_tier_of`), the digest keeping pages of two answers apart
(10.689). Anything else is refused, and never run a second time to make a
page.

**Not the order class of 10.351**, which looked like the right test and is
not. That table answers whether a lost order may be retried, and `apply` is
idempotent there, rightly: netcfgd is declarative, and applying an end state
twice converges to it once. But running `apply` again to produce page two
would open a second confirm window. A page is no reason for an effect to
happen again, so the criterion is whether the request has one.

Kept rather than refused when it does not fit, because whether an answer fits
is known only after the change has run. `apply` answers with its journal,
which on a large change is many pages. Refusing it then would leave a change
made whose result the operator cannot read.

## A remote change carries its window

**`apply` from an operator of the estate needs a confirm window**, and is
refused without one. Commit-confirm (M2) exists so that a change which cuts
the caller off undoes itself. Across the estate that is the normal way to
fail: an operator who mis-states a route on a node has no other way back to
it. On this machine the same request without a window stays legal, because
there the person is at the console.

Refused rather than given a default window, because the operator should know
the change is provisional. A default they never asked for would make a
`confirm` they never sent look like a bug.

## What it does not decide

- **Partial authority** (an operator who may do some things on some nodes,
  beyond the `remote` block's tiers) remains beyond the simple case, as 0311
  left it.
- **The order queue** of 10.350 is a different path: work that whichever
  node is responsible takes, chosen by an assignment function, where this is
  one operator asking one named node. The two do not share a rule: the
  queue retries by 10.351's order class, and a page here repeats only a read.
- **Streams** (`monitor`) are not requests and are not carried. fuzznet's
  `get events` is the estate's stream, and netcfgd publishes into it.
