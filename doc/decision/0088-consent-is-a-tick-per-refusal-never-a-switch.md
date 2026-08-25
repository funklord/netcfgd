# 0088: consent is a tick per refusal, never a switch

Status: accepted
Date: 2026-08-04
Milestone: M8, the gap the GUI's first commit recorded

## Context

`gui/project.md`'s order-of-work entry ended with what the window still could not
do, and this was first on the list:

> **no consent**, so a refusal is an absolute stop; the remedy is shown as
> something to run elsewhere.

The daemon refuses two things and says how to proceed with each: a guard
protecting an interface (`--allow-disruption IFACE`) and a credential netcfgd
would walk away from (`--strand-credentials DEV`). `ncfg_client_apply` took only
a confirm window, so the GUI showed the daemon's remedy verbatim as a command
for the operator to type into a terminal. That is a client telling somebody to
go and use a different client.

## Decision

**A checkbox per refused thing, each naming the one interface or device it
covers.** Never one control marked "override refusals".

The wire already has the right shape and the reason is in `ncfg`'s own help:
both flags are repeatable and "deliberately not a blanket --force". A single
switch would be that blanket with a friendlier label, and the two lists stay
apart for the reason the daemon keeps them apart -- an operator who accepted a
brief outage on one interface has not agreed to leave a private key on another.

Nothing is pre-ticked. A refusal is the daemon saying no; a dialog that opened
with the override already on would be answering on the operator's behalf.

`ncfg_consent_t` is a separate argument to `ncfg_client_apply` rather than a
field on the plan, because it is the operator's *answer* and the plan is the
daemon's *question*. Folding them into one value would blur which of the two
said what.

## What the probe found

The dialog is driven headless by a throwaway probe: build it against a real
daemon with a guarded interface, find the consent boxes, tick one, click Apply,
then ask the kernel whether the refused action happened.

It failed on its first run, and the bug was mine and one line old. **A guard
refusal usually means the plan has no actions at all** -- the guard stops the
ones it covers, so a plan whose only content is a refusal has an empty action
list. The dialog read "nothing to do" off `actions.isEmpty()` and disabled
Apply, which is exactly the plan consent exists for. Reading "is there anything
to do" off the actions alone is wrong the moment a refusal can be consented to.

`ncfg plan`'s summary said the same thing in words -- "apply is blocked until the
refusals are resolved" -- and a screen saying *blocked* beside a checkbox that
unblocks it is a screen arguing with itself. It says "these do not run unless
consented to" now.

Neither would have been caught by the headless run that existed: opening the
window proves the window opens, and the whole of this change is what one
particular click sends.

## The gates

**The exact bytes**, in `client/tests/`. This is the one request where being
wrong is worse than failing: a client that put an interface in the wrong list
would have the operator agreeing to leave a private key behind when they agreed
to an outage, and the daemon would do it. Three checks -- both lists together, a
list nobody filled in being *absent* rather than an empty array, and a name with
a quote in it escaped rather than interpolated.

**The dialog, clicked without a person**, against a real daemon under
`unshare -rn`: the refusal becomes a box naming the interface, Apply is offered,
the box is not ticked to begin with, and after one click the guarded interface is
down. Passing an empty consent instead of the ticked one leaves it up, which is
the break.

## What is still not there

The operator's **tier** is still not asked for, so the window offers an apply an
`observe` connection will be refused (`gui/project.md` sec 4 wants otherwise).
That needs the daemon to say which tier a peer holds, which it currently only
does by refusing something -- a request nobody can send, from the other side, and
worth its own piece of work rather than a guess here.
