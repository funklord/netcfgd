# 0139: three kinds of state, and one that must not survive

Status: accepted
Date: 2026-08-25
Milestone: M8; closes the restart-and-crash sequence begun at
[0134](0134-an-unannounced-stop-holds.md)

## Context

Asked directly: is there an intended-state file that can be picked up after a
crash and verified or re-applied on restart?

There is, and answering it properly needed the pieces separated, because
`/run/netcfgd` holds several things that look alike and have opposite rules.
0138 boot-scoped one of them; the question of whether the same applies to the
others is settled here, along with a fourth kind that does not exist in this
tree yet and should have a rule before it does.

## The four kinds

**1. Intended state -- `/etc/netcfgd/*.conf`.** Authoritative by constraint 1,
recompiled at every start. This is the answer to the original question:
netcfgd picks it up after a crash because it never depended on anything else,
and [0132](0132-netcfgd-applies-its-configuration.md)'s reconcile loop is the
"verified or re-applied" half. Nothing in `/run` is consulted to decide what
*should* be true.

**2. A projection of it -- `/run/netcfgd/desired.json` and `desired/*.json`.**
Written by five call sites so that `cat` can answer what netcfgd decided.
**Nothing reads it back, and nothing should.** A reader would make `/run`
authoritative, which is the contradiction constraint 1 exists to prevent and
the same one 0135 rejected `StateDirectory` for. Its absence of a reader is the
design, not a gap.

**3. A claim about objects that exist -- `/run/netcfgd/owned.json`.**
Boot-scoped, per [0138](0138-a-record-outliving-its-boot-is-wrong-not-stale.md):
the objects it names die at a reboot, so a claim that outlives one is not stale
but wrong, and can match something new.

**4. A promise that was never kept -- `/run/netcfgd/confirm.json` and the
last-good document.** Not boot-scoped, and that is the part this record
settles.

## The window does not carry a boot id, and the reason is not consistency

It would be easy to apply 0138 to `confirm.json` on the grounds that both live
in `/run` and both can outlive a boot. That would be wrong, and the difference
is what each file asserts.

**`owned.json` asserts that objects exist and are netcfgd's.** A reboot
destroys the objects, so the assertion becomes false with nothing to signal it.

**`confirm.json` asserts that somebody applied a change and never confirmed
it.** A reboot does not make that false. The operator still did not confirm,
and the configuration they applied is still the one in `/etc` waiting to be
applied again at boot -- so if it is the change that takes the network away,
the reboot has not saved anybody. **Reverting is still the right answer, and
boot-scoping the window would remove the protection exactly where the outage
was worst.**

That the file exists at all is meaningful: `confirm_window` deletes it on
confirmation, so a window present at startup is by construction one that was
never resolved.

`resolve_on_startup` therefore reverts on finding a window at all, without
consulting the deadline, and its own comment carries the argument:

> A daemon that died inside a window cannot have received a confirmation, so
> the window is resolved by reverting whether or not the deadline has passed.
> The alternative -- honouring the remaining time -- assumes the operator is
> still there and still able to reach a socket that has been gone for however
> long the daemon was down, which is exactly the assumption commit-confirm
> exists because you cannot make.

**What was missing was not the code but the evidence.** `confirm.sh` had eight
checks and killed the daemon only in cleanup, so the recovery path for the
recovery path -- the one that runs when something has already gone wrong -- was
covered by reasoning alone. It has five checks now, with `kill -9` rather than a
term so that the daemon gets no chance to tidy up on the way out, and a window
long enough that it cannot expire while the daemon is dead. Without that, the
test could not tell "reverted because a window was found" from "reverted
because it ran out".

The last check is the one that matters most and is easiest to leave out: the
revert must still stand a reconcile later. A daemon that reverted and then
reconciled straight back to the rejected configuration would satisfy every
check before it and undo itself a tick later, which is worse than not reverting
-- the operator watches it work and then watches it fail.

## The fourth kind: state that must not survive at all

**netcfgd has none of this today**, and the rule belongs here because the code
that will have it is designed and not yet written -- the remote protocol with
Monocypher in section 10's M8 row. A rule written after the first ratchet is a
rule written after the first mistake.

The class is state whose *restoration* is the failure: a ratchet, an AEAD nonce
or sequence counter, a session key. For classes 1 to 3 losing state is the
hazard and restoring it is the remedy. **Here that is exactly inverted.**
Losing a ratchet costs a reconnection. Restoring one means a nonce is used
twice under the same key, which for the constructions in question does not
degrade the security, it removes it.

Three rules follow, and the first is the one this tree can already break:

- **It never enters `/run/netcfgd`.** `owned.json` is written `0o666` into a
  directory the unit creates `0755`, so it is world-readable on every machine
  netcfgd is installed on. Constraint 5 says the desired-state *document*
  carries no secret material; **there is no equivalent sentence about the
  runtime record**, and this is it.
- **Boot-scoping is the wrong tool, so do not reach for 0138 here.** A boot id
  makes state die at a reboot. A ratchet must die at *process exit*, which
  happens far more often -- a crash and a restart inside one boot would replay
  it, and the boot id would say everything was fine.
- **Where it cannot live only in memory, it lives in a file unlinked at open**,
  so the state cannot outlive the descriptor holding it. That is the only shape
  that makes "gone when the process is gone" a property of the filesystem
  rather than of cleanup code running.

**And the direction of failure has to be stated per class, not inherited.**
[0134](0134-an-unannounced-stop-holds.md) chose holding for the network because
losing a link is worse than leaving one up. That reasoning does not transfer:
for a ratchet the safe direction is to lose it, and a component that inherits
"hold by default" from the rest of this tree will be wrong in the one place it
matters.

## Consequences

**The answer to the original question is "yes, and it is `/etc`".** Anything
tempted to add a state file so netcfgd can resume after a crash should be read
against constraint 1 first: netcfgd resumes by recompiling, and the only things
`/run` legitimately carries are a claim about existing objects and an
unresolved promise.

**A future component with ephemeral cryptographic state has a rule to meet**
rather than a precedent to copy, and the precedents in this tree are the wrong
ones for it.

## Alternatives considered

**Boot-scope `confirm.json` for consistency with `owned.json`.** Rejected
above: it removes the revert in the case where the operator lost the machine
hardest.

**Have `resolve_on_startup` honour the remaining deadline instead of reverting
outright.** Rejected, and it is not this record's call -- the existing comment
already argues it, and the live test now holds it in place. Recorded here so
that the next person to find it surprising reads the argument before changing
the behaviour.

**Add a reader for `/run/netcfgd/desired.json` so a crash can resume from the
compiled document.** Rejected: it saves a recompile that costs milliseconds and
buys a second authority for what should be true, which is the whole thing
constraint 1 forbids.
