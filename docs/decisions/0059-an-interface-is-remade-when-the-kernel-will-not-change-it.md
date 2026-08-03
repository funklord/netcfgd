# 0059: An interface is remade when the kernel will not change it

Status: accepted; this closes 0057's list
Date: 2026-08-03
Milestone: the last shape on [0057](0057-a-link-kind-is-compared-like-a-daemon.md)'s list

## Context

0057 and [0058](0058-a-change-carries-the-whole-nest.md) closed six link kinds by
comparing what the kernel holds against what the document says and sending the
difference. One kind was left twice, deliberately, because it is not that shape:

```
interface work-net { vlan { parent = "base0"; id = 42 } }   # apply
# edit the id to 43
$ ip link set work-net type vlan id 43
$ ip -d link show work-net
vlan protocol 802.1Q id 42
```

**The kernel takes the request and changes nothing.** `vlan_changelink` handles
the flags and the priority maps and ignores the id; the same is true of the tag
protocol, measured separately because two attributes being ignored is two facts.
Of the four answers the kernel gives -- takes it, refuses it loudly, refuses it
only in some directions, accepts and ignores -- this is the worst, because a
planner that emits a set reports a change that never happened and goes on
reporting it.

**And there was a second customer for the answer.** Measured while bounding
0058: an interface that exists as an entirely *different kind* was not compared
at all. A document declaring `mixup` as a macvlan, against a `mixup` that is a
dummy, planned a `link.up` and nothing else -- netcfgd brought somebody else's
device up and called the network configured.

## Decision

**Delete it and make it again**, as one pass that runs before the creation pass:

1. `plan_recreation` finds every interface the document describes that exists
   with an identity the kernel will not change -- a VLAN whose id or tag protocol
   differs, or a link whose kernel kind is not the one the document asks for.
2. For each, it stops what netcfgd is running on that interface, then emits
   `link.delete`.
3. It returns their names, and the plan continues against **an observation with
   those interfaces, and everything the kernel holds on them, taken out**.

The third step is the whole design. Every pass below then plans for a remade
interface exactly as it plans for one that was never there: the creation pass
makes it, the addressing pass puts its addresses back, the routing pass its
routes, and the backend pass restarts its client. None of them knows this
happened, and a pass added later gets it right without being told.

The alternative -- a flag threaded through eleven passes, each deciding what a
"being replaced" interface means for it -- is the same information written eleven
times.

## Only a link netcfgd created

This is the one place in the planner that throws an interface away. Everything
else adds or corrects.

So the ownership rule that governs addresses and routes governs this too, and it
is checked before anything is emitted: a link netcfgd has no record of creating
gets a sentence naming what differs, what correcting it would cost, and that
netcfgd will not do it. `ncfg apply` leaves it alone.

That leaves a real gap and it is the right gap: a VLAN somebody else built with
the wrong id stays wrong until an operator removes it or adopts it. The
alternative is a config file that deletes interfaces netcfgd never made, which is
not a tool anybody should point at a running machine.

## What the observation surgery has to take out

Not just the link. Each of these was a defect the first version had, or would
have had:

- **Its addresses and routes**, or the passes that would put them back see them
  already present and plan nothing. The interface comes back bare and the plan
  says there was nothing to do.
- **Its backends**, so the client is started again -- with a `backend.stop`
  emitted beside the delete, because a client bound to an interface that is about
  to vanish would otherwise be left holding a name that comes back as a different
  device, while netcfgd's record still says it runs.
- **The `master` of every link enslaved to it.** A member's `master` field still
  names the bridge that is about to be deleted, so leaving it makes the
  enslavement pass see the membership it wants: the remade bridge comes back
  empty and nothing says so.
- **Its bridge VLANs**, which are keyed by interface *index* -- the one thing
  about a remade interface that does not survive, since the kernel hands out a new
  one.

What is deliberately **not** taken out is the three `*_applied` lists. Those
record that netcfgd once set a qdisc, a redirect or a sysctl on an interface,
which is still true and is what makes deleting the setting from the document mean
something. What the kernel held is what went away with the link.

The filter lists every field of `Observed` rather than filling the rest in with
`..observed.clone()`, so a new per-interface field stops it compiling instead of
being carried through stale.

## A guard refuses the whole thing

`link.delete` is disruptive, so a guarded interface (0010) refuses it, and the
`backend.stop` beside it is disruptive too -- both go through the one function
that decides, so both are refused together and the interface is left entirely
alone rather than half torn down.

**And a refused delete must not leave the rest of the plan written as though it
happened.** The name only joins the returned list if the delete was actually
emitted; otherwise the observation is not filtered, so nothing plans a
`link.create` for an interface that still exists.

## Consequences

- Editing a VLAN's id or tag protocol under a name that does not encode it now
  does something. Under a name that does -- `br0.42` to `br0.43` -- it always
  did: that is a different interface, so it was already a create and a delete.
- An interface that exists as the wrong kind is corrected rather than brought up.
- The plan says what it is doing: `link.delete work-net`, reason
  `vlan.id: 43 (was 42)`, then the create and everything that follows. It is the
  most destructive sequence netcfgd emits and it is entirely visible before it
  runs, which is what `ncfg plan` is for.
- `link.delete` is offered no inverse here, and that is deliberate: the create
  that follows is in the same plan, but commit-confirm cannot put back an
  interface's addresses and routes from the observation. Claiming otherwise would
  make a revert lie.
- The fixture harness had to become more faithful. Its simulated `link.create`
  produced an empty link with the right name, so a recreation loop would have
  looked converged there -- the second plan would find nothing to compare and
  call that agreement. It now fills in what the kernel would report about the
  device that was just made, which makes every comparison 0057, 0058 and 0059
  added testable without a kernel.
- `+12 KB` installed, with a line in `size-budget.txt` saying what it bought.
- The observed schema gains a struct; its witness moved. A minor addition.

## What is left

**A macvlan's parent**, which the kernel also accepts and ignores. It is the same
answer and the same remedy, and it is not done here: nothing has asked for it,
and the fix is only worth having when somebody moves a macvlan between NICs. It
is written down in project.md rather than pretended away.
