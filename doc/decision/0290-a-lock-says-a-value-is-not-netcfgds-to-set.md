# 0290: a lock says a value is not netcfgd's to set

Status: accepted
Date: 2026-10-23
Milestone: M6
Follows: [0002](0002-object-ownership-tagging.md), [0010](0010-interface-guards.md), [0289](0289-guard-generalises-its-subject-and-not-its-predicate.md)

## The unification the holder gave

2026-10-23:

> why we want these locks is basically the same thing, something external has
> been configured, and we need a mechanism to stop netcfgd from changing those
> values.

One reason behind all of it: the operator's vital link, the daemon's claim on
its interface, the rc-script's setting, the NFS root. **Something outside
netcfgd put a value there, and netcfgd must not change it.**

## Which is a question netcfgd does not currently ask

netcfgd has a thorough answer to a *different* question. 0002 tags what it
installs -- routes with protocol 110, links by altname, addresses by recorded
prior state -- and `ownership.c` holds "the three judgements that decide what
netcfgd may delete", with 0002's asymmetry as its reading instruction:
"under-claiming costs a little convenience, over-claiming deletes somebody's
manual change". What netcfgd does not own is **reported, never reconciled
away**.

So:

| question | answered by | how |
|---|---|---|
| may I **remove** this object? | ownership, 0002 | discovered from a tag |
| may I **set** this value? | nothing | -- |

**The second is the hole, and it is not an oversight so much as the cost of
being a desired-state system.** A document that names `mtu = 1500` is an
instruction to make the MTU 1500, whoever set it to 9000 and why. Ownership
cannot help: there is no protocol field on an MTU, a MAC, a sysctl, an offload
flag or a qdisc parameter, so netcfgd cannot tell "9000 because an rc-script
set it" from "9000 because nobody has touched it". The tag answers for objects
it can carry and says nothing about scalars.

**A lock is the declared form of the same fact a tag discovers**: this value is
foreign. 0010 already has that shape for guards -- declared, discovered,
delegated -- so a lock is not a new kind of thing, it is the declaration where
discovery has no instrument.

## What a locked value does, which is mostly already built

A value declared foreign takes the path an untagged object already takes:
**netcfgd reports the difference and does not act.** Drift is shown, the plan
says what it would have done and why it did not, and nothing is written. That
is `reported, never reconciled away` applied to a scalar, and it needs no new
reporting machinery -- only a way to route a value onto that side.

Three consequences worth stating because they are decisions rather than
details:

- **A locked value does not make the document wrong.** The document still says
  what the operator wants; the lock says netcfgd is not the one who may apply
  it. The difference between those two is exactly what a drift report is for,
  and collapsing them -- by deleting the value from the document instead --
  loses the record of intent.
- **A lock is per value, not per interface.** This is where it differs from a
  guard, which refuses the disruptive ops against a subject. Locking an MTU
  must not stop an address being added, and guarding an interface must not be
  the only way to protect its MTU.
- **It composes with the guard rather than replacing it.** A guard answers
  "may I take this link down"; a lock answers "may I write this field". Both
  are refusals, both carry a reason, and both name their consent.

## Enforced at the configuration stage, and removed rather than overridden

The holder, narrowing it:

> so this is at the configuration stage. netcfgd refuses to change this setting
> until the lock is removed.

Both halves are decisions.

**At the configuration stage means the planner refuses, not the executor.**
That is 0010's argument and its reason is worth repeating rather than citing: a
veto at apply time means `ncfg plan` said "will set mtu 1500" and then the MTU
did not change, and "a plan that lies is worse than no plan". So a locked value
appears in the plan as a refusal with its reason -- what netcfgd would have
done, and that it will not -- which is also what makes a lock reviewable before
anything runs and visible to a distributed coordinator reading a node's plan.

**Removed rather than overridden is what makes it stronger than a guard.** A
guard has a per-apply consent: `--allow-disruption <iface>`, a tick per refusal
(0088), granted in the same breath as the change. **A lock has none.** The only
route is to remove the lock, which is a separate change to the configuration --
so changing a locked value takes two deliberate acts and cannot happen in one
pass by accident.

That property is the point, and it is worth more in a distributed design than
on one host: **a document written elsewhere cannot stomp a locked value in a
single sweep.** It would have to carry the lock's removal as well, which is
itself a visible change to the node's configuration -- and 0289's rule applies
to that removal exactly as it applies to any other directive, so the node can
refuse it. A per-apply override would have given a coordinator a way to tick
the box on the node's behalf; not having one is what keeps the node's
declaration the node's.

**What this leaves open is whether removing a lock needs ceremony of its own.**
Two deliberate acts is already the property asked for; requiring confirmation
on the removal as well would be a third. The argument for it is the
distributed case above, and the argument against is that a lock nobody can
remove without a ritual is a lock people stop using. Not decided here.

## What can be locked is a closed set, without a new vocabulary

0289 answered "too general" by keeping the predicate closed. This answers it a
second way, and more cheaply: **the lockable set is the comparable set.**
netcfgd's reconcile loop already enumerates every value it compares between
desired and observed -- addresses, routes, MTU, MAC, master, sysctls, offloads,
qdisc parameters, rules, the nat table. A value netcfgd cannot compare is a
value it cannot change, so there is nothing to lock; a value it can compare is
already named in the model.

So locking needs no subject vocabulary of its own. It needs the identity that
0287 and 0289 both already ask for, and nothing else.

## And this matters more once the config is distributed

While a document is written on the machine it configures, the person writing
`mtu = 1500` is the person who would know about the rc-script. **0285 removes
that.** A network-wide config naming an MTU everywhere is written by somebody
who does not know what each node's local circumstances are -- and the holder's
own sequence arrived at locks immediately after describing distribution, which
is not a coincidence.

So a lock is also **the node's defence against a document written elsewhere**,
which is the same thing 0289 says about a guard and a directive: the node's
declaration wins, and consent is granted to the node rather than asserted by
the message.

## What is not decided here

The syntax -- whether a lock is a modifier on the value in the document, a
separate list, or a runtime assertion like a report; whether locking a value
netcfgd would not have set is an error or a no-op; how a lock on a value inside
a distributed document is expressed when the node did not write that document;
and whether a lock can be scoped to "not by the network, but yes by a local
operator", which is the natural meeting of this record with 0289's
provenance-and-lifetime table.
