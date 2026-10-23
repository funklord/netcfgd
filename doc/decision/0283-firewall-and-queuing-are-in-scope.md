# 0283: firewall and queuing are netcfgd's, in full

Status: accepted
Date: 2026-10-23
Milestone: M6
Supersedes: [0022](0022-netcfgd-may-own-one-nftables-table.md)
Amends: [0023](0023-netcfgd-owns-the-root-qdisc-and-nothing-below-it.md), [0009](0009-router-side-addressing.md)

## Context

The copyright holder, 2026-10-23, on being told that netfilter support was
"complete against the scope netcfgd chose":

> We have not chosen such a narrow scope, that is your invention. We want full
> firewall and queuing support. netcfgd is a network configurator software.
> Those are basic networking. And later we want distributed rules to be
> integrated with higher level subsystems like guest network, auth etc.

**The narrow scope was written into this tree by sessions, not by the holder**,
and it is in five places: 0022's "NAT, never filtering", 0023's "no classes,
filters or actions", 0009's capability table, `c/src/plan/nat.c`'s comment that
this project "has no model of [security policy] and will not grow one by
accident", and the design document's own type table, where `forwarding` is
annotated "sysctl only, never a firewall rule". Each cites the others, which is
how a scope decision nobody made becomes load-bearing: 0023's hard half quotes
0022 as precedent, and 0022 quotes 0009.

## Decision

**Packet filtering and traffic queuing are netcfgd's business, in full.** A
network configurator that cannot express a firewall rule or a class hierarchy
is not configuring the network; it is configuring addresses and leaving the
rest to a second tool the operator must also learn.

The two lines those records drew are withdrawn:

- ~~"netcfgd translates addresses because address translation is addressing.
  It does not filter packets, because filtering is security policy."~~
- ~~"netcfgd sets how a link drains its queue... It does not decide which
  traffic wins, because that is policy."~~

**And the direction past that is stated now so the design is not drawn without
it: rules are to be distributed, and integrated with higher-level subsystems
-- guest network, authentication, and whatever else grows.** A rule whose
subject is "a guest device" or "an authenticated user" is not expressible as a
static ruleset written at apply time, so the mechanism has to admit membership
that changes while the ruleset stands. That is a constraint on the design from
the first line of it, not a later feature.

## What was wrong with the old argument, which is worth keeping

0022 and 0023 did not argue that filtering and queuing belong elsewhere. They
argued that **a configuration language covering them is larger than the one
netcfgd has for addressing** -- "a class hierarchy, a filter language, an
action framework and about thirty schedulers" -- and that writing into a
ruleset netcfgd does not own means fighting another tool.

Both observations are true and neither is a scope argument:

- **Cost is a reason to stage work, not to refuse it.** The right conclusion
  from "this is larger than what we have" is a milestone, not a boundary.
- **Ownership is a coexistence problem and it survives intact.** Docker,
  podman and libvirt insert their own tables at runtime; firewalld and fw4 own
  rulesets on the machines they are installed on. Deciding how netcfgd behaves
  beside them is now one of the design questions below rather than a reason to
  own only NAT.

What 0022 got right and keeps: netcfgd speaks nftables over
`NETLINK_NETFILTER` rather than shelling out to `nft`, it tags what it owns,
and it replaces its own objects atomically. Those are mechanisms, and they
scale to a filter model unchanged.

## The vocabulary moves, and an apply has to survive that

Stated by the holder the same day, while this record was being written:

> The netfilter landscape keeps changing all the time, so we need to be able
> to handle the syntax changing a bit while rules are being applied.

This is a constraint on the mechanism rather than on the scope, and it has
three separable halves. One already holds, two do not.

**Reading tolerantly, which holds.** netcfgd looks attributes up by number and
ignores what it did not ask for, and `wire.h` separates "well-formed and
absent" from "malformed" -- a missing attribute means an older kernel, not a
message to throw away. So a dump from a kernel whose nftables grew new
attributes, new expressions or new chain types still reads. **Asserted rather
than assumed since this record**: `nft_test` feeds a rule carrying an unknown
attribute and an unknown expression between the two netcfgd reads, and a chain
record with unknown attributes inside the hook nest, and requires both to be
recognised. Controlled by making the reader refuse an unfamiliar expression,
where the case fails.

A reader that refuses an unfamiliar *expression* is the worse failure of the
two and is why that case exists: netcfgd's ownership claim over a rule is what
the expressions say, so a reader that gives up stops recognising netcfgd's own
rules and the next apply duplicates or orphans them.

**Noticing that the ruleset moved under the apply, which does not hold.**
netcfgd reads a dump, decides, and sends a transaction; nothing detects a
change in between. The transaction itself is atomic and touches only netcfgd's
table, so the *write* is safe -- but the conflict report is computed from the
dump, and a table that appeared or vanished in the gap makes it wrong in both
directions. nftables publishes a ruleset generation (`NFT_MSG_GETGEN`,
`NFTA_GEN_ID`) for exactly this, and `nft` uses it to notice that it is acting
on a stale view. Reading the generation with the dump and again with the
transaction -- and retrying rather than reporting from a view that has moved --
is the shape that belongs here.

**Refusing legibly where the kernel cannot do what was asked, which does not
hold either.** When netcfgd emits an expression a kernel does not support, the
operator gets that kernel's errno. For a moving target the useful behaviour is
to name the construct and the kernel: `EOPNOTSUPP` from a statement is a
feature difference, not a malformed message, and it is the one error whose
remedy ("this kernel is too old for X") an operator can act on.

Taken together these are what "handle the syntax changing a bit while rules are
being applied" asks for, and the first is the one that keeps a kernel upgrade
from becoming an outage.

## The questions this opens, and whose they are

None of these is decided here. Each is the holder's, and each one changes the
schema rather than an implementation detail:

1. **Ownership beside another firewall.** Own one table and accept that
   another table may also drop (coexist), or be the machine's firewall and
   replace what is there (take over), or emit rules another tool loads? The
   container runtimes are the hard case: they add tables while netcfgd runs.
2. **The rule language.** Zones with inter-zone policy, in the shape firewalld
   and OpenWrt's `fw4` use, or flat ordered rule lists, or zones over rules?
   This decides the document schema, the diff, and what an operator types.
3. **Default policy and state.** What a machine that writes `firewall {}` and
   nothing else gets: default-deny inbound with established accepted, or
   default-accept until told otherwise.
4. **How far queuing goes.** Classes and filters as well as the root qdisc,
   ingress policing, and whether netcfgd creates the `ifb` device that ingress
   shaping needs -- [0255](0255-there-is-no-ifb-to-write.md) says there is no
   ifb to write today, and full queuing reopens that.
5. **Identity in rules, and how it arrives.** Guest-network and auth
   integration means rule *subjects* that change at runtime. nftables sets and
   maps are the mechanism that allows that without rewriting rules, and the
   control socket is where membership would arrive -- but what the subjects
   are, and who may change them, is a decision about the daemon's interface.
6. **Size.** `size-budget.txt` is a ratchet, and the installed total stands at
   1176624 bytes of a 1177000 limit -- 376 bytes of headroom. A filter model
   and a class hierarchy do not fit in that, so either the ratchet is raised
   deliberately or these become separately installable backends, which design
   section 10.3 already contemplates for exactly this.

## Consequences

**The five assertion sites are corrected** rather than left to contradict
intent: this record is cited from each, and `plan/nat.c`'s comment and the
design document's `forwarding` annotation are rewritten.

**0022 is superseded, not deleted.** Its mechanism work stands and its
reasoning is the clearest statement in the tree of what coexistence costs; a
reader who finds it needs to arrive at this record, which is why it is cited
there.

**What exists today is the floor, not the ceiling**: one `inet` table named
`netcfgd`, masquerade per uplink, conflict detection against other source-NAT
tables, the root qdisc with an optional rate, ingress redirect, and policy
routing rules. All of it keeps working; none of it is the scope any more.
