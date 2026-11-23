# 0340: a slot is a named set a chain opens for live updates

Status: accepted
Date: 2026-11-23
Milestone: the firewall's layer four ([0284](0284-the-ruleset-is-netcfgds-and-rules-arrive-in-five-layers.md))
Follows: [0339](0339-live-rules-win-and-there-is-no-controller.md), which left how a node declares a slot, who may write into one and how long an element lives

## The grammar

A slot is declared in the chain it acts in, beside the rules, with the verdict
its members get and which address of a packet is matched against them:

    firewall {
        forward {
            policy = "drop"
            slot "quarantine" { action = "drop";   match = "from" }
            slot "guests"     { action = "accept"; match = "from"; timeout = "1h" }
            accept "lan-out" { interface = "lan0"; out_interface = "wan0" }
        }
    }

- **`action`** is one of the rule actions, `accept`, `drop` or `reject`.
- **`match`** is `from` (the packet's source address) or `to` (its
  destination).
- **`timeout`**, optional, is how long a member written with no lifetime of
  its own stays: `"90s"`, `"30m"`, `"1h"`, `"2d"`. Without it a member stays
  until it is removed.

**A slot's name is unique across the whole firewall**, not only its chain,
because a live write names the slot and nothing else.

Rejected: a slot as a bare set that hand-written rules reference
(`from = ["@quarantine"]`). Where the referencing rule stood would decide
whether the live layer won, which is exactly the order 0339 fixed; and a
writer could not tell from the slot alone what a member gets. Declaring the
verdict on the slot keeps "what does being in this slot do" in one line.

## How it compiles: ahead of every rule in its chain

Each slot is two nftables sets in netcfgd's table, `slot-NAME-4` of IPv4
addresses and `slot-NAME-6` of IPv6, both with per-element timeouts, and two
kernel rules at the **head** of the chain, before the first hand-written
rule, in the order the slots were written:

    ip  saddr @slot-quarantine-4 counter drop
    ip6 saddr @slot-quarantine-6 counter drop

That is 0339's precedence in nftables terms: the live layer's verdict is
reached before the operator's rules. The rules are static -- they never
change while the slot's membership does -- which is 0284's fast path: a
membership change is an element added or removed, never a rule rebuilt.

Members are single addresses. A prefix needs an interval set, whose element
encoding is a pair per member; nothing that writes membership (an
authentication, a quarantine, a failover) names a network rather than a
host, so it waits for one that does.

## Who may write, and what is refused

**A write names a slot, an address, and optionally a lifetime**, and is one
element added to or removed from that slot's set, sent to the kernel at once
without an apply. **A write naming anything that is not a declared slot is
refused**, whoever sent it: that is 0339's static value.

**The tier is `root`**, netcfgd's operator tier, which is 0311's simple case
-- an operator of the estate, locally or remotely, may do what it asks. A
narrower authority, "may write into this slot and nothing else", is the one
0284 anticipated, and it is a tier question for when a subsystem other than
an operator writes; it is not built here.

## How long a member lives

- **Across an apply**: carried. netcfgd replaces its table whole, which would
  empty every set, so the apply reads each slot's members first and writes
  them into the new table in the same transaction, with what remains of each
  one's lifetime. A slot the new document no longer declares loses its
  members with it.
- **Across a daemon restart**: the table, and so the membership, stays in the
  kernel, and the first apply carries it as above.
- **Across a reboot**: the kernel's sets are gone, so netcfgd keeps a record
  of each slot's members in `/var/lib/netcfgd/slot/NAME`, one `ADDRESS
  EXPIRES` a line, rewritten from the kernel after every live write and every
  replacement. The first apply after a boot -- the table absent -- writes the
  recorded members back, less those whose lifetime ran out meanwhile. Without
  it a restrictive slot (a quarantine) would be open from boot until its
  writer wrote again, which is failing open; `/run` is not the place for the
  record for exactly that reason.

**Drift is not membership.** The planner compares the slot's rules and sets
with the document as it compares any rule; the members are nobody's desired
state and are never drift.
