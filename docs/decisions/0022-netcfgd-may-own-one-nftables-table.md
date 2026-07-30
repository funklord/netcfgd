# 0022: netcfgd may own one nftables table, for NAT and nothing else

Status: accepted
Date: 2026-07-30
Milestone: not scheduled
Amends: [0009](0009-router-side-addressing.md)

## Context

Decision 0009 excluded masquerade and gave the reason:

> A masquerade rule is an entry in a packet filter that something else owns --
> `firewall4` on OpenWrt, `firewalld` or nftables directly elsewhere. Writing
> into a ruleset netcfgd does not own means either fighting that tool over rule
> ordering or requiring it to be absent.

Two things reopened it. The first is a question: netcfgd now configures
multiple kinds of device, and a router without NAT is not a router -- telling
that operator to install a firewall tool is passing the buck on the one rule
that makes their machine work.

The second is sharper, and it is the reason this record exists rather than a
restatement of 0009. **Staying out of the way is not always right.** Sometimes
the user's configuration is broken and the useful thing is to fix it, which
means deleting or replacing what is there. A tool that only ever adds is a tool
that cannot repair.

## What actually changed since 0009

0009's argument is about *ordering fights*, and that argument was formed
against iptables: one global chain per hook, every tool appending to it, and
the outcome decided by who ran last. In that world "writing into a ruleset you
do not own" is exactly right, because there is only one ruleset.

**nftables does not work that way.** Tables are named and independent. `table
inet netcfgd` can be created, replaced and deleted atomically without reading
or touching `table inet fw4`. There is no shared chain to append to and no
ordering to lose, because tables do not interleave -- each registers its own
chains at its own hook priority.

So the premise has weakened. Not vanished: two tables can still conflict
*semantically*, which is dealt with below. But "fighting over rule ordering" is
no longer the obstacle, and a decision resting on it should say so.

This is also the ownership model netcfgd already uses everywhere else. Decision
0002 tags routes with protocol 110 and refuses to touch anything it did not
tag. **An nftables table is a tag** -- a coarser one, and a better one, because
it is atomic.

## Decision

**netcfgd may own exactly one nftables table, named `netcfgd`, containing NAT
and nothing else.** It replaces that table wholesale on every apply and never
reads, writes or deletes any other.

### NAT, never filtering

This is the line, and it is sharper than "firewall support":

> netcfgd translates addresses because address translation is addressing. It
> does not filter packets, because filtering is security policy.

That is the same distinction 0009 drew when it said "netcfgd configures; it
does not serve", applied one layer down. Masquerade on an uplink is a
consequence of how the machine is addressed. A rule about which ports the
outside world may reach is a statement about risk, and netcfgd has no model of
risk and should not grow one.

The practical test: if a rule's content is derivable from the addressing
already in the document, it is in scope. Masquerade on the interface marked as
the uplink is. `accept tcp dport 22` is not, and never will be.

`nftables` supports a table containing only `nat`-type chains, so this is a
line the mechanism itself enforces rather than a convention.

### Repairing is what owning means

Within its own table netcfgd has total authority and uses it. Every apply
replaces the table atomically -- rules the operator added by hand inside it are
removed, exactly as an address netcfgd owns is removed when the document stops
asking for it. That is the "fix a broken configuration" case, and it needs no
special machinery because it is ordinary reconciliation.

The case that cannot be handled that way is a *different* table doing NAT on
the same interface, which double-translates. netcfgd can detect that -- another
table with a `nat` chain at the same hook -- and it reports it, in the same
words and the same places as the NetworkManager contention check.

### Why netcfgd will not delete somebody else's table

It is the obvious way to make the report actionable, and it is refused.

Deleting `table inet fw4` to resolve a NAT conflict removes a firewall to fix a
routing problem. The conflict netcfgd can see is one chain; the table it would
delete contains filtering it cannot evaluate. Trading a working firewall for
working NAT is not a trade a network daemon gets to make on the operator's
behalf, and it is worse for being silent -- the machine keeps working, and is
open.

The wholesale option does have a legitimate home: an appliance image where
netcfgd is the only network configuration and the existing ruleset is a
leftover. There, `nft flush ruleset` before applying is correct, it is one line,
and it belongs in a `pre_up` hook -- the escape hatch that already exists for
"I know what this machine is and you do not". An operator who types that has
made a decision. A config flag called `on_conflict = "replace"` looks innocuous
and would be typed by people who had not.

### Container runtimes are the reason the default is narrow

Docker, podman and libvirt all insert nftables rules at runtime, in their own
tables, as containers come and go. A netcfgd that flushed what it did not
recognise would break every container host -- intermittently, since it depends
on what is running when the apply lands, which is the worst way for it to
break.

That is not an argument against owning a table. It is the argument for owning
*only* one, and it is why "netcfgd never touches a table it did not create" is
stated as an invariant rather than a default.

## Consequences

**0009's exclusion of masquerade is amended rather than reversed.** Its
reasoning about iptables was right when written; the conclusion changes because
nftables offers something iptables did not. The row in its capability table
should read "yes, in netcfgd's own table" rather than "no".

**netcfgd would speak nftables directly, not through `nft`.** nftables is
netlink -- `NETLINK_NETFILTER`, protocol 12 -- and netcfgd already has the
socket layer, having added generic netlink for WireGuard. Shelling out to `nft`
would be a tool dependency and would mean parsing its output to detect
conflicts, which decision 0014 rejected for `iwctl` for reasons that apply
unchanged here.

**It costs size, and the budget is already over.** Another netlink message
family in the audited crate, plus a model, a planner op and an executor path.
Design section 10.3 makes optional backends separately installable for exactly
this, and NAT is a good candidate for that treatment -- a machine that is not a
router should not carry it.

**`fwmark` stays out.** `RoutingRule` can match a mark and the model says
netcfgd never sets one. That does not change: setting a mark is filtering by
another name, and it would be the first step across the line this record draws.

## Alternatives considered

**Keep 0009's exclusion.** Rejected on the reason above: it rests on an
iptables-shaped constraint that nftables removed, and it leaves the one rule a
router cannot work without permanently outside a tool that claims to configure
routers.

**A general firewall model** -- zones, policies, port rules. Rejected. It is a
different product, it needs a model of risk netcfgd does not have, and every
tool that has tried has ended up with a configuration language larger than the
one for addressing. `firewalld` and `fw4` exist and are good.

**Write netcfgd's NAT into the operator's existing table**, so there is one
place to look. Rejected: that is 0009's original objection, still valid. It
means reading and modifying a structure somebody else maintains, and the first
`fw4 reload` discards it.

**Emit `nft` rules to a file for the operator's firewall to include.** Tempting
-- it is the DNS backend pattern, and 0007's precedent for handing policy to a
tool that owns delivery. Rejected because there is no equivalent of
`resolvconf`: no convention every firewall tool honours for including a
fragment, so it would be per-tool integration with each one, and a fragment
that is silently not included is NAT that silently does not work.

**A config flag to delete conflicting tables.** Rejected above. The capability
is reachable through a hook, where it reads as the deliberate act it is.
