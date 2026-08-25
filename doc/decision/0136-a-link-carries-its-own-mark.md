# 0136: a link carries its own mark

Status: accepted
Date: 2026-08-25
Milestone: M8; the last piece of ownership that lived only in `/run`

Completes [0135](0135-the-kernel-holds-the-ownership-record.md), which left
this named as the obvious next step and deliberately did not take it.

## Context

0135 made addresses and routes survive losing `/run`, because the kernel
carries netcfgd's protocol tag on both. It closed with a table of what still
could not be re-derived, and the first row was links:

> **A kernel-visible marker for created links is the obvious next step and is
> not taken here.** An altname would do it, and adding one is a change to what
> netcfgd puts on the machine rather than to how it reads it back.

A link has no protocol field. [0002](0002-object-ownership-tagging.md) could
stamp `rtm_protocol` on a route and `IFA_PROTO` on an address; there is nothing
equivalent on `RTM_NEWLINK`, so `created_links` in `/run/netcfgd/owned.json`
was the whole record, and a restart deletes it.

**The cost was the same shape 0135 measured.** A netcfgd that forgets it
created a bridge can never remove that bridge, so a bridge deleted from the
config stays on the machine for ever while `ncfg apply` reports success having
done nothing.

## Decision

**Every link netcfgd creates gets an alternative name, `netcfgd:<name>`.**

`IFLA_ALT_IFNAME` inside an `IFLA_PROP_LIST` nest, sent with
`RTM_NEWLINKPROP` immediately after the link is created, and read back out of
the ordinary link dump. `link_ownership` reads the mark first and the record
second.

### The name

**The prefix and the link's name at creation**, not a constant. Alternative
names share the lookup namespace with real ones, so a constant marker would
collide the moment netcfgd created a second link. Keeping the original name in
it also records what netcfgd made the link *as*, which survives a later rename.

**Matched by prefix, never by the whole string.** A link can be renamed after
it is created, at which point the mark and the name disagree -- and they should,
because the mark is a record of creation rather than a second copy of the name.
Matching the whole string would make a rename look like a change of owner.

**A colon**, matching `@secret:` elsewhere in this project. `dev_valid_name`
was expected to reject one, and does not: `netcfgd:nc0`, `netcfgd-nc0` and
`netcfgd.nc0` were all accepted by a 6.12 kernel, and `ip link show
netcfgd:nc0` resolves the device without shadowing its real name. The
expectation was wrong and the test is why this record does not say otherwise.

### Failing to mark a link is not failing to create it

The mark is added on a best-effort basis and its failure is reported, not
propagated. Two ways it can fail and neither is a reason to refuse a link that
was created perfectly well:

- **`EEXIST`**, because alternative names share the lookup namespace and this
  machine already has an interface by that name.
- **A kernel without `RTM_NEWLINKPROP`.** It arrived in 5.5 and netcfgd's floor
  is 5.10 (0002), so this should not happen -- but "should not happen" is not a
  reason to turn it into a failed apply.

An unmarked link falls back to the recorded state, which is exactly where every
link was before this. **The failure is said out loud** rather than swallowed,
because what is lost is invisible until much later, as a restart that quietly
fails to reconcile:

    netcfgd: could not mark ncbr0 as netcfgd's with the alternative name
             netcfgd:ncbr0: Invalid argument (os error 22)
    netcfgd:   its ownership is recorded in /run instead, which a restart loses

That is not hypothetical text. It is what the first implementation printed, and
it is how the next section was found.

## `NLA_F_NESTED`, and why this was worth the detour

The first attempt returned `EINVAL` with nothing to say about why. The cause is
that **`RTM_NEWLINKPROP` parses its nest strictly**: a container attribute
without `NLA_F_NESTED` set is rejected outright. `IFLA_LINKINFO` on
`RTM_NEWLINK` goes through the lenient path, which is why netcfgd had been
sending unflagged nests since it was written and had never met this.

The constant already existed in `netcfgd-sys`, private to the ethtool module,
under a comment saying the ethtool family's parsers require it -- the same
discovery, made once before, in a place the second discoverer could not see. It
lives in `wire` now, with both callers using it, because two copies of a
netlink constant is exactly what
[0002](0002-object-ownership-tagging.md)'s duplicate-constant test exists to
prevent for the protocol number.

**Set it on every nest, not on the ones that complain.** The message says
`EINVAL` and nothing about nesting, so the alternative is finding out per
message type, each time at the cost of an afternoon.

## Consequences

**Link ownership no longer depends on `/run`.** With
[0135](0135-the-kernel-holds-the-ownership-record.md) this leaves the residue
at sysctls, DNS scopes, qdisc and ingress -- all of which fail toward holding,
none of which creates an object that outlives netcfgd's memory of it.

**The mark is legible without netcfgd running**, which is 0002's second
argument arriving here too. `ip -d link show br0` says `altname netcfgd:br0`,
so somebody debugging a machine can see which bridges are netcfgd's without
asking netcfgd.

**netcfgd now writes something to the machine it did not write before**, which
is the reason 0135 declined to do this in passing. An alternative name is
visible in `ip link`, is usable to address the device, and persists until the
link is deleted. It is small and it is not nothing.

**A link created before this ships carries no mark.** `link_ownership` reads
the record as well, so those links stay netcfgd's; they simply do not gain the
new protection until they are recreated. Nothing migrates them, deliberately --
stamping marks on links at startup would mean netcfgd claiming links on the
strength of a record that this decision exists because it does not trust.

## Alternatives considered

**Match the whole alternative name against the current link name.** Rejected:
it breaks on a rename, and a rename is ordinary. The suffix is a record of what
the link was called when netcfgd made it, not an assertion about what it is
called now -- and a test asserts the suffix is not consulted, using one that
matches nothing.

**Use a constant mark, `netcfgd`, on every link.** Rejected: alternative names
must be unique across the machine, so the second link would fail with `EEXIST`.

**Write the mark into `IFLA_IFALIAS` instead.** Rejected. It is a free-text
field with one slot, so netcfgd would be overwriting whatever an operator or
another tool had put there, and losing it. An alternative name is a list and
netcfgd adds one entry to it.

**Stamp existing links at startup to migrate them.** Rejected, above: it would
have netcfgd claim links on the authority of the record whose loss is the
entire problem. A link gets its mark when netcfgd creates it and not otherwise.

**Leave it and rely on `RuntimeDirectoryPreserve=restart`.** Rejected for the
reason 0135 rejected it as the whole answer: it is systemd's alone, and netcfgd
ships OpenRC and procd scripts that manage that directory themselves.
