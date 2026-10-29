# 0295: what identifies an installed rule

Status: accepted
Date: 2026-10-25
Accepted: 2026-10-29, the holder answering the product half
Milestone: M6
Follows: [0022](0022-netcfgd-may-own-one-nftables-table.md), [0283](0283-firewall-and-queuing-are-in-scope.md), [0287](0287-a-rule-carries-its-own-standing.md), [0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md)

## What this is for

0294 settled layer one's grammar, that the whole table is replaced in one
transaction, and that a refusal names the rule. **It did not say how netcfgd
reads the installed ruleset back**, and that is the question the planner cannot
be written without.

**Status is `proposed` and not `accepted`**, unlike 0294: one half of it is a
product question that belongs to the copyright holder. The other half -- a fact
this machine could not establish -- **was measured on 2026-10-26** and is below;
only the product question is left.

## Why an observation is not optional

A planner with no observation emits its op on every pass. The machine would
never converge: `ncfg plan` would say "replace the firewall" for ever, each
apply would replace an identical ruleset, and the plan -- which this tree
treats as the thing an operator reads before consenting -- would be lying about
there being work to do.

This is not a theoretical bound. `nat.c` sorts the document's uplinks and
compares them against `observed->nat` *in order*, and its comment says why in
as many words: an unsorted observation would differ from a machine that is
already right and replace the table on every pass. The firewall needs the same
property over a much larger object.

## The two answers, with what each costs

### A. Decode the rules back into the model

The renderer's inverse: walk each rule's expressions and rebuild an
`ncfg_firewall_rule_t`, refusing anything netcfgd did not write.

**The shape already exists at one-rule scale.** `ncfg_nft_rule_uplink` walks
nested attribute areas -- expressions, then each expression, then its data --
accumulating what it recognises into a `masquerade_t` and refusing the rest,
and it checks the family and the table name itself rather than trusting the
kernel's dump filter (0022's "reads another table", arriving through the
reader). A general decoder is that, generalised to every expression layer one
can emit: `meta` and `cmp` for protocol and interface, `payload` and `cmp` for
addresses and ports, `ct` for state, `immediate` for the verdict.

- **Cost: large, and it is the whole renderer written backwards.** Every
  refusal the lowerer can name has a counterpart here, and a decoder that
  silently mis-reads one expression produces a false difference -- which is a
  table replaced on every pass, the failure this record exists to prevent,
  arriving through the mechanism meant to prevent it.
- **Benefit: the observation is the model.** `ncfg status` could show the
  installed ruleset; a rule somebody edited by hand inside netcfgd's table
  would be reported as what it now says rather than merely as "not ours"; and
  the diff is exact.

### B. Identity in the rule's own userdata

Write each rule with its name and a digest of the content netcfgd rendered,
in `NFTA_RULE_USERDATA`. The observer reads each chain's policy with
`ncfg_nft_chain_read` and, per rule, that name and digest. The comparison is
the ordered list of `(name, digest)` against the ordered list the document
would produce.

- **Cost: small**, and most of it is the digest, which netcfgd computes over
  its own rendered form rather than over anything the kernel returns.
- **It avoids a trap that a cheaper-looking version falls into.** Comparing
  the returned rule payload byte-for-byte against what was sent cannot work:
  the kernel normalises, so the bytes that come back are not the bytes that
  went in, and the difference is a property of the kernel version rather than
  of the configuration. A digest of netcfgd's own form has no such exposure.
- **It gives 0294's per-rule naming for free** on the path that needs it: a
  refusal already has the rule's name to quote because the name is in the
  object the kernel refused.
- **Limit, and it is the real cost:** netcfgd learns that a rule *is not what
  it wrote*, not what it now is. A hand-edited rule inside netcfgd's table is
  replaced -- the right action -- but reported only as differing, which is a
  worse sentence than A could write.
- **Bound: 128 characters, not the kernel's 256.** `NFT_USERDATA_MAXLEN` is
  256, but nft refuses a comment longer than 128, and keeping `nft list
  ruleset` readable is the point of using its TLV at all -- so 128 is the real
  budget for a name plus a digest. Measured, not read off a header; see below.

## The fact this record could not establish, now measured

**Measured 2026-10-26** in the `netcfgd/natcap` guest, which gained the
`nftables` tool for this -- netcfgd speaks netlink itself and does not need it,
and a rig whose subject is nftables is the one place a human debugging it wants
`nft` to hand. Reproduce with, in that guest:

    nft add table inet probe
    nft add chain inet probe c '{ type filter hook input priority 0; policy accept; }'
    nft --debug=netlink add rule inet probe c drop comment '"name=block"'

**The TLV, as nft 1.1.3 emits it:**

    userdata = { \x00\x0bname=block\x00 }

So it is `u8 type`, `u8 length`, value -- type **0** is the comment, the string
is NUL-terminated, and the NUL is counted in the length (`name=block` is ten
characters and the length byte is eleven). A rule written that way lists back
as `accept comment "name=ssh"` and appears in `nft -j list ruleset` as
`"comment": "name=ssh"`.

**So netcfgd writes nft's own TLV**, and the question this section was opened
for answers itself: an operator running `nft list ruleset` sees the rule's name
as its comment, which is better than netcfgd's private encoding would have
been. There is no tolerance question left to ask, because there is no foreign
encoding to tolerate.

**And a limit this record had wrong: 128, not 256.**
`NFT_USERDATA_MAXLEN` is 256 and this record said a name and a digest fit
inside it comfortably. **nft refuses a comment over 128 characters** --
*"comment too long, 128 characters maximum allowed"* -- so a scheme that wants
to stay readable through nft has half the room, and a name plus a hex digest
has to be budgeted against 128. Measured by asking for 300 and reading the
refusal.

## What is proposed, and what is the holder's

**Proposed: B first, A later, and they compose rather than compete.** B is
enough for the planner, the transaction and per-rule refusals -- which is all
of layer one -- and it is small enough that getting it wrong is cheap. A is a
*reader*, and the thing that makes it worth its size is `ncfg status` showing
the installed ruleset rather than the diff needing it.

**The holder's half: whether `ncfg status` must show the installed firewall as
rules.** If it must, A is not optional and is better done with B rather than
after it, because a decoder written later has to be reconciled with a digest
scheme already in the field. If showing names and standing is enough, B alone
carries layer one and A waits for a reason of its own.

## Decided, 2026-10-29

**The holder: `ncfg status` must show the installed firewall as rules.** So A
is not optional, and by this record's own argument it is built *with* B rather
than after it: a decoder written later would have to be reconciled with a
digest scheme already in the field.

What that settles for the slices that follow:

- **Every rule carries B's identity** -- its name and a digest of netcfgd's
  own rendering, in nft's comment TLV, within 128 characters -- and the
  planner's comparison is the ordered list of `(name, digest)`, which is
  exact and cheap.
- **A decodes every expression layer one writes back into an
  `ncfg_firewall_rule_t`**, refusing anything netcfgd would not have written,
  and `ncfg status` shows what it decoded. A rule inside netcfgd's table that
  A cannot read, or whose digest does not match what A read, is reported as
  what it is -- not netcfgd's as written -- and replaced on the next apply.
- **The two are checked against each other**: a rule A decodes and B's digest
  disagrees with is a defect in one of them, and the suite says which.

Nothing here is implemented yet; project.md 10.592 tracks the slices.
