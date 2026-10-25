# 0295: what identifies an installed rule

Status: proposed
Date: 2026-10-25
Milestone: M6
Follows: [0022](0022-netcfgd-may-own-one-nftables-table.md), [0283](0283-firewall-and-queuing-are-in-scope.md), [0287](0287-a-rule-carries-its-own-standing.md), [0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md)

## What this is for

0294 settled layer one's grammar, that the whole table is replaced in one
transaction, and that a refusal names the rule. **It did not say how netcfgd
reads the installed ruleset back**, and that is the question the planner cannot
be written without.

**Status is `proposed` and not `accepted`**, unlike 0294: one half of it is a
product question that belongs to the copyright holder, and one fact in it is
unverified on this machine. Both are named below rather than resolved.

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
- **Bound: 256 bytes.** `NFT_USERDATA_MAXLEN` is 256, which a bounded name and
  a fixed-width digest fit inside with room to spare. Worth stating because it
  is a hard limit on this scheme ever carrying more.

## The fact this record cannot establish here

**Whether netcfgd's userdata keeps `nft list ruleset` readable is unverified.**
nft(8) stores its own `comment` in that attribute under a TLV of its own, so
bytes written naively may print as nothing, as garbage, or make nft refuse the
rule -- and an operator running `nft list ruleset` on their own router is a
first-class reader of netcfgd's output, not an afterthought.

Neither libnftnl's headers nor an `nft` binary is installed on this machine, so
nothing here can answer it, and this record does not guess.

**The experiment that settles it, named so it is run rather than reasoned
about:** `tests/hull/natcap/` already boots a machine with nftables for the NAT
capability work. Write one rule with userdata through netcfgd's own transaction
builder in that guest, run `nft list ruleset`, and read what it prints. If nft
refuses or garbles it, the answer is to adopt nft's TLV -- type 0, the comment
-- so the name appears as a comment an operator can read, which is a better
outcome than netcfgd's private encoding would have been anyway.

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

Nothing here is implemented. This record exists so that the next slice does not
answer it by accident, which is the reason 0294 gives for existing at all.
