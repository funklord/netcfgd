# 0294: layer one is named rules in netcfgd's own table

Status: accepted
Date: 2026-10-25
Milestone: M6
Follows: [0022](0022-netcfgd-may-own-one-nftables-table.md), [0283](0283-firewall-and-queuing-are-in-scope.md), [0284](0284-the-ruleset-is-netcfgds-and-rules-arrive-in-five-layers.md), [0287](0287-a-rule-carries-its-own-standing.md), [0293](0293-an-optional-action-may-be-red-on-its-own.md)
Supersedes: 0022's "NAT and nothing else", and nothing else of 0022

## What this is for

0284 settled that rules arrive in five layers and deliberately decided none of
their grammar: *"the rule language's grammar, the precedence between layers,
the carve-out syntax ... each is a decision rather than a detail, and this
record exists so that none of them is answered by accident while something
else is being implemented."*

This record answers **layer one only** -- the operator writing rules for the
host in front of them -- and says which of 0284's open questions it is
deliberately not touching. Layer one is first because every other layer
compiles into it: a preset expands to these rules, a zone compiles to them,
and layer four's sets are referenced *by* them. A grammar decided here is the
target the others aim at.

## The grammar

```
firewall {
    input {
        policy = "drop"
        accept "ssh"      { protocol = "tcp"; port = [22]; from = ["10.0.0.0/8"] }
        accept "established" { state = ["established", "related"] }
        drop   "netbios"  { protocol = "udp"; port = [137, 138] }
    }
    forward { policy = "drop" }
    output  { policy = "accept" }
}
```

**The action is the keyword and the name is the label**, for two reasons. The
word `rule` is already policy routing's in this configuration language --
`interface eth0 { rules = "..." }` -- and `code-style.md` asks for one word per
concept; and a rule that reads `accept "ssh" { ... }` says what it does before
it says what it matches, which is the order an operator scans for.

**Every rule is named, and the name is its identity.** 0287 needs a rule to
carry its own standing, and a red row has to say *which* rule; a position in a
list is not an identity, because inserting a rule above it renames everything
below. The name is unique within its chain, it is what the subject key
(10.549) renders as `firewall:input/ssh`, and it is what a later layer refers
to when it says a rule came from a preset rather than from the operator.

**The order is the file's order.** nftables evaluates a chain in order and so
does this; nothing is sorted, and the renderer writes rules back in the order
the document holds them.

### What may be matched, in version one

`protocol` (`tcp`, `udp`, `icmp`, `icmpv6`), `port` (a list of numbers, only
with a protocol that has ports), `from` and `to` (lists of addresses or CIDRs,
either family), `interface` (an input or output device name, whichever the
chain's hook makes meaningful), and `state` (`new`, `established`, `related`,
`invalid`).

**The actions are `accept`, `drop` and `reject`**, and the chain policies are
`accept` and `drop`.

**That is the whole vocabulary, and widening it is a decision each time.** The
same discipline 0293 puts on the optional-action list, for the same reason: a
match that goes in cannot come out, every one of them has to be renderable on
the oldest kernel netcfgd supports or carry a capability sentence, and each
addition is a thing an operator will write and expect to keep working. What is
*deliberately* absent from version one: rate limits, marks, logging, sets and
maps (layer four's, per 0284), nat redirection (0022's chain already does
masquerade), raw nftables text, and anything addressed by interface group or
by zone name -- that last being layer three's whole point.

## Where it lives, and what owns it

**In netcfgd's one table, which is what this widens about 0022.** That record
says netcfgd may own exactly one table named `netcfgd` "containing NAT and
nothing else". The restriction's purpose was that netcfgd must never write
into a ruleset somebody else owns, and that purpose is untouched: this adds
three base chains to the same table, in the same `inet` family, and still
writes nothing outside it. `nft.h`'s guarantee -- no call takes a table or
chain name, and the assembled transaction is audited as bytes before it is
sent -- extends to the new chains rather than being relaxed.

The chains are `input`, `forward` and `output`, hooked at `filter` priority 0,
each with the policy the document gives it. The NAT chain stays as it is: a
`nat`-type chain at `srcnat`, which 0022's own argument says cannot coexist
with filter rules *in one chain* and has never needed to.

**The whole table is replaced in one transaction, as NAT already is.** Reading
the generation before and after (0283, 10.541) is what makes that safe against
a container runtime adding a table mid-apply.

## What happens when the kernel refuses one rule

**The ruleset is all-or-nothing, and this record says so rather than implying
per-rule standing it cannot deliver.** An nftables transaction either lands or
rolls back; a rule the kernel will not take makes the whole transaction fail,
so the other rules are not in effect either. What netcfgd does with that:

1. The refusal names the rule, using the message the kernel refused and the
   rule's own name -- which is what `ncfg_nft_message_text` and the subject key
   were built for, and what makes 0287's red row possible at all.
2. The action is **not** optional in 0293's sense. A firewall whose rules did
   not apply is not a slower host, it is a differently-protected one, which is
   the same argument that keeps bridge VLAN filtering required (10.561).
3. The previous ruleset stands, because the transaction rolled back. That is
   the safe failure and it is worth stating: an operator whose new rule is
   unsupported keeps the rules they had.

**Per-rule exclusion is not decided here**, and it is the same question 0283
left open as "a probe rather than a refusal": netcfgd could try each rule in a
throwaway table, learn which the kernel accepts, and send the rest with the
unsupported ones red. That writes to the kernel to answer a question about it,
costs a transaction per apply, and changes what "the ruleset" means when a rule
is silently absent. It is the holder's, and layer one does not need it to be
useful.

## The carve-out, which this record narrows rather than settles

0284 names the hard half: docker, podman and libvirt add tables while netcfgd
runs. Layer one's position:

**netcfgd reports a foreign base chain at its own hooks and does not fight
it.** The dump that 0022 already takes for NAT conflict detection sees every
table in every family, so the same pass can say "another table has an `input`
chain at filter priority" -- and nftables is additive, so both chains see the
packet and the strictest verdict wins.

**Which means a `forward { policy = "drop" }` on a host running docker will
drop what docker forwards**, and netcfgd must say so before it is applied
rather than after. For layer one that is a plan note naming the foreign table,
on the same surface as the conflict report 0022 requires.

**Refusing instead of reporting is the holder's call.** A guard (0010) or a
lock (0290) would make the operator say "yes, drop it"; a note lets them break
their containers at three in the morning. The argument for the note is that
netcfgd cannot know which is wanted -- some hosts *should* stop forwarding
container traffic -- and the argument for refusing is 0288's: the control path
is part of what is being configured, and a `forward` policy is exactly how a
router stops routing. Reported, not decided.

## What is explicitly not decided here

- **Precedence between layers**, which 0284 says must be stated before any
  layer is written. Layer one alone has no precedence question: the operator's
  rules are the only rules, in file order. **This record does not create a
  precedence rule by implication** -- when presets or zones arrive, how their
  rules interleave with these is still open, and a reader should not read "file
  order" as "manual rules win".
- **The carve-out syntax**, per above: named rather than inferred is 0284's
  requirement, and layer one needs no syntax because it carves nothing out.
- **Sets and maps**, which are layer four's mechanism and whose absence from
  version one is why `state` is a match and membership is not.
- **Whether a rule may name a zone**, which is layer three's and would make
  this grammar a compilation target rather than a surface.
- **The size question** 0283 leaves open: these chains and their rendering cost
  binary, and `size-budget.txt` will say how much when there is code to
  measure.
