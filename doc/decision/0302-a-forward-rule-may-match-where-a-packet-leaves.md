# 0302: a forward rule may match where a packet leaves

Status: accepted
Date: 2026-10-30
Milestone: the router side, after the input-chain warnings (project.md 10.623)
Amends: [0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md)

## Context

0294's `interface` is "an input or output device name, whichever the chain's
hook makes meaningful": `iifname` in `input` and `forward`, `oifname` in
`output`. The forward chain is the one chain where a packet has both, and the
vocabulary could name only one. So the commonest firewall request on a router
after a port forward -- a guest network that reaches the internet and not the
LAN -- could be written only by address, `to = ["192.168.1.0/24"]`, which
drifts the moment the LAN's network changes and says nothing about a second
LAN. 0294 makes each widening of its vocabulary a decision.

The holder asked for it on 2026-10-30.

## Decision

**`out_interface`, in the forward chain only: the interface a forwarded packet
leaves by.** `interface` keeps its meaning there, the one it arrived on.

```
forward {
	policy = "drop"
	accept "established" { state = ["established", "related"] }
	drop   "guest-lan"   { interface = "guest0"; out_interface = "lan0" }
	accept "out"         { out_interface = "wan0" }
}
```

- **Refused in `input`**, where nothing leaves, and **in `output`**, where
  `interface` already is the interface a packet leaves by -- the refusal says
  so rather than accepting a second spelling of one match.
- **Encoded as `oifname`** after the rule's other matches, exactly as nft
  writes `iifname "guest0" oifname "lan0" drop`, measured with
  `tests/live/firewall.sh`.
- **The digest text gains `out_interface NAME`** only where it is set, so no
  rule written before this changes its identity and no installed table is
  replaced by the upgrade.
- **Read back into its own field**: the decoder takes `oifname` in the forward
  chain as `out_interface` and in `output` as `interface`, as before. The
  observation carries it, the plan's comparison and its undo step carry it,
  `ncfg status` and a saved profile write it.

## Alternatives considered

**`interface = ["guest0", "lan0"]`, in and out by position.** Rejected: a list
whose positions mean different things is read wrong by everybody who did not
write it.

**`from_interface` and `to_interface`, renaming `interface`.** Rejected: every
existing ruleset would need rewriting for a word, and `interface` in `input`
and `output` already reads correctly.

**Leaving guest isolation to addresses.** Rejected by the holder: a rule that
names the LAN's network is a second copy of the LAN's address, and 0300 was
written to stop exactly that kind of copy.
