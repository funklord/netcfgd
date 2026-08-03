# 0067: A suffix is not a routing domain

Status: accepted
Date: 2026-08-03
Milestone: the key [0066](0066-a-lease-reports-its-nameservers.md) left out

## Context

[0049](0049-a-server-may-name-resolvers-not-where-queries-go.md) refused two things
in one sentence, and they are not the same thing:

```
dhcp-option DNS 10.0.0.53          # a resolver         -- allowed, gated
dhcp-option DOMAIN corp.example    # ...and these names -- refused, no key
```

The second was read as *routing*: "which names travel down this tunnel". On the
wire it is usually the weaker thing -- a **suffix to complete a bare name with**.
DHCP has two options for it (15 `Domain Name`, 119 `Domain Search`) and OpenVPN
pushes `DOMAIN` and `DOMAIN-SEARCH`; none of them says which resolver answers.

So a lease's suffix reached nothing, and on a corporate LAN `ssh wiki` did not work
under netcfgd while it worked under every other tool.

## Decision

**A report may carry search suffixes. It still may not carry routing domains.**

`search=` joins the contract, one suffix per line, and lands in
[`DnsPolicy::search`] and nowhere else. There is still no key for a routing domain
and there will not be: which resolver answers for a zone is authority over where
queries go, which is 0049's refusal and constraint 1's rule.

**The gate is the same one the servers use, and that is the argument rather than a
convenience.** A suffix is delivered only where that report's *resolvers* are --
`Reported` addressing, or a `dns { }` block on the interface. The reasoning is
worth stating because it is what makes this safe:

- If you accepted the network's resolvers, they already answer every query you
  make. A party that can answer `wiki.corp.example` with anything it likes gains
  **nothing** by also getting to append `corp.example` to `wiki`.
- If you kept your own resolvers, a lease that could set your search list would
  make `wiki` resolve as `wiki.evil.example` -- *through your trusted resolver*.
  That is a real escalation, and it is exactly what the gate refuses.

So the dangerous case is the one where the suffix and the servers come apart, and
the gate keeps them together.

**All three writers report it**, because one contract means one thing: the two DHCP
scripts (option 119 where the server sent one, option 15 otherwise -- the precedence
dhcpcd's own `20-resolv.conf` uses) and the OpenVPN report script, whose `DOMAIN` and
`DOMAIN-SEARCH` are suffixes and are now reported as such.

**The document comes first.** An operator's `dns { search = [...] }` is placed ahead
of a reported suffix, because resolution tries them in order and what somebody wrote
down beats what a network suggested.

## What this does not change

- **Split DNS is still written down.** A VPN pushing `DOMAIN corp.example` gets a
  suffix, not a rule sending `*.corp.example` to the tunnel's resolver. That needs
  `dns { domains = ["corp.example"] }` in the document, which is 0007's whole point
  and 0049's refusal intact.
- **What the contract has no key for is still a comment.** The OpenVPN script writes
  `# the server also said: dhcp-option WINS 10.0.0.7` and netcfgd's reader drops it.
  Its test pushes a `WINS` option for exactly that reason: with only `DOMAIN` in the
  environment, deleting the comment path would have left every assertion passing.

## Consequences

- `config = "dhcp"` with `dns { }` now gives an address, a route, resolvers and a
  search list -- the whole of what a lease carries that netcfgd has anywhere to put.
- The observed schema gains `ObservedReport::search`; its witness moved. A minor
  addition, and the contract document gains a row.
- `+4 KB` installed.
- Three breaks checked: not reporting the suffix (live), delivering it to an
  interface that asked for nothing (fixture), and putting it in `domains` where 0049
  refuses it (fixture, and the live resolver file notices too -- a routing domain is
  not a `search` line).
