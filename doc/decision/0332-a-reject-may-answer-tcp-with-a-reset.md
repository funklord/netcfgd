# 0332: a reject may answer tcp with a reset

Status: accepted
Date: 2026-11-21
Milestone: the firewall's layer one ([0294](0294-layer-one-is-named-rules-in-netcfgds-own-table.md))
Rests on: project.md 10.895, the inventory the holder asked for

## Context

`reject` always answered with ICMP port-unreachable. For TCP that is not what a
closed port says: a host with nothing listening answers a SYN with a reset, and a
client told "unreachable" by ICMP may retry where one told "reset" stops at once.
`iptables -j REJECT --reject-with tcp-reset` is the usual way to refuse ident on
port 113 so a mail exchange does not wait half a minute for it, and it was among
what the inventory found the language could not say.

## Decision

**`reset = true` on a `reject` of `protocol = "tcp"` answers with a TCP reset.**

- Refused anywhere else, naming the rule: the kernel refuses `reject with tcp
  reset` on a rule that is not tcp's, and a reset on an accept or a drop is
  nothing anybody can act on.
- In the document, the digest and the rendered text only where set, so nothing
  written before changes.
- The reader takes the two answers netcfgd writes and no other, and reports
  `reset`, which the planner compares: a kernel rule swapped to answer with ICMP
  under the same identity is planned back, though its comment and digest did not
  move. `ncfg status` says "with a reset".
- The window's rule dialog has a checkbox, and the client reads the key.

## Rejected

- **A general `with = "..."` key** naming any ICMP code. Nobody has asked for
  admin-prohibited or host-unreachable, and one boolean says the case that comes up.
