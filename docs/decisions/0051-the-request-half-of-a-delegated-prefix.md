# 0051: The request half of a delegated prefix

Status: accepted
Date: 2026-08-02
Milestone: completes 0009, amends [0050](0050-a-delegated-prefix-is-odhcp6cs-to-report.md)

## Context

0050 established that only odhcp6c can report a delegated prefix, and left the
config syntax unwritten with a stated reason:

> It would be config-language surface that nothing here can exercise end to end
> -- odhcp6c is not packaged for Debian, so the client that serves the feature
> cannot be run on the machine this was written on.

That reason has stopped being true, which is the only good reason to revisit a
decision this recent. odhcp6c builds from source in about two minutes -- libubox
with `-DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF`, then odhcp6c against it -- and
`kea-dhcp6` is one `apt-get install` away. A veth pair between them is a line
from an ISP.

So the loop 0009 describes now runs: the document asks for a prefix, odhcp6c
solicits it, the server delegates `2001:db8:1234::/56`, the hook netcfgd
generated reports it, and netcfgd derives `2001:db8:1234::1/64` on the LAN from
`@pd:wan0=::1/64`. That is `tests/live/delegation.sh`.

## Decision

**Three modifier words on a `dhcp6` entry**, in the vocabulary the language
already uses for modifiers:

```
config = "dhcp6 pd"                       # whatever the ISP gives out
config = "dhcp6 pd_length 56"             # ask for a /56
config = "dhcp6 pd_hint 2001:db8:: pd_length 56"
```

`pd_length` and `pd_hint` each imply `pd`, so a length with no `pd` beside it is
not silently inert. All three are a **request**: a server may hand back a
different size or a different block, which is why `PdRequest` carries a hint
rather than a value and why what arrives is read back from the report instead of
assumed. odhcp6c takes exactly this shape -- `-P <[pfx/]len>`, split on the
slash and parsed with `inet_pton`, checked in its `config.c`.

**A `dhcp6` that says nothing about delegation asks for no prefix.** It used to
ask anyway: `-P 0` went to odhcp6c unconditionally, so every `config = "dhcp6"`
solicited a delegation nobody had written down and an ISP handed out a prefix
that nothing on the machine would ever use.

## What it cost to find out

**A keyword source dropped its modifiers.** `config = "dhcp4 metric 100"`
compiled and threw the metric away, because the `dhcp4`, `slaac`, `link-local`
and `reported` arms returned before the modifier loop ran. Section 2's rule
about unknown fields is a rule about the language too, and it matters more here
than in the document because the author is looking at the line. All four now
refuse what they cannot take -- found by adding words to that loop and noticing
the old arms would never see them.

**iproute2 prints the same protocol tag in two bases.** A route shows
`proto 110` and an address shows `proto 0x6e`. The obvious assertion fails on a
perfectly correct address, and the tag is netcfgd's own in both cases.

## Consequences

- Prefix delegation is now expressible, and needs odhcp6c to serve it. On
  OpenWrt -- the device this feature is for -- that is already installed. On
  Debian it is a build, and `tests/live/delegation.sh` says how in its header.
- `tests/live/delegation.sh` is the third root-only live test, alongside
  `hwsim.sh` and `pppoe-session.sh`. It skips without root or without odhcp6c,
  and `make live` does not run it.
- 0050 stands in every other respect. dhcpcd still cannot report a prefix, the
  refusal still names odhcp6c, and the reasoning there is unchanged -- what
  changed is that the client could be run after all.
