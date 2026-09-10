# 0200: two settings that contradict each other

Status: accepted
Date: 2026-09-11
Milestone: M8; the wifi MAC and privacy audit

## What is right already

IPv6 privacy extensions are applied properly: `use_tempaddr` is written 2 or 0,
and the failure is fatal for a stated reason -- the planner never asks about an
absent sysctl, so reaching the write means the file was there when it was read.

`mac_policy` reaches the supplicant correctly as `mac_addr=0/1/2`, and the
`MacPolicy` variants carry what each costs: `PerConnection` "breaks anything
that recognises a returning client: DHCP reservations, captive portal sessions,
MAC-based admission".

## The contradiction

`mac` on a device is planned as a `link.set_mac`. A randomising `mac_policy` is
sent to the supplicant, which applies its own address **when it associates**,
over whatever the link is carrying. netcfgd does both, and said nothing.

Measured on a plan with both set:

```text
0  link.set_mac wlan0  mac: 02:00:00:00:00:01 (was 6a:d3:38:d3:a9:bb)
1  link.up wlan0  enabled: true (was false)
2  backend.start wlan0  addressing[0]: Dhcp4 (was <absent>)
```

netcfgd setting an address it is about to have overwritten. The configured
address is on the interface right up until the moment the radio starts being
used, and from then on it is not.

**What it costs is the reason somebody pins an address at all.**
`MacPolicy::Permanent`'s own documentation names it -- "a network with MAC-based
admission control is the usual reason" -- so an operator who set `mac` for
admission and `mac_policy` for privacy gets neither the admission nor a
diagnosis. The network refuses them and nothing on the machine explains why.

**Warned, not refused and not resolved.** Either could be what was meant: a
pinned address that a random one is layered over is wrong, and so is a
randomised association on a device pinned for some other purpose. Picking for
the operator would silently discard whichever was actually wanted, which is the
failure this is about.

## The reference was wrong, and nothing could have caught it

`netcfgd.conf.example` told the reader:

> `scan_randomization` and `mac_policy = "random"` are the privacy pair

**`random` is not a MAC policy.** Confirmed against the compiler rather than by
reading:

```text
`random` is not a MAC policy
  help: one of permanent, per_network, per_connection
```

And the sentence presents the two as equals when `scan_randomization` is
accepted and inert -- the planner warns about it, but a reference that reads as
though both work is how somebody concludes they are covered while scanning and
is not.

That file calls itself "every feature, with the syntax to use it", and the
postinst points an operator at it as the thing to read on a machine with no
network. **Nothing checked a word of it.** The Makefile installed it and removed
it, and that was the whole relationship -- which is also how it came to have no
`probe` block at all while shipping a `probe` feature with a script (10.84).
Two faults, in one file, in one session, found only because somebody read it.

## `tool/example_gate.py`

Every commented top-level block is uncommented and compiled alone. 81 blocks;
79 compile, and the two that cannot are **named rather than skipped by
pattern**, so a third joining them is a failure:

- `override interface` needs the block it overrides;
- one `interface eth0` carries a `dns` scope with routing domains, which needs
  the `global` block whose `dns_mode` can express them.

**What it does not inspect, stated in the gate itself**: prose. The
`mac_policy = "random"` above was in a sentence, not a block, and this gate
would have passed the file carrying it. Saying so where somebody will read it,
because a check trusted for more than it does is worse than none -- the next
person stops reading the file by hand and the gate never told them not to.

It also refuses to pass on an empty block list, which is the failure every gate
shares: a sweep over nothing reports success exactly as loudly as a real one.

Sabotage: the real fault moved into a block is caught by name and line;
breaking the extractor trips the empty-list guard rather than passing quietly;
and a named exception that starts compiling is reported so the list cannot rot.
