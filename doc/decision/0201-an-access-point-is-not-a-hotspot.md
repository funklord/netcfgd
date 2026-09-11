# 0201: an access point is not a hotspot

Status: accepted
Date: 2026-09-11
Milestone: M8; the wifi AP and hotspot audit

## What was already right

The access-point warnings are thorough and predate this: a device with no
`interface` block, an empty `allow` list that closes the network completely,
more than one BSS on a radio that runs one, and a radio asked to be an access
point and a station at once. `ap.sh` drives a real `hostapd` against the
generated file and checks it parses. The ACL is written as one list or the
other because hostapd reads one file or the other.

## Following the advice exactly leaves an unusable radio

The first of those warnings ends "Adding `interface wlan0 { }` is enough".
Doing exactly that plans:

```text
0  link.up wlan0  enabled: true (was false)
1  backend.start wlan0  access_point: AccessPoint (was <absent>)
```

**and no address.** The sentence is true about what it is about -- that is what
brings the radio up and starts hostapd -- and it reads as an answer to "what do
I need for an access point", which it is not. The SSID beacons, a station
associates, and there is nothing on this end for it to talk to.

**netcfgd serves no DHCP**, which is the half an operator is most likely to
assume. `dnsmasq` appears in this tree only as a `dns_mode` -- a way of writing
resolver configuration -- and nothing here hands out a lease. So an address on
that interface is *necessary and not sufficient*, and the warning says both
rather than the easy one: give the interface an address, and either run a
server on it or configure the stations by hand.

Nothing can warn about the missing server, because netcfgd cannot see one it
does not run. Saying so is the honest substitute.

## The reference said the block was the whole of it

```text
# AN ACCESS POINT. netcfgd generates hostapd's configuration under /run and
# runs it; this is the whole of what you write.
```

It is not. The block as printed, compiled exactly as it stands, produces
`nothing to do` and netcfgd's own warning that it needs an `interface` block.
The example now carries both blocks, gives the interface an address, and states
what an access point does and does not get you.

**The example gate did not catch this and could not.** That gate (0200)
compiles each block, and this block compiles -- it plans nothing, which is a
different failure. A block that is valid and inert is exactly the shape the
gate is blind to, which is worth knowing now that a gate exists and somebody
might stop reading the file.

## `ncfg wifi clients` existed everywhere except in the list of what exists

The command has worked since access points did, and
`netcfgd.conf.example` tells the reader to use it. The usage line printed by
`ncfg wifi` listed "radios, activate, deactivate, scan, status, add, forget,
connect or disconnect" -- so the one place somebody looks to find out what
`ncfg wifi` can do was the only place that did not mention it.

Checked in both directions while fixing it: `add` and `forget` are in that list
and are *not* in the same match, being handled a few lines above. They exist,
so the list was wrong by omission only.

## Verification

Three checks in `ap.sh`. The control first and from the existing fixture, which
already gives its access point an address: a warning that fired on every access
point would tell nobody anything. Then the same configuration with the address
removed, which must be warned, and must be told the part about DHCP -- the half
netcfgd cannot fix and therefore has to say.

Sabotage: disabling the warning takes the two address checks red; restoring the
old subcommand list takes the third.

**One thing found by writing the test**: a check name in backticks is command
substitution inside double quotes. The first version ran `ncfg wifi` and
printed a check called "  offers the command that lists stations". The
assertion was correct and the label was gone -- which would have made a future
failure unreadable rather than wrong.
