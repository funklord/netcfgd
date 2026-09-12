# 0220: the address in a probe request

Status: accepted
Date: 2026-09-12
Milestone: M9; the wifi MAC and privacy audit

## The half that was accepted and did nothing

`mac_policy` works: it becomes a per-network `mac_addr`, sent for every network
including `permanent`, so the address a radio presents once it has joined
something is netcfgd's to decide and not a supplicant default's.

`scan_randomization` beside it was accepted and inert, and `ncfg plan` said so
on every apply -- honestly, which is why this is an implementation rather than
a correction.

**It is the more exposed half.** `mac_policy` governs the address used once a
network is joined; this governs the address in *probe requests*, which are
broadcast to everyone in range whether or not anything is ever joined. A laptop
walking through a station announces the same address to every receiver it
passes, and never associates with any of them.

It is the supplicant's global `preassoc_mac_addr`. Asked of wpa_supplicant 2.10
over its own control socket, on the `none` driver so no radio is needed:

```text
SET preassoc_mac_addr 1  -> OK
SET preassoc_mac_addr 0  -> OK
SET not_a_key 1          -> FAIL
GET preassoc_mac_addr    -> 1
```

The `FAIL` is the control that makes the rest mean something: the parser does
reject an unknown global, so `OK` says the setting exists rather than that
everything is accepted.

## Sent in both directions

A global rather than a per-network setting, so it goes beside `SET
update_config 0` at population time rather than into `add_network`.

Sent explicitly even when the answer is "use the permanent address", for
[0015](0015-the-supplicant-holds-no-state.md)'s reason: a silent
default is not a control. An unset global inherits whatever this distribution's
supplicant defaults to, and a privacy property that depends on somebody else's
default is not a property.

## The digest gains a line only when it is on

This is the part that needed care, and it is the same hazard the access point
round met from the other side.

The networks digest decides whether a *running* supplicant still matches the
document, and a mismatch replaces its whole network set -- which drops the
association. Encoding the off state as a line would change the digest of every
machine that has never used this, so the first apply after an upgrade would
disconnect all of them to record a setting none of them asked for.

So absence means off, which is what the document means by absence too. All
three cases come out right and the test asserts the first two:

```text
never used     -> byte-identical, nothing is repopulated
turned on      -> the digest changes once, and the supplicant is told
turned off     -> it changes back
```

## What the audit found sound

- **IPv6 privacy addresses.** `use_tempaddr` is written as `2` for on and `0`
  for off, and the observation reads `== "2"` -- which is the pair that
  matters, because `1` generates temporary addresses and then prefers the
  stable one, so a machine set that way would be configured for privacy and
  not have it.
- **`mac_policy` and `addr_gen_mode` do not contradict each other.** netcfgd
  leaves `addr_gen_mode` alone, so a stable SLAAC address is derived from
  whatever address the interface currently has -- which under a randomising
  `mac_policy` is the randomised one. Checked on the reporting machine, where
  `fe80::2a5:54ff:fe22:3e90` is the EUI-64 of `00:a5:54:22:3e:90`: the
  derivation follows the current address, so randomising the one randomises the
  other.
- **A fixed `mac` and a randomising `mac_policy`** already warn against each
  other.

## What is still not done

`powersave` and a wifi device's `regdom` remain accepted and inert, and the
plan still says so -- with `scan_randomization` removed from that sentence,
because it is no longer true of it.
