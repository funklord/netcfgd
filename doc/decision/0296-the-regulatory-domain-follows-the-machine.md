# 0296: the regulatory domain follows the machine

Status: accepted
Date: 2026-10-27
Milestone: found while re-reading project.md 10.173's last open half
Follows: [0061](0061-a-key-that-compiles-does-something-or-says-it-does-not.md), [0263](0263-the-c-port.md)

## Context

10.173 left one question for the holder: whether a radio's `regdom` should
reach anything. Today only an access point's does, as hostapd's
`country_code`; a radio's is stored, warned about at plan time and inert, and
the C executor's `wifi.set_regdom` has no producer.

The holder's answer was not about that key. It was about the case the key
cannot serve: **a laptop that moves.** When this was handled by hand, the
person moving the machine set the country they were in and the radio used
that country's channels -- the right ones, in the right place. What Linux
offers instead is a setting that, once made, stays made, so a machine carried
into another region goes on using the rules of the one it left, or falls back
to the world domain's, which are the most restrictive of all. Either way it
does not work properly where it is.

## Decision

**netcfgd follows the machine's location, and a configured country is an
override rather than the mode.**

- **The country is inferred from what the radio hears.** Access points
  advertise one (802.11d); agreement across several is the signal, and one
  access point alone does not decide, since one can be misconfigured.
- **It changes when the location does, and only then.** When nothing nearby
  says anything, the last answer stands rather than a fall back to the world
  domain.
- **A configured country wins** over an inferred one, for a machine somebody
  wants pinned.
- **What was decided, and from what, is reported** -- in `ncfg status`, as a
  country and its evidence -- because a laptop that cannot see a network
  nobody can explain is the failure this exists for.
- **The aim is the correct country's rules, as fully as they allow**, not
  some other country's.

## What is not decided

**How, because the kernel has not been measured.** The regulatory domain is
one setting per kernel rather than per radio, and how far a running system
can move it -- which sources cfg80211 accepts once a country is set, what a
disconnect does, which drivers ignore it -- decides whether this is a daemon
feature or needs a kernel patch. That is measured first, by the `regdom` hull
rig (project.md 10.585), and the mechanism is designed from what it finds.

Also open: whether the radio's `regdom` key survives as the override or
becomes a machine-wide one, since a per-device key cannot express a
per-kernel setting.

## Rejected

- **Wiring the radio's `regdom` as it stands.** It would make a per-kernel
  setting look per-radio, and it serves only a machine that never moves.
- **Leaving it inert.** That is the state a moving laptop is already failing
  in.
