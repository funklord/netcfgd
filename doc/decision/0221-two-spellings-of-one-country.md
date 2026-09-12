# 0221: two spellings of one country

Status: accepted
Date: 2026-09-12
Milestone: M9; the wifi regulatory domain audit

## The setting that reads as authoritative is the inert one

The language spells `regdom` twice:

```
device wlan0 { wifi { regdom = "SE" } }    stored, and not acted on
access_point "Home" { regdom = "SE" }      written, as hostapd's country_code
```

The radio's is parsed, kept in the document, rendered back by `ncfg profile
save`, and read by nothing. The access point's becomes `country_code` in the
generated hostapd configuration. hostapd's own documentation, on the machine
this was audited on:

```text
# Country code (ISO/IEC 3166-1). Used to set regulatory domain.
# Set as needed to indicate country in which device is operating.
# This can limit available channels and transmit power.
#country_code=US
```

So the setting written in the place that reads as belonging to the hardware
does nothing, and the one added almost as an afterthought to an access point is
the one with an effect.

Three faults followed from that, and none of them was visible from either side
alone.

## A plan that warned nothing sets the domain, while starting what sets it

`warn_wifi_device_policy` carried one fixed clause:

> `regdom` on wlan0 is understood and not acted on by this build: **nothing
> sets the regulatory domain or the power-saving mode**.

The first half is false whenever an access point on that radio carries a
`regdom`, which is the ordinary way to run one. A single plan could warn that
nothing sets the domain and, four lines down, start hostapd with
`country_code=US`.

This is the shape the campaign keeps finding: **a true statement about one
setting used as a verdict about the machine.** It was true of
`device { wifi { regdom } }` and said about the radio.

The clause is now built beside the name it belongs to, so the sentence says
only what was written:

```rust
if wifi.regdom.is_some() {
    stated.push("`regdom`");
    because.push("a radio's `regdom` reaches nothing, and an access point's is
                  the only one this build writes -- as hostapd's `country_code`");
}
```

## Two countries on one radio, silently

`device wlan0 { wifi { regdom = "SE" } }` beside `access_point "Home" { device
= "wlan0" regdom = "US" }` compiled, planned and applied, and the machine got
`US`. Nothing said the radio's line had lost, because from the device's side it
was never in the running.

The other direction is the commoner mistake: the country written once, on the
radio, where it reads as belonging -- and hostapd started with no
`country_code` at all.

`warn_regdom` covers both. It fires **only where a radio names one**, which is
what keeps it quiet: an access point carrying the only `regdom` is the correct
arrangement, and an access point with neither is a machine that has not been
told about regulatory domains, where a paragraph on every plan would be the
noise `plan_dns`'s empty-scope guard records shipping once.

## What it deliberately does not say

The first draft predicted the radio's behaviour. The reasoning was that a
machine netcfgd never set a domain on sits in the world domain, where 5 GHz is
marked no-IR -- may not initiate radiation, which is what a beacon is -- so a 5
GHz access point with no `regdom` would fail to start. `iw reg get` on the
audit machine:

```text
global
country 00: DFS-UNSET
        (5170 - 5250 @ 80), (N/A, 20), (N/A), AUTO-BW, PASSIVE-SCAN

phy#0 (self-managed)
country SE: DFS-UNSET
        (5735 - 5755 @ 80), (6, 22), (N/A), AUTO-BW, NO-HT40MINUS
```

**The phy is self-managed.** iwlwifi carries its own regulatory domain from
firmware, it is `SE` while the global one is `00`, and the kernel does not let
a user-space country code move it. The per-channel list agrees and contradicts
the global block:

```text
* 2467.0 MHz [12] (22.0 dBm)          <- usable, though 00 marks it passive
* 5180.0 MHz [36] (22.0 dBm) (no IR)
* 5745.0 MHz [149] (22.0 dBm)         <- usable, though 00 marks it passive
```

So the prediction would have been a false alarm on every modern Intel radio,
and the premise -- "every netcfgd machine is in the world domain" -- was wrong
for exactly the hardware netcfgd is most often run on. It was caught by
measuring the machine rather than by reasoning further from `iw reg get`'s
first stanza, which is the half that supported the theory.

Which channels a domain permits is the kernel's answer to give, and netcfgd
does not observe it. The warning says which `regdom` netcfgd writes and which
it drops, because that is the part netcfgd knows. Observing the phy's actual
domain, and reporting it in `ncfg status`, is the fix that would let netcfgd
say the rest; it needs nl80211 and is not in this build.

## One validator, and it uppercases

The two keys were checked by two functions that differed in one byte:
`lower_regdom` asked for `is_ascii_alphabetic`, the device block's inline copy
for `is_ascii_uppercase`. So `regdom = "se"` compiled as an access point's and
was refused as a radio's, with a different help string, in the same file:

```text
ncfg: a.conf:2:9: `se` is not a regulatory domain
  help: an ISO 3166-1 alpha-2 code in capitals, such as SE
```

Merged towards the permissive one, because widening cannot break a
configuration that already compiles, and normalised to upper case on the way
in.

**The existing test asserted the refusal**, and it is the first suspect only
after it is understood. Its stated reason -- "a regulatory domain the kernel
ignores is a radio quietly using the world-roaming defaults" -- is an *end*,
and refusal was one means to it. Uppercasing serves the same end better: the
kernel never sees a code it would ignore, and the operator who spelt the right
country in lower case gets the radio instead of a diagnostic. The test now
asserts the normalisation and keeps refusing everything that is not two
letters.

## A third and a fourth paragraph on the wrong function

0219 moved a doc comment that had run together with the one below it, leaving
one function documented with another's prose. Reading the regulatory code found
two more of exactly that:

- `warn_access_points`' documentation sat on `warn_unmanaged`, and had gone
  stale where it stood -- it said "three things" and the body has five;
- `band_of`'s sat on `band_of_hw_mode` in the hostapd renderer, which is in the
  regulatory path this audit was walking.

**Both of the new ones are private items, and that is the whole reason they
survived.** The two found earlier were caught by `missing_docs`, which covers
public items only. The lint that would catch this class is
`clippy::missing_docs_in_private_items`, and it reports **447** items in this
tree today:

```text
$ cargo clippy --workspace --all-targets -- -W clippy::missing_docs_in_private_items | grep -c 'missing documentation'
447
```

So it is a piece of work rather than a flag to set. The number is recorded here
rather than the class being called fixed, because four occurrences in three
audits is a rate, and the next session should know what closing it costs.

## Sabotage

Each fix reverted in turn, with the test that is supposed to notice:

| reverted | test | result |
| --- | --- | --- |
| `warn_regdom` not dispatched | `two_regulatory_domains_...` | FAILED |
| warns even when the two agree | `two_regulatory_domains_...` | FAILED |
| no uppercasing in `lower_regdom` | `a_malformed_regulatory_domain_is_refused` | FAILED |
| " | `a_lower_case_regdom_...` | FAILED |
| device key back on `is_ascii_uppercase` | `a_malformed_regulatory_domain_is_refused` | FAILED |

## Documentation

The README's feature table said `powersave`, `scan_randomization` and `regdom`
"are understood and **not acted on yet**". Two thirds of that was false: 0220
implemented `scan_randomization` the day before, and an access point's `regdom`
has always been written. The same table's own access-point row lists
"regulatory domain" as supported, four rows above -- so the document
contradicted itself and neither row was wrong about its own subject.

`netcfgd.conf.example` showed both `regdom` keys with nothing to distinguish
them. It now carries the two-spellings table, the `iw reg get` output with its
two stanzas, and what self-managed means -- in the file the postinst calls "the
one for a machine with no network to look anything up with", which is the
machine most likely to be the one with a regulatory problem.
