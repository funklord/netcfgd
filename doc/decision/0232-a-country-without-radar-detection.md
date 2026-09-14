# 0232: a country without radar detection

Status: accepted
Date: 2026-09-14
Milestone: M9; the wifi country and channel width audit

## Re-auditing means re-checking what the last round assumed

0221 covered the country code. 0230's lesson was that an existing assertion is
not a source, so this round went back over what 0221 took for granted rather
than over what it concluded -- and found a line it had considered and dropped.

During that round `ieee80211h` was raised as a candidate and set aside as
unverifiable. It is verifiable, from a file on the same machine.

## The line that was missing

netcfgd writes `country_code` and `ieee80211d=1` when an access point names a
`regdom`. hostapd's own documentation, installed here:

```text
# Enable IEEE 802.11h. This enables radar detection and DFS support if
# available. DFS support is required on outdoor 5 GHz channels in most
# countries of the world. This can be used only with ieee80211d=1.
# (default: 0 = disabled)
```

Default off, and netcfgd never wrote it. The radio on the reporting machine
marks **fifteen** of its 5 GHz channels as needing radar detection:

```text
* 5260.0 MHz [52] (22.0 dBm) (no IR, radar detection)
* 5180.0 MHz [36] (22.0 dBm) (no IR)
```

52 through 64 and 100 through 144. `channel_in_band` accepts the whole 36..=177
range, so every one of them compiles, plans and renders like any other -- into a
configuration with DFS support switched off.

`ieee80211h=1` is written beside `ieee80211d=1` now, in the same branch, because
hostapd says it "can be used only with ieee80211d=1". An access point with no
`regdom` gets neither, which is the answer it already had, and is one more
reason to set one.

**What is measured and what is not.** Measured: hostapd documents the flag as
enabling DFS support and defaults it off; the radio marks fifteen channels; the
reference test renders every variant and hands it to the real hostapd 2.10,
which accepts the new line -- and its companion test proves that check can fail,
so the acceptance means something. Not measured: what hostapd does on a DFS
channel *without* the flag. Establishing that needs a radio to bring up, and the
only way to get one here would be loading `mac80211_hwsim` on a machine whose
netcfgd enumerates radios -- which would hand the running daemon two interfaces
it did not have a moment ago.

## The wait nothing mentioned

A DFS channel needs a channel availability check before the access point may
beacon: the radio listens, typically for a minute and longer on some channels,
and sends nothing until it is done.

`ncfg apply` returns as soon as hostapd is started. So an access point on one of
those channels is configured, running and silent -- which looks exactly like one
that is broken, and is the failure this planner's warnings exist for.

Warned rather than refused, because a DFS channel is a legitimate and often
deliberate choice: it is the half of 5 GHz that is usually empty. What is worth
saying is that the silence is expected and roughly how long it lasts.

**The kernel is the authority and the model is not.** `channel_in_band`'s
documentation already says why a channel table does not belong in this tree.
The same applies here with one difference that earns the exception: this drives
a warning rather than a refusal, so being wrong about a channel costs a sentence
rather than an access point. The range is the one that is DFS in every domain
netcfgd is likely to meet.

## Channel width, which is not a defect yet

Nothing in this tree writes `ht_capab`, `vht_oper_chwidth` or anything else
about width, and 0222 recorded why: no `ieee80211n` is written either, so an
access point runs at 802.11a/g rates and 20 MHz is the only width it has.
Width becomes a question the moment that changes, and not before.

The station side sets none of `disable_ht`, `disable_ht40` or `disable_vht`,
which is right -- those exist to work around broken access points, and a
default that uses what the peer offers is the one to have.

## Sabotage

| reverted | test | result |
| --- | --- | --- |
| `ieee80211h` not written | `a_regdom_is_advertised_as_well_as_recorded` | FAILED |
| the radar predicate never fires | `a_radar_channel_says_...` | FAILED |
| it fires on everything | `a_radar_channel_says_...` | FAILED |
| the block boundary slips by one | `a_radar_channel_says_...` | FAILED |

The last two are the pair worth having. A warning that cannot stay quiet is as
useless as one that cannot fire, and an off-by-one at 64 is the shape this kind
of range gets wrong.
