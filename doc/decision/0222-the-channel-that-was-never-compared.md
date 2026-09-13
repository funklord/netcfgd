# 0222: the channel that was never compared

Status: accepted
Date: 2026-09-12
Milestone: M9; the wifi channel and band audit

## A fix that nothing was holding

An access point naming no channel used to be stopped and started on every
reconcile: the document says `None`, the renderer writes `channel=0` to ask
hostapd to survey and choose, and the observation reads that back as `Some(0)`.
`Some(0) != None` is true on every pass, and a reconcile runs on every netlink
event -- a permanent deauthentication loop for a document nobody had touched.

That was found and fixed before this audit, with a guard:

```rust
} else if started.channel != access_point.channel && access_point.channel.is_some() {
```

**The guard was load bearing and completely unprotected.** Removing it broke no
test in the tree:

```text
$ sed -i 's/&& access_point.channel.is_some()//' crates/netcfgd-plan/src/lib.rs
$ cargo test --workspace
   (no failures)
```

The reason is in the plan fixture, which builds the observed side from the
document. Its comment said the fields were converted "as the renderer would
write them, not as the document states them" -- and `band` and `channel`, the
two the sentence was written about, were copied straight across. So `None` in
the document became `None` in the observation, the comparison the guard exists
to fix was never exercised, and the harness reported a pass for a question it
had not asked.

The same check run on the `band` guard failed a test, which is what made the
asymmetry visible: one of the two was protected and the other only looked it.

## And the guard had opened the opposite hole

`&& access_point.channel.is_some()` says: *if the document names no channel,
never restart for a channel.* That silences the loop. It also silences the real
change.

An operator who deletes `channel = 36` to get automatic selection back is left
pinned to 36 for ever, and the plan says nothing -- the edit is in the file, the
radio ignores it, and netcfgd reports no drift. The band arm carried the same
guard and the same hole: `band = "5"` with no channel, whose `band` line is then
deleted, means 2.4 GHz from that moment, and the access point stayed on 5 GHz.

This is the round's recurring shape and the campaign's: **a true statement about
one direction used as a fix for both.** The guard was right that an absent
channel is not a change from `0`. It was wrong that an absent channel is not a
change from `36`.

The fix is to compare the two things actually in play -- the number this build
would write, and the number in the file it wrote:

```rust
} else if started.channel.unwrap_or(0) != access_point.channel.unwrap_or(0) {
```

No guard is needed, because absent and `0` are the same statement and compare
equal on their own. The band arm derives instead of defaulting, through a rule
that now has one home.

## One band rule, because three places need it

The rule -- `band` decides when stated, the channel decides when it is not with
the split at 14, neither means 2.4 GHz -- was written in the hostapd renderer,
and the planner is not allowed to ask it: a planner that depends on a backend
crate is the thing `key_mgmt_of` was moved into the model to prevent. The
compiler needed it too, to answer a question it was not asking at all.

Three copies of a rule that decides whether a running access point matches its
document is an access point that restarts for ever, so it is stated once, in
`netcfgd-model`, as `effective_band` and `channel_in_band`. The renderer, the
planner and the compiler all call it.

## The pair that was checked nowhere

`band` is validated against a closed set. `channel` is validated as a number.
Their *combination* was validated only by the renderer, so this compiled,
planned, and failed at `ncfg apply` with the interface already up:

```text
FAIL backend.start ap0  access_point: AccessPoint (was <absent>)
     `Home`: channel 36 is not in the 2.4 GHz band
```

That is exactly the lateness that moved `band` and `regdom` into the compiler
(and 0221 the second of those), left behind for the one question that needs two
keys. It also kept the example gate blind, by that gate's own account: it
compiles each block, and a render-time refusal is invisible to it.

Checked at compile now, pointing at the `channel` line, with help that differs
depending on which half the operator is more likely to have got wrong. The
renderer keeps its own check, because it is reachable from a document that did
not come through the compiler.

`channel = 0` is refused with it, and deliberately: it is hostapd's spelling of
"survey and choose", which an absent `channel` already says, so writing it by
hand asks for something the document has another way to spell.

## Fakes built from the code rather than from the thing

Two hand-built observations in the plan tests said `band: None, channel: None`
for a document stating neither. The renderer always emits both keys -- `hw_mode`
and `channel` -- so a real observation of a running access point can never read
back `None` for them. Both tests passed only because the planner was comparing
the document against a copy of itself.

The comment beside them had got it right for `key_mgmt`, and for the same
reason, three lines up: *"stated rather than left at `None` ... which would read
as the generation having changed on every pass"*. The reasoning was there and
had not been applied to the two fields next to it.

## What is not fixed

The renderer writes none of `ieee80211n`, `ieee80211ac` or `wmm_enabled`, and
hostapd defaults them off, so a netcfgd access point runs at 802.11a/g rates --
54 Mbps -- in either band. Written up in `netcfgd.conf.example` and the README's
feature table rather than implemented: `ieee80211n=1` is one line, and the
`ht_capab` that should go with it is a function of what the radio reports, which
netcfgd does not observe. Implementing it against a machine with no spare radio
to test on is how a fake gets built from the code again.

## Sabotage

| reverted | test | result |
| --- | --- | --- |
| channel compared as written | `a_deleted_channel_or_band_...` | FAILED |
| the old `is_some` guard restored | `a_deleted_channel_or_band_...` | FAILED |
| compile-time band/channel check | `a_channel_outside_its_band_...` | FAILED |
| `effective_band` forgets the neither-stated case | `a_deleted_channel_or_band_...` | FAILED |
| fixture copies again *and* guard removed | `a_deleted_channel_or_band_...` | FAILED |

The last row is the one that matters: the new test holds the fix up even with
the harness weakened back to what it was, because it builds its observations
from what the renderer writes rather than from the document.
