# 0239: a different address is not a roam

Status: accepted
Date: 2026-09-14
Milestone: M9; the wifi roaming and BSSID audit

## What the code kept re-checking, and what it never checked

0122 audited the roam *policy* -- `bgscan`, opportunistic key caching, what a
move costs on an enterprise network. This pass is about the other half: how
netcfgd decides a move happened, and which configured network an association
belongs to.

Re-measured rather than inherited, against wpa_supplicant 2.10 on the `none`
driver, because every one of these is a field netcfgd writes and nothing had
read back:

```text
SET_NETWORK 0 bgscan "simple:30:-70:300"   ->  OK
GET_NETWORK 0 bgscan                       ->  "simple:30:-70:300"
SET_NETWORK 0 bssid_accept aa:.../ff:... b8:.../ff:...  ->  OK
GET_NETWORK 0 bssid_accept                 ->  aa:a4:7f:23:9a:cf b8:27:eb:11:22:33
SET_NETWORK 1 bssid a0:a4:7f:23:9a:cf      ->  OK
SET_NETWORK 1 bssid zz:zz:zz:zz:zz:zz      ->  FAIL
```

All four land. `bssid_accept` in particular: it is the 2.10 spelling of what
used to be `bssid_whitelist`, both names are in this machine's binary, and
netcfgd sends the new one. The mask form is what the parser wants and it reads
back without the masks, which is the supplicant having understood them.

## A roam is a different access point *on the same network*

That sentence is `HookPhase::Roam`'s own documentation, and it is what the hook
is for. What the watcher did:

```rust
let moved = last.as_deref().is_some_and(|was| was != bssid);
```

A different address than last time. Those are not the same question, and the
difference is not exotic: **a machine that leaves one network for another it
also holds credentials for satisfies the address test while contradicting the
sentence.** Switching from home wifi to the office ran the `roam` hooks, with
`NCFG_REASON` saying the station had moved to an access point on a network it
had just left. This machine has switched networks three times during this
campaign; each would have fired it.

The event answers the question itself. The format string netcfgd already reads
the address out of carries the configured network's id beside it:

```text
CTRL-EVENT-CONNECTED - Connection to %02x:...:%02x completed [id=%d id_str=%s%s]
```

So `connected_network_id()` reads the seventh word, and `is_roam` takes the pair:
the same id with a different address is a roam, and everything else is not. A
station moving between access points on one network keeps that id. A station
leaving for another network does not.

**`Event::field` is deliberately not used for it**, and the reason is worth a
line because it looks like the obvious tool: that helper requires its key at a
field boundary -- start of text, or after a space -- and this key is preceded by
`[`. It would find nothing and report that as `None`, which is the same answer a
genuinely missing field gets.

An unreadable id answers "not a roam" rather than falling back to comparing
addresses. The cost is a hook that does not fire, which is the direction the
first association after start-up already errs in.

## The fixture asserted the defect as a justification

`fake_supplicant.py` hard-coded `id=0` in all three places it emits a
`CONNECTED`, with a comment explaining why that was fine:

> from netcfgd's side a network change and a roam arrive identically and it is
> `STATUS` that tells them apart

That is true of the fake and false of a supplicant. Eleven lines above it, the
same file says `ROAM` "is the *same* network under a different access point and
is a different thing entirely" -- so the fixture knew the distinction it was
erasing. **A fixture built from the reader rather than from the thing modelled**,
which is the sixth instance of that shape in this campaign and the first where
the fixture wrote down its reasoning.

It emits the real index now, so `JOIN` announces a different network and `ROAM`
does not, and `roam.sh` has the case it never had: leaving for another network
is not a roam, and a move within the new one still is. The second half is the
control -- without it the first passes for a watcher that stopped reporting
roams altogether.

## And the rule for "which network is this" had no test at all

`network_for` is shared between the socket and the observation, deliberately,
and its own documentation says why:

> Two copies of this rule could disagree, and the disagreement would show up as
> a route metric that does not match what the window says the machine is
> associated with.

Nothing anywhere called it in a test. The single copy could produce exactly that
outcome on its own: it took the first block matching on *either* rule, in `id`
order, so two blocks sharing an SSID and pinned to different access points were
both answered with whichever sorted earlier. That configuration compiles with no
diagnostic -- write the name as hex in both -- and it was checked on this machine
before the fix, with `ncfg plan` answering `nothing to do`.

The address is the more specific statement and the only thing separating such
blocks, so it is asked first: a block naming this access point answers ahead of
one that merely shares the name, and a block with no SSID is still matched on its
addresses alone because it has nothing else. A block naming this address but a
*different* network no longer answers for it.

## Sabotage

Six, five of which failed as they should on the first run and one of which did
not -- and the one that did not was the useful one.

| what was broken | what caught it |
|---|---|
| `is_roam` back to comparing addresses | `a_roam_stays_on_one_network`, and `roam.sh` twice |
| an unreadable id falls back to addresses | `a_roam_stays_on_one_network` |
| the id parsed with the `[id=` prefix trimmed loosely | `a_connected_event_names_the_network_as_well` (`-1` became 1) |
| `network_for` back to first-match-on-either | `the_block_that_names_the_access_point_answers_first` |
| the SSID agreement dropped from the address pass | the same test |
| the SSID fallback dropped entirely | the same test |

**The one that passed was not a sabotage of the code but of a claim about it.**
A first draft of `is_roam`'s documentation said the code guarded against
`None == None` comparing two unknown networks as one. The sabotage that would
prove it could not be written: what the watcher stores is an
`Option<(u32, String)>`, so there is no room in it for an address without a
network and the comparison is unreachable. The representation was doing the
work and the comment took credit for a check. Rewritten to say which.

That is the eighth time in this campaign a sabotage has passed on its first run,
and the first time the answer was to fix the sentence rather than add a test.

## Three live scripts fail, and none of them because of this

`wifi_journey.sh`, `wifi.sh` and `wifi_trouble.sh` fail, and were failing
before this round -- confirmed by stashing the six changed files, rebuilding,
and running them against `9dad858`, where all three fail identically. Named
here because a round that touches both the roam watcher and the supplicant
fixture is the one that would be blamed for them, and because nothing in this
tree had recorded them. Not investigated: they belong to their own pass.

`roam.sh`, `switch_network.sh` and `select.sh` pass. `association.sh` passes
against this machine's own radio, which is the only check the `network_for`
change gets against real hardware.
