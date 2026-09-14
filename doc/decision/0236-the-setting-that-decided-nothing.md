# 0236: the setting that decided nothing

Status: accepted
Date: 2026-09-14
Milestone: M9; the wifi disconnect and reassociation audit

## What was sound

`ncfg wifi disconnect` sends `DISCONNECT` rather than `REMOVE_NETWORK`, with the
reason written beside it: the network stays configured and stays in the
supplicant, so reconnecting does not resolve the credential again, and the next
reconcile does not see a network missing and put it back a second later.
`ncfg wifi connect` uses `SELECT_NETWORK` rather than `ENABLE_NETWORK`, which
disables the others -- the difference between joining one network and adding one
to the set.

The per-network `autoconnect` is acted on: `ENABLE_NETWORK` when it is true and
`DISABLE_NETWORK` when it is false, with a comment saying why -- "a network left
enabled would be joined the moment it came in range, which is not what
`autoconnect = false` asks for".

Two things about `autoconnect` were not sound, and they are opposite ends of the
same setting.

## The radio's `autoconnect` was read nowhere

`WifiDevicePolicy::autoconnect` is documented in the model as "whether to
connect to known networks without being asked". It is parsed, kept in the
document, rendered back by `ncfg profile save`, carried in the frozen schema --
and read by nothing. A radio told `autoconnect = false` joined networks anyway.

The planner did not warn either. `warn_wifi_device_policy` covers `regdom` and
`powersave` and says of them "the setting is kept, so a configuration written
now still means this when the code arrives"; `autoconnect` was not in that list,
so nothing anywhere said it was inert. That is 0061's shape exactly, in the
function written to prevent it.

It is acted on now: after the networks are added, a radio that does not join by
itself is sent `DISABLE_NETWORK all`. Asked of wpa_supplicant 2.10 on the `none`
driver, so no radio was involved:

```text
DISABLE_NETWORK all -> OK
ENABLE_NETWORK all  -> OK
DISABLE_NETWORK 99  -> FAIL
LIST_NETWORKS       -> 0  [DISABLED]
```

The `FAIL` is the control that makes the first line mean something, and
`LIST_NETWORKS` showing `[DISABLED]` is what the command did rather than what it
answered.

After the networks and not before, because `add_network` enables each one it
adds -- a disable sent first would be undone by the next addition.

## And neither flag reached the digest

`autoconnect` drives `ENABLE_NETWORK`, which is not a `SET_NETWORK`, and the
digest is built from the rendered settings. So changing it in a document left
the digest identical: the planner saw no drift, the supplicant was never
repopulated, and the edit did nothing. **A network the operator had just marked
automatic stayed disabled**, and one marked manual kept being joined, until
something else forced a population.

This is the same class as 0233 and 0234 from a third direction: a statement the
operator makes that nothing acts on, because the thing that would have noticed
was not asked.

Both flags are in the digest now, and both add a line **only when the answer is
not the default**. `autoconnect` defaults to true on a device and on a network,
so a machine where everything joins automatically -- nearly every machine --
produces the same digest as the previous build, and an upgrade repopulates
nothing. 0220 arranged that asymmetry for `scan_randomization` and the reason is
the same: a digest that moved for everybody would drop every association on
upgrade.

## What is covered and what is not

- the digest, both levels: a unit test, and it fails either way round;
- the default, which is the part of the new lookup that can be wrong: absent
  means yes, tested against an empty list and a list without the radio in it.
  Reading absence as "no" would send a disable to every radio nobody had
  configured -- the opposite of the setting's meaning, and a machine with no
  wifi at all;
- **that the disable is not sent for an ordinary radio**: `enterprise.sh`, which
  asserts the command is absent. The half of a new behaviour most likely to be
  wrong is the one that fires when it should not.

Not covered end to end: that the command is *sent* when a radio says
`autoconnect = false`. No existing live test writes that document --
`privacy.sh` is about IPv6 temporary addresses and `select.sh` is about the
manager switcher, and reshaping either to carry this would have made it a test
of two things. So that half rests on the named predicate above plus a one-line
guard, and is recorded here rather than claimed.

## Sabotage

| reverted | test | result |
| --- | --- | --- |
| the network flag leaves the digest | `autoconnect_reaches_the_digest_...` | FAILED |
| the device flag leaves the digest | `autoconnect_reaches_the_digest_...` | FAILED |
| an absent entry reads as "does not join" | `a_radio_joins_by_itself_...` | FAILED |
| the disable is sent regardless | `enterprise.sh` | covered by `lacks` |
