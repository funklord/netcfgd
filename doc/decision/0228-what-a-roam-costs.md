# 0228: what a roam costs

Status: accepted
Date: 2026-09-13
Milestone: M9; the wifi rekey and PMK caching audit

## Rekeying is not netcfgd's to set, and it was right to leave it

Nothing in this tree writes `wpa_group_rekey`, `wpa_ptk_rekey`,
`wpa_gmk_rekey`, `wpa_strict_rekey` or `disable_pmksa_caching`, and after
reading hostapd's own documentation on the reporting machine that is the
correct answer rather than an omission:

```text
wpa_group_rekey       defaults to 86400 with CCMP, 600 with TKIP
disable_pmksa_caching 0 = PMKSA caching enabled (default)
wpa_ptk_rekey         "PTK rekeying is buggy with many drivers/devices"
```

The group key already rotates daily under CCMP, caching of keys made by EAP is
already on, and upstream warns against forcing pairwise rekeying at all. A
setting netcfgd wrote here would be netcfgd overriding a good default with a
number nobody asked for.

hostapd's `okc` is in the same position for a different reason: it shares a key
cache "among configured interfaces and BSSes (i.e., all configurations within a
single hostapd process)", and netcfgd runs one BSS per radio, so there is
nothing for it to share with.

## The station side is netcfgd's, and it was left expensive

A `roam` block becomes a `bgscan`, so **netcfgd is what decides how hard the
radio looks for a better access point**. It turns roaming on and it did not
turn on the thing that makes a roam cheap.

On an enterprise network a move to a new access point means a full EAP exchange
with the authentication server -- several round trips, during which traffic
stops -- unless the pairwise key can be carried across. Opportunistic key
caching is what carries it. From wpa_supplicant's own documentation:

> By default, OKC is disabled unless enabled with the global `okc=1` parameter
> or with the per-network `proactive_key_caching=1` parameter.

netcfgd set neither. Measured against wpa_supplicant 2.10 on the `none` driver,
so no radio was involved:

```text
GET okc                          -> 0     the default
SET okc 1                        -> OK    reads back 1
SET_NETWORK 0 proactive_key_caching 1 -> OK    reads back 1
SET not_a_real_global 1          -> FAIL  an unknown global is refused
SET_NETWORK 0 not_a_real_key 1   -> FAIL  and so is an unknown network key
```

**A weaker control than `sae_pwe`'s, and worth saying so.** `SET okc 7` also
answers `OK`, so this parser does not range-check the value. What the `FAIL`
lines establish is that the *key* exists -- not that the value was understood.
`sae_pwe` at least refused 99, even while assigning it (0226).

## Why this is safe to turn on for everybody

Where the access points do not share a key, nothing changes: the station offers
a `PMKID`, the access point does not recognise it, and a full authentication
happens exactly as before.

It cannot leak the key either. A `PMKID` is derived from the pairwise master key
and both addresses, so an access point that does not already hold the key can
neither produce one nor use one -- which is what makes offering it to a stranger
uninteresting rather than dangerous.

## The global, and the cost of that choice

Sent as the global `okc`, not as a per-network `proactive_key_caching`, for the
reason `preassoc_mac_addr` and `sae_pwe` are globals: it is netcfgd's own choice
about how to drive a supplicant rather than anything the document asked for.

The per-network form would have one advantage -- it enters the networks digest,
so netcfgd could tell whether a running supplicant has it. It would also change
that digest on every machine with a wireless network, which repopulates every
radio on upgrade and drops every association. 0220 arranged the digest
specifically to avoid that, and this is not the setting to reverse it for.

The cost of the global is the one 0226 recorded for `sae_pwe`: it is sent at
populate time, so on a machine whose supplicant is already running it takes
effect at the next populate -- a configuration change, a supplicant restart or a
reboot. **Three settings now share that property**, and it is worth naming as a
class rather than rediscovering it a fourth time.

Not fatal, for `sae_pwe`'s reason: a supplicant that will not take `okc` cannot
do opportunistic key caching at all, so there is nothing to fall back to and
nothing worth losing every network on the radio over.

## Sabotage

Covered by `tests/live/enterprise.sh`, which is the file that configures an
enterprise network -- the case this setting is about -- and which drives a real
daemon against a fake supplicant and reads what was sent.

```text
ok   key caching across access points is on     (with the fix)
FAIL key caching across access points is on     (with the command renamed)
```

That suite is not part of `make check`, which is the same weaker half of the
evidence 0226 recorded, and for the same reason: an executor sending a command
is not something a unit test can render.
