# 0230: the privacy option that named the vendor

Status: accepted
Date: 2026-09-14
Milestone: M9; the wifi MAC address and randomization audit

## This ground was walked before

0220 audited this area and implemented `scan_randomization`. What it did not do
was check the numbers `mac_policy` turns into against the daemon that reads
them, because a test already asserted them -- and that test had been written
from the mapping rather than from `wpa_supplicant.conf`.

Its own doc comment names the risk exactly:

> The numbers are not guessable from the names, and getting one wrong is a
> privacy setting that silently does something else.

It then asserted the wrong number.

## Two is not "more random", it is "keeps the vendor"

`wpa_supplicant.conf` documents the three values of `mac_addr`, per-network and
global alike:

```text
0 = use permanent MAC address
1 = use random MAC address for each ESS connection
2 = like 1, but maintain OUI (with local admin bit set)
```

netcfgd's table read:

```text
Permanent      0   uses the hardware address
PerNetwork     1   a random address per ESS
PerConnection  2   a random address per association
```

**2 is not a random address per association.** It is 1 with the manufacturer
prefix preserved -- the first three octets, which say who made the radio. So for
the policy netcfgd documents as the strongest, and which an operator picks when
they want the most privacy available, netcfgd was sending the one value that
identifies the hardware.

Checked against a real supplicant on the `none` driver, so no radio was
involved:

```text
SET_NETWORK 0 mac_addr 0  -> OK
SET_NETWORK 0 mac_addr 1  -> OK
SET_NETWORK 0 mac_addr 2  -> OK
SET_NETWORK 0 mac_addr 3  -> FAIL
SET_NETWORK 0 mac_addr 4  -> FAIL
```

Three values and no fourth, so there is no number that ever meant "per
association". The distinction netcfgd's model offers is not one this key makes.

## What does separate them

`rand_addr_lifetime`, a global, 60 seconds by default:

```text
GET rand_addr_lifetime -> 60
SET rand_addr_lifetime 0 -> OK
```

A random address is reused while it is still in date, so rejoining the same
network inside a minute comes back on the same address. That is exactly
`per_network`'s documented meaning -- *"a fresh address per network, kept for
the association"* -- and zero is exactly `per_connection`'s.

So both randomising policies send `mac_addr 1`, and the lifetime is what tells
them apart. Sent in both directions rather than left at the supplicant's own 60,
for 0015's reason: a privacy property that depends on somebody else's default is
not a property.

**A global costs nothing here**, which is worth stating because it usually
would. `mac_policy` is a property of the *device*, so there is one policy per
radio, and netcfgd runs one supplicant per radio. There is no second network on
the same radio to disagree with.

## What this changes for a machine already running

`per_connection` moves from `mac_addr 2` to `mac_addr 1`, which is strictly more
private -- the address stops carrying the manufacturer prefix. `per_network`
keeps `mac_addr 1` and gains an explicit 60. Nothing gets weaker.

The prefix-keeping value is now unreachable from the model. Admitting by vendor
is a real thing to want and some networks do it, but it is a third policy rather
than a stronger version of the second, and nothing has asked for it.

## The fifth fixture written from the code

This is the pattern this campaign keeps finding, and the clearest instance of
it so far: a test that stated the hazard in prose, in the same paragraph as the
assertion that embodied it. 0222 had two fixtures built from the implementation,
0224 a third, 0225 a seam that simulated its own call site, and this is the
fifth.

What separates this one is that the correct source was a file on the same
machine the whole time. `wpa_supplicant.conf` is installed at
`/usr/share/doc/wpasupplicant/examples/`, it documents the key in two places,
and both say the same thing. Nobody opened it.

## Sabotage

| reverted | test | result |
| --- | --- | --- |
| `PerConnection` sends 2 again | `the_mac_policy_maps_to_the_documented_numbers` | FAILED |
| " | `the_mac_policy_is_always_sent` | FAILED |
| the two policies share a lifetime | `the_mac_policy_maps_to_the_documented_numbers` | FAILED |
| the lifetime is not sent | `enterprise.sh` | FAILED |

The third is the one worth having: with both policies on `mac_addr 1`, a
lifetime that does not differ makes `per_connection` and `per_network` the same
setting under two names, which is the failure this fix could most easily have
shipped with.
