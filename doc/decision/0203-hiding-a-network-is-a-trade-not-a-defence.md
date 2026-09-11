# 0203: hiding a network is a trade, not a defence

Status: accepted
Date: 2026-09-11
Milestone: M8; the wifi hidden network and SSID audit

## What was already right, and it is most of it

The SSID handling is the strongest part of this tree's wifi surface, and this
audit changes none of it.

`Ssid` is octets rather than a string, because 802.11 places no encoding
requirement on a name and real networks ship ones that are not UTF-8. Its
canonical encoding is lowercase hex, and uppercase is *refused* rather than
accepted, so two spellings of one SSID cannot exist. 33 octets is refused with
the count in the message. Two `network` blocks with one name is refused naming
where the first was defined.

An empty name is refused with the sentence somebody actually needs:

```text
a `network` block needs a name
  help: the label is the SSID; a hidden network is `hidden = true` beside its
        own name, not an empty one
```

-- which anticipates the exact confusion this audit went looking for.

**SSIDs reach the supplicant as hex, always**, and the reasoning is written
where it is done: a network called `"; REMOVE_NETWORK all; "` should be a
network with a silly name rather than a command, and hex removes the question
instead of answering it carefully. `scan_ssid=1` for a hidden network is tested
in both directions, and `ignore_broadcast_ssid=1` for a hidden access point is
checked against a real hostapd in `ap.sh`.

## What was wrong: the caveat never reached the reader

`AccessPoint::hidden` carries this, in the model:

> Not a security measure and not documented as one: it stops the network
> appearing in a list and makes every client that knows it broadcast the name
> while probing, which is worse than the problem.

The shipped reference said none of it. The access point's `hidden` appeared in
a block with no explanation at all, and the station side got one line -- "A
hidden network has to be probed for by name" -- which states the mechanism and
not what it costs.

**Probing by name means sending the name, in the clear, from wherever the
machine happens to be.** A laptop configured for a hidden network announces it
in every airport it passes through. That is the opposite way round from how
hiding is usually described, and it is the fact somebody choosing `hidden`
needs before choosing it, not after.

Both places say it now. Documented rather than warned about, which is the same
treatment `powersave` and the rest get: it is a legitimate thing to want --
sometimes a network has to be set up to match one that already exists -- and a
warning on every hidden access point would nag somebody who has already decided.

This is the third fault found in `netcfgd.conf.example` in one session, after a
missing `probe` block and a `mac_policy` value that does not exist. The gate
from 0200 compiles its blocks; none of these three were compile failures.

## Two tests that should have existed

Asked whether every check this session had been made into a script. The answer
was **no, once**, and the audit that followed found a second:

- `warn_mac_contradiction` (0200) was verified by hand at a terminal and
  committed on that basis. It now has a fixture test asserting it fires on the
  contradiction and stays quiet on a pinned address alone and on a randomising
  policy alone -- the second and third being exactly the shape the 0201/0202
  false positive took.
- `probe_gate.py` had no test at all, and its predicate had just been changed
  to fix a false positive. It now self-checks on the seven lines that have
  confused it, including `"$ncfg" plan &`, which looks like a backgrounded
  netcfgd and is the client.

Both sabotages land: restoring the `&&` bug takes the self-check red, and a
predicate that never fires takes it red the other way.

The order was wrong in both cases -- the test after the fix, and the fix after
the ship -- and saying so is the point of recording it.
