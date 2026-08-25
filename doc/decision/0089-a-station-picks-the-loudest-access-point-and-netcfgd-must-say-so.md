# 0089: a station picks the loudest access point, and netcfgd must say so

Status: accepted
Date: 2026-08-04
Milestone: the wifi netcfgd had forgotten how to ask for

## Context

An ESS is several access points sharing one SSID. A station picks whichever of
them it hears best, and moves as it walks — the oldest thing wifi does, and the
one nobody writes down any more.

netcfgd could not ask for it. `wpa_supplicant` roams within a network block by
itself, but **only while a `bgscan` module is asking it to look**. Its own
configuration says so:

> These modules are responsible for requesting background scans for the purpose
> of roaming within an ESS (i.e., within a single network block with all the APs
> using the same SSID).

Nothing in this repository set one. Grepped: no `bgscan` anywhere, in any crate,
in any test. So every netcfgd station re-selected an access point only after the
link had already gone — a client that roams by first losing the network.

## Decision

**A `roam { }` block on a network, stating intent rather than a module.**

```
network "Corridor" {
	wifi {
		psk = "@secret:Corridor"
		roam { signal = -68; interval = 20; slow_interval = 240 }
	}
}
```

Three numbers: below `signal` dBm the link is weak enough to look for better,
`interval` seconds between scans while it is weak, `slow_interval` while it is
not. Defaults `-70`, `30`, `300` — `wpa_supplicant`'s own documented example,
rounded to numbers an operator would recognise.

**No module name in the document.** `netcfgd-supplicant` renders
`bgscan="simple:<interval>:<signal>:<slow>"`, the way every other backend detail
is rendered rather than passed through (design section 8). A
`bgscan="simple:30:-70:300"` in `netcfgd.conf` would be netcfgd asking the
operator which supplicant is underneath. `simple` and not `learn`: the learn
module keeps a channel database on disk, which is a second piece of state
netcfgd would then own the lifetime of, and its benefit is fewer scans rather
than better roaming.

**Off unless asked for.** `wpa_supplicant`'s own default, and the right one: a
background scan costs airtime and interrupts traffic, and a router with a radio
or a server that never moves should not pay for it.

**Pinned or roaming, never both.** `bssid` says "use this access point" and
`roam` says "use whichever is loudest"; given both, `wpa_supplicant` scans in the
background for a better BSSID it is then forbidden to associate with.

That check lives where the whole network is known, not inside the `wifi` block —
`bssid` is a network key and `roam` is a `wifi` one, so a check made inside the
inner block would have been made before the pin was read, and the contradiction
would have been caught or missed depending on which of two lines somebody typed
first. Both orders are in the test for exactly that reason.

## What was measured

**`wpa_supplicant` 2.10 accepts `bgscan` over the control socket.** That is not
the same question as the config file taking it, and the difference is a real one:
netcfgd writes no config file for a station — it sets fields with `SET_NETWORK`,
which goes through `wpa_config_set` against a table of settable fields. A key the
file parser takes and the socket rejects would leave roaming silently off with
the daemon reporting a configured network.

Asked, in `backend/netcfgd-supplicant/tests/live.rs`, against a real
`wpa_supplicant` on the `wired` driver: `SET_NETWORK <id> bgscan
"simple:20:-68:240"` is accepted, and `GET_NETWORK` reads it back — which is the
half that says it was stored rather than accepted and dropped.

## The gates

Rendering, both ways: a roaming network produces the module string, and one that
did not ask carries no `bgscan` at all. Removing the rendering turns the first
red; **swapping the interval and the threshold also turns it red**, which is the
one worth having — `simple:-68:20:240` is a plausible-looking string that scans
every -68 seconds above a 20 dBm signal, and no roaming at all.

In the compiler: the block parses, an empty one takes the defaults, a network
that does not mention it does not get it, a positive or absurd signal is refused
with what dBm is, an `interval` longer than `slow_interval` is refused as the
policy inverted, and a pinned network that also roams is refused in both writing
orders.

The document witness carries a roaming network of its own rather than adding the
field to one that is pinned — the two are mutually exclusive, so a sample with
both would pin a document nothing can produce. Additive: a **minor** bump.

## What this does not do

**The `roam` hook still does not fire.** 0084 left it as wanting the supplicant's
event socket rather than an observation, and that is still true — this decision
makes the station roam, and nothing yet tells a script that it did.

**An access point identified only by BSSID is still not expressible.**
`wpa_supplicant`'s `ssid` is mandatory in a network block and `bssid` only
narrows one, so "join this MAC, whatever it calls itself" cannot be passed
through: netcfgd would have to scan, find that BSSID and learn its SSID before
writing the network. That is a real feature and a different one, and it is
recorded here rather than guessed at.
