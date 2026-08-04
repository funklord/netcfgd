# 0090: a network may be named by its access points

Status: accepted
Date: 2026-08-04
Milestone: the second half of the wifi netcfgd had forgotten how to ask for

## Context

A network was an SSID and optionally one pinned BSSID. Two ordinary ways of
describing wifi could not be written down:

- **"that access point, by address"** — the one in the lobby, whatever it calls
  itself. Two access points share an SSID and you want a specific one; or the
  name is generic and the address is what identifies it.
- **"any of these"** — a site's access points, listed, join whichever is best.

The first looks like it should already work: `bssid` exists. It does not, because
`bssid` *narrows* a network that is still identified by its SSID, and the SSID
came from the block's label. There was no way to say "I do not know the name".

## What decided the design

`wpa_supplicant`'s configuration has a wildcard-SSID example, which would seem
to make all this unnecessary. It is annotated:

> Wildcard match for SSID (**plaintext APs only**). This example select any open
> AP regardless of its SSID.

**WPA derives its key from the passphrase and the SSID.** A secured network
cannot be joined without knowing what it is called — not as a parser limitation
but as arithmetic. So a network named by address has to have its name *read*
before anything is sent, and there is no passthrough that avoids it.

That settles where the work happens: netcfgd resolves, from a scan, at apply
time.

Measured on `wpa_supplicant` 2.10 rather than assumed, and both answers matter
because netcfgd writes no config file for a station — it sends `SET_NETWORK`,
which goes through a different table of settable fields than the file parser:

- `bssid_accept` is accepted over the control socket and reads back.
- `bgscan` likewise (0089).

## Decision

**`bssid` takes one address or a list.**

```
network "Lobby" {
	bssid = "aa:bb:cc:dd:ee:ff"
	ssid  = "@bssid"
	wifi  { psk = "@secret:lobby" }
}

network "Site" {
	bssid = ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
	wifi  { psk = "@secret:site"; roam { } }
}
```

**One pins, several choose.** `wpa_supplicant` spells those differently and the
difference is the feature: `bssid` refuses every other access point, while
`bssid_accept` limits selection to the set and lets the supplicant pick among
them by signal. Rendering a list as a pin would join one of them and never move.

That also settles a rule 0089 got half right: a *pin* contradicts a roam policy,
a *list* does not. "Any of these, whichever is loudest" is exactly what an
operator who listed their site's access points wants, and it is now the one case
where naming addresses and roaming compose.

**`ssid = "@bssid"` says the name is not the operator's to state.** The `@` is
the DSL's existing mark for a value resolved elsewhere, as in `@secret:NAME`.
Required rather than inferred from `bssid` alone: a network's label is its SSID
by default, and quietly changing what that means for anything carrying a `bssid`
would re-point configurations that work today.

`WifiNetwork::ssid` is therefore `Option<Ssid>`, and `bssid_pin: Option<String>`
becomes `bssid: Vec<String>`. **Major** bump.

## Resolution

`add_network` reads `SCAN_RESULTS` and takes the name the listed addresses
advertise, before any setting is sent — so a network whose access points are out
of range leaves nothing half-configured.

**No `SCAN` is issued.** A scan takes seconds and interrupts traffic on the
radio, and this runs inside an apply. If the access point is not in what the
supplicant last saw, the honest answer is that netcfgd cannot see it — with the
address in the message, because "network not found" about a network identified
by address is not a sentence anybody can act on.

**Addresses that disagree are refused.** Two BSSIDs advertising different names
are two networks; one passphrase cannot be right for both, WPA's key being
derived per SSID. Picking either would be netcfgd choosing for the operator.
One in range and one not is fine: the absent one says nothing.

The choosing is `pick_ssid`, split from the socket so that "none of them is in
range" and "they are on different networks" can be checked without a supplicant.

## Elsewhere

`configured_for` — which labels a scan result with the network block it belongs
to — matches by address for a network that has no SSID to match on. Without it,
exactly the networks whose point is being identified by address would show as
unconfigured in `ncfg wifi scan`, which is the list an operator checks to see
whether netcfgd knows about what it can see.

The NetworkManager shim leaves the SSID out of a profile it has not resolved
rather than projecting an empty one, which would describe a profile matching
anything; and it does not project a *list*, NM having no "any of these". The
addresses are still in netcfgd's own document. Constraint 6's direction: the
shim reports what netcfgd has and does not invent what it does not.

## The gates

Compiler: one address, a list, a list that also roams, and a discovered name
with nothing to discover it from. Renderer: one pins and several become the
masked `bssid_accept` list; an unresolved network is refused rather than sent as
an empty SSID, which would associate with anything. Resolution: an address
matched case-insensitively (an address an operator typed and one a driver
reported differ in case often enough that exact comparison is a bug waiting for
a capital letter), several that agree, one present and one absent, none present,
and two that disagree.

Three breaks, each failing exactly one test: a list rendered as a pin,
case-sensitive matching, and never comparing the names.

**One of those breaks was read wrongly first.** A test asserting the network's
*id* appeared in the message was failing before any break was applied — the
fixture helper's first argument is the SSID, not the id — so it showed as FAILED
in all three runs and made each break look like it caught two things. The signal
was still there, but a constant failure in a break sweep is noise that reads
exactly like evidence. Fixed, and the sweep re-run to confirm each break fails
one test and the right one.
