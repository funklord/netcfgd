# 0223: the name a hidden network will not give

Status: accepted
Date: 2026-09-13
Milestone: M9; the wifi hidden SSID audit

## Both halves of hiding were already right

A station probes for a hidden network -- `scan_ssid=1`, without which it is
never probed for and "simply never appears, with no error anywhere to say why".
An access point hides one -- `ignore_broadcast_ssid=1`, mode 1 rather than 2 and
the reason is written down. `ncfg wifi add --hidden` carries the flag from the
command line through the wire type to the written block, checked end to end. A
scan row with an empty name prints `(hidden)` rather than a blank cell, and the
comment beside that says it used to draw blank in two clients.

The defect is not in any of those. It is in the one place that has to *read* a
name rather than write one.

## A network named by address, pointed at a hidden radio

A `network` block may name access points by BSSID and leave the SSID out.
netcfgd then reads the name off the last scan when it hands the network to the
supplicant -- `pick_ssid`, split from the socket so the choosing can be checked
without one.

It had two failure cases: none of the addresses is in range, and the ones that
are disagree about the name. It was missing the third, which is the one a
BSSID-pinned network is most likely to meet:

**a hidden access point is in range and still says nothing.** Its beacons carry
an empty SSID -- that is what hiding *is* -- so its scan row has a zero-octet
name, and `pick_ssid` returned it. Measured, before the fix:

```text
parsed 1 result(s)
  bssid=aa:bb:cc:dd:ee:ff ssid=<> (0 octets)
RESOLVED to <> (0 octets)
```

`add_network` then sent `ssid ""` to wpa_supplicant. That matches nothing, and
for anything but an open network it cannot even derive the right key, because
WPA derives the key from the passphrase *and* the SSID. No error anywhere said
why -- the same silence `scan_ssid`'s own comment was written to prevent, one
layer up.

Nothing in the type system stops it: `Ssid::new` rejects only more than 32
octets, so zero is a valid SSID, and it is valid because the standard says so.

## Declining to say is not disagreeing

The first shape of the fix was to reject an empty result. That is wrong for the
mixed case, which is real: a network whose radios are listed together, one
hidden and one not.

Comparing them the old way reported *"lists access points that are on different
networks"* -- both wrong and unactionable, since they are the same network and
one of them simply declines to answer. So the silent ones are **partitioned out
before the agreement check** rather than compared:

- some advertise a name: use it, and require the advertising ones to agree;
- all of them are hidden: refuse, and say which addresses and what to do;
- none is in range: the existing error, unchanged.

"Not in range" and "in range and hidden" now read differently, and the test
asserts that they do, because they need different things done about them.

## The summary that was not there

`add_network`'s doc comment opened with a bare `///` and went straight to
`# Errors`, so the rendered page for a public function began with a heading and
the module index had nothing to show beside it.

`missing_docs` cannot see this: the comment is present. It just says nothing.

**This one is worth a gate, where the run-together case from 0219 and 0221 is
not.** That class -- two doc comments with no item between them, four
occurrences so far -- has no exact textual signature, and the lint that would
catch it reports 447 items in this tree. This one is a single unambiguous
pattern: a `///` line whose predecessor is not a doc comment and which carries
nothing after the slashes. `make style-docs` checks it now, and prints the
population it inspected -- 167 Rust files -- for the reason that mode already
prints its heading count: a verdict with no count cannot tell a clean tree from
a tree nothing looked at.

There was exactly one instance in the tree, which is what made the gate cheap
rather than a project.

## Sabotage

| reverted | check | result |
| --- | --- | --- |
| take the first found, hidden or not | `a_hidden_access_point_...` | FAILED |
| compare the silent ones for agreement | `a_hidden_access_point_...` | FAILED |
| remove `add_network`'s summary again | `make style-docs` | Error 1, named by line |

And the four existing `pick_ssid` tests were re-run **by exact name** after the
change, rather than by a filter: an earlier run in this session matched zero
tests and reported no failures, which is the same "a passing check is not
evidence" the channel audit had just found in the plan fixture.
