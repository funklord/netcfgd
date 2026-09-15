# 0245: a link has a kind, and presence is three-valued

Status: accepted
Date: 2026-09-15
Milestone: M9; the links view

## What the GUI was calling things

The first tab was named `devices` and showed `ncfg_client_links()` -- interface,
kind, state, network, addresses, mtu, mac. So it was the **link** list wearing
the other noun, and there was no view of `device` blocks at all: no hardware
identity, no `mac_policy`, no `regdom`, no backend choice.

The document has had the split since the beginning. A `Device` carries what has
to be true before a link can exist -- a `DeviceMatch` on MAC or PCI path, `mtu`,
`mac_policy`, `regdom`, the wifi backend, `managed`, and the `InterfaceKind` for
the virtual ones netcfgd creates. An `Interface` carries the networking:
`addressing`, `routes`, `preference`, `dns`, `probe`, `hooks`, `nat`,
`forwarding`.

**The two-list shape is not a new idea, it is the model's own**, and the GUI was
the thing out of step. Renamed to `links`, which costs one string.

Collapsing them into one list was considered and is wrong for a reason that is
not taste: **the cardinalities differ**. One device carries many links -- a
trunk port with several VLANs, a radio with several networks -- and one link
spans devices, which is what a bond is. Either direction of collapse means
duplicating device settings per link or burying link settings under a device.
`ObservedLink::master` already supports the other half of the operator's
instinct: a card enslaved to a bridge or bond can be shown greyed with the
reason named, and that enslavement is a *link* property.

## A filter cannot be built from `kind`

Measured on the reporting machine:

```text
enp0s31f6   kind=""           wireless=false
wlp0s20f3   kind=""           wireless=true
lo          kind=""           wireless=false
docker0     kind="bridge"     wireless=false
wg-test     kind="wireguard"  wireless=false
```

**The kernel reports an empty kind for every real card.** Wired, wireless and
loopback are one value there; `wireless` separates the radio and the name
separates the loopback. And nothing on a link says *modem* -- `sim.rs` puts that
in exactly one place, a `device` block with a `modem` policy, so the rule needs
the document as well as the observation.

So "show me only the radios" is a small rule over three sources, and
`netcfgd_model::link::category_of` is where it lives. Carried on `ObservedLink`,
through the C client, into the row type; no client classifies anything.

**This is not a consolidation, which makes it unusual here.** 0243 and
`wifi::network_for` each pulled a rule back after several clients had written
their own. No client classifies links today, so this is the same mistake
declined in advance -- and the failure it avoids is the quiet kind: a link in no
category is a row that simply does not appear in a filtered list.

A category the daemon has no word for is `Other`, never absent, for the same
reason.

## A configured wifi network is a link

The holder's position, and the model half agrees already. A `network` block
carries `addressing`, `routes`, `dns`, `metric` and `hooks`; an `Interface`
carries `addressing`, `routes`, `dns`, `preference` and `hooks`. **A wifi
network is already a link in all but name**, and `metric` against `preference`
is the same number under two spellings that 0154 had to reconcile once.

So unifying removes a duplicate rather than adding a concept, and it is what
makes a linkset expressible: a group holding `eth0` and `wifi:office` and
picking one requires both to be the same kind of thing.

**Identity is the block's label, and that answers the case the holder was unsure
of.** Every `network` block is named, and `network "office" { ssid = "@bssid";
bssid = [...] }` gives one name to a whole set of access points. The
ssid/bssid/ssid+bssid scheme describes how a *default* label is chosen; a list
of BSSIDs under one SSID is one network the operator named, which is exactly
what a label is for.

## Presence is three-valued, and the third value is the point

The links view was called observation-driven in this discussion, and that was a
statement about today's code rather than about the design -- the tab renders
`observed.links`, which is netlink's table. The holder's model is right: a link
is configuration.

What survives is that the row set is a **union of two sets that do not
coincide**, with three provenances:

- configured and present -- the ordinary case;
- configured and not present -- a saved network out of range, an `interface`
  whose card is not plugged in;
- present and not configured -- `docker0`, a card another manager owns.

The second is why the list cannot stay observation-driven and the third is why
it cannot become document-only.

**And presence is not a boolean.** Raised by the holder and it is the sharpest
point in the discussion: a hidden network, or any network on a radio that is not
allowed to probe actively, cannot be found by looking. netcfgd already says so
in its own words, in `pick_ssid`:

```quote from=backend/netcfgd-supplicant/src/lib.rs
the access points `{}` names are in range and hidden, so a scan cannot say what
the network is called
```

A hidden access point still beacons, so its **address** is observable and the
name-to-address mapping is not. `scan_ssid=1` is what sends a directed probe for
a hidden name; where that is refused -- by policy, or on a `no IR` channel where
transmitting first is forbidden, which `device.rs` documents for 5180 and 5260
-- there is no method that could find it. The only evidence is an attempt to
associate.

So presence is:

- **present** -- seen;
- **absent** -- looked, with a method that would have found it, and it was not
  there;
- **unknown** -- no method available that could have found it.

This tree already has that convention and states it twice.
`ObservedLink::reachable` says `None` "is **not** the same as `Some(false)`",
and `ObservedBackend::networks_match` says the same about a supplicant netcfgd
could not ask. 0241's `started_metric` is a third. The rendering rule follows:
**unknown must never be drawn as absent** -- a hidden network shown as "not
present" looks permanently gone, and the operator's correct response, which is
to try it, is the one thing that display argues against.

**The consequence for linksets, recorded now rather than rediscovered.** A group
that picks one member cannot conclude "absent" from "I did not see it". For a
hidden member the only evidence is an attempt, so selection may have to *try*
rather than only observe -- which changes the cost of a failover decision from
free to an association attempt, and is the shape of "why does it not switch to
my hidden network".

## Sabotage

Two on the filter, both caught: hiding an uncategorised row, and `all` ceasing
to mean all. The second rule is the one with the trap in it -- an empty category
means a daemon older than the window, and such a row shows in **every** filter
rather than in none, because a row that disappears when two programs disagree
about its kind is the worst outcome available here.

The filter's rule is a free function beside the row type it is about rather than
a member of the view, so it can be checked without a daemon, a window or a row.
Reaching it through the view would have dragged the whole dialog chain into a
test binary for three lines.

## Not done

The links list is still the observation. Making it the union above, and giving
`state` a value for "not present" and another for "unknown", is the next step
and it needs no document change. The document change -- one schema for link
configuration instead of `interface` and `network` carrying near-identical
fields -- is the expensive half and is its own round.
