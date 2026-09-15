# 0246: the link list is a union, and presence is its own column

Status: accepted
Date: 2026-09-15
Milestone: M9; the links view, second pass

## What 0245 left

0245 settled the shape and changed none of it: the link list is a union of two
sets that do not coincide, and presence has three values because a hidden
network cannot be found by looking. This is that, built.

## The union

`netcfgd_model::link::inventory` takes the document and the observation and
returns every link this machine has or has been told about. Three provenances,
all of them in the list:

| provenance | example on the reporting machine |
|---|---|
| configured and present | `wlp0s20f3`, `OpenPC.se` |
| configured and not present | a saved network out of range; an `interface` whose card is out |
| present and not configured | `docker0`, `wg-test`, `enp0s31f6` |

Dropping either half loses something real. An observation-only list cannot show
a configured network that is out of range, because there is no kernel link for
it at all. A document-only list would hide `docker0`, which is demonstrably on
the machine and holding an address.

**It sits beside `observed.links` rather than replacing it**, and that is not
tidiness. The planner iterates `links` as "what the kernel has" -- `has_carrier`,
`link(name)`, the drift passes -- and a synthetic row for something that does
not exist would be read as one that does. Two lists, one of which is a
superset, is the smaller risk.

## Presence

Three values, with the asymmetry between an interface and a network being the
whole rule.

**An interface is present or absent and never unknown.** The kernel's link table
is complete: netcfgd has seen every interface there is, so one it cannot find is
one that does not exist. There is no third answer because there is no question
netcfgd was unable to ask.

**A network can be unknown, and often is.** `presence_of_network` takes whether
a radio is on it, and what a scan said as an `Option<bool>`:

- associated -- `Present`, and it outranks a stale scan that disagrees;
- hidden -- `Unknown`, *even when a scan has been read and did not find it*;
- seen -- `Present`; looked for and not seen -- `Absent`; no scan -- `Unknown`.

The hidden case is what the enum exists for. A hidden access point beacons with
an empty name, so a scan sees its address and not its name -- which is what
`pick_ssid` refuses over -- and on a `no IR` channel the directed probe that
would resolve it is forbidden. "Not in the scan" is not evidence about a hidden
network, and treating it as evidence reports a network that is right there as
gone.

**An enum rather than `Option<bool>`, deliberately.** The rendering rule is the
reason: unknown must never be drawn as absent, and a type whose third state is
spelled `None` invites exactly that collapse at the point of display. The tree
states the same convention twice in `Option<bool>` form -- on
`ObservedLink::reachable` and `ObservedBackend::networks_match` -- and both
carry a paragraph warning the reader not to conflate them. Here the type does
that work instead.

Today the observation carries no scan results, so a configured network that
nothing is associated with reads `Unknown` rather than `Absent`. **That is
honest rather than unfinished**: narrowing it needs a scan, and for a hidden
network no scan could settle it anyway. A caller holding scan results can ask
`presence_of_network` directly, which is why the rule takes its evidence as
arguments rather than reaching for it.

## What the machine says

```text
EMP-XYLEM    wifi       unknown   configured=true
OpenPC.se    wifi       present   configured=true
docker0      bridge     present   configured=false
enp0s31f6    ethernet   present   configured=false
lo           loopback   present   configured=false
wg-drop      wireguard  present   configured=false
wg-test      wireguard  present   configured=false
wlp0s20f3    wifi       present   configured=true
```

Two of those rows looked wrong on first reading and were not: the radio had
moved to `OpenPC.se` since the last time this session looked at it, and
`EMP-XYLEM` is `unknown` because nothing has scanned for it -- not because it is
hidden. Checked rather than assumed, which is the only reason it is recorded as
correct.

## The view

The row set is the union where the daemon reports one, with the detail columns
-- kind, state, network, addresses, mtu, mac -- looked up from the observed link
by name. **A row with no observed link has those cells blank rather than
invented**, which is the honest rendering of a link that is not there.

A daemon that reports no inventory is one older than the window, and the list
falls back to the kernel's links rather than going blank. That path marks every
row `present`, which is true of it: the kernel has the link.

## Sabotage

Five, all caught.

| what was broken | what caught it |
|---|---|
| a hidden network treated as scannable | `a_hidden_network_is_unknown_and_not_absent` |
| no scan read as absent | the same test |
| an interface's absence read as unknown | `an_interface_is_present_or_absent_and_never_unknown` |
| the union drops unconfigured links | `the_inventory_is_a_union_of_two_sets_that_do_not_coincide` |
| the union drops absent interfaces | the same test |

## Still not done

The document change. `interface` and `network` still carry near-identical
configuration -- `addressing`, `routes`, `dns`, `metric` against `preference`,
`hooks` -- and collapsing them into one schema for link configuration is the
expensive half, with a format change, the compiler and migration behind it.
Nothing here depends on it, which is why it was left.
