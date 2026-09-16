# 0248: a linkset is a named group of links, with one in use

Status: accepted
Date: 2026-09-16
Milestone: M9; the grouping 0246 said was coming

## What netcfgd could not say

Failover, in one sentence: *these links can reach the same place, use the best
one that actually works*. A laptop with a cable and two saved networks, a
router with fibre and an LTE modem behind it, a machine that prefers its VPN
while the VPN is up -- all the same sentence, and netcfgd had no way to write
it down.

What it had was `preference`, which is the mechanism and not the idea. It ranks
interfaces by metric and withholds the routes of one with no carrier or a
failing probe. Nothing named the group, nothing said only one of them is in
use, and **a wifi network could not be in it at all**: a `preference` lives on
an interface and a network is not one.

## The block

```ini
linkset "uplink" {
    members = ["eth0", "office", "wwan0"]
}
```

A member is an `interface` block's name, a `network` block's id, or another
linkset's name. Which of the three it is comes from the rest of the document
rather than from the block, so moving a member between kinds does not mean
editing two places.

**A linkset is itself a link**, which is the property the shape was chosen for
rather than a curiosity: a set composes into a set, so "the office pair, or
failing that the modem" needs no second mechanism. It is not a kernel device --
no index, no address, no row in the link table -- so what a set contributes to
the machine is entirely the member it picked.

**`uplink` is special by its name and nothing else.** No flag, because a
boolean needs a rule for what two of them mean and a name cannot be ambiguous.
The set called `uplink` carries the default route and is what `connectivity`
means by connected; every other name is an ordinary group.

## Choosing

Eligible members ranked by metric -- an interface's `preference`, a network's
`metric` -- lowest wins, ties going to the order the document lists them in.
That is why nothing sorts the member list: a bond's members are a set and get
canonicalised, and these are a ranking.

**An absent metric reads as 0, the strongest.** It looks backwards -- writing a
metric on one member demotes it against a member with none -- and it is the
only answer that keeps the set and the kernel agreeing, because an unnumbered
route goes into the table at metric 0 as well. A set that ranked the unnumbered
member last would choose one link while the routing table used the other.

A member is eligible when the link carrying it has carrier and has not failed
its probe. Three notes, each of which is a way to get this wrong:

* **`up` is not consulted.** It is netcfgd's own setting and a plan is usually
  in the middle of applying it, so a set that called a down link unusable would
  withhold every route on the first pass and install them on the second -- a
  machine that needs two applies to come up. Carrier is the fact about the
  world.
* **`None` is not `Some(false)`.** A link nobody probed keeps its standing,
  which is the rule that stops every set emptying on a machine with no probes.
* **A configured network nothing is on is `unjoined`, not absent.** That is the
  ordinary state of every saved network but one.

A set that names itself, directly or through a chain, is refused by the
compiler with the way round printed -- `a -> b -> a` is a fix, "there is a
cycle" is not -- and the model reports `cycle` rather than following one,
because a document can arrive over the socket without having been compiled.

## Acting

**The chosen member gets its routes and the others do not.** A spare holding a
default route at a worse metric is not a spare: it is a second path the kernel
falls back to on its own, with nothing having decided that it works. That is
the same answer `preference` already gives a link with no carrier, now said
about a group.

What this does *not* yet do is demote a lease's default route. netcfgd installs
what the document declares; on a `config = "dhcp"` member the route is
dhcpcd's, and netcfgd's only handle on it is the metric it passes the client at
startup. So on a machine whose members are all DHCP -- which is most laptops --
a set today decides, reports, and drives what "connected" means, while the
routing order stays the metric ranking it already was. Demoting a standby
member's lease is the next round, and it has a design question of its own: the
metric change means restarting the client, and restarting it on every failover
is churn on the link you are switching to.

## Two defects it found

**A probe that says no did not take away the route it already had.** 0119 says
a link failing a probe "gets the same answer" as one with no carrier, and the
carrier answer is withholding the route *and* withdrawing one already
installed. Only the withholding half was ever written. Every route on a freshly
applied machine is installed before the first probe runs, so the black hole the
probe exists to detect kept its better metric for ever. One line beside the
carrier clause, and a fixture that fails without it.

**The daemon's published record disagreed with what the daemon did.** Probe
verdicts are stamped onto a fresh observation *after* it is built -- the
observer reads the kernel and no probe result comes from there -- so everything
derived inside `augment` was derived from `reachable: null` on every link. The
set's published choice named the better-ranked link while the planner, which
reads the stamped observation, had just taken that link's routes away. The same
was true of `connectivity` with `requires = "probe"`: the rung could never
reach `online`, because the verdict it asks for had not been written yet. The
derived answers are now a named function the daemon runs again once the
verdicts are on; everything in it is pure, so a second pass changes nothing
that was already right.

## What is still divergent, and is older than this

**A probe verdict has exactly one producer.** A client that observes for itself
-- which `ncfg status` and `ncfg plan` do when they can read the kernel -- sees
`reachable: null` on every link and works out a different winner. `ncfg status`
on a machine with a running daemon can therefore print a set choice that is not
the one in the routing table.

That divergence is older than linksets and wider than them: `ncfg apply` from
the command line would re-add a route the daemon withheld for a failing probe.
What a set does is make it visible. It is recorded here and not fixed here,
because the fix is a question about where a client's observation comes from,
which is bigger than this round: `tests/live/linkset.sh` therefore asserts
against the daemon's own published record rather than against `ncfg status`.

## Twelve sabotages, all caught

The worst member winning; ineligibility ignored; an unprobed link treated as
failing; a network standing on itself rather than on its radio; a self-naming
set reported as absent; the uplink set not deciding what connected means; every
member keeping its routes; the chosen member held back with the rest;
canonicalisation sorting a ranked list; a member that resolves to nothing
accepted; the probe half of the teardown rule removed; the daemon not
re-deriving after stamping its verdicts.

The ninth passed on the first attempt and the test was the fault: it asserted
that `["eth0", "office"]` survived canonicalisation, and those two are in
alphabetical order, so sorting them changed nothing. A fixture built so that
the wrong answer and the right one are the same string -- the same shape this
campaign has found five times now.
