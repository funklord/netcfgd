# 0076: the `up` hook is the moment a link is live and bare

Status: accepted
Date: 2026-08-03
Milestone: the laptop list -- five inert hook phases, and the one with a moment of its own

## Context

Five of the eleven hook phases were recognised, materialised into
`/run/netcfgd/hooks/`, hashed, carried in the document -- and never run. `up` was
one of them, and it is the one an operator reaches for after `pre_up` turns out
not to be able to see anything: `pre_up` runs while the interface is **down**, so
the kernel answers `EINVAL` for carrier and `ethtool` and `mii-tool` fail
([0011](0011-preup-runs-before-the-link-is-up.md)). `HookPhase::PreUp`'s own
documentation sent the reader to `Up` for exactly that, and `Up` did nothing.

[0063](0063-the-down-hooks-run-before-the-interface-goes.md) implemented `down`
and `post_down` and deliberately left `pre_down` alone, because it would fire at
the same point as `down` and its distinct meaning needs a teardown ordering
netcfgd does not have. `up` is the opposite case: it has a moment of its own, and
the moment is useful.

## Decision

**`up` runs after `link.up` and before anything is addressed**, and the addressing
waits for it.

That last clause is the decision rather than a detail. Three moments exist in an
interface coming up, and each is defined by what a script there can see:

| phase | the link | the addresses |
|---|---|---|
| `pre_up` | down -- carrier unreadable (0011) | none |
| `up` | **up** | **none yet** |
| `post_up` | up | installed |

Without the dependency edge, "before anything is addressed" would be emission
order and nothing more -- and this repository has already had a `depends_on` edge
that was decoration, found by deleting it and watching no test notice. So the
addressing actions, the 802.1X prerequisite and the routes all take the `up`
hook's action as a dependency.

**The price is stated rather than discovered**: a slow `up` hook delays the
addresses. That is the guarantee working, and it belongs in the phase's
documentation, which now says so.

`up` fires only where netcfgd is bringing the interface up, which is 0063's rule
for the other two up phases: a converged interface runs no hooks at all, and an
interface being taken *down* does not run its up hooks on the way.

## What the test is worth

The fixture asserts the two edges rather than the two positions -- `up` depends on
`link.up`, and `addr.add` depends on `up` -- and removing the second edge fails it
by name.

`tests/live/hooks.sh` asserts the three moments by **what each hook could see**,
which is the only way to tell a phase from its neighbour:

```
ok   pre_up ran before the link came up          (link.up = 0)
ok   and up ran after it, with the link live     (link.up = 1)
ok   but before anything was addressed           (addresses = 0)
ok   and the address was there by then           (post_up: addresses = 1)
```

Two things the writing of it cost, both worth keeping:

**`/sys` is not the namespace's.** The first version had the hook read
`/sys/class/net/hooked0/carrier`, which does not exist in an `unshare -rn` test at
all: sysfs is the host's mount, and an interface created in the namespace is not
in it. Netlink -- `ip -br link` -- is namespace-correct, which is why the `down`
hook was already using it.

**A check that counts lines is not counting runs.** `pre_up ran` was
`grep -c '^pre_up '`, and grew to 2 the moment the hook wrote a second `echo`. It
counts one specific line now. Nothing was wrong with the feature; the check was
measuring the transcript rather than the event.

## Consequences

- Seven of the eleven phases fire. The four that do not are `pre_down`, `roam`,
  `portal` and `drift`, and a plan still names each one per interface.
- **The warning that says so reads the list** rather than naming phases by hand.
  It had said "only `pre_up` and `post_up` fire" since it was written, and was
  wrong from the day 0063 landed -- a warning that misdescribes the feature it is
  warning about. Two lists of the same thing, one of them prose.
- `HookPhase::PreUp`'s documentation stops enumerating which phases fire. It had
  gone stale twice: once naming `Up` and `Carrier` when neither fired, once
  carrying a count that changed. The plan says which phases fire, per interface,
  where an operator will actually see it.
- `+0 KB`.

## What is still open

**`roam` is the next one worth having**, and it is a different shape: it wants the
supplicant's event socket rather than an observation, because roaming between
access points changes nothing netcfgd's netlink dump would show. `portal` and
`drift` are both waiting on something netcfgd does not do yet -- a captive-portal
check would need netcfgd to fetch a URL somebody chose
([0061](0061-a-key-that-compiles-does-something-or-says-it-does-not.md) refused
that as a default), and `drift` needs a decision about whether it fires per
difference or per reconcile.

**`pre_down` stays unimplemented**, unchanged from 0063: it would fire at the same
moment as `down`, and giving it a distinct meaning needs a teardown ordering that
does not exist.
