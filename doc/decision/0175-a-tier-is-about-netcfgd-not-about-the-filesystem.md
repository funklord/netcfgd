# 0175: a tier is about netcfgd, not about the filesystem

Status: accepted
Date: 2026-09-08
Milestone: M8; corrects the *reasoning* in
[0174](0174-netcfgd-can-list-its-own-configuration.md) and in
[0013](0013-three-things-a-caller-may-be-allowed-to-do.md)'s implementation, and
leaves both outcomes standing

## The correction

Stated by the copyright holder, twice, after this tree had argued otherwise:

> You are still confusing file with netcfgd permissions. An observer is
> allowed to request the data from netcfgd, and an admin is allowed to write
> all the data via netcfgd and request secrets as well.

> netcfgd bridges the host gap, so never confuse them.

## What was wrong

`authorize.rs` placed `ProbeList` at `observe` partly because "the files are
0755 on disk so anybody on the machine can already read them", and 0174
repeated the shape for `ConfigList`: "world-readable on disk", "adds nothing a
local user does not have".

**Both tiers are still right. Both arguments were wrong**, and that is worse
than it sounds: a correct decision resting on a wrong reason is one the next
person applies to a case where the reason holds and the decision does not.

**The reasoning assumes the caller is on the machine, and spanning that gap is
what netcfgd is for.** The peer may be another user, a process in another
namespace, or -- once `remote` is in use -- somebody with no filesystem in
common with this host at all, which is why [0128](0128-origin-is-which-socket-you-arrived-on.md)
gives remote callers a policy of their own. "Anybody local could read it
anyway" is a fact about somebody else, not about the caller.

It fails from the other end too. A mode changes, or the answer stops being a
file -- half of what these requests return is assembled from netlink and from
memory and was never on disk -- and the justification evaporates while the
tier it was used to justify stays.

## The rule

**Ask only what the caller is asking netcfgd to do.**

    observe   request the data netcfgd holds
    admin     write all of it through netcfgd, and request secrets

Everything else is detail about the answer's *contents*. That is worth naming
-- `ApStations` says in as many words that it hands out other people's
hardware addresses -- but it is not what decides the tier.

## What this opens, and does not settle

The holder's sentence puts **requesting secrets** inside `admin`. netcfgd has
no request that returns a secret's value: `SecretList` carries names and
whether the store holds them, `install_secret` says "the only direction
credentials travel in netcfgd is inward", and the gui's credentials tab is
built on the same rule.

That is a real gap between what the tier is defined to permit and what the
protocol offers, and closing it is a change to a boundary several records rest
on ([0042](0042-only-a-key-nobody-can-revoke-stops-a-plan.md) on what cannot
be got back, [0127](0127-netcfgd-is-the-only-writer-and-the-socket-carries-the-rest.md)
on the socket's direction). **It is recorded here rather than built**: a verb
that returns credentials is the copyright holder's to ask for, and inventing
one from a sentence about tiers would be reading an instruction wider than it
was given.

## Consequence

No behaviour changes. The comments in `authorize.rs`, the doc on
`Request::ConfigList`, `doc/socket-protocol.md` and project.md 10.64 say why
each tier is what it is in terms of netcfgd, and the two that appealed to file
modes say what was wrong with doing so -- because the argument is what gets
copied, and this one was copied once already.
