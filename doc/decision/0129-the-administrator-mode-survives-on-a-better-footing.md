# 0129: The administrator mode survives, on a better footing

Status: accepted
Date: 2026-08-20
Milestone: M8's desktop half

Answers the question
[0127](0127-netcfgd-is-the-only-writer-and-the-socket-carries-the-rest.md)
left open: "Whether the elevator survives is decided when the classification
is." It is decided, and it survives.

## What decided it

0127 removed the premise 0118 and 0120 were built on. Both exist because a
desktop client cannot write `/etc/netcfgd`, so changing the control policy
needed a privileged process -- an elevator, a toolkit-free helper, and a red
frame that means a real credential boundary. Under 0127 a client no longer
needs to write anything: it asks, and netcfgd writes.

That could have made the whole mechanism unnecessary. It did not, because the
classification put the control policy in `Reason::Authorization`:

> `control { admin = "any" }` and `remote { admin = true }` are
> ordinary-looking assignments that widen the authorization policy, so a caller
> able to send either can grant itself -- or the network -- what it was not
> given.

So `config_put` carrying a `control` block needs **root on this machine**,
which is exactly what a desktop client is not. Asking the daemon reaches the
same refusal by a longer route.

## Decision

**`ncfg control set` keeps its direct write, and the administrator mode keeps
its job.** 0118's two ways to be allowed and 0120's process boundary are
unchanged.

## Why this is not an exception to 0127

0127's rule bounds *clients*, and the distinction is worth stating because
somebody will otherwise read the two records as contradicting each other and
"fix" it.

A client is a program run by somebody who is not root, on behalf of a person
who cannot write system files. Root with an editor was never a client, and
`ncfg control set` is a typed editor for one block -- it exists so that the
policy is written correctly rather than so that somebody unprivileged can
write it. Routing it through the socket would add a hop and change nothing
about who may do it, because the daemon refuses the same caller for the same
reason.

**And it would reintroduce a deadlock this project has already paid for
once.** `ncfg control set` is what opens the socket to a desktop user, and the
session that found the original bootstrap failure found it because that command
could not run on a fresh install. A version requiring the daemon could not run
before the daemon does -- which is the same shape, arrived at from the opposite
direction.

## What did change, and it is the better half

0118 and 0120 rested on a filesystem fact: a client cannot write root's files.
That is a weak footing for a security property, because it is incidental --
change how configuration reaches the daemon and the reasoning evaporates, which
is precisely what 0127 did.

They now rest on a property of the configuration language itself: **the policy
that decides who may do what is root's, wherever it arrives from.** The
classification says so, a gate keeps the classification complete, and the
answer is the same over a socket, over the network, and on disk.

That is worth more than the mechanism it justifies. The red frame is still the
right way to show a credential boundary; what changed is that the boundary is
now somewhere defensible.

## Consequences

**The GUI's access tab is unchanged**, including the part that was checked by
counting pixels. `Administrator Mode...` still starts `ncfg control helper`
through an elevator and reddens only on `ready uid=0`.

**A desktop client still cannot widen its own rights**, which is the property
that makes an open local policy survivable. A member of the `netcfgd` group
can configure the network and cannot decide who else may.

**The remote policy inherits it for free.** `remote { admin = true }` is the
same classification, so opening remote access is root's too -- and 0128 already
refuses privileged productions from off the machine outright, so there is no
route to it from the network at all.
