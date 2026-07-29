# 0013: three things a caller may be allowed to do

Status: accepted
Date: 2026-07-29
Milestone: M3

## Context

Design section 13 settles authorisation in five words: "Authorisation is
unix-socket permissions." The socket is `root:netcfgd` mode 0660, group
`netcfgd` may read status and plan, and "a separate `netcfgd-admin` group (or
an `allow_apply` socket) gates state-changing verbs. That is the entire auth
model."

It is a good model and it was written before wifi existed. Wifi breaks it,
because the question an operator actually has on a laptop is not "may this
user change the network" but two separate questions:

- May a logged-in user join a wireless network?
- May they change anything else about the networking?

The desirable answer on a desktop is *yes* to the first and *no* to the
second, and socket permissions alone cannot express it. One socket has one
mode. Expressing it that way needs a socket per capability, and then the
client has to know which socket a given verb lives behind -- which makes the
permission model something you discover by trial rather than by reading.

Section 13 anticipated the shape of the problem, though, in its own aside:
"or an `allow_apply` socket". The distinction it wanted is real; the mechanism
it named does not reach far enough.

## Decision

**Filesystem permissions stay the outer gate. A policy in the config draws the
finer line, and there are exactly three tiers.**

```
global {
	control {
		observe = "group:netcfgd"   # ask what the network looks like
		wifi    = "group:netdev"    # join, leave and scan wireless networks
		admin   = "root"            # change anything else
	}
}
```

Everything defaults to `root`. A machine that never edits this block behaves
exactly as section 13 describes, and the desktop case is two lines.

**The values are the ones people actually want**: `root`, `any`,
`user:NAME`, `group:NAME`. Not an expression language, not a rule list, not a
policy file in another directory -- principle 12 says the filesystem reflects
use, and an authorisation *system* is precisely the sort of thing that grows a
directory tree if allowed to.

### Why three tiers and not two

`observe` is separate from the other two because reading is not writing, and a
status display that has to run as root is how status displays end up running
as root.

`wifi` is separate from `admin` because that is the whole point. It covers
scanning, and joining or leaving a network **that is already in the
configuration**. It does not cover creating one, because creating a wifi
profile means writing config, and config is the source of truth (constraint
1). A tier that could write config would be `admin` wearing a hat.

That leaves a real gap -- a user cannot join a network nobody has configured
yet -- and it is the gap design section 9.4 already answers: a GUI's edits
become a file under `conf.d/nm/`, written by an adapter that "runs as a
dedicated unprivileged user in the appropriate group" and "must not widen who
can reconfigure the network". Until that exists, adding a network is `admin`,
and the documentation says so rather than implying otherwise.

### Peer credentials, and the group problem

`SO_PEERCRED` gives the connecting process's pid, uid and primary gid. It does
**not** give supplementary groups, and a user's primary group is usually their
own -- so `group:netdev` checked against the primary gid alone would deny
almost everybody it is meant to allow, which is the worst kind of security
control: one that looks configured and does nothing.

Supplementary groups come from `/proc/<pid>/status`. That introduces a pid
reuse race: between the credentials arriving and the file being read, the
process could exit and the pid be recycled. The mitigation is to compare the
uid recorded in `/proc/<pid>/status` against the uid `SO_PEERCRED` reported
and refuse on a mismatch, which closes every recycling that lands on a
different user. A recycled pid belonging to *the same user* is not a
privilege boundary, so what remains is not an escalation.

This is written down rather than left implicit because it is the one place in
netcfgd where a check could plausibly be defeated, and a reader deserves to
find the analysis rather than reconstruct it.

### The socket has to be reachable or the policy lies

If `observe = "any"` but the socket is mode 0660 owned by a group the caller
is not in, the caller cannot connect and the config has told them a
falsehood. So the mode follows the policy: the most permissive tier decides
it, and where a tier names a group, netcfgd tries to give the socket to that
group.

Where it cannot -- the group does not exist, or the daemon is not root --
**it says so, loudly, at startup**. A daemon that quietly leaves a socket
root-only while its config says `group:netdev` produces a bug report about
wifi not working that takes an afternoon to trace.

## Consequences

**Two mechanisms now decide access rather than one**, and section 13's
sentence is no longer the whole story. The outer gate is unchanged and still
does the coarse work; what is new is a finer distinction inside it, which is
enforced in one function so that "who may do this?" has a single answer.

**Every request is classified, and the classification is exhaustive.** A new
request added without a tier fails to compile, which is deliberate: the
failure mode of a permission system is a verb nobody remembered to cover, and
a match arm is a better reminder than a review checklist.

**`ncfg` needs no privilege changes.** It connects as whoever ran it and the
daemon decides. There is no setuid anything, and no helper binary.

## Alternatives considered

**A socket per capability**, as section 13's aside suggests. Rejected: the
permission model becomes something a client discovers by trying sockets, three
paths need packaging and cleanup, and adding a fourth capability later means a
fourth socket rather than a line of config.

**polkit.** Rejected by constraint 3, and it would be the largest dependency
in the project by a wide margin. It is also the thing design section 1.1 lists
as part of Pain 2.

**Primary gid only, no `/proc`.** Rejected above: it would deny nearly
everybody `group:` is meant to allow, while appearing to work.

**A rule language rather than four value shapes.** Rejected. Every
authorisation system that grew an expression language did so one reasonable
extension at a time, and the result is a thing operators copy from forums
without understanding. Four shapes cover what people ask for; a fifth is a
decision to make deliberately, later, with a reason.
