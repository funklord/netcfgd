# 0118: Two ways to be allowed, and one of them is visible

Status: accepted
Date: 2026-08-07
Milestone: M8's desktop half; what makes the clients usable at all

## Context

Every control tier defaults to `Root`
([0013](0013-three-things-a-caller-may-be-allowed-to-do.md)), and the socket's
mode follows the policy -- so a default install has a `0600` socket and
netcfgd's own GUI, running as a desktop user, cannot open it.

That is the safe default and it is right for a router, an appliance and a
hand-built install: constraint 2 says the filesystem reflects use rather than
capability, and a daemon that granted network configuration to a logged-in
session by default would be making a site's security decision for it.

It is also, on a laptop, a wall. The operator installs netcfgd, opens the
client, and is refused -- and the refusal they get is **wrong about why**:

    cannot reach netcfgd at /run/netcfgd/netcfgd.sock: Permission denied.
    Is the daemon running?

The daemon is running. That message sends the reader to `systemctl status` and
the journal for a problem that is in a config file. Section 2.1 already worries
about exactly this confusion from the other side -- it makes the daemon
complain loudly when a policy names a group it cannot make the socket reachable
for, "a lie that costs an afternoon to diagnose" -- and the client side has the
same failure with none of that care.

So there are two questions, and they are different: **how does an operator
grant themselves access**, and **how do they find out that is what they need to
do**.

## Decision

**Two ways to be allowed, and neither is the only one.**

### 1. A reserved group, which is the mechanism

The packages create a group -- empty -- and the shipped policy points `observe`
and `wifi` at it, with `admin` left at root. Joining it is one command and a
re-login, it is a mechanism every Unix operator already understands, and it
composes with everything a site already does about groups.

Empty by default and **not** `netdev`, which is the tempting choice because
NetworkManager uses it and every desktop has one. Installing netcfgd would then
silently grant network configuration to everybody already in `netdev` -- a
package changing who may configure the network, on machines where somebody
joined that group for an unrelated reason years ago. A site that wants exactly
that writes one line of policy and gets it; the default should not.

### 2. Administrator mode in the client, which is the discoverable one

KDE 3.5's pattern, deliberately: the section that edits the control policy is
read-only until the operator authenticates as root, and while it is live it is
**surrounded by a red frame**.

The frame is not decoration and it is the reason to prefer this shape:

> **Privilege you can see.** polkit's model is per-action prompts, and between
> them there is nothing on screen that says whether you are currently
> privileged. A frame is a *mode*, and a mode can be looked at. An operator who
> walks away from a machine can tell at a glance whether they left it able to
> change the system.

It edits one thing -- the `control` block -- and must not become a general
configuration editor. netcfgd's configuration is a text file on purpose; this
exists because the *bootstrap* cannot be done any other way, not because
editing config in a GUI is a goal.

## Why this does not contradict 0117

[0117](0117-adding-a-network-is-a-typed-request-not-a-written-file.md) refused a
privileged helper for adding a network, and this accepts one for granting
access. The difference is not taste, it is that one of them had an alternative
and the other cannot:

- **Adding a network** could go over the socket, because the daemon is already
  privileged and already authorizes. A helper would have been a second
  authorization system that must agree with 0013's tiers or be a second,
  disagreeing answer -- so it lost on merit.
- **Granting yourself socket access** cannot go over the socket. You would be
  asking the daemon for permission to ask the daemon. There is no path through
  the thing being unlocked, so the option that lost on merit there wins here on
  necessity.

That asymmetry is the whole argument, and it also bounds the helper: it exists
for the one operation with no other route, and every operation that *has* one
keeps using it.

## What is privileged, and how little

**Not the whole GUI.** 0117 already refused running Qt as root "so that it can
write one file", and nothing here changes that: a Qt application with a theme
engine and a plugin loader is not a thing to hand uid 0.

So the privileged part is a small separate program doing one typed job -- write
a control policy -- launched by whatever the desktop has. The client does not
own an authentication mechanism and must not grow one; handling a password
itself is the thing to avoid, not the thing to build.

## What this leaves open

- **The group's name.** `netcfgd` is the obvious reserved one. It is a
  packaging-visible name that cannot be changed later without an upgrade path,
  so it is worth a moment.
- **Which launcher, and whether the client picks.** `pkexec`, `kdesu`,
  `sudo -A`, `su` -- all present on some machines and none on all. Trying
  several in turn is one answer; printing the command for the operator to run
  is another, and is the one with no dependency at all.
- **Whether `admin` is ever granted to the group by default.** This decision
  says no: `observe` and `wifi` make a client usable, and `admin` can apply any
  configuration change on the machine. Adding a network needs it (0117), which
  means the friendly path still stops short of the thing a laptop does most --
  and that tension is real and not resolved here.
- **Whether the shipped policy is a `conf.d` drop-in or a compiled default.** A
  drop-in is visible, diffable and removable, which suits a file that decides
  who may configure the network. It also means an operator who deletes it gets
  the root-only default back rather than a broken machine.

## What is not open

**The connect diagnostic is wrong and is fixed regardless of any of the
above.** `EACCES` on connect is not "is it running", it is "you may not talk to
it", and the client has the errno to tell the two apart. Whatever else is
built, an operator who is refused should be told which file decides it.
