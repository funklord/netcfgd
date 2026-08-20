# 0128: Origin is which socket you arrived on

Status: accepted
Date: 2026-08-20
Milestone: M8's remote half, ahead of `agent/` existing

Reverses a stated property of the remote design: §5 has `agent/` terminating
the remote protocol and holding "an ordinary local socket connection", with
"the daemon itself is unchanged". The daemon changes.

## Context

[0127](0127-netcfgd-is-the-only-writer-and-the-socket-carries-the-rest.md) has
clients sending configuration over the socket, and the holder's intent is that
**local is deliberately open** -- open enough that a distribution could put
every user in the `netcfgd` group by default -- while remote is not. Those two
cannot both be served by one policy, because today they are one policy: the
daemon has no notion of where a connection came from. `authorize.rs` sees a
`Peer` from `SO_PEERCRED` and nothing else, and that is not an oversight, it is
the remote design working as written -- the agent connects like any local
client precisely so the daemon needs no remote code.

That was the right trade while remote meant "read the network's state from
another host". It is the wrong one when a remote caller can send configuration,
because "open to every local user" would then mean "open to the network".

## Decision

**A connection's origin is which socket it arrived on, and nothing a client
says.**

- `/run/netcfgd/netcfgd.sock` is local, and is what exists today.
- A second socket carries remote connections. `agent/` connects to it; nothing
  else has a reason to.

Origin is therefore a property the daemon observes rather than a claim it
evaluates. A local process cannot present itself as remote and, more
importantly, the reverse cannot happen either -- there is no field to forge,
because there is no field.

**The remote socket exists only when a remote policy does.** With none, the
file is not created, and a machine that has never configured remote access has
nothing listening for it. That is constraint 2 -- the filesystem reflects use,
not capability -- applied to the one place where the difference is a security
property rather than tidiness.

## Remote policy is a set of tiers, not principals

The local policy names principals: `root`, `any`, `user:alice`,
`group:netdev`, checked against `SO_PEERCRED`. **None of that can mean anything
for a remote connection**, because every remote caller arrives as the agent.
Writing `user:alice` in a remote policy would be a sentence the daemon cannot
evaluate and an operator would reasonably believe.

So the remote policy says which of 0013's three tiers are reachable from off
the machine at all:

```
global {
	remote {
		observe = true
		wifi    = true
		admin   = false
	}
}
```

Everything defaults to false. A machine that never writes the block is exactly
as reachable as one running the code before this decision.

## The agent authenticates, the daemon bounds

This is the division the split creates, and it is worth stating because each
half is useless alone:

- **The agent decides who the remote caller is.** It terminates the remote
  protocol, which is `fuzznet`'s, and it is the only thing positioned to know
  -- the daemon sees a unix socket and could not check a signature if it
  wanted to.
- **The daemon decides what remote can ever do**, whoever it is. That bound
  holds even if the agent is wrong about identity, which is the property worth
  having: a compromised agent reaches what the remote policy allows and not
  the machine.

It also keeps constraint 3 intact. The daemon still speaks no network protocol,
links no crypto, and reads a unix socket -- what changed is that it reads two
of them.

## Reachability is a filesystem question, as it already was

The remote socket's mode and group follow the same mechanism the local one
uses, which means `agent/` need not run as root: a dedicated unprivileged user
in a named group reaches the socket, and nothing else does. That mechanism was
broken under systemd until the day before this was written -- the unit granted
no `CAP_CHOWN`, so the local socket could not be given to its policy's group --
which is worth remembering here because the remote socket depends on the same
call and would have failed the same way, silently, on the machine that most
wanted it.

## Rejected

**An origin field in the protocol**, set by the agent. Rejected: it is a claim
rather than an observation, and every local process that can reach the socket
could set it. The failure that matters is not a remote caller claiming to be
local -- the agent controls that either way -- it is that the daemon would be
evaluating trust in a string, and the whole point of a second socket is that
there is nothing to evaluate.

**A dedicated uid for the agent**, recognised through `SO_PEERCRED`. It is
unforgeable and needs no second socket, and it was close. Rejected for two
reasons: it cannot be exercised until `agent/` exists and a system user is
created, so the mechanism would ship untested against its only consumer; and
it leaves nowhere to express *who may connect remotely at all* except a user
database, where a socket has a mode and a group already.

**One policy with a remote flag per tier**, rather than a second block.
Rejected as the same sentence meaning two things: `wifi = "group:netdev"` with
a remote flag beside it reads as though the group applies remotely, and it
cannot.

**Leaving it until `agent/` is built.** The reason not to is 0127: config now
crosses the socket, so the bound has to exist before the thing it bounds, not
after. A remote path built first and bounded afterwards is one that was
unbounded for however long that took.

## What this does not decide

**Whether `agent/` ships in netcfgd's packages**, which §10 already records as
the maintainer's and is now sharper: it is a question about exposing a network
service, and this decision makes the exposure bounded rather than making it
somebody else's problem.

**Per-remote-user policy.** The daemon bounds remote as a whole; if a site
wants alice to reach `wifi` and bob not to, that is the agent's to enforce and
this decision gives it nowhere to say so. Adding it later means the agent
passing identity the daemon would have to trust, which is the rejected option
above wearing a better hat -- so it wants its own record and a reason.
