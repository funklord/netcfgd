# 0159: who may open a socket is not who may use it

Status: accepted
Date: 2026-09-06
Milestone: found by an exhaustive sweep of the core networking paths

Narrows [0128](0128-origin-is-which-socket-you-arrived-on.md) in one place and
implements another: the remote policy gains a principal, and it is not the kind
0128 rejected.

## Context

0128 gave the daemon two sockets. `netcfgd.sock` is local and judged against
the local `control` principals through `SO_PEERCRED`; `remote.sock` is the
agent's, and `check` short-circuits for it:

```rust
if origin == Origin::Remote {
    return check_remote(remote, request);
}
```

No principal, no peer, by design -- every remote caller arrives as the agent,
so there is nobody for the daemon to identify. **Whoever can open `remote.sock`
therefore has whatever the remote policy allows.**

`bind_sockets` passed the same `Control` to both, and said so:

> Both carry the same `Control`, and that is not an oversight: the local policy
> is what `Origin::Local` connections are judged against, and a remote
> connection never consults it.

The second half is true and is the reason the first half is wrong. The mode is
a statement about *local processes* for both files, so the local policy was
deciding who could reach a socket that ignores the local policy. Measured, as
an ordinary user, against a daemon carrying

```
control { observe = "any"  wifi = "root"  admin = "root" }
remote  { observe = true   wifi = true    admin = true   }
```

```text
netcfgd.sock  reload -> error: this needs the `admin` tier,
                        which the configuration opens to `root`
remote.sock   reload -> ok
```

`remote.sock` was mode 0666. The tier that exists so a status display need not
run as root was handing out `admin`.

**The group-shaped policy is worse, because it is the one that ships.** With
`observe = "group:netcfgd"` -- what `debian/postinst` writes -- `remote.sock`
comes out 0660 owned by that group, so every member gets the remote tiers. The
same measurement: `reload` refused locally, accepted remotely.

## Decision

**A socket's permissions come from the policy that speaks about that socket.**

`serve` takes the principals that decide who may open the file, rather than a
`Control`. The local socket passes its three; the remote socket passes one,
which is new:

```
global {
	remote {
		observe = true
		admin   = false
		agent   = "group:netcfgd-agent"
	}
}
```

`agent` is `root` by default, so a machine that opens remote access without
saying who runs the agent gets a socket only root can reach. That is a
narrowing: before this, such a machine got whatever its `control` block
happened to say.

**This is not the principal 0128 rejected, and the distinction is the whole
record.** 0128 refused principals for the *tiers* because they would describe a
caller the daemon cannot see -- `user:alice` arriving through an agent is a
sentence the daemon cannot evaluate. `agent` describes the local process
holding the other end of a unix socket, which is exactly what `SO_PEERCRED`
answers and exactly what the local principals already mean. The asymmetry
inside the block is real and it is the point: booleans for what a remote caller
may do, a principal for who may act as the agent.

It also implements what 0128 already promised and never wired up. That decision
says "the remote socket's mode and group follow the same mechanism the local
one uses, which means `agent/` need not run as root: a dedicated unprivileged
user in a named group reaches the socket, and nothing else does." The mechanism
was there; it was pointed at the local users' policy, so there was no way to
name that dedicated user at all.

## Alternatives rejected

- **Make `remote.sock` root-only, full stop.** Two lines, closes the hole, and
  it would have removed 0128's stated mechanism while leaving the sentence
  describing it in the record. `agent/` does not exist yet, so nothing would
  have complained -- which is what makes it the tempting answer and the wrong
  one.
- **A dedicated uid for the agent, recognised through `SO_PEERCRED`.** 0128
  rejected this and the reasons still hold: it cannot be exercised until
  `agent/` exists, and it leaves nowhere to say who may connect except a user
  database. `agent` is that "nowhere", and a socket has a mode and a group
  already.
- **Refusing `agent = "any"` at compile time.** It is an explicit sentence by
  an operator about their own machine, where before the same exposure arrived
  as a side effect of an unrelated key. The daemon says who it opened the
  socket to on the line it already prints for remote access, which is the
  channel for this rather than a diagnostic.

## Consequences

- The schema witness moved: `globals.remote` gains `agent`, additive and with
  a default, so no version bump (`SCHEMA_VERSION` does not count minor bumps
  before a release).
- `named_groups` is a free function over principals now, because the remote
  socket's reachability is one principal and the local socket's is three, and
  both are given to a group the same way.
- `tests/live/remote_socket.sh` is new; there was no live coverage of the
  remote socket at all. It asserts modes rather than connects, because the
  daemon under test is owned by whoever runs it and an owner can always open
  their own 0600 file -- in production the owner is root and the mode is what
  shuts everybody else out.
