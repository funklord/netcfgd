# 0054: A kernel object is compared like a daemon

Status: accepted
Date: 2026-08-03
Milestone: closes for `WireGuard` what [0052](0052-a-daemon-is-compared-to-what-it-was-started-with.md) closed for hostapd and radvd

## Context

0052 asked one question of every backend netcfgd starts -- is what is running
still what the document says -- and 0053 finished it by hashing the one file
netcfgd will not read. Its closing line says the next thing of this shape would
be "a backend netcfgd does not start".

It was not. It was a `WireGuard` device, which netcfgd creates itself, and the
gap had been there since WireGuard arrived at M4.

`configure_wireguard` was called from exactly one place: inside `Op::LinkCreate`.
Everything that makes a `WireGuard` interface a tunnel -- the private key, the
listen port, the firewall mark, the peers -- went over generic netlink when the
link was created and was never sent again. For a device that already existed,
the planner had nothing to compare, because the observation carried nothing to
compare *with*: `ObservedLink::private_key_loaded`, a boolean, was the whole of
what netcfgd knew about a running tunnel.

So:

```
$ ncfg apply          # after editing listen_port and deleting a peer
nothing to do
$ wg show wg0
  listening port: 51820                       # the old one
peer: 6Q/Ck9hKThb0wPKABJlpq2K02iNFcF7YJdtSLINc7VY=   # the deleted one
```

Measured exactly like that, against a real kernel and a real `wg`, before
anything was designed.

## Why this one is worse than the others

An edited SSID announces the wrong name. A stale advertised prefix hands out
addresses that will not route. **A peer that is still in the kernel is access
that was not revoked**, and the operator has every reason to think it was: they
deleted it from the file, they ran the tool, and the tool said there was nothing
to do. That sentence was true about the plan and false about the network.

The two other kinds of drift are wrong answers. This one is a wrong answer that
looks like a completed security operation.

## Decision

**The observation carries what the kernel holds**, on the request that was
already being made. `read_wireguard_keys` asked `WG_CMD_GET_DEVICE` for the
public key, used it to set a boolean, and dropped the rest of the reply --
listen port, firewall mark and every peer. `ObservedLink::wireguard` now carries
all of it.

Nothing in it is secret, and that is a property of what the kernel returns
rather than a choice made here. The device's public key is derived from the
private one and is the thing an operator hands a peer. A preshared key comes
back **zeroed** -- the kernel refusing to hand back a secret -- so it becomes a
boolean, exactly as `netcfgd_sys::wg::PeerState` already made it one. The
private key has no field, here or there.

**The planner compares and emits the two ops the taxonomy already declared.**
`wg.set_device` and `wg.set_peers` have been in `Op` since the action taxonomy
was written, pinned by the plan witness, and reached the executor's
`"{} is not implemented in this build"` arm -- because nothing had ever emitted
one. They are now what a difference produces:

| what moved | op | reversible |
|---|---|---|
| `listen_port`, `fwmark` | `wg.set_device` | yes -- the inverse is what was just observed |
| the peer list | `wg.set_peers` | no |

The peer op carries no inverse because there is nothing to build one from: an
observed peer has no operator's label and no `SecretRef` for a preshared key, so
a reverting `wg.set_peers` would restore something that is not what was there.
The plan says it cannot be undone, which is true, rather than offering a revert
that would quietly differ.

**The kernel's own partial update is used, because it exists.** `SET_DEVICE`
leaves out what it does not mention and replaces the peer list only under
`WGDEVICE_F_REPLACE_PEERS` -- that is how `wg set wg0 listen-port 51821` changes
a port without touching a peer. `netcfgd_sys::wg::Device` grew an optional
private key and a `replace_peers` flag to say the same thing, so that a plan
reading `wg.set_device` does not silently replace the peer list as well. A
comment in that file claiming "`WireGuard` has no partial update that netcfgd
wants" was written when netcfgd wanted only the whole thing.

## What is deliberately not compared

**The endpoint.** A peer roams: the kernel rewrites the endpoint from the
packets it receives, which is the feature, and the document's endpoint is where
to look first rather than where a peer must stay. It is also a *name* at least
as often as an address, resolved at apply time -- so comparing it against what
the kernel reports would reconcile a device forever over a value the document
never claimed to fix.

**A rotated private key.** The kernel reports the public key derived from it,
and deciding whether that matches the secret store means deriving a public key
from a private one, which is curve25519. netcfgd does not carry that arithmetic
and this is not a good enough reason to add it. The limit is stated here rather
than left to be discovered: rotate a key and the device keeps the old one until
something recreates it.

**A port the document does not state.** An absent `listen_port` means the kernel
chooses, so a document that says nothing is not a document asking for the
ephemeral port to change. This is the trap 0052 fell into with an access point's
band, arriving by a different road, and it has the test that says so.

## Consequences

- Deleting a peer from the config revokes its access on the next apply, which is
  what everyone already believed it did.
- `ncfg status --json` shows a tunnel's real state: which port, which peers,
  what is routed to them. `wg show` was previously the only way to know.
- Two ops that existed only in a type and a witness now run. That they could be
  declared, frozen and pinned without ever being emitted is worth noticing --
  the plan witness proves an op's *shape*, not that anything produces one.
- The observed schema gains a struct and its witness moved. A minor addition:
  nothing changed in what was already there.
- `tests/live/wireguard.sh` drives a real kernel and cross-checks with a real
  `wg`, which is not installed on the machine this was written on -- the header
  says how to run it uninstalled, the way `tunnel.sh` does for openvpn.
