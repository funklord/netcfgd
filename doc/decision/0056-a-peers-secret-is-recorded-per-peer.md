# 0056: A peer's secret is recorded per peer

Status: accepted
Date: 2026-08-03
Milestone: finishes what [0055](0055-a-secret-can-be-hashed-too.md) named as next

## Context

0055 made a rotated `WireGuard` private key visible by recording a digest of
what netcfgd loaded and comparing it against the store. Its last consequence
names the gap it left:

> What is still not compared for a `WireGuard` device is a peer's *preshared*
> key, which has the same shape and would want the same treatment.

It asked for "a reason to want it beyond symmetry". There is one, and 0053
already wrote it down about a different backend:

> a reconciler that notices an edited SSID, an edited passphrase and a
> renumbered prefix but not an edited `.ovpn` is one whose coverage an operator
> cannot predict. Predictable is the product.

A netcfgd that rekeys a tunnel when the private key moves and does nothing when
a peer's preshared key moves has exactly that shape. Both are 32 octets in the
secrets directory, both are edited by the same hand for the same reason, and one
of them silently does nothing.

## What the peer list comparison cannot do

Adding or removing a preshared key *is* already noticed, and it is worth being
exact about why. The kernel reports whether a peer has one, the document says
whether a `SecretRef` is there, and the peer lists differ when those disagree --
so `preshared_key = "@secret:x"` appearing or disappearing plans a
`wg.set_peers` on its own.

**Rotation is the case that is invisible**, because both sides say the same
thing: the kernel returns `WGPEER_A_PRESHARED_KEY` **zeroed** -- it will not
hand a secret back -- so the observation can only carry a boolean, and the
boolean does not move when the value does.

## Decision

**The record is per peer, keyed by the peer's public key.**
`/run/netcfgd/wireguard/<iface>.psk.sha256` holds one line per peer that has a
preshared key: the public key as base64, then a digest of the secret.

Keyed by public key because that is the only name both sides have. The document
labels a peer with a word the operator chose and the kernel has never heard of
it; the public key is what identifies a peer on the wire and in `wg show`.

**Written whole whenever the peer list is sent, and only then.** A
`wg.set_device` leaves the kernel's peers alone, so rewriting the record from a
list that was not sent would claim every preshared key had gone. Writing it
whole is what makes a peer that *lost* its preshared key lose its line rather
than keep a stale one.

**A rotation replaces the whole peer list**, through the same `wg.set_peers` the
rest of this uses, because that is what the kernel takes. There is no
per-peer op and there should not be one: `WGDEVICE_F_REPLACE_PEERS` is how the
list is set, and a plan that claimed to change one peer would be describing
something the netlink layer cannot do.

The comparison is the observer's and what travels is a boolean, which is 0052's
rule and 0055's mechanism unchanged. `None` is not `false` here either: a peer
with no record, a secret that will not resolve, and a peer with no preshared key
at all are all unanswered, and an unanswered question does not replace a peer
list.

## The same caveat as 0055, because it is the same technique

A preshared key is 32 octets from `wg genpsk`, so a digest of one is not a route
back to it. **This remains wrong for a passphrase**, which is low-entropy and
dictionary-attackable, and an access point's is still compared in memory with
nothing written down (0052). Anyone applying this to a third secret has to make
the entropy argument again rather than cite the precedent.

## Consequences

- Every secret a `WireGuard` device holds is now compared: the private key by
  0055, each peer's preshared key by this. What netcfgd notices no longer
  depends on which of the two an operator edited.
- `tests/live/wireguard.sh` asserts the strongest thing in the file:
  `wg show wg0 preshared-keys` prints the *value*, so the kernel's key is
  compared octet for octet against the store's by a tool that is not netcfgd.
- The observed schema gains a field on a peer. A minor addition.
- A peer's preshared key is the last secret in the model that netcfgd loads and
  could not check. The next thing of this shape would be a secret netcfgd hands
  to a daemon rather than to the kernel, and 0052 already covers the one that
  exists.
