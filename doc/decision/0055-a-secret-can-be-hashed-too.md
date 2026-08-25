# 0055: A secret can be hashed too

Status: accepted; the preshared key its last consequence names is taken by
[0056](0056-a-peers-secret-is-recorded-per-peer.md). Lifts the limit
[0054](0054-a-kernel-object-is-compared-like-a-daemon.md) stated
Date: 2026-08-03
Milestone: the last of the "is what is running still what the document says" questions

## Context

0054 gave a `WireGuard` device the comparison every other backend had, and
stated one limit in the terms it was reached in:

> **A rotated private key is not compared either**, and that is a limit rather
> than a decision: the kernel reports the public key derived from it, and
> deciding whether it matches the secret store would mean deriving a public key
> here, which is curve25519 and is not arithmetic this project carries.

project.md carried it as a next step needing "a plan for where that arithmetic
lives". That framing is the mistake. The question is not *what public key does
this private key derive* -- it is **has the secret moved since netcfgd loaded
it**, and that question has an answer with no curve arithmetic in it at all.

## The dead end, and why it looked like the only road

The kernel reports `WGDEVICE_A_PUBLIC_KEY` and nothing else about the key. The
document holds a `SecretRef`. Comparing those two directly means deriving one
from the other, which is X25519 -- a dependency, a review burden, and a thing
this project has no other use for.

What made it look unavoidable is that both other comparisons of this shape
compare *the thing itself*: 0052 compares an access point's passphrase against
the store, and 0053 compares a `.ovpn`'s bytes. Neither can be done here,
because the kernel will not give the key back -- deliberately, and rightly.

## Decision

**netcfgd records a digest of the key it loaded, and compares digests.**

`configure_wireguard` writes `sha256(private key)` to
`/run/netcfgd/wireguard/<iface>.key.sha256` at 0600, after the kernel has
accepted the configuration -- the same "after it was taken" rule 0053 uses for a
`.ovpn`, because a record of a configuration that was refused is a record of
nothing. The observer hashes what the store holds now and compares. What leaves
the observer is `ObservedWireGuard::key_matches`, a boolean, which is where 0052
already put this kind of answer and for the same reason: the planner is pure and
may not hold a secret.

This is decision 0053's trick -- *a thing netcfgd may not carry can still be
hashed* -- played on a secret instead of on a file. 0053 hashed bytes it was
forbidden to interpret; this hashes bytes it is forbidden to keep.

**A rotated key then reconfigures the device through `wg.set_device`**, which
already carries the private key by reference and already existed. The reason
names `wireguard.private_key` and says which way it went, and nothing in the
plan can print a key.

## Is a digest of a private key safe to write down?

Stated plainly, because the answer is "yes, and it would be no for the next
secret somebody tries this on".

A `WireGuard` private key is 32 octets of kernel randomness. There is no
dictionary, no structure and no small search space, so a SHA-256 of one is not a
route back to it. **A passphrase is the opposite** -- low entropy, dictionary
attackable -- which is why 0052 compares an access point's passphrase in memory
and writes nothing down. The technique is fit for this secret and not for that
one, and anyone reaching for it elsewhere has to make that argument again.

The file is 0600 under `/run`, which is tmpfs and does not survive a boot.
Nothing reads it but the observer. It is not in the document, not in the
observation, and not on the socket.

Three alternatives were considered and are worth recording:

- **Carry curve25519 and derive the public key.** The obvious road, and it
  would also let netcfgd check a *peer's* key against something. Rejected: a
  cryptographic dependency in the core for one comparison that a digest answers,
  and constraint 3 is about mandatory system dependencies rather than crates --
  so the objection is the review burden and the surface, not the rule.
- **Record the public key the kernel derived, at load time.** Costs nothing and
  answers a different question: it notices somebody else rekeying the device,
  and cannot notice the store moving, because the kernel still holds the old key
  and still reports the old public key. That is precisely the case this is for.
- **Nothing, with the limit written down.** What 0054 did. Rejected now that the
  limit turns out to be an artefact of asking the wrong question.

## Consequences

- Rotating a `WireGuard` private key is a thing `ncfg plan` reports and `ncfg
  apply` performs. Before this it was a file edit that changed nothing, with a
  tunnel still authenticating as the old key.
- `None` is not `false`, again: a device netcfgd did not configure has no record,
  and a secret that will not resolve has no answer. Neither rekeys a working
  tunnel.
- The observer now needs the secret store, which it already needed for an access
  point's passphrase (0052). No new dependency and no new boundary.
- The digest is written wherever `NCFG_RUN_DIR` points, so the live test reads
  it back and asserts it is a digest rather than a key -- a behavioural test
  alone would not notice the day somebody makes that file the key itself.
- What is still not compared for a `WireGuard` device is a peer's *preshared*
  key, which has the same shape and would want the same treatment.
