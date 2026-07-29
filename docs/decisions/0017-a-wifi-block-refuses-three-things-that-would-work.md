# 0017: a wifi block refuses three things that would work

Status: accepted
Date: 2026-07-29
Milestone: M3

## Context

The `network` block from design section 3.2 is now a thing the compiler
lowers. Writing it turned up three cases where the obvious permissive
behaviour is the wrong one, and all three are the kind a future contributor
would reasonably try to remove -- each looks like the compiler being awkward
about something that plainly works.

They are recorded together because they share a shape: the config compiles, the
network joins, and the operator is worse off in a way nothing tells them about.

## Decision

**An inline passphrase does not compile.** `psk = "hunter2"` is refused, and
the diagnostic says to write `@secret:NAME`.

Design section 3.3's premise is that config files stay safe to commit. If a
literal string works, that stops being a property of the system and becomes a
convention people follow until they are in a hurry -- and the failure is
silent, because a committed passphrase works perfectly. The diagnostic does
not echo the value, for the same reason the secret resolver's does not.

**A `network` with no `wifi` block does not compile.** An open network needs
`wifi { open = true }`.

An open network is a real thing and this is not an argument against joining
one. It is an argument against joining one *by omission*: a `network "Cafe"`
with only a `config` line looks like a network somebody described incompletely,
and treating it as a deliberate choice to associate with anything broadcasting
that name is a guess. One line makes it a statement.

**An EAP network with no `ca_cert` compiles, and says so.** Not refused --
plenty of real deployments pin nothing and refusing would make netcfgd unusable
on them -- but a supplicant with no CA certificate authenticates to whatever
answers, and that is the entire attack against enterprise wifi.

This is the one of the three that is a warning rather than an error, and the
line between them is whether a correct config exists that would be rejected.
For the first two there is always a correct config one line away. For this one
there is not: the operator may genuinely not have the certificate.

### The SSID is the label, and also the id

`network "HomeFiber"` gives the profile both its name and its id. A separate
handle would mean two names for one thing in every diagnostic, and an operator
reading `ncfg wifi connect` output would have to know which they were looking
at. Where the SSID is not text -- 32 arbitrary octets is what the standard
allows -- `ssid = "<hex>"` overrides the octets while the label stays the
readable handle.

## Consequences

**Three diagnostics exist that a permissive compiler would not emit**, and each
is a place somebody will file a bug. The messages carry the reason rather than
the rule, which is the only thing that makes the difference between a
diagnostic and an obstacle.

**The secret indirection is now load-bearing rather than encouraged.** Every
credential in a wifi config goes through `@secret:`, so "the config directory
is safe to commit" is checkable rather than aspirational -- there is no
syntax for the other thing.

**The `ca_cert` warning will be ignored by people who cannot act on it.** That
is accepted. A warning nobody can silence is noise, and the alternative -- a
`insecure = true` key to acknowledge it -- is a key whose only use is turning
off a warning, which is how config languages acquire fields that mean nothing.

## Alternatives considered

**Allow an inline passphrase with a warning.** Rejected. A warning on something
that works is a warning people learn to scroll past, and the whole value of
the secret indirection is that it holds without anybody remembering it.

**Default an omitted `wifi` block to open.** Rejected above; the objection is
to joining by omission, not to open networks.

**Refuse EAP without `ca_cert`.** Tempting, and rejected because it would make
netcfgd unable to configure networks that other tools configure fine. Refusing
to support a real deployment on security grounds it did not ask for is how a
tool gets replaced by the one that works.

**A separate `id` alongside the SSID.** Rejected: two names for one network,
and every diagnostic would have to pick one.
