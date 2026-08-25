# 0004: DHCPv4 comes from an external client, and the schema keeps the door open

Status: accepted
Date: 2026-07-28
Milestone: M1 (schema consequence lands before the M4 freeze)

## Context

`project.md` §8 question 4. §1 constraint 3 says the core has no mandatory
dependencies beyond libc and the kernel, which reads at first like an argument
for a built-in client. It is not: the constraint names D-Bus, glib, polkit and
systemd, and it is about what the binary links, not about whether it may
execute a helper. Reading it the other way is what makes a built-in DHCP
client look mandatory.

## Decision

Delegate to `dhcpcd` or `udhcpc` through `netcfgd-dhcp`. No built-in client
in M1–M4. `AddressSource::Dhcp4.backend` keeps its `Builtin` variant in the
schema — unimplemented, but **recognised**.

**A DHCP client is the largest correctness surface in the project and is not
its thesis.** Hostile-input option parsing, a retransmission state machine,
a lease database, RFC 2131 plus classless static routes (option 121) plus
rapid commit, and raw sockets with BPF filters under `CAP_NET_RAW` because
there is no address yet. Every one of those is a thing to get wrong before
the walking skeleton works.

**The embedded story does not need one.** `udhcpc` is in busybox, which is on
every OpenWrt image already. The zero-extra-dependency claim holds on the
reference target without writing a line of it.

**The integration work is identical either way.** Whatever produces a lease
has to hand it to the model: a lease-to-`AddressSource` path, the `Lease` hook
phase, and the drift semantics for leased addresses from decision 0006 rule 7.
That code is written now for external clients and would be reused unchanged by
a built-in one.

**Keeping the variant is what makes this reversible.** The schema freezes at
M4 (§7), and §2 says a consumer rejects a document containing a field it does
not recognise. Adding `Builtin` after the freeze is a major version bump;
adding it now is one enum variant.

The recognition nuance matters and is easy to get wrong: a build without a
built-in client must parse `backend = "builtin"` and fail with *this build has
no built-in DHCP client*, not with *unknown value*. Only the first tells the
operator whether the problem is their config or their package.

## Consequences

**netcfgd has a runtime dependency for the most common addressing mode there
is.** That is a genuine weakening of the zero-dependency pitch, and it belongs
in the README where a reader meets it, rather than in a bug report.

Two backends to integrate, and their script output and IPC are hostile input
like any other parser — §6's fuzzing gate covers them.

Revisit at M5 only if a target platform ships neither `dhcpcd` nor busybox
`udhcpc`. In practice that platform does not exist.

## Alternatives considered

**Built-in from M1.** Rejected: it front-loads the project's largest attack
surface ahead of the thing that proves the design, and the design is the risk
worth retiring first.

**Built-in for nano only**, to keep that tier free of helper processes.
Rejected, and it inverts its own argument — nano is the tier that can least
afford the bytes, and a DHCP client is not small.

**Drop `Builtin` from the schema entirely.** Rejected: it is free now and a
major version bump later, which is the cheapest kind of option to hold.
