# 0024: One binary, and what the 1 MB target would actually cost

Status: accepted
Date: 2026-07-30
Milestone: M5
Amends: [0022](0022-netcfgd-may-own-one-nftables-table.md)

## Context

M5's last open item is design section 10.2's embedded budget: `netcfgd-embedded`
under 1 MB. The install was 2.89 MB.

`size-budget.txt` named two routes, and both were guesses:

> Meeting the embedded budget is M5's job, through the build profiles that
> compile the DSL compiler, the client and the adapters out -- and probably
> through making `ncfg` and `netcfgd` one multi-call binary, since duplicating
> the shared crates is most of what is being paid for here.

Decision 0021 exists because the last size premise on this project was inverted
when it was finally measured. So this one was measured first.

## What the measurement said

`nm --print-size` over the two stripped release binaries:

| | bytes |
|---|---|
| `ncfg` symbols | 926,716 |
| `netcfgd` symbols | 1,199,298 |
| sum | 2,126,014 |
| union -- what one binary would hold | 1,363,701 |
| **duplicated between them** | **775,178** (1939 symbols) |

The guess was right. The model, the compiler, the planner, the executor and the
netlink layer are nearly everything either program is, and both carried a
private copy.

## Decision

**`netcfgd` and `ncfg` are one binary with two names**, dispatching on
`argv[0]`, as busybox and `util-linux` do it. The file is `netcfgd`; `ncfg` is
a symlink to it. Each program keeps its own argument parsing, usage text and
exit codes, because they are still two programs.

Measured after: **2,892,760 -> 1,743,384 bytes, a saving of 1,149,376 (40%)**.
Larger than the symbol figure, because a second ELF also carries its own
headers, relocations and unwind tables.

That is the single largest size change this project has made, and it is the end
of the easy ones.

## The 1 MB target is not reachable, and here is the arithmetic

1,743,384 against 1,048,576 means finding another 694,808 bytes. Where the
merged binary's 1,288,574 bytes of symbols actually are:

| | bytes | share |
|---|---|---|
| serde and its derived encoders/decoders | 371,581 | 28.8% |
| language runtime (`core`, `std`, `alloc`) | 460,425 | 35.7% |
| netcfgd's own code | 556,544 | 43.2% |
| `Debug` impls | 19,370 | 1.5% |
| `fmt` machinery | 22,465 | 1.7% |

(The first two overlap the third; serde's derived impls are attributed to the
crates that use them.)

### Optional backends would save almost nothing

This record amends 0022, which said of NAT:

> Design section 10.3 makes optional backends separately installable for
> exactly this, and NAT is a good candidate for that treatment -- a machine
> that is not a router should not carry it.

`size-budget.txt` repeated it: NAT is "the one to reach for first when the
install has to shrink".

**Measured: `netcfgd-netlink` is 11,904 bytes of symbols in total.** That crate
holds the nftables encoder, the qdisc and filter encoders, the WireGuard and
generic-netlink layers, the ifb plumbing and every rtnetlink message. All of
it, twelve kilobytes.

So the "+72 KB for NAT" and "+56 KB for ingress shaping" this file recorded
were never the encoders. They were the model fields, the derived serde code for
them, the planner passes and the format strings. Compiling the *backend* out
leaves all of that behind, because the document must still parse `nat = true`
on a build that cannot do it -- the schema is frozen and a build-dependent
document format would be a different format.

The optional-backend route is therefore worth single-digit kilobytes, not
hundreds. It is not a size lever. It may still be worth doing for other reasons
-- an appliance that cannot possibly NAT is easier to audit -- but not this
one.

### `Debug` and `fmt` are not the problem either

Together 41,835 bytes, 3.2%. Stripping diagnostics to save it would cost the
project its main selling point for one fortieth of the gap.

### What is left is serde, and it is a real decision

371,581 bytes, 28.8%, and it is the only remaining item of the right order of
magnitude. Decision 0021 measured the *library* at 29 KB and correctly
concluded that swapping JSON for CBOR saves nothing. What it did not weigh is
the other 340 KB: the encoders and decoders `derive` generates from the model's
types.

Hand-writing serialization for the model would trade most of that for perhaps a
fifth of it. It is affordable in a way it would not normally be, because
**the schema is frozen and there are two witnesses guarding it**
([0020](0020-the-freeze-is-two-witnesses.md)) -- hand-written code cannot drift
from the schema without the witness failing, which is exactly the risk that
makes hand-written serialization a bad idea on a moving format.

It is still a large, dull, error-prone piece of work touching every type in the
model, and it would buy roughly 300 KB. That lands near 1.4 MB, not 1 MB.

**So: 1 MB is not reachable without giving something up that this project is
not willing to give up.** The budget is set to the measured figure and
ratcheted, as every other number in `size-budget.txt` is. Design section 10.2
called 1 MB "a budget to validate, not a measurement". It has now been
validated, and it is wrong.

## Consequences

**Section 10.2's 1 MB figure is superseded by 1.75 MB**, measured, for a build
with every feature compiled in. A `netcfgd-embedded` profile that drops the
optional backends would not meaningfully beat it, per above.

**The ratchet still holds.** Growth still fails the build and raising the
number is still a reviewable edit. What changes is only the number, and that it
is now derived from a measurement rather than from a target set before any code
existed.

**`make install` installs one file and one symlink.** The symlink is absolute,
so it dangles inside a `DESTDIR` staging root and resolves when that root is
unpacked at `/`, which is what a package expects.

**Invoked under any other name, the binary refuses and says what its two names
are.** Guessing would start a daemon for somebody who wanted a client.

## Alternatives considered

**Keep two binaries and feature-gate harder.** Rejected on the measurement:
the duplication was 775 KB and the gateable code is about 30 KB.

**Three binaries** -- splitting the compiler out so the daemon need not carry
it. That is decision 0003's nano tier, killed by
[0021](0021-no-nano-tier.md) on the measurement that decoding a compiled
document costs more than compiling the source.

**Hand-written serialization now.** Not rejected -- deferred, and written down
above with its size so it can be picked up as a deliberate piece of work rather
than discovered. It does not reach 1 MB either, so doing it under the belief
that it would is the mistake to avoid.

**Dynamic linking against a shared `libnetcfgd`.** Rejected: it trades install
size for a static musl binary's main virtue on this class of device, which is
that it has no runtime dependencies to get wrong.
