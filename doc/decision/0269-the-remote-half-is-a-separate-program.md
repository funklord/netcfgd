# 0269: the remote half is a separate program, and it starts by linking

Status: accepted
Date: 2026-09-29
Milestone: M10; fuzznet integration

## What this decides

**fuzznet is a pinned submodule at `fuzznet/`, and it is linked by
`bridge/netcfgd-remote` and by nothing else.** The daemon does not link it, the
client does not link it, and `c/` is untouched.

This is the first commit of the integration. It builds, it does one real thing,
and it says what it has not built rather than stubbing it.

## Why a separate program, which was decided before today

`doc/shared-protocol-brief.md` section 3 and design section 11.3: **the daemon
never grows a network listener.** Whatever speaks UDP is a separate process
holding an ordinary local socket connection, exactly as the NetworkManager shim
does for D-Bus. So the consequence for this work is fixed in advance — the
library is linked by an unprivileged bridge, never by the process holding
`CAP_NET_ADMIN`.

That is worth restating because it is the constraint that makes the rest cheap.
A fault in framing, signing, chunking or reassembly reaches a program that can
do nothing to the machine. netcfgd's existing authorisation does the
security-critical work, where it already has tests.

## What is built

`netcfgd-remote --peek` reads one frame on stdin and asks fuzznet what it is.
That is the first step of receiving one, it needs no policy, and it proves the
seam: netcfgd's build linking fuzznet's wire layer and getting a real answer
out of it.

    a zeroed 256-byte frame   fuzznet refused the frame (-2)   exit 1
    empty stdin               nothing to read on stdin         exit 2

`-2` is `FZN_SEAL_ERR_SHAPE`, which is the correct reading of 256 zero bytes.

**The refusal path is proven and the acceptance path is not**, and the
distinction matters: everything measured so far is fuzznet saying no. A
positive control needs a frame that verifies, and that is blocked on the next
decision rather than on effort — see below.

## What is deliberately not built

**The UDP socket, the connection to netcfgd, and the capability-to-tier
mapping.** The last is the one to be careful about. The brief says a remote
capability must map onto `observe`, `wifi` and `admin` (0013) rather than
introduce a parallel vocabulary, and those tiers are independent rather than a
ladder (0092). *How* a `fzn_cap_id_t` names one of them — fixed ids, a policy
file, a grant carried in the chain — is a design decision, and inventing one
because it was the next thing to write is how a security boundary acquires a
shape nobody chose.

A program that refuses what it has not built says so. It does not open a socket
that does nothing.

## The measurement, and the one that went stale in an hour

fuzznet at the pin: `make all` succeeds, 107 objects, and a netcfgd-style C11
program compiles against its headers and links against those objects.

**An earlier run of that same measurement was already wrong when it was
quoted.** It was taken against `c535fae`, the HEAD of the checkout beside this
tree — and `git submodule add` pinned `97719d9`, because that checkout is 145
commits behind its own remote. The numbers moved with it: 81 objects became
107, and a linked artifact of 674,600 bytes became 969,272.

Nothing was decided on the stale figure, because the pin was re-measured before
anything was written. The lesson is the cheap one: **a sibling checkout is
whatever its session last fetched**, which is the argument `harmonization.md`
already makes for vendoring, arriving as a measurement rather than as advice.

## The next decision, which this one uncovers

**netcfgd must choose a crypto backend, and fuzznet deliberately does not
choose for it.** The crypto is a vtable rather than a dependency — measured
here, `wire/seal.o` carries no undefined AEAD or `crypto_` symbol at all, and
there is no Monocypher in the submodule. fuzznet's own golden-frame test is
gated on Monocypher for exactly this reason.

So a frame that *verifies* cannot be produced until netcfgd says what performs
the AEAD and the hash. That blocks the positive control above, and it is the
first thing the next increment has to settle.

## What it costs

    fuzznet submodule      pinned at 97719d9
    bridge/netcfgd-remote  969,512 bytes, which is almost entirely fuzznet

The size is worth stating rather than discovering: the bridge links fuzznet
whole, because fuzznet builds objects and no archive, so the linker has no
member granularity to exploit. A project that gates on size elsewhere should
know that this program is a megabyte before it has opened a socket, and whether
that matters is a question for when it does something.
