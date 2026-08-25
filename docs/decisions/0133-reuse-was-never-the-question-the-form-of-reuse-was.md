# 0133: reuse was never the question, the form of reuse was

Status: accepted
Date: 2026-08-25
Milestone: M3 boundary, revisited under a question 0016 did not answer

Extends [0016](0016-which-half-of-a-supplicant-could-ever-be-ours.md). It does
not reverse it: the boundary stands exactly where 0016 put it. What changes is
the argument, because 0016 rejected an alternative nobody proposed and left the
one somebody would ask about unrecorded.

## What 0016 answered, and what it did not

0016 decomposed "roll our own supplicant" into six parts and marked key
management and EAP **never ours**. The reasoning was implementation risk:
KRACK, Dragonblood, and the observation that a project whose pitch is
predictability has nothing to gain from having opinions about Dragonfly.

Its alternatives section rejected "write a full supplicant, crypto included",
"take the nl80211 path now", and "say nothing".

**All three are about writing the code.** The question actually put to this
project was different, and it is the obvious one:

> But most of the functionality already exists in libraries and in
> wpa_supplicant etc?

That is true, and 0016 has no answer to it. An argument from implementation
risk is weak against reuse -- if the risky part is somebody else's audited
code, the risk argument is being aimed at a proposal nobody made. A record
that answers a question nobody asked is how a decision gets relitigated, and
this one was, six weeks later, by the copyright holder.

## The first half of the answer: we already reuse

**netcfgd does not implement a supplicant, and it does not want to.** It runs
wpa_supplicant. 0014 makes it the floor rather than a fallback, 0015 keeps the
state on netcfgd's side, and 0091 has the supplicant *tell* netcfgd about a
roam rather than netcfgd inferring one. The M3 design is reuse throughout.

So the question was never reuse versus reimplementation. It is **which form of
reuse**: a process behind a control socket, or code linked into the daemon.
Everything below is about that, and only that.

## The second half: there is no library to link

Measured on a Debian machine, `wpasupplicant` 2:2.10-24:

    dpkg -L wpasupplicant | grep -E '\.so|\.a$|include'
    (nothing)

**The package ships no shared library, no static archive and no headers.**
hostap's `eap_peer/`, `crypto/` and `rsn_supp/` are internal source
directories compiled into the executables. Upstream has never published them
as a library with a stable ABI, and `ldconfig -p` on this machine finds
nothing matching `wpa` or `hostap` at all.

So "link wpa_supplicant's EAP" is not `-lwpa`. It is **vendoring a fork of
hostap's source tree**, and inheriting the obligation to track the security
updates of a codebase whose whole reason for being delegated is that its
defects are the ones that get CVEs. That is a materially worse position than
running the distribution's build of it, which is patched by somebody whose job
that is.

## The third half: the dependency set travels with the code

What wpa_supplicant links, from `objdump -p /usr/sbin/wpa_supplicant`:

    libnl-3, libnl-genl-3, libnl-route-3, libm,
    libpcsclite, libssl, libcrypto, libdbus-1, libc

What netcfgd links:

    libncursesw, libtinfo, libgcc_s, libc, ld-linux

and ncurses is a *default feature*, not a requirement: `--no-default-features`
leaves libc and libgcc_s alone and produces a byte-identical document.

**Constraint 3 says the core has no mandatory dependencies beyond libc and the
kernel, and names D-Bus.** Adopting hostap's EAP stack into the daemon means
adopting OpenSSL and libdbus into the core. `make linkage` gates the shipped
binary's `NEEDED` list against `LINKAGE_ALLOWED`, and would refuse it --
correctly, and with a message that points at this record rather than at a
workaround:

    linkage:   if this is deliberate, it is a decision to record,
    linkage:   not a line to add to LINKAGE_ALLOWED in passing

The same holds for reaching the functionality through a crate rather than
hostap. A Rust TLS stack is a fine piece of software and it is still a TLS
stack: it puts certificate validation inside the process that is meant to be
predictable, and it puts the core's dependency budget somewhere it cannot come
back from. The linkage gate does not care which language the dependency was
written in.

### Corrected, 2026-08-25: OpenSSL is avoidable, so this argument is weaker than it was written

**The paragraph above overstates, and the correction is the strongest form of
the question this record answers.** It says adopting hostap's EAP stack means
adopting OpenSSL. Measured in the 2.10 source rather than inferred from the
Debian build: hostap's crypto backend is pluggable, and one of the options is
its own.

    src/crypto/crypto_openssl.c      src/crypto/crypto_internal.c
    src/crypto/crypto_gnutls.c       src/crypto/crypto_internal-cipher.c
    src/crypto/crypto_wolfssl.c      src/crypto/crypto_internal-modexp.c
                                     src/crypto/crypto_internal-rsa.c

`CONFIG_TLS=internal` builds against a bundled LibTomMath and links no TLS
library at all. What `objdump` shows on `/usr/sbin/wpa_supplicant` is Debian's
build configuration, not hostap's requirement -- exactly the mistake
`reject-the-dependency-keep-its-knowledge` warns about, where a distribution's
`Depends:` was read as a property of the software and the real linkage said
otherwise. It was made here in the other direction: the linkage was read as a
property when the build configuration was the variable.

**So a vendored hostap could in principle keep netcfgd's `NEEDED` list at
libc**, and `make linkage` would not refuse it. The linkage argument does not
decide this on its own. What decides it is below, and it is a better argument
because it does not depend on how anybody configures a build.

## What vendoring actually costs, measured

**The size.** The minimum set for EAP and key management, excluding
`src/drivers` (52,445 lines) and the control interface:

    src/eap_peer, src/eap_common, src/crypto,
    src/rsn_supp, src/tls, src/common, src/utils     171,885 lines

    netcfgd today, crates + backend + adapter + helper  81,957 lines

**More than twice the size of the project absorbing it.** That is not a
subsystem netcfgd takes on; it is a codebase netcfgd becomes an accessory to,
and every argument this project makes about being small enough to read stops
being true on the day it lands.

**The maintenance, which is the part that decides it.** Debian carries three
CVE patches on top of 2.10:

    0017-CVE-2023-52160-PEAP-client-Update-Phase-2-authentica.patch
    CVE-2022-37660.patch
    CVE-2024-5290-lib_engine_trusted_path.patch

hostap 2.10 was released in January 2022. Those patches are three and a half
years of somebody whose job it is tracking upstream security traffic and
backporting it to a frozen base.

**Read the first one's name.** CVE-2023-52160 is the PEAP client's Phase 2
authentication -- not a peripheral part of the tree, but precisely the code
path netcfgd would be vendoring it *for*, and precisely the code path
`tests/live/enterprise.sh` exercises. It is remotely triggerable by a hostile
access point against a client that merely tries to associate.

**Vendoring moves that job to this project.** Not the writing of the code --
the *watching* of it: reading hostap's git log for security-relevant commits
that carry no CVE, deciding which apply to a fork, and doing it for as long as
netcfgd exists. Running the distribution's build means a machine that takes
security updates gets the fix without netcfgd knowing there was one.

## Decision

**The boundary from 0016 stands, on a different argument.**

Key management and EAP stay outside the daemon, and the reason of record is no
longer "this code is hard to write". It is:

1. **The process boundary is the property**, not the absence of the code. A
   handshake and a TLS stack on the other side of a control socket cannot take
   the daemon's address space with them.
2. **There is nothing to link.** Reuse in library form is not on offer, so the
   real comparison is a vendored fork against a distribution package, and the
   fork loses on the two numbers above: twice netcfgd's size, and a CVE in the
   exact code path, patched by somebody else three years after the release.
3. **A fork owns its own security watch, for ever.** This replaces the linkage
   argument as the load-bearing one, because `CONFIG_TLS=internal` means a
   vendored hostap need not link OpenSSL at all. Constraint 3 still holds and
   `make linkage` still enforces it; it simply is not what decides this.

**Reuse is affirmed, not declined.** Nothing here argues for writing a
supplicant. It argues that running one is the reuse, and that linking one is a
third option that is worse than both.

## What this weakens, and it should be said

**The middle rows of 0016's table are on softer ground than they were.** Scan
and BSS selection were marked "could be ours" partly on effort, and effort is
exactly what available libraries reduce. `netcfgd-sys::genl` already resolves
nl80211 -- id 35, six multicast groups -- and needed no `unsafe` of its own,
so the plumbing is paid for.

The thing that still blocks that path is not implementation cost and never
was: **pinning a BSSID defeats 802.11r fast transition.** That argument is
about behaviour on somebody's laptop during a call, so it survives any amount
of library availability. It is the one to re-read if this comes up again, and
0016 states it in full.

## Consequences

**The record now answers the question that gets asked.** "Why not use a
library?" has a measured answer -- no library exists, and the dependency set
that comes with the source would fail a gate that exists to protect the
project's headline claim.

**A future proposal has a shape to meet.** Anything arguing for linked crypto
in the core has to either produce a stable-ABI supplicant library that does
not drag OpenSSL and libdbus in, or argue that constraint 3 should change.
Those are both real arguments; neither is a line in `LINKAGE_ALLOWED`.

**0016 is not edited.** It records what was decided on 2026-07-29 and the
reasoning available then, which is what a decision record is for. This one
carries the part it was missing.

## Alternatives considered

**Vendor hostap's `eap_peer` and `crypto` into the tree, and use it rather
than run it.** Rejected on the two measurements above: 171,885 lines against
netcfgd's 81,957, and a security watch this project would then owe in
perpetuity over code whose defects are reachable from a hostile access point.
It buys nothing the process boundary does not already give, and it spends the
boundary to get it. Note that this is *not* rejected for linkage --
`CONFIG_TLS=internal` would keep `NEEDED` at libc -- which is why the reason of
record is maintenance rather than dependencies.

**Dig into hostap without taking it.** *Accepted, and it is not the same
proposal.* Reading it for how it splits the problem costs nothing and is worth
doing, particularly if netcfgd is ever rewritten in C: its EAP method
registration and its pluggable `crypto_*` backend are shapes worth copying even
where the code is not. This is the move 0043 already made with ModemManager --
reject the dependency, keep its knowledge, and prefer expressing what was
learned as data rather than as branches. The line that keeps holding: a wire
protocol is netcfgd's to own, and an accumulated body of security-critical
implementation is not.

**Link a Rust TLS stack for EAP only, leaving the handshake to
wpa_supplicant.** Rejected, and it is the most tempting of these because it
sounds bounded. It is not: EAP-TLS means certificate validation, trust stores
and chain building inside the daemon, and it would split the supplicant's job
across two processes with the security-relevant half in the one that has
`forbid(unsafe_code)` and no business holding it. 0008 already puts wired
802.1X through wpa_supplicant for the same reason.

## If netcfgd stops being Rust

The copyright holder has said a rewrite in C or C++ is possible. Three of the
arguments above are language-independent and one is not, and the split matters
because the wrong half is the memorable one.

**Independent, and they carry the decision on their own:** there is no library
to link, so reuse in library form is not on offer whatever netcfgd is written
in; the dependency set travels with the source, and `make linkage` reads an ELF
rather than a crate graph, so constraint 3 is enforced identically; and the
process boundary is a property of processes, not of languages.

**Not independent:** the alternatives section says a linked TLS stack would put
certificate validation "in the one that has `forbid(unsafe_code)`". In a C or
C++ netcfgd that clause is simply gone.

**It makes the conclusion stronger, not weaker, and this is the part to get
right.** The reason to keep a TLS stack and a 4-way handshake behind a process
boundary is that a memory-safety defect there cannot reach the daemon. A daemon
with no memory-safety guarantee of its own needs that boundary *more*, because
it is then the only thing standing between a malformed EAP frame and everything
netcfgd holds. A rewrite is a reason to restate this record, never to reopen it.

**Edit 0016 to add this reasoning.** Rejected on the standing rule that an
accepted record is not edited: a later record supersedes or extends it and
says so. The gap between the two dates is itself information -- it says the
argument was found wanting under questioning rather than written correctly the
first time.
