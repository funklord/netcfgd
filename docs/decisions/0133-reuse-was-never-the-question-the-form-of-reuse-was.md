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

## Decision

**The boundary from 0016 stands, on a different argument.**

Key management and EAP stay outside the daemon, and the reason of record is no
longer "this code is hard to write". It is:

1. **The process boundary is the property**, not the absence of the code. A
   handshake and a TLS stack on the other side of a control socket cannot take
   the daemon's address space with them.
2. **There is nothing to link.** Reuse in library form is not on offer, so the
   real comparison is a vendored fork against a distribution package, and the
   fork loses.
3. **Constraint 3 is a promise with a gate behind it.** Linking OpenSSL and
   libdbus into the core is not a build detail, it is the headline claim.

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

**Vendor hostap's `eap_peer` and `crypto` into the tree.** Rejected: it is a
fork of security-critical code, with the maintenance burden landing on the
project least equipped to carry it, in exchange for removing a process
boundary that is itself the safety property.

**Link a Rust TLS stack for EAP only, leaving the handshake to
wpa_supplicant.** Rejected, and it is the most tempting of these because it
sounds bounded. It is not: EAP-TLS means certificate validation, trust stores
and chain building inside the daemon, and it would split the supplicant's job
across two processes with the security-relevant half in the one that has
`forbid(unsafe_code)` and no business holding it. 0008 already puts wired
802.1X through wpa_supplicant for the same reason.

**Edit 0016 to add this reasoning.** Rejected on the standing rule that an
accepted record is not edited: a later record supersedes or extends it and
says so. The gap between the two dates is itself information -- it says the
argument was found wanting under questioning rather than written correctly the
first time.
