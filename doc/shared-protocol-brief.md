# What netcfgd needs from a shared protocol library

**Audience: whoever authors the shared IPC and network protocol** — the
library provisionally called `fuzznet`, produced in `../fuzzypickles` and
intended for fuzzypickles, netcfgd and a planned `raidcfgd`.

**Status: netcfgd's requirements, not a design.** The design is the library
author's. This says what netcfgd would consume, what it cannot trade away and
why, what it has already decided that you may knowingly overrule, and what it
cannot tell you. Written 2026-08-08, on being told the library is being
authored.

You do not have to read this repository to use this. Where more detail exists,
it is named — `doc/remote-access-feasibility.md` is the long form and
`doc/socket-protocol.md` specifies what exists today.

---

## 1. The one-line answer

**netcfgd wants the remote half and already has the local half.**

The brief that started this names two needs: local group-gated access to a
daemon running as root, and authenticated remote access over UDP. For netcfgd
the first is built, specified, pinned by a generated witness and implemented
three times; the second does not exist at all and is the reason this is
interesting.

That asymmetry is the single most important thing to design around, because
the obvious shape of a shared library — one encoding, one parser, both hops —
is the shape netcfgd cannot adopt. Section 4 argues that properly rather than
asserting it.

---

## 2. What netcfgd would consume

Two things, and neither is inside the daemon:

- **`wire/`** — the framed, authenticated datagram protocol: envelope,
  capabilities, signing, verification, chunking and reassembly.

  **Everything in that list is built, in `../fuzznet`** (reported 2026-08-19
  and checked here file by file): `wire/frame.situ` with its `.wire` and
  `.map` beside it and `wire/seal.c` to open and seal a frame, `chain/` for
  minting, delegation and verification against a pinned root, `chunk/split.c`
  and `chunk/reassembly.c` with a chunk cap and a per-sender quota, and
  `frame/freshness.c` for section 5's expiry rule. The crypto is a vtable
  rather than a dependency, so nothing here is forced to take Monocypher.

  This bullet used to read "Planned as netcfgd's own C, at the repository
  root beside `crates/`. **It does not exist yet**", and that was withdrawn
  on 2026-08-10 — 180 lines below, in section 7, where a reader of this
  section would not meet it. **A document that corrects itself downstream of
  the claim lets the withdrawn text go on reading as current**, which is how
  the library author read this one as saying their tree was unbuilt. The
  sentence was about netcfgd's own planned directory, which genuinely does
  not exist and never will (section 7, item 5) — but being technically true
  is no defence when the correction is 180 lines away.

  What the old bullet got right is worth keeping: the alternative was to
  *copy* fuzzypickles' design into a second implementation, and consuming a
  library instead means that second implementation is never written. That is
  now a fact rather than a plan.
- **`agent/`** — a small bridge that terminates the remote protocol, maps a
  remote capability onto a local tier, and then speaks netcfgd's ordinary
  local socket as an unprivileged client. Netcfgd-specific; not yours to
  write, but its shape is fixed by section 3.

The GUI (`gui/`, Qt Widgets, desktop and Android from one source) speaks one
request vocabulary over two transports: the local socket directly, or the
remote protocol to an agent.

---

## 3. Hard constraints

These are design commitments with records behind them. If the library's shape
conflicts with one, that is a conversation with the maintainer, not something
to work around.

**The daemon never grows a network listener.** Design §11.3 fixes this and
constraint 6 says it from the other side: whatever speaks UDP is a separate
process holding an ordinary local socket connection, exactly as the
NetworkManager shim does for D-Bus. No new authority layer inside the daemon.
The consequence for you is that the library is linked by an unprivileged
bridge, never by the process holding `CAP_NET_ADMIN`.

**Authorisation is capability → tier, and the tiers already exist.** 0013
defines three: `observe`, `wifi`, `admin`. They are **independent, not a
ladder** — a machine may grant `admin` to a group somebody is in and `wifi` to
one they are not, so there is no maximum to report (0092). A remote capability
must map onto that vocabulary rather than introduce a parallel one; the
daemon's existing enforcement then does the security-critical work, where it
already has tests.

**A stolen device is a capability to revoke, not a password to change.** This
is the part of fuzzypickles' identity model netcfgd most wants, and it is a
requirement rather than a preference.

**Nothing transmitted may carry secret material.** Constraint 5: the
desired-state document carries `SecretRef` indirections only, "invariant
across local files, `/run` state, and any future wire transmission". The
library never needs to carry a passphrase or a private key.

**A received document may not carry executable content.** Hooks are
`{phase, path, sha256}` references, never inline shell, because "a document
that can carry shell is remote code execution with extra steps" (§2.2). A
non-local document may reference only paths that already exist on the device,
and the receiving side refuses hook entries entirely unless local policy opts
in.

**Constraint 6, the one-way rule, applies to you.** No change to netcfgd's
model, config language or socket API may be justified *solely* by a client's
needs — a concept must independently be something a local operator would want
in their own config file. That rule was written about adapters; a shared
library is the same pressure with more leverage, and raidcfgd wanting
something is not a reason netcfgd's protocol gains it.

---

## 4. Why netcfgd's local hop stays newline-delimited JSON

You will want to know this early, because fuzzypickles' own core deliberately
does the opposite — one canonical encoding for local and remote, so there is
one parser — and that is a good rule that netcfgd does not follow.

The full argument is `doc/socket-protocol.md` §3.1 and §3.2. In summary:

- **A protocol needing generated bindings rebuilds the bargain netcfgd exists
  to refuse.** Constraint 3 is no mandatory D-Bus, glib, polkit or systemd, and
  a large part of the audience is people escaping exactly that. Codegen between
  an operator and their own daemon is the same trade in different clothes.
- **It is the same claim as `/run` being greppable.** Not being a black box is
  the product (constraint 7). Runtime state is readable JSON files; the socket
  carries the same shapes, so one serde derive and one witness cover both. A
  binary control channel would make the daemon's state inspectable and its
  conversation opaque.
- **A shell script with `jq` is a legitimate client**, and so is a Python
  service on a router with no Rust toolchain. For a tool whose adapters are
  meant to live at the edge, the cost of entry is a feature.
- **Diagnosis without a decoder.** The machine having the problem is usually a
  router reached over the network being reconfigured.

The costs are stated in that document rather than glossed: a JSON parser is a
larger attack surface than a fixed frame (so the framing carries a hard bound
and both parsers are fuzzed), and **messages have no canonical form, so nothing
can hash or byte-compare one**.

**The seam is where the trust boundary already is**, which is what makes two
encodings defensible rather than merely tolerated:

| | local control socket | remote path |
|---|---|---|
| carries | newline-delimited JSON | a binary framed message |
| reaches | this machine only | across a trust boundary |
| authenticated by | the kernel, before a byte is parsed | a signed capability |
| chosen for | no bindings, greppable, `socat`-able | exactness, authentication, size |

**And the local encoding is not a placeholder waiting for a real protocol**,
which is the reading to head off. The cost that would make it one is not
there: `serde_json` is a dependency of eight crates because principle 2 puts
runtime state in JSON files and because the schema witnesses are JSON, so the
socket's encoding costs the binary approximately nothing extra. The one tier
where that arithmetic changed was `nano`, which had a hand-rolled codec in the
design and was dropped in 0021 — the placeholder theory lost its own use case.

It has also been validated the hard way. `client/` is a C implementation
written in a separate workspace against the witness rather than against the
Rust types, and building it found **three defects in the protocol itself**: a
request the daemon accepted that no client could send (0081), and one
operation carrying two different names depending on which message it appeared
in (0082, 0083). A protocol with generated bindings would not have produced
those, because the second implementation would have been generated from the
same source as the first. That is the specific value the boring choice buys,
and it is the thing a shared library with codegen would take away.

**What would change the answer**, so this is falsifiable rather than dogma: if
a control message ever needed to be hashed, signed or byte-compared; if the
local socket became a bulk path rather than a handful of round trips per
reconcile; or if an embedded tier returned with a budget JSON alone breaks.
None is true today.

---

## 5. Two requirements a messaging protocol gets wrong

Both are recorded in `doc/remote-access-feasibility.md` §5 and both are places
where inheriting fuzzypickles' instincts inherits a bug.

**Freshness: commands expire, grants do not.** fuzzypickles is built so a
message reaches a sleeping peer eventually — senders hold until settled, hosts
store and forward, authority is not ended by a clock. Every one of those is
wrong for configuration. A command that reconfigures a router an hour after it
was sent, because the router was off, is precisely the failure commit-confirm
exists to prevent; and netcfgd computes a plan against a *current* observation,
so a stale command is not merely late, it was computed against a machine that
no longer exists. The envelope already carries the fix — `nonce | expiry`
inside the signed region — so the adaptation is a policy statement rather than
code. **Please make expiry mandatory for commands rather than optional**, since
the default that arrives with the protocol will push the other way.

**Payload size, which is the one nobody expects.** fuzzypickles' control
channel is local, where a `SOCK_SEQPACKET` datagram can be large. netcfgd's
responses are not small: a `status` is the entire observation — every link,
address, route, backend and DNS scope — and a `show` is the compiled document.
On a router with a dozen interfaces that is comfortably past any UDP MTU and
past the practical limit of IP fragmentation, which should be avoided anyway
since fragmented UDP is widely dropped. So the library needs
**application-level chunking with reassembly**, retransmission of missing
pieces, and a bound on the memory a half-finished response may hold.
fuzzypickles has chunking, but for content-addressed assets rather than for
control responses. This is the largest single piece of new work and the
highest-risk part.

---

## 6. What netcfgd already decided, and may be overruled on

Taken 2026-08-04 and carried into `gui/project.md`. They were decided when the
protocol was going to be netcfgd's own code; a shared library is a good reason
to revisit any of them, deliberately.

1. **C/C++ with Monocypher** for the protocol and the agent, one crypto
   implementation across the family. (The alternative was Rust in its own
   workspace, at the cost of a second implementation of the same primitives.)
2. **LAN only first**, and *first* is the operative word — no rendezvous, no
   hole punching, no relay in the first cut, because the case a person actually
   wants is "I am at home, fix the wifi". **Superseded in intent 2026-08-08:
   netcfgd is not going to remain LAN-only.** The staging stands; the
   destination is not a LAN. For the library that means **do not read this item
   as a permanent constraint** — a design that assumes both endpoints are
   directly reachable, or that a hostile network is somebody else's problem, is
   built against a premise that has already expired. See
   `doc/remote-access-feasibility.md`, "Beyond the LAN".
3. **The local hop stays JSON**; the agent translates. Section 4.
4. **Makefiles and qmake only** in this tree, no CMake.
5. **The four directories live at the repository root**, beside `crates/`,
   `backend/` and `adapter/`: `gui/`, `client/`, `wire/`, `agent/`.
   **Superseded 2026-08-10 in the `wire/` entry only** — see below. Three, not
   four.
6. **`situ` describes the frame**, with Monocypher bound as an extern codec,
   and the hand-written half built to be deleted as situ absorbs chunking and
   encryption. **Corrected 2026-08-08 and retired 2026-08-10** — see below.

**These are the numbers `doc/remote-access-feasibility.md` §8 uses**, and this
list now matches it. An earlier version of this brief renumbered them, which is
how "netcfgd's decision 4" came to mean *situ describes the frame* in
`../fuzznet/project.md` §6 while decision 4 in the source list is about
Makefiles. The source list is the one to cite. Apologies for the citation that
no longer resolves; it is worth one edit there rather than two numbers for one
decision across three repositories.

Item 6 is worth flagging: netcfgd's own §9 evaluated `situ` against the control
socket and split the answer — the *framing* is describable, and situ's
`unbounded-scan` rule would have predicted the `MAX_LINE` bound netcfgd reached
by judgement; the *payload* is not, because a JSON object has no byte layout to
pin. That split is the same seam as section 4's, and it is also why the split
does not constrain `fuzznet`: both halves there are binary.

**Correction to item 6, from the library author (2026-08-08).** The phrase "as
situ absorbs chunking and encryption" bundled two things that have since gone
opposite ways, and planning around it would put the risk in the wrong place:

- **Encryption is absorbed already.** situ's phases 7 and 8 — extern codecs and
  the cryptographic model — both record status *complete*, not planned. Nested
  tag coverage recomputes innermost first, and the sealed interior is reachable
  only through a view type the verified open produces. So do not write that half
  at all, rather than writing it to be deleted.
- **Chunking is not going to be absorbed on any timescale worth waiting for**,
  and the reason is weaker than a first version of this note claimed. situ's §2
  non-goals say nothing about protocols at all; the "service and RPC out of
  scope entirely" line is from its protobuf importer, about what a `.proto`
  will not translate. So chunking is **unaddressed and unplanned rather than
  excluded** — no construct for retransmission, reassembly or timers, nothing
  in the thirteen-phase plan, and nothing about request/response correlation
  anywhere in that document. Planning around its arrival is still wrong; the
  door is merely not bolted.

`doc/remote-access-feasibility.md` §5.0 carries the same correction in longer
form.

**Retirement of item 6 (2026-08-10).** The decision is confirmed in substance
and is no longer netcfgd's to hold, and those are separate statements.

Confirmed: `../fuzznet` exists and `wire/frame.situ` is in it, so the frame is
written, in situ, with the crypto inside the schema. Retired: decision 6 was
taken when `wire/` was going to be netcfgd's own C, and a netcfgd record
describing how a shared library encodes its frame is a copy of somebody else's
decision with nothing keeping the two honest — the exact drift this workspace
has already paid for in three shared files. **netcfgd consumes `fuzznet`'s
frame and has no opinion on how it is described.** What netcfgd keeps is the
requirements, which hold whoever writes the code: section 5 here, and the
constraints in section 3.

Item 5 falls with it — `wire/` is not a netcfgd directory. `project.md` §5's
layout and `gui/project.md` §§6, 8 and 10 still describe it as one; they are
named rather than rewritten, since the protocol documents are yours to edit.

**The advice this brief gave for two days was withdrawn, and the withdrawal is
now itself withdrawn — by measurement.** It said the chunking state machine was
permanent code and should be designed as such, reasoning from situ describing
messages and not protocols. situ's decision 0032 puts protocol dynamics on a
six-rung ladder chosen at `situc build --layer`, and this brief read `frame` and
`drive` as covering exactly that work.

They do not. The fuzznet session built `wire/frame.situ` at every rung and
reported the result (its commit `87d1b39`): `view`, `edit` and `relate` emit an
identical 18746 bytes, `frame`, `converse` and `drive` an identical 24313, and
the only thing the upper rungs add is a **stream** reader — a byte stream in,
whole messages out. **No rung emits datagram reassembly at all**, which is the
problem this protocol actually has. So chunking staying hand-written in fuzznet
is a finding rather than a temporary arrangement, and the original advice was
right for a reason nobody had measured when it was given.

**What went wrong here is worth more than the conclusion.** The withdrawal was
made on the strength of a design document saying which rungs cover protocol
dynamics, and reversed by somebody running the compiler and reading the byte
counts. `evidence.md` has the rule and this brief broke it: a document stating
an intent is not a measurement of what a tool emits, and deferring to the
project that owns a decision is not the same as checking what its tool does.
Where this brief says "situ will absorb X", read it as a prediction with no
measurement behind it unless it names one.

The durable part is the requirement, not the prediction: a bound on the memory
a half-finished response may hold, and retransmission of what is missing,
however that code arrives.

Nothing else in this brief changes: the local hop, the tiers, the freshness
rule and the constraints are untouched.

---

## 7. What netcfgd cannot tell you

**`raidcfgd` exists, and this section used to say it did not.** It read "no
repository, no directory, and it is not in the private-project list" -- true
when written, and false on all three counts now: `~/src/raidcfgd`, a remote at
`git@github.com:funklord/raidcfgd.git`, and an entry in the private-project
list. Checked here rather than taken on report.

That retires the risk this paragraph was about. The shared core is no longer
being designed around two real consumers and one imagined one, and the
requirements that could not be checked are now stated by the project that has
them. netcfgd's position is unchanged and its reason is better: it still has no
opinion on what a RAID daemon needs, and no longer needs to have one, because
there is somebody to ask.

**Which package the agent ships in is open**, and it matters to you only in
that it is a daemon that listens on a network — a thing netcfgd has
deliberately never had.

The rest of netcfgd's open questions are in `gui/project.md` §9: whether a
remote `apply` may run without a confirm window, how a phone finds a host on
the LAN, and how first pairing works.

---

## 8. Authority, and editing this tree

`project.md` is netcfgd's source of truth and wins over its code;
`netcfgd-design.md` holds the rationale. For netcfgd's *semantics* — what a
field means, what a device must reject, how versions skew — those documents
decide.

For **encoding, framing, authentication and encryption, the library decides**,
and that is not a concession made today. Design §11.3 wrote it down before any
of this: those four are "out of scope for this document, since you already have
a protocol design tool for exactly that."

The maintainer has said the protocol parts of this repository are yours to edit.
Two requests, both about keeping the seam visible rather than about ownership:

- **`doc/schema/socket.json` is generated**, and `make schema-bless` is the
  only way it moves. If a change makes it move, that is intended to be
  reviewable — do not hand-edit it.
- **`make check` is green**, and `make conformance` specifically diffs what the
  Rust and C clients extract from the same bytes. It is the gate that caught
  three spellings of one access point's name, and it is the one worth keeping
  green through this work.
