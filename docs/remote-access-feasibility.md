# Remote access over an encrypted datagram protocol: a feasibility analysis

**Status: analysis, not a decision.** Nothing here is settled and nothing is
built. It exists to answer one question -- *could netcfgd's remote and Android
story be fuzzypickles's protocol and auth structure, rather than something new?*
-- with enough detail that the decision after it is an informed one.

Written 2026-08-04, against fuzzypickles as it stands in the sibling tree.

---

## 1. What is actually being proposed

Three separable things, and separating them is most of the analysis:

1. **A Qt Widgets GUI**, desktop and Android from one source, in the sibling
   projects' style.
2. **A remote transport**, because an Android build cannot run netcfgd's daemon:
   it configures a Linux host through rtnetlink with `CAP_NET_ADMIN`, `/etc` and
   `/run`. Anything on a phone is a client of a netcfgd elsewhere.
3. **An authentication and authorisation model** for that transport, since
   netcfgd's current one is `SO_PEERCRED` on an `AF_UNIX` socket -- a uid and a
   gid, which do not cross a network.

(1) is independent and could ship against the local socket alone. (2) and (3) are
one piece of work, and are what this document is about.

---

## 2. What netcfgd has already settled, which is more than expected

The design anticipated remote use in several places, and each of those is a
constraint the transport has to satisfy rather than a question it gets to answer.

**§11.3, "if a bespoke controller is ever built anyway"**, already fixes the
shape:

> The seam is already there: a remote configuration source is **a compiler that
> runs somewhere else**. It would resolve site intent, templates and per-device
> variables on a real machine, emit the same desired-state document the local
> compiler emits, and ship it down; the device reconciles it identically to a
> local file. It would *not* be a firmware manager [...] and **not a new
> authority layer inside the daemon** -- the receiving agent is an ordinary
> unprivileged socket client, exactly like the adapters in §9.

That single paragraph decides the architecture: **the daemon does not grow a
network listener.** Whatever speaks UDP is a separate process that holds a local
socket connection, exactly as `netcfgd-nm` does for D-Bus. Constraint 6 says the
same thing from the other side -- no change to the model, config language or
socket API may be justified solely by a client's needs.

**§2 already makes the document safe to transmit**, and says so in as many words:
the desired-state document carries `SecretRef` indirections and never secret
material, "invariant across local files, `/run` state, and any future wire
transmission". §2.2 goes further and pre-answers the remote-code-execution
question: hooks are `{phase, path, sha256}` references, never inline shell,
because "a document that can carry shell is remote code execution with extra
steps" -- and **a received, non-local document may reference only paths that
already exist on the device, and the receiving side refuses hook entries entirely
unless local policy opts in.**

**0013's control tiers** -- `observe`, `wifi`, `admin` -- are already the
vocabulary a remote capability would name. They exist, they are enforced, and
they were designed as "three things a caller may be allowed to do" rather than as
a uid check that happens to work locally.

**Authorisation today is `peer.uid` / `peer.gid`.** A remote peer has neither, so
the agent must map a remote identity onto a tier and then connect locally as a
principal holding it. That is not a workaround; it is what §11.3 describes.

What is *not* settled, and cuts the other way: **§11.1 says conform, don't
invent.** RESTCONF is the preferred multi-host answer precisely because it is not
a bespoke protocol. This proposal is §11.3 territory -- the escape hatch for when
the standards answer does not give the experience wanted -- and it should be
argued on that basis rather than as a replacement for M9. They serve different
audiences: a site with four hundred hosts and Ansible wants RESTCONF; a person
with a phone and their own router wants this.

---

## 3. What fuzzypickles has that would be copied

Read from its `project.md` (§§1-9, 13) and its `core/` tree.

| Piece | What it is |
|---|---|
| **Datagram non-negotiable** | "Never build or reintroduce a TCP-style ordered-byte-stream abstraction. Message boundaries are preserved end to end." UDP on IP links. |
| **Identity model** | User and host as separate keypairs, never conflated. Several hosts per user, each with its own **capability set** rather than a permission scalar. |
| **Key discipline** | Separate keypairs per role; long-term keys sign, ephemeral keys do DH, never both. User root cross-signs host keys; host keys sign role capabilities. |
| **Signed command envelope** | Every privileged command covers, inside the signed region: `command \| target host id \| nonce or counter \| expiry \| capability`. Authentication is not authorization; a relay must not be able to forge, redirect or usefully replay what it forwards. |
| **Revocation** | Explicit signed act, propagated host to host on contact. Authority is not ended by a clock. |
| **Crypto** | Monocypher only: X25519, ChaCha20-Poly1305, BLAKE2b, EdDSA. Platform supplies entropy explicitly, never defaulted. |
| **Key-committing AEAD** | Mandatory: derive an AEAD key *and* a short commitment from each shared secret, put the commitment in the frame, reject on mismatch. |
| **One-sided session establishment** | Published prekey bundles per device, so a sender can open a forward-secret session to a sleeping peer with no round trip. |
| **Local IPC** | `AF_UNIX` `SOCK_SEQPACKET`, the *same* canonical wire encoding as the network link -- one parser, not two. Trust boundary is filesystem permissions; no session crypto on the local hop. |
| **Frontend model** | A frontend runs the same protocol engine as the daemon against a memory-only store. Not a thin RPC shim. |
| **Parser discipline** | The hand-rolled binary parser is "the highest-risk code in the project", fuzzed on both surfaces, validated by mutation, with the acceptance rate printed so it cannot silently fall to zero. |

---

## 4. Feasibility, piece by piece

### Transfers essentially as-is

- **The identity and capability model.** User root → host keys → role
  capabilities maps onto netcfgd's three tiers with no invention: a capability
  says *this host may `observe` / use `wifi` / `admin` on that host*. netcfgd
  already has the vocabulary and the enforcement point; what it lacks is a way to
  say it about somebody who is not a local uid.
- **The signed command envelope**, unchanged. `command | target host id | nonce |
  expiry | capability` is exactly right for a configuration command, and the
  target binding matters more here than in a chat app: an `apply` addressed to
  the office router must not be replayable at the home one.
- **Key discipline and key-committing AEAD.** Nothing about netcfgd argues for
  weakening either.
- **The "authentication is not authorization" rule**, which netcfgd already
  half-holds: the socket proves who you are, the control tiers decide what that
  permits.
- **The local-hop trust argument.** netcfgd's socket already relies on filesystem
  permissions and peer credentials; fuzzypickles's §13 states the same position
  in more words.

### Transfers with adaptation

- **One parser for both hops.** fuzzypickles reuses its canonical binary encoding
  on the local socket. netcfgd's local protocol is newline-delimited JSON, pinned
  by `docs/schema/socket.json` and consumed by `ncfg`, the TUI and (soon) a GUI.
  Replacing it to share one encoder would be a large, disruptive change to a
  frozen surface; keeping two means the agent translates. **Recommendation:
  translate.** The agent is the natural place -- it is already the thing that
  turns a remote identity into a local principal -- and the JSON side has a
  witness that goes red when it drifts.
- **Sessions and prekeys.** Worth having for the phone-wakes-up case, but netcfgd
  has no offline-peer problem: a router that is down cannot be configured, and
  should say so rather than accept a command for later (see §5 below).
- **The frontend-runs-the-same-engine model.** netcfgd's engine is the planner and
  the executor, and neither belongs in a GUI: a plan is computed against a
  *machine's* observation. The netcfgd analogue is thinner -- the GUI renders what
  the daemon computed. This is a real difference in kind, not a shortfall.

### Does not apply

- **Groups, sender-keys, multi-recipient fan-out.** One operator, one device;
  there is no group of routers that must all decrypt one command. If fleet
  management ever wants that, §11.1 says the answer is RESTCONF plus existing
  tooling.
- **Content-addressed assets and swarm distribution.** Nothing here moves large
  immutable blobs.
- **Traffic classes, link budgets, the scheduler.** These exist for multi-radio
  nodes with money and energy budgets. netcfgd has one link and no budget model,
  and importing the scheduler would be importing a solution to a problem netcfgd
  does not have.
- **Delivered/settled two-ack durability.** netcfgd's semantics are
  request/response against a machine: an apply either happened, or failed with a
  journal. "Settled" has no meaning that `plan.last.json` does not already carry.

---

## 5. The four hard problems

None is a blocker; all four are work, and the third is a decision rather than a
task.

### 5.0 The frame itself, which is mostly solved already

Written before `../situ` was looked at. It is a sibling compiler that takes a
schema of a binary format and generates accessors in C, C++, Rust and Python,
with `authenticated { }`, `sealed(codec, nonce = ref) { }` and `tag ... covers()`
as first-class constructs -- its own §14 is a cryptographic model, not an
afterthought. Tried from a clone on a netcfgd-shaped envelope: it generates C that
compiles clean, gates the sealed interior behind a type only a verified open can
produce, and refuses to hand out a transmittable buffer while a tag is stale.

That moves the risk. **The frame stops being hand-rolled**; what stays hand-rolled
is the framing -- the chunking and reassembly below -- which situ says is not its
job today, in a comment in its own generated output. Everything in §5.1 still
applies to that half and to no other.

**And "today" is the operative word.** situ already carries codecs and transforms;
encryption and plausibly chunking are expected to move into it over time, taking
work off the implementor. So the hand-written half should be built to be deleted:
the crypto bound as an extern codec rather than wrapped, the chunk header a schema
struct with only the state machine in C, nothing above `wire/` aware that any of
it is generated, and no hand-written check that restates something the schema
could say. `gui/project.md` §§6.1-6.2 has the detail.

Versioning is this repository's job and situ supplies the tools rather than a
scheme: version as a *field*, `[since = N]` enforced append-only, `variant` where
a revision re-lays the bytes, and a committed `wire` signature whose change is a
change somebody reviews -- which is `docs/schema/` and `make schema-bless` in
another language.

### 5.1 Payload size, which is the one nobody expects

fuzzypickles's control channel is local, where a `SOCK_SEQPACKET` datagram can be
large. netcfgd's responses are not small: a `status` is the whole observation --
every link, address, route, backend, DNS scope -- and a `show` is the compiled
document. On a router with a dozen interfaces that is comfortably past any UDP
MTU, and past the practical reassembly limit of IP fragmentation, which should be
avoided anyway (fragmented UDP is dropped by a great deal of middleboxes).

So the protocol needs **application-level chunking with reassembly**, or the
requests need to be made small enough that responses are not. fuzzypickles has
chunking, but for content-addressed assets rather than for control responses.
This is the single largest piece of new work and it is where a
"datagrams, not streams" design has to be honest: a large answer *is* a sequence,
and something has to reassemble it, retransmit the missing pieces and bound the
memory a half-finished one can hold.

### 5.2 Reaching the daemon at all

A phone on mobile data and a router behind NAT do not have a path to each other
without help. The options are the usual three: a static endpoint with a port
forward (fine for one's own router, useless in general), a rendezvous and hole
punching, or a relay. fuzzypickles has relay machinery; adopting it means adopting
a peer-discovery model along with it, which is a substantially larger surface than
"an encrypted UDP protocol".

**The cheap first cut is worth naming**: on a LAN -- the phone and the router on
the same wifi -- none of this is needed, and that covers the case a person most
often wants ("I am at home, fix the wifi").

### 5.3 Which language holds the crypto

fuzzypickles's answer is Monocypher, C, one implementation everywhere. netcfgd's
core is Rust with `#![forbid(unsafe_code)]` everywhere except `netcfgd-sys`, and a
twelve-crate dependency budget that `make nm-containment` enforces.

These do not conflict, because the agent is **not the core**. `netcfgd-nm` already
carries ninety-nine crates in its own workspace and the gate proves the core does
not link them. The agent can be:

- **C or C++ beside the GUI**, linking Monocypher, in the sibling style -- one
  crypto implementation shared with fuzzypickles, and the family's own review
  history behind it; or
- **Rust in its own workspace**, using a vetted crypto crate, at the cost of a
  second implementation of the same primitives in the family.

The first is more in the spirit of "same tooling as the siblings" and gives the
GUI and the agent one language. The second keeps netcfgd's tree in one language
and its safety property everywhere it can hold. **This is the decision the rest
depends on** and it is the user's.

### 5.4 Freshness, where a chat app's instincts are exactly wrong

fuzzypickles is built so a message reaches a sleeping peer eventually: senders
hold until settled, hosts store and forward, authority is not ended by a clock.
**Every one of those is wrong for configuration.** A command that reconfigures a
router an hour after it was sent, because the router was off, is precisely the
failure commit-confirm exists to prevent -- and netcfgd's own rule is that a plan
is computed against a *current* observation, so a stale command is not merely late
but computed against a machine that no longer exists.

The envelope already carries the fix: `nonce | expiry` inside the signed region.
The adaptation is a policy statement, not code -- **commands expire, grants do
not** -- and it is worth writing into whatever record follows this, because the
instinct inherited with the protocol will push the other way.

---

## 6. The shape that fits

```
   Android GUI            desktop GUI
        |                      |
        |  encrypted UDP       |  AF_UNIX, local, uid/gid
        |  (signed envelopes)  |
        v                      v
   netcfgd-remote  ------>  netcfgd daemon
   (agent, own workspace)   (unchanged)
        ^
        |  holds a local socket connection as a principal
        |  whose tier the remote capability entitles
```

- The daemon is **unchanged**. No listener, no new authority layer, no model
  change -- constraint 6 and §11.3 both demand this, and it is also what keeps the
  core's dependency budget intact.
- The agent maps **remote capability → local tier**, then speaks the ordinary
  socket protocol. An `observe` capability gets a connection that can only ask;
  `admin` gets one that can apply. The daemon's existing enforcement does the
  rest, which means the security-critical decision stays where it already is and
  has tests.
- The GUI speaks **one protocol in two transports**: locally the AF_UNIX socket
  directly, remotely the encrypted datagram protocol to an agent. Same request
  vocabulary either way, which is what makes desktop and Android one codebase
  rather than two.
- **A stolen phone is a capability to revoke**, not a password to change, which
  is the part of fuzzypickles's model most worth having here.

---

## 7. Cost, honestly

Rough, and rough on the high side, because the parser is the part that always
costs more than it looks:

| Piece | Size |
|---|---|
| Envelope, capabilities, signing, verification | moderate -- the design is copyable, the code is not |
| Datagram framing, chunking, reassembly, retransmit | **large**, and the highest-risk part |
| Fuzzing to the family's standard (two surfaces, mutation-validated) | moderate, non-optional |
| Agent: socket bridge, capability→tier mapping | small |
| NAT traversal beyond a LAN | large, and separable -- LAN first |
| GUI, desktop and Android, against the local socket | moderate |

Against that: the GUI on the local socket is independently useful and needs none
of the rest. **That is the natural first milestone**, and it makes the second one
cheaper by proving the request vocabulary is right before it is carried anywhere.

## 8. What was decided after this was written

Answered on 2026-08-04, and carried into `gui/project.md`:

1. **C/C++ with Monocypher** for the protocol and the agent, in the sibling
   projects' style -- one crypto implementation across the family.
2. **LAN only first.** No rendezvous, no hole punching, no relay.
3. **The local hop stays JSON**, pinned by `docs/schema/socket.json`; the agent
   translates. Two encodings, one on each side of a seam that already exists.
4. **Makefiles and qmake only**, no CMake in this tree, even though a sibling
   uses it.

5. **The four directories live at the repository root**, beside `crates/`,
   `backends/` and `adapters/`: `gui/`, `client/`, `wire/`, `agent/`.
6. **`situ` describes the frame**, with Monocypher bound to it as an extern
   codec.

Still open, and listed in `gui/project.md` §9: whether a remote `apply` may run
without a confirm window, LAN discovery, the first pairing, whether the agent
ships in netcfgd's own packages, and whether situc is vendored or its output
committed.

Whether this is M8 or a milestone of its own is also still open. It is not
RESTCONF's replacement and M9 should stay where it is.

## 9. The verdict

**Feasible, and the auth structure is the part worth copying wholesale.** The
identity/capability/envelope design answers questions netcfgd would otherwise
have to answer badly, and it answers them in a way that already has a sibling
implementation and a review history.

The transport is the expensive half, and most of its cost is not the crypto -- it
is chunking a large answer into datagrams and proving the parser safe to a
standard the family already sets. Nothing about netcfgd's design forbids it; §11.3
anticipated it and told it where to live.

The one thing to carry across with care rather than by copying is **freshness**:
a configuration command is not a message, and the instinct that a message should
eventually arrive is the instinct that would let a stale `apply` land on a router
that has moved on.
