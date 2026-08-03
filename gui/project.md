# gui/ — the Qt Widgets client, and what sits under it

Design brief for netcfgd's graphical client: **M8's first half**, desktop and
Android from one source. Written for a fresh Claude Code instance picking up
implementation work in this directory — it assumes no memory of the sessions that
built the daemon, so it says what already exists, what must be reused rather than
reinvented, and what is a genuine open question to raise with the user before
writing code.

**Read the repository's `project.md` in full before starting**, especially §1
(hard constraints, particularly 3 and 6), §2 (the desired-state document and why
it is safe to transmit), §9 (code style and the verification method), and §10
(where the daemon is now). Read `netcfgd-design.md` §11 (multi-host: conform,
don't invent) and §13 (security and privilege model). Where this file says
**OPEN**, it means undecided: ask, do not assume.

Nothing here is built yet. The one thing that *is* settled beyond argument is the
shape of the split, because it is a sibling project's, arrived at over a longer
time than this directory has existed.

---

## 1. What this is, and the one sentence that decides most of it

A full-featured client for netcfgd, on the desktop and on Android, in the style of
the sibling `fuzzypickles`, `hydra` and `beerssh` trees.

> **Both builds have the same features. What differs is which are reachable, and
> that is a function of the capability the operator holds and of what the target
> machine offers — never of which binary is running.**

The desktop build is *mostly* used to configure and monitor the machine it runs
on; the Android build is *almost exclusively* used to configure a network from a
phone. That difference is real and it is **not** a difference in feature set. A
laptop configuring a router across the room and a phone doing the same thing want
the same screens. Do not build a "lite" Android client, and do not put desktop-only
code behind a platform `#ifdef` when the honest gate is a capability check.

## 2. Non-negotiables

Inherited from the family, and from netcfgd:

- **Qt Widgets. No QtQuick, no QML, ever.** Not for one screen, not for Android.
  The other three projects in this family state this as a non-negotiable and it is
  restated here so nobody has to go and find it.
- **Makefiles and qmake only.** No CMake anywhere in this tree, even though a
  sibling uses it. `gui/gui.pro` with a `gui/Makefile` wrapper, the way
  `fuzzypickles/gui` does.
- **The daemon does not change to suit this.** Constraint 6: no change to the
  model, the config language or the socket API may be justified solely by a
  client's needs. If the GUI wants a concept, it must independently be something a
  local operator would want in their own config file. This has already killed
  several things the NetworkManager shim wanted (0036, 0077) and it applies here
  unchanged.
- **No secret material reaches this program.** §2 of `project.md`: the document
  carries `SecretRef` indirections and never values. `ncfg secret set` writes them
  (0075); the shim's `GetSecrets` refuses (0029). A GUI that displayed a
  passphrase would be the first thing in the tree to break that rule.
- **Code style is netcfgd's three rules**, which are already the siblings' three
  rules: `snake_case` for identifiers this project defines — including in Qt C++,
  where Qt's own camelCase API is called exactly as it is — tabs to indent and
  spaces to align, lowercase filenames. Types this tree owns take an `ncfg_`
  prefix (`ncfg_client_t`, `ncfg_status_model`), matching `fzp_`/`bssh_`. ASCII
  in source, comments and commit messages.

## 3. The split, and why each seam is where it is

`fuzzypickles` separates its tree four ways, and the reasoning transfers almost
line for line. **The seam goes below the widgets.**

```
   gui/            Qt Widgets, C++17.  Desktop and Android.  Draws things.
   ---------------------------------------------------------------------
   client/         C.  Connection handling, request/response matching, event
                   subscription, the models behind interfaces/wifi/plan,
                   formatting.  Both transports live here.
   ---------------------------------------------------------------------
   wire/           C.  The remote protocol: envelope, capabilities, signing,
                   Monocypher, chunking.  Used by client/ and by agent/.
   ---------------------------------------------------------------------
   agent/          C.  Runs on the netcfgd host.  Terminates the remote
                   protocol, holds a local socket connection, maps a remote
                   capability onto a control tier.
```

- **`client/` is C, not C++**, and that is the sibling's reasoning verbatim:
  everything shareable here is plumbing, a C++ layer would be unusable from
  anything C, and it would complicate the Android story. C++ belongs on the Qt
  side of this seam, never below it. If a function here would need to know what a
  widget is, it is on the wrong side.
- **`wire/` is separate from `client/`** because the agent needs the protocol and
  the crypto and none of the frontend plumbing. That is exactly why fuzzypickles
  splits `core/` from `client/`.
- **`agent/` is a separate process on the netcfgd host, and the daemon is
  untouched.** `netcfgd-design.md` §11.3 fixes this: *"not a new authority layer
  inside the daemon — the receiving agent is an ordinary unprivileged socket
  client, exactly like the adapters in §9."* It is also what keeps the core's
  twelve-crate dependency budget and its `forbid(unsafe_code)` intact: Monocypher
  and a UDP socket live in a C program, outside the Rust workspace, contained the
  way `adapters/netcfgd-nm` is.
- **Build integration comes last.** `fuzzypickles/gui` is deliberately not wired
  into its root Makefile; this directory should be the same until it is worth
  doing as its own step. `cd gui && make` builds what it needs.

## 4. The two transports, and the one thing that genuinely differs

`client/` offers one request vocabulary over two transports:

| | local | remote |
|---|---|---|
| carries | `AF_UNIX` stream, newline-delimited JSON | encrypted datagrams over UDP |
| pinned by | `docs/schema/socket.json` | this tree's own format |
| authenticated by | the socket's peer credentials, `SO_PEERCRED` | a signed envelope, verified by the agent |
| authorised by | the daemon, against 0013's `observe`/`wifi`/`admin` tiers | the same tiers, reached through the capability the envelope carries |

The local hop is **pre-authenticated by construction** — the kernel says which uid
and gid is on the other end, and `netcfgd-daemon`'s `authorize.rs` decides from
that. The remote hop has no such thing, which is the whole reason the encrypted
protocol exists. That asymmetry is the sibling's too (its §13: "no additional
session crypto layered on top of local IPC"), and it must not be smoothed over by
running the crypto locally as well: it would buy nothing and would make the
already-authenticated case slower and less obvious.

**What the GUI sees is the same either way.** A `status` is a `status`. The two
things that must be visible in the UI rather than hidden by the abstraction:

- **which machine this is** — a client that can configure a router across the room
  must never leave the operator unsure whose wifi they are about to change;
- **which tier the operator holds** — a connection with `observe` should not offer
  an apply button that will be refused.

## 5. What the daemon already offers

Fifteen requests and twelve responses, pinned by `docs/schema/socket.json` — which
exists precisely so a second implementation is legitimate rather than a fork:

```
hello  status  plan  apply  confirm  revert  reload  show  explain  monitor
wifi_scan  wifi_status  wifi_connect  wifi_disconnect  ap_stations
```

Three things about that list are worth knowing before designing screens:

- **`plan` before `apply` is the product.** `project.md` constraint 7: not being a
  black box is the point. A GUI that applies without showing the plan would be
  the first client here to hide it. `ncfg tui`'s plan pane is the precedent.
- **`monitor` is a stream**, and it is how a live UI learns that something changed
  without polling. The TUI's events pane already consumes it.
- **`apply` takes a confirm window.** Commit-confirm exists because a network
  change can cut off the person making it — which is *more* true from a phone than
  from a terminal on the machine. A remote apply should default to a confirm
  window; **OPEN:** whether the GUI ever offers an apply without one.

## 6. What the remote protocol is, in outline

The auth structure is copied from `fuzzypickles` deliberately. Read its
`project.md` §3 (identity), §5 (crypto), §6 (wire format) and §13 (local IPC)
before writing any of this; what follows is what carries over and what does not.

**Carried over as-is:**

- User and host as separate keypairs, never conflated. Several hosts per user,
  each with its own capability set rather than a permission scalar.
- Separate keypairs per role; long-term keys sign, ephemeral keys do DH, never
  both.
- The signed command envelope, covering **`command | target host id | nonce |
  expiry | capability`** inside the signed region. The target binding matters more
  here than in a chat application: an `apply` addressed to the office router must
  not be replayable at the home one.
- Monocypher, one implementation: X25519, ChaCha20-Poly1305, BLAKE2b, EdDSA, with
  platform entropy supplied explicitly and never defaulted.
- **Key-committing AEAD**, mandatory, exactly as the sibling states it.
- Revocation as an explicit signed act. A stolen phone is a capability to revoke.

**Deliberately not carried over:**

- Groups, sender-keys, multi-recipient fan-out. One operator, one device.
- Content-addressed assets and swarm distribution.
- Traffic classes, link budgets and the scheduler. netcfgd has one link and no
  budget model.
- Delivered/settled two-ack durability. An apply either happened, with a journal,
  or it did not.

**Carried over inverted, and this is the one to get right:**

> **Commands expire. Grants do not.**

fuzzypickles is built so a message reaches a sleeping peer eventually — senders
hold until settled, hosts store and forward, authority is never ended by a clock.
For configuration the first two are wrong. A command that reconfigures a router an
hour late, because the router was off, is precisely what commit-confirm exists to
prevent, and netcfgd computes a plan against a *current* observation, so a stale
command is not merely late: it was computed against a machine that no longer
exists. The envelope already carries the fix in `nonce | expiry`. The grant half
of the sibling's rule stands unchanged — a capability is revoked by a signed act,
not by a timer.

**LAN first.** The first target is a phone and a netcfgd host on the same network,
which is the case an operator most often has ("I am at home, the wifi is wrong").
No rendezvous, no hole punching, no relay. Discovery on a LAN is **OPEN** — mDNS,
a broadcast probe, or a typed-in address — and typing an address is a perfectly
good first answer.

**The datagram problem is the real work.** A `status` is the whole observation and
a `show` is the compiled document; on a router with a dozen interfaces both are
past any UDP MTU. Application-level chunking with reassembly, retransmission of
what is missing, and a bound on the memory a half-finished response can hold. This
is the largest piece and the highest-risk code in the tree — the sibling says the
same of its parser and fuzzes it on both surfaces, mutation-validated, with the
acceptance rate printed so it cannot silently fall to zero. **That standard
applies here from the first commit**, not once it works.

**And it is the half `situ` does not do**, which is the most useful thing to know
about it -- see §6.1. Asked to generate this envelope it says so itself, in a
comment in its own output:

> No `envelope_required`: one of its members has no length this can compute.
> Framing such a message is the layer below's job -- situ can say what the bytes
> mean and not when they have all arrived.

So `wire/` is two pieces with a seam between them: **the frame, which is a situ
schema**, and **the framing, which is hand-written C and is where the risk went**.

### 6.1 `situ` for the frame itself

`../situ` is a sibling compiler for exactly this problem: a schema of a binary
format in, accessors in C, C++, Rust and Python out, with a capability model that
says what it *cannot* generate and why. Its README says the first real use case is
compact encrypted protocols, and §14 of its `project.md` is a cryptographic model
rather than an afterthought.

**Tried rather than read about**, on 2026-08-04, from a clone -- the tree is under
active work and must not be built in. The probe was an envelope with an uncovered
version byte, an `authenticated { }` region carrying command, target host, sender,
nonce, expiry and capability, a `sealed(chacha20_poly1305, nonce = nonce) { }`
body, a 16-byte tag, and `require canonical(envelope)` plus
`require verify_gated(envelope.sealed)`. It generated C that compiles clean under
`-Wall -Wextra -std=c11`, and three things in that output are the reason to use
it:

- **The verify gate is a type.** The sealed interior is reachable only through a
  `situ_envelope_sealed_t`, and the only thing that produces one is
  `situ_envelope_sealed_open(view, verified, out)`, which returns `SITU_ERR_TAG`
  when `verified` is false. Every interior accessor takes that type. In C that is
  a discipline the compiler enforces rather than a proof -- the struct could be
  hand-assembled -- but "parse before verify" stops being something a reviewer has
  to catch.
- **A stale tag cannot be transmitted.** Every setter for a covered field marks
  the message dirty, and it will not yield a transmittable buffer until `finalize`
  recomputes. Mutate a field and forget the MAC is a bug class, and it is handled
  by construction.
- **`gen-fuzz` emits the harness** and `wire` emits a reviewable byte-level
  contract to commit and diff. The family's standard for a hand-rolled parser is
  met by not hand-rolling the parser.

**Monocypher and situ compose rather than compete.** A codec is declared with its
properties and bound to an implementation the user supplies -- `impl
chacha20_poly1305 extern "ncfg_monocypher_aead";` -- so situ decides layout,
coverage and gating, and Monocypher does the arithmetic.

**The dependency is on a generator, not a library.** Generated C is checked in, so
a person building netcfgd needs no situc. situ is also unpackaged -- no release,
no version number, runs from a tree -- which makes committing its output the
natural pinning mechanism, and the same one this repository already uses for
`docs/schema/` witnesses.

**OPEN:** vendor situc, commit the generated sources, or both.

## 7. Build

- `gui/gui.pro`, driven by `gui/Makefile`, out-of-source into `build/`.
- Android by kit, not by codebase: `build-android-arm64/`, `build-android-x86_64/`
  beside it, the way `fuzzypickles/gui` does it. One source tree, several ABIs.
- `client/`, `wire/` and `agent/` are plain C with hand-written Makefiles in this
  repository's existing style — the root `Makefile` is the model for how flags and
  toolchain injection are threaded.
- The four directories live at the **repository root**, beside `crates/`,
  `backends/` and `adapters/`: `gui/`, `client/`, `wire/`, `agent/`. The Rust
  workspace does not gain them -- `Cargo.toml`'s member list stays as it is, and
  `make size` keeps measuring the Rust install alone.

## 8. Order of work

1. **`client/` against the local socket, and the GUI on top of it.** Desktop only,
   no crypto, no agent. Independently useful, and it proves the request vocabulary
   and the models before anything carries them over a wire.
2. **`wire/` plus `agent/`, LAN only**, with the fuzzing standard from the first
   commit.
3. **Android**, which by then is a kit and a transport choice rather than a port.
4. Anything beyond a LAN, if it is ever wanted.

## 9. Questions to raise rather than answer alone

- Whether a remote `apply` may ever run without a confirm window (§5).
- How a phone finds a host on the LAN (§6).
- How pairing works the first time: the sibling has QR and camera code in its
  `client/` for exactly this, and reusing it is plausible — but netcfgd's first
  pairing may be simpler, since the operator is usually root on the host already
  and can run a command there.
- Whether `agent/` ships in netcfgd's own packages or as a separate one. It is a
  daemon that listens on a network, which is a thing this project has deliberately
  never had.
