# netcfgd — implementation brief

**Status: a proof of concept, substantially built and not yet proven.** Milestones M1 through M9 are worked, with the state of each in §7 and what to pick up next in §10. The design is what is under test, and **§10's *What would prove it* is the bar** — until those are met, this is a system that works everywhere it has been run and has not been run in the places that matter.

**Deferred is not broken, and this is the distinction to read the document with.** Size, language and multiple client implementations are all *refinements that come after the concept proves itself*, not promises being missed now. Reading a deferred measurement as a contradiction produces work nobody wanted: the 2.3 MB install against §10.2's sub-megabyte router figure is a measurement not yet taken on a target nobody has built for, and `size-budget.txt` is deliberately a **ratchet against drift** rather than a tier goal ([0024](docs/decisions/0024-one-binary-and-what-a-megabyte-would-actually-cost.md), [0104](docs/decisions/0104-the-four-megabytes-belonged-to-a-tier-that-was-dropped.md)).

**A proof of concept is not licence for bad code, and here the structure is half of what is being proven.** The concept is a config-driven reconcile loop; the *claim* is that it can be built with a frozen model, no mandatory dependencies, `forbid(unsafe_code)` outside one audited crate, and gates that catch their own blind spots. Code written carelessly now does not prove that claim, it hides it — and poorly written code is not something a later pass repairs cheaply. **Everything in `code-style.md` and §9 applies at full strength.** What a proof of concept relaxes is *scope and measurement*, never craft.

This document is the working brief; `netcfgd-design.md` is the reference design and holds all rationale. Where the two disagree, this document wins for *what to build*, the design doc wins for *why*.

*(The status line read "pre-implementation, nothing is built yet" until 2026-08-06, roughly two hundred commits after it stopped being true. §7 had been kept current throughout, so the file contradicted itself in its own header — see §10's note on a document nobody re-reads from the top.)*

**What it is, in one line:** a Linux network configuration daemon whose plain-text config is the single source of truth, whose runtime state is greppable files in `/run`, and whose behaviour is a visible reconcile loop (`plan` then `apply`, like Terraform for interfaces).

**Getting started:** [docs/first-run.md](docs/first-run.md) — taking a laptop from NetworkManager, wired first.

**Handing a device away:** `device X { managed = false }` stops netcfgd operating on it and changes nothing; adding `on_unmanage = "clear"` removes everything netcfgd owns first, credentials included ([0035](docs/decisions/0035-managed-false-means-it.md), [0037](docs/decisions/0037-clear-then-unmanage.md)).

**Names:** project and daemon `netcfgd`; CLI `ncfg`; TUI is `ncfg tui` (a subcommand, not a separate binary); adapters `netcfgd-nm` and `netcfgd-restconf`; build tiers `netcfgd-embedded` / `netcfgd-full` (nano dropped, [0021](docs/decisions/0021-no-nano-tier.md)); hook env prefix `NCFG_`. Language: **Rust**.

---

## 0. Do this first: reserve the names

Verified free on 2026-07-28: `netcfgd` and `ncfg` on both crates.io and GitHub. Crate names are **first-come and unreclaimable** — yanking removes a version, it does not free the name. Reserve before any public mention.

```bash
# 1. GitHub: create org (or user repo) `netcfgd`, repo `netcfgd`.

# 2. crates.io: publish minimal placeholders.
#    Requires a verified email on crates.io and `cargo login`.
cargo new --lib ncfg && cd ncfg
# Cargo.toml must have: description, license, repository, readme
#   description = "Reserved for the netcfgd network configuration tool (CLI). Not yet released."
#   license = "MIT OR Apache-2.0"
#   repository = "https://github.com/netcfgd/netcfgd"
cargo publish
cd .. && cargo new --lib netcfgd && cd netcfgd   # same treatment
cargo publish
```

Also cheap and worth taking while you are there: `netcfgd-nm`, `netcfgd-restconf`, `netcfgd-model`. Publishing a placeholder for a project you are actually starting is accepted practice on crates.io; publishing names you have no intent to use is not, so keep the list short and the descriptions honest.

Note the crate name and the installed binary name need not match — if anything is ever contested, the binary can still be `/usr/bin/ncfg` while the crate is `netcfgd-cli`.

---

## 1. Hard constraints (violating these is a bug, not a tradeoff)

1. **Config files are the only authority.** Anything netcfgd does traces to a file under `/etc/netcfgd/`. Runtime state in `/run/netcfgd/` is derived and disposable.
2. **The filesystem reflects use, not capability.** A default install is `netcfgd.conf` plus `conf.d/`. Nothing else appears until a feature is actually used. CI enforces this against a fixture (§6).
3. **Core has no mandatory dependencies** beyond libc and the kernel. No D-Bus, no glib, no polkit, no systemd. Adapters carry their own dependencies in their own packages.
4. **`#![forbid(unsafe_code)]` everywhere except `netcfgd-sys`**, which is the sole audited exception and carries its own fuzz targets and review bar.
5. **The desired-state document never contains secret material.** Only `SecretRef` indirections. This is invariant across local files, `/run` state, and any future wire transmission.
6. **The one-way rule.** No change to the model, config language or socket API may be justified *solely* by an adapter's needs (NM, RESTCONF/YANG, or anything else). If an adapter wants a concept, it must independently be something a local user would want in their own config file.
7. **`ncfg plan` survives to the smallest build.** Not being a black box is the product; a black box on an embedded device with no console is worse than one on a laptop.
8. **Size budgets are CI gates from commit 1.** Budgets adopted later are budgets already blown.
9. **Virtual networking features that are not directly useful for real-world networking, or are not very common use cases, are deferred indefinitely.** An overgrown VM topology is not a use case, it is a failure. This is why Open vSwitch is not on any list; `ifb`, `veth`, `dummy`, `vrf` and `macvlan` are here already and earn their places. See [0036](docs/decisions/0036-the-shim-is-not-the-roadmap.md).

---

## 2. The desired-state document

This is the load-bearing artifact. Everything hangs off it: the compiler emits it, the reconciler consumes it, the NM and RESTCONF adapters project onto it.

**Encoding.** JSON for humans and `/run` introspection; CBOR for compact/embedded storage. Identical schema. The canonical form is whole-host; the per-interface files in `/run/netcfgd/desired/` are projections for convenience, not separate documents.

**Determinism.** The same config must produce a byte-identical document. All lists sort by their declared key; field order is fixed by the schema; integers canonical; no floats anywhere; no map types with unordered iteration. This is what makes plan diffs and caching trustworthy.

**Versioning.** `schema_version` is `{major, minor}`. A consumer **rejects** a document whose major differs from its own, and **rejects any document containing a field it does not recognise** — silent field-dropping is forbidden. A remote producer must negotiate the consumer's version and emit at or below it.

**Not yet, though.** The version is pinned at **1.0 until netcfgd ships** ([0038](docs/decisions/0038-versioning-starts-at-the-first-release.md)): a version is a promise to consumers and there are none before a release, so counting minor bumps through a schema still being designed measures effort rather than compatibility. Adding a field bumps minor *from the first release onwards*. What keeps a schema change visible meanwhile is the witnesses under `docs/schema/`, which move on every change and have to be blessed deliberately ([0020](docs/decisions/0020-the-freeze-is-two-witnesses.md)) — the mechanism that was doing the work all along. There are **four**, not the two 0020 named: `Observed` and `Plan` had none until a field was added to one of them and nothing asked to be blessed, and the socket witness carried a comment claiming they were pinned elsewhere.

### 2.1 Types

```
Document {
  schema_version : Version            // {major: u16, minor: u16}
  generated_by   : string?            // informational only, excluded from equality
  globals        : Globals
  devices        : [Device]           // sorted by name
  interfaces     : [Interface]        // sorted by name
  networks       : [WifiNetwork]      // sorted by id
}

Globals {
  dns              : DnsPolicy
  on_drift_default : DriftPolicy      // = Report
  confirm_default  : u32?             // seconds; commit-confirm default window,
                                      // armed on every apply that does not say
                                      // otherwise. `--confirm-within 0` says
                                      // otherwise (0094)
  hostname_policy  : enum { None, FromDhcp, Static(string) }
  control          : Control          // who may do what; see 0013
}

Control {                             // every tier defaults to Root
  observe : Principal                 // ask what the network looks like
  wifi    : Principal                 // join, leave and scan known networks
  admin   : Principal                 // change anything else
}

Principal = Root | Any | User(string) | Group(string)
```

Written in a config as a `control` block inside `global`:

```
global {
	control {
		observe = "any"
		wifi    = "group:netdev"
		admin   = "root"
	}
}
```

Everything defaults to `root`, so a machine that never edits this block behaves exactly as design §13 describes. The socket's mode and group follow the policy, and netcfgd complains loudly at startup if it cannot make the policy reachable — a config that says `group:netdev` over a root-only socket is a lie that costs an afternoon to diagnose.

```

DnsPolicy {                           // see docs/decisions/0007
  mode      : enum { None, WriteResolvConf, Resolvconf, Openresolv,
                     Resolved, Dnsmasq, Unbound, Exec(string) }
                                      // no Auto: never guess where queries go
  servers   : [DnsServer]
  search    : [string]                // suffix completion; every mode
  domains   : [RoutingDomain]         // query routing; scope-capable modes only
  options   : [string]
  dnssec    : enum { No, Allow, Yes }?
  transport : enum { Plain, Tls, Https }?
}

DnsServer     { addr: IpAddr, port: u16?, sni: string? }
RoutingDomain { suffix: string, exclusive: bool = false }   // "." = catch-all
```

A per-interface `DnsPolicy` is a **scope**, not an overlay: globals are the
fallback scope and the most specific matching domain wins. It is never merged
into one flat list at compile time. A mode that cannot express routing domains
is a compile error when the config uses them, never a silent flattening — 0007
explains why that distinction is a security property rather than a stylistic
one.

```

Device {                              // per-device policy, not addressing
  name     : string                   // "wlan0"
  match    : DeviceMatch?             // prefer matching over naming; see note
  managed  : bool = true              // false => netcfgd never touches it
  wifi     : WifiDevicePolicy?
}

DeviceMatch {                         // all present fields must match
  mac        : string?
  path       : string?                // e.g. "pci-0000:03:00.0"
  driver     : string?
  name_glob  : string?
}

WifiDevicePolicy {
  backend      : enum { Auto, Iwd, WpaSupplicant } = Auto
  autoconnect  : bool = true
  portal_check : string?             // an http:// URL to fetch; no default,
                                     // and never https -- a portal intercepts,
                                     // which is what TLS prevents (0095)
  regdom       : string?              // ISO 3166-1 alpha-2
  powersave    : enum { Default, On, Off } = Default
}

Interface {
  name        : string
  kind        : InterfaceKind
  enabled     : bool = true
  mtu         : u32?
  mac         : string?
  addressing  : [AddressSource]       // ordered; may be empty
  routes      : [Route]               // sorted canonically
  dns         : DnsPolicy?            // merges over globals
  hooks       : [HookRef]             // references only, never inline shell
  on_drift    : DriftPolicy?          // overrides globals
  master      : string?               // bridge/bond membership
  guard       : Guard?                // something depends on this; see 0010
  dot1x       : EapConfig?            // wired 802.1X; see 0008
  advertise   : RaPolicy?             // RA handoff to odhcpd/radvd; see 0009
  forwarding  : bool?                 // sysctl only, never a firewall rule
  nat         : bool?                 // masquerade what leaves here; see 0022
  qdisc       : QdiscPolicy?          // root qdisc only; see 0023
  ingress_redirect : string?          // synthesised ifb; see 0023 amendment
}

InterfaceKind =
  | Physical
  | Bridge    { members: [string], stp: bool, forward_delay: u32? }
  | Bond      { members: [string], mode: string, miimon: u32? }
  | Vlan      { parent: string, id: u16, protocol: enum { Dot1q, Dot1ad } }
  | Vxlan     { id: u32, local: IpAddr?, remote: IpAddr?, port: u16? }
  | WireGuard { private_key: SecretRef, listen_port: u16?, fwmark: u32?,
                peers: [WgPeer] }
  | Pppoe     { parent: string, username: string, password: SecretRef,
                service: string?, ac: string? }        // see 0009
  | Dummy
  | Veth      { peer: string }

WgPeer {
  name         : string               // local label, for diagnostics
  public_key   : string
  preshared_key: SecretRef?
  endpoint     : string?
  allowed_ips  : [string]
  keepalive    : u16?
}

AddressSource =
  | Static    { address: string,       // CIDR, e.g. "192.168.1.10/24"
                peer: string?,
                preferred_lifetime: u32?,
                valid_lifetime: u32? }
  | Delegated { prefix: PrefixRef, suffix: string }   // see 0009
  | Dhcp4     { hostname_mode: enum { None, Send, SendFqdn },
                client_id: string?,
                metric: u32?,
                request_options: [u8],
                backend: enum { Auto, Dhcpcd, Udhcpc, Builtin } = Auto }
  | Dhcp6     { mode: enum { Managed, OtherConf },
                rapid_commit: bool,
                prefix_delegation: PdRequest? }
  | Slaac     { privacy: enum { None, PreferTemporary } }
  | LinkLocal

PrefixRef { source: string, index: u8 = 0, subnet: u16 = 0 }  // NEVER a value
PdRequest { hint: string?, length: u8? }

Route {
  destination : string                // CIDR or "default"
  via         : IpAddr?
  metric      : u32?
  table       : u32?
  src         : IpAddr?
  scope       : enum { Global, Link, Host }?
  onlink      : bool = false
  proto       : u8?                   // rt protocol tag; see §2.3
}

Guard {                               // see docs/decisions/0010
  reason : string                     // what depends on it, in the operator's words
}

RaPolicy {                            // policy only; netcfgd never sends RAs
  backend      : enum { Auto, Odhcpd, Radvd, Exec(string) } = Auto
  prefixes     : [PrefixRef]
  managed      : bool = false         // M flag
  other_config : bool = false         // O flag
  dns          : bool = true          // RDNSS/DNSSL from the interface DnsPolicy
  lifetime     : u32?
}

WifiNetwork {                         // an SSID profile, not bound to a device
  id          : string                // stable key, usually the SSID as text
  ssid        : bytes                 // 0..32 octets; NOT guaranteed UTF-8
  hidden      : bool = false
  security    : Security
  priority    : i32 = 0               // higher wins
  autoconnect : bool = true
  metered     : bool = false
  bssid_pin   : string?
  addressing  : [AddressSource]
  routes      : [Route]
  dns         : DnsPolicy?
  hooks       : [HookRef]
}

Security =                            // wifi only; wired uses Interface.dot1x
  | Open
  | Psk { passphrase: SecretRef, proto: enum { Wpa2, Wpa3, Wpa2Wpa3 } }
  | Eap(EapConfig)
  | Owe

EapConfig {                           // top-level: EAP is not a wifi concept
  method             : enum { Peap, Ttls, Tls, Pwd }
  identity           : string
  anonymous_identity : string?
  password           : SecretRef?
  ca_cert            : string?
  client_cert        : string?
  private_key        : SecretRef?
  phase2             : string?
}

SecretRef {                           // NEVER a value
  provider : enum { File, Keyring, Pass, Exec }
  name     : string
}

HookRef {                             // NEVER inline shell; see §2.2
  phase   : enum { PreUp, Up, PostUp, PreDown, Down, PostDown,
                   Carrier, Lease, Roam, Portal, Drift }
  path    : string                    // absolute
  sha256  : string                    // content hash at compile time
  run_as  : string?                   // user; default from globals
  timeout : u32?                      // seconds
}

DriftPolicy = enum { Report, Reconcile, Ignore }
```

### 2.2 Why hooks are references, never inline shell

The DSL lets you write inline shell in a `post_up { ... }` block. The **compiler materialises those blocks into files** under `/run/netcfgd/hooks/` (tmpfs, regenerated on every compile) and the document carries only `{phase, path, sha256}`.

Three payoffs. The document becomes safe to transmit — a document that can carry shell is remote code execution with extra steps, and this closes that door structurally rather than by policy. The `sha256` lets drift detection notice that a hook script changed underneath you. And a build without the hook runner ignores hook entries rather than needing to parse something it cannot execute.

A received (non-local) document may reference only paths that already exist on the device, and the receiving side refuses hook entries entirely unless local policy opts in.

### 2.3 Knowing which objects are ours

Drift detection is meaningless if netcfgd cannot distinguish objects it installed from objects someone else installed. Two mechanisms:

**Routes:** set the netlink route protocol field (`rtm_protocol`) to a netcfgd-specific value on every route we install, and filter on it when computing observed state. Pick one constant, define it in `netcfgd-model`, and document it. Anything not carrying our tag is somebody else's route and is reported as foreign rather than reconciled away.

**Addresses:** modern kernels expose an address protocol attribute (`IFA_PROTO`); use it where available. Where it is not available, fall back to reconciling against our own recorded prior state in `/run`. Be explicit in `ncfg explain` about which mechanism produced the answer, because the fallback is weaker and the operator should know.

This needs verifying against the minimum kernel you intend to support — treat the exact attribute availability as an implementation question, not a settled fact.

---

## 3. Config DSL grammar

Lexically simple by design: no significant indentation, no expression language, no interpolation in the local dialect.

```ebnf
config        = { statement } ;
statement     = include | block | hook_block | assignment | comment | NL ;

include       = "include" , ws , string , terminator ;

block         = block_head , ws? , "{" , NL , { statement } , "}" , terminator ;
block_head    = identifier , [ ws , block_label ] ;
block_label   = string | identifier ;

assignment    = identifier , ws? , "=" , ws? , value , terminator ;

value         = string | number | boolean | secret_ref | list ;
string        = '"' , { char - '"' | escape } , '"' ;
number        = [ "-" ] , digit , { digit } ;
boolean       = "true" | "false" ;
secret_ref    = '"' , "@secret:" , [ provider , ":" ] , name , '"' ;
list          = "[" , [ value , { "," , ws? , value } ] , "]" ;

terminator    = NL | ";" ;
comment       = "#" , { char - NL } , NL ;
identifier    = letter , { letter | digit | "_" | "-" } ;
```

**Hook bodies are the one irregular production.** They contain arbitrary shell, so brace-counting would require parsing shell. Instead:

```ebnf
hook_block    = hook_phase , ws? , "{" , NL , shell_body , close_line ;
hook_phase    = "pre_up" | "up" | "post_up" | "pre_down" | "down" | "post_down"
              | "on" , ws , event_name ;
shell_body    = { any_line - close_line } ;
close_line    = "}" , NL ;          (* a line consisting solely of "}" *)
```

A hook body ends at **the first line consisting solely of `}`**. Unambiguous, requires no shell knowledge, and is trivially explained in documentation. Nested braces inside the shell are irrelevant.

**Top-level blocks:** `interface`, `network`, `device`, `global`.
**Nested blocks:** `wifi`, `dhcp`, `vlan`, `wireguard`, `peer` (inside `wireguard`), `bridge`, `bond`, plus hook blocks.

**Drop-in precedence:** `/etc/netcfgd/netcfgd.conf` first, then `conf.d/*.conf` in lexical filename order. Later wins for scalar keys. Lists replace rather than append unless the key is declared additive in the schema. An explicit `override` keyword before a block makes replacement intent visible; without it, redefining a block that already exists is a compile **error**, not a silent win. That last rule is deliberate — silent last-wins is where every config system becomes unpredictable.

**~~netifrc compatibility~~ — dropped, see [0019](docs/decisions/0019-no-importers-for-config-stores-that-rewrite-themselves.md).** A second permanent parser behind a feature flag, for an audience that is mostly one distribution. What netifrc was worth has already been taken without it: [0001](docs/decisions/0001-native-config-syntax.md) took the vocabulary and rejected the syntax, and [0011](docs/decisions/0011-preup-runs-before-the-link-is-up.md) found the `preup` ordering trap, which is the most useful thing the comparison produced.

---

## 4. Reconciler action taxonomy

A plan is an ordered DAG of typed actions. Every action is idempotent by construction, carries the reason it exists, and declares its inverse so commit-confirm can revert.

```
Action {
  id         : u32
  op         : Op
  reason     : Reason        // which desired field differs from which observed field
  depends_on : [u32]         // ids earlier in the list; see the invariant below
  inverse    : Op?           // None => irreversible; plan warns loudly
}

**`depends_on` has one structural invariant: an action may only depend on an
action that exists and comes before it.** Execution follows the list, so a
correct plan satisfies it by construction and a violation is silent — the
planner declines to emit some actions (`u32::MAX`), and five internal
accumulators collect ids without asking whether they are real
([0097](docs/decisions/0097-a-refused-action-is-not-something-to-wait-for.md)).
Every fixture in `netcfgd-plan` is checked against it, because the defect is
wherever the next edge is added rather than where the last one was.

Reason {
  interface : string?
  field     : string         // dotted path into the document, e.g. "addressing[0]"
  desired   : string         // rendered value
  observed  : string         // rendered value, or "<absent>"
}
```

**Ops:**

```
link.create      { name, kind, params }
link.delete      { name }
link.set_mtu     { name, mtu }
link.set_mac     { name, mac }
link.set_master  { name, master }
link.unset_master{ name }
link.up          { name }
link.down        { name }

addr.add         { iface, addr, lifetimes }
addr.del         { iface, addr }

route.add        { route }
route.del        { route }

backend.start    { kind, iface, params }      // dhcp4/dhcp6/wifi/wireguard
backend.stop     { kind, iface }
backend.reload   { kind, iface, params }

wifi.set_profiles{ device, profiles }
wifi.associate   { device, network_id }
wifi.disassociate{ device }
wifi.set_regdom  { device, country }

wg.set_device    { iface, private_key_ref, listen_port, fwmark }
wg.set_peers     { iface, peers }

dns.apply        { policy }

hook.run         { iface, phase, path, env }

commit.arm       { window_seconds }
commit.confirm   { }
commit.revert    { to_document_hash }
```

**Ordering rules** (the DAG edges the planner must emit):

1. `link.create` before any action referencing that link.
2. `link.set_master` before addressing the master, and before bringing the master up.
3. `link.up` before `backend.start` for DHCP — a lease needs a live link. Addresses may be added to a down link, so `addr.add` does not require `link.up`.
4. `addr.add` before `route.add` for routes whose next hop lies in that address's subnet. Routes marked `onlink` are exempt.
5. `wifi.associate` before any DHCP backend start on that interface.
6. `hook.run(pre_up)` before `link.up`; `hook.run(post_up)` after the last addressing action for that interface completes.
7. **Teardown is the reverse dependency order**: routes, then addresses, then backends, then links.
8. `commit.arm` is emitted first when a confirm window is requested, and `commit.revert` is precomputed at plan time — not derived after failure, when the network may already be unreachable.

**Failure semantics.** Execution stops at the first failed action. Progress is recorded to `/run/netcfgd/plan.last.json` with each action marked done, failed or skipped. The remainder is re-runnable: `ncfg apply` recomputes from current observed state and resumes cleanly. There is no rollback-on-failure by default — that is what commit-confirm is for, and conflating the two produces surprising behaviour.

**Empty plan is the normal case.** Applying an already-correct state produces zero actions, runs zero hooks, and touches nothing.

---

## 5. Repo layout

```
netcfgd/
  Cargo.toml                    # workspace
  gui/                          # Qt Widgets client, desktop and Android. C++17,
                                # qmake behind a Makefile, no CMake and no QML.
                                # Its own build; not in the Rust workspace and
                                # not in the size budget. See gui/project.md
  client/                       # C. The frontend layer under the widgets:
                                # connections, request matching, models. Shared
                                # by any client, and C so that anything can use it
  wire/                         # C. The remote protocol: a `situ` schema for the
                                # frame, hand-written framing under it, and
                                # Monocypher bound as the codec
  agent/                        # C. On the netcfgd host: terminates the remote
                                # protocol and holds an ordinary local socket
                                # connection. The daemon itself is unchanged
  crates/
    netcfgd-model/              # document types, serde, canonical encode. NO I/O.
    netcfgd-compile/            # DSL -> model. Pure.
    netcfgd-sys/            # rtnetlink. ONLY crate permitted `unsafe`.
    netcfgd-observe/            # netlink + backend reports -> observed model
    netcfgd-plan/               # diff(desired, observed) -> Plan. Pure.
    netcfgd-apply/              # executes a Plan
    netcfgd-proto/              # control socket types
    netcfgd-host/               # reads /etc, writes /run, materialises hooks
    netcfgd-daemon/             # `netcfgd` binary
    netcfgd-cli/                # `ncfg` binary (incl. `ncfg tui`)
    netcfgd-testdir/            # a temporary directory that removes itself.
                                # A dev dependency only: nothing links it into a
                                # binary, so it is in no tier and costs the size
                                # budget nothing
  backends/
    netcfgd-dhcp/  netcfgd-supplicant/  netcfgd-wg/  netcfgd-dns/  netcfgd-ppp/
    netcfgd-hostapd/            # access points, added with M4's last inert feature
  adapters/
    netcfgd-nm/                 # milestone M7. Its own workspace and lockfile:
                                # excluded from the root, so its D-Bus stack
                                # cannot reach the core's twelve dependencies
    netcfgd-restconf/           # milestone M9 — LAST
  tests/
    fixtures/                   # config + observed snapshots -> expected plans
    footprint/                  # §6 filesystem-footprint fixture
  fuzz/
```

`netcfgd-host` is not in the original list and was added in M2. Both binaries need to read the config directory in the same order, write the same `/run` files and materialise hooks the same way; two copies of "which files are the config" is how `ncfg` and `netcfgd` come to disagree about what the config says. Keeping the filesystem side in one crate is also what lets the pure crates stay pure.

The critical property: `netcfgd-model`, `netcfgd-compile` and `netcfgd-plan` are **pure and hardware-free**. The entire planner is unit-testable by feeding fixture configs plus fake observed snapshots and asserting on the action list. Build that harness first; it is what makes the rest safe to write.

---

## 6. CI gates — establish before writing features

| Gate | What it checks |
|---|---|
| Size budget | `make size`. **Total installed size, not per binary** — merging two binaries that each link most of the workspace makes the one binary bigger and the install a megabyte smaller, so a per-binary gate points the wrong way. It **ratchets**: the limit is the last measured size, and `size-budget.txt` carries a line per feature saying what it bought. The 3% tolerance is for compiler-version noise; spend it on a feature and the next feature fails the gate for the wrong reason. Design §10.2's 1 MB embedded target was measured as unreachable ([0021](docs/decisions/0021-no-nano-tier.md), [0024](docs/decisions/0024-one-binary-and-what-a-megabyte-would-actually-cost.md)) |
| RSS budget | `make rss`, `VmHWM` of the **release** daemon — what ships. It measured the debug one until [0098](docs/decisions/0098-a-supplicant-that-bound-its-socket-and-stopped-answering.md), which made it sensitive to something it is not about: an *unused* dependency edge moved the debug figure ~190 KB while the release build stayed byte-for-byte identical. `size` already builds release and runs first, so this costs nothing. A **ratchet on a measurement**, not a tier target: §10.4's "< 4 MB RSS steady-state" is written *for nano*, and [0021](docs/decisions/0021-no-nano-tier.md) dropped that tier — the same distinction `size-budget.txt` has carried since M5 and this gate had not ([0104](docs/decisions/0104-the-four-megabytes-belonged-to-a-tier-that-was-dropped.md)). On **musl**, which is what the size posture targets and what the apk ships, the daemon peaks at **~2.9 MB** with ~205 kB of it anonymous; the glibc figure is ~4.2 MB because glibc is bigger. The gate prints all three numbers and pins VmHWM. **It is noisy in a way the size gate is not** — runs of an *identical* binary spread by hundreds of KB — so the limit carries a full noise band above the observed peak, and the measurements are in the Makefile so the next person can tell drift from spread |
| Filesystem footprint | `find /etc/netcfgd` on a fixture install with no optional features used must match a build compiled without those features |
| Unsafe policy | `forbid(unsafe_code)` holds everywhere except `netcfgd-sys` |
| Supply chain | `cargo-deny`, `cargo-audit`, pinned lockfile, stated MSRV |
| Packaging | `make packaging`: every path an init script names is a path that gets installed, every maintainer script parses **and is executable** (dpkg silently skips one that is not), and every `@TOKEN@` in a package template is one a recipe substitutes. `make deb` and `make apk-container` build real packages, with dependencies derived from the ELF by `dpkg-shlibdeps` and `abuild` rather than typed out ([0099](docs/decisions/0099-a-package-installs-netcfgd-and-changes-nothing.md)) |
| Adapter containment | `make nm-containment`: every crate in the core lockfile appears in `deny.toml`'s allow list, so an adapter's dependencies cannot reach the core. Design §9.2 asks for exactly this assertion; [0027](docs/decisions/0027-the-shim-is-a-separate-workspace-and-libnm-reads-interfaces.md) |
| Fuzzing | every parser — DSL, netlink messages, backend IPC — has a `cargo-fuzz` target running in CI |
| Determinism | same config compiles to byte-identical document across runs and platforms |
| Plan idempotence | applying a plan twice produces an empty second plan |

Size posture in `Cargo.toml`: `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`, static musl target. ~~Avoid `serde_json` in the nano tier — hand-roll a minimal CBOR codec there.~~ Measured at M5 and wrong: the JSON library is 29 KB, while the encoder and decoder generated from the model's types are 283 KB. A different codec saves nothing; see [0021](docs/decisions/0021-no-nano-tier.md).

---

## 7. Milestones

Order matters: the model freezes before any adapter exists, so no adapter can shape it.

| # | Milestone | Contents |
|---|---|---|
| **M1** | Walking skeleton | `netcfgd-model` + DSL compiler + rtnetlink observe + planner + `ncfg apply --oneshot`. Wired static and DHCP only. Fixture test harness. Size/footprint CI live. **The whole model lands here in types, including the parts nothing implements until M3–M4** — DNS scopes (0007), `EapConfig` (0008), `Delegated`/`PrefixRef`/`RaPolicy` (0009) — because M4 is the freeze and a structural change after it is a major bump. |
| **M2** | Daemon and safety | `netcfgd` daemon, control socket, inotify reload, drift detection, hook runner, **commit-confirm**, `ncfg explain`, `ncfg monitor`. Flat DNS backends (`WriteResolvConf`, `Resolvconf`) so ordinary single-link hosts resolve long before scopes matter. |
| **M3** | Wifi and 802.1X | **wpa_supplicant backend; iwd deferred** — reversed from the original order, see [0014](docs/decisions/0014-wpa-supplicant-is-the-floor-not-the-fallback.md): iwd is D-Bus-only and 0008 already commits wired 802.1X to wpa_supplicant, so one integration with no new dependency covers both. Secret providers, `ncfg wifi *`, and the control-tier policy that decides who may use them ([0013](docs/decisions/0013-three-things-a-caller-may-be-allowed-to-do.md)). |
| **M4** | Link types, DNS scopes, router side | WireGuard, bridge/bond/VLAN/VXLAN polish. Scope-capable DNS backends (0007). DHCPv6-PD, `Delegated` resolution and RA handoff (0009). PPPoE via `netcfgd-ppp`. A read of the foreign formats against the model, in place of the importers that were dropped ([0019](docs/decisions/0019-no-importers-for-config-stores-that-rewrite-themselves.md)) — the gap-finding was the part worth keeping. **Model, document schema and socket API freeze here** -- enforced by the witnesses under `docs/schema/`, see [0020](docs/decisions/0020-the-freeze-is-two-witnesses.md). |
| **M5** | Embedded | ~~Getting `netcfgd-embedded` under 1 MB~~ — one multi-call binary took the install from 2.89 MB to 1.75 MB (40%); 1 MB measured as unreachable, [0024](docs/decisions/0024-one-binary-and-what-a-megabyte-would-actually-cost.md). ~~procd integration~~ (done, `packaging/procd/`), ~~read-only-root support~~ (done: factory layer under the writable one, `ncfg reset`, `tests/live/readonly.sh`). ~~Nano consumer without compiler~~ — dropped, [0021](docs/decisions/0021-no-nano-tier.md). ~~`uci` import~~ — dropped, [0019 amendment](docs/decisions/0019-no-importers-for-config-stores-that-rewrite-themselves.md): OpenWrt provisioning generates uci and never reads it, and the factory config layer is the netcfgd shape of that flow. |
| **M6** | TUI | ~~`ncfg tui` including the interactive plan-preview pane~~ — done: four panes over the public socket only, 80x24, no colour required. Drawing and key decoding are ncurses behind a default-on cargo feature; with it off nothing links beyond libc ([0025](docs/decisions/0025-the-audited-crate-is-the-libc-boundary-not-netlink.md)). |
| **M7** | NetworkManager shim | `netcfgd-nm`, tier 1 (`nmcli`, `nm-applet`, `plasma-nm` wifi flows). **Tier 1 is essentially there:** bus name, object tree, `ObjectManager` at `/org/freedesktop`, every device with its properties, `AccessPoint` objects with `RequestScan`, connection profiles with derived UUIDs, and activation -- all driven by a real `nmcli` in `tests/live/nm.sh`. The write path is in too: `nmcli connection add` writes a netcfgd `network` block, with the passphrase going to the secret provider and a `@secret:` reference into the block ([0030](docs/decisions/0030-a-gui-is-an-editor-of-config-files.md)) — the files are `conf.d/nm-*.conf`, flat, because `conf.d` is not read recursively and making it so would be a core change justified only by an adapter. `GetSecrets` refuses, which is a security property rather than a gap ([0029](docs/decisions/0029-a-profile-is-a-projection-and-secrets-do-not-travel.md)). The `AgentManager` secret bridge is in as well: an agent supplies a credential netcfgd lacks, it goes to the provider at 0600, and the block keeps its `@secret:` reference — inbound only, since `GetSecrets` still refuses ([0031](docs/decisions/0031-the-secret-bridge-runs-one-way.md)). That closes tier 1. Tier 2 has started: `IP4Config`/`IP6Config` objects make a settings panel's Details tab show the addresses, gateway, routes and nameservers netcfgd actually applied ([0032](docs/decisions/0032-the-details-panel-is-the-observation.md)). Static addressing round-trips too — a panel sees a profile's configured address and can write one back, with the default route moving between netcfgd's route list and NM's `gateway` field ([0033](docs/decisions/0033-nm-splits-what-netcfgd-keeps-together.md)). Per-connection options round-trip too — metered, autoconnect priority and per-profile DNS, with an MTU named in the file as unexpressible rather than dropped ([0034](docs/decisions/0034-libnm-validates-what-the-shim-projects.md)). **Tier 2 is done.** Tier 3 has started with the part that was a live defect: `Managed` now reads the document, and an unmanaged device reports `UNMANAGED` ([0035](docs/decisions/0035-managed-false-means-it.md)) — which needed a core fix first, because `managed = false` did not actually stop the planner. **Tier 3 bounds the shim, not netcfgd** ([0036](docs/decisions/0036-the-shim-is-not-the-roadmap.md)): VPN, modems and complete wifi are wanted in netcfgd and simply will not be projected through NM's interfaces. `AddConnection` creates wifi networks only. Each adapter is its own cargo workspace so its dependencies cannot reach the core, enforced by `make nm-containment` ([0027](docs/decisions/0027-the-shim-is-a-separate-workspace-and-libnm-reads-interfaces.md)). A scan's security detail is lost at the socket, so the shim reads it from the document rather than growing the socket an adapter wanted ([0028](docs/decisions/0028-the-scan-is-lossy-and-the-document-is-not.md)) -- which leaves `ncfg wifi scan`'s own lossiness as work with a local justification. |
| **M8** | Desktop | GUI + tray applet; NM shim tier 2. **The shim half is done** (0032-0034). **The desktop half is in progress, and section 10 item 5 is where it is tracked**: the GUI has gained a wifi tab and a tray applet, and what stands between it and a network manager is adding a network — which is a security decision rather than a UI task, because writing config needs privileges a desktop client does not have. The GUI is Qt Widgets, C++17, desktop and Android from one source, in the style of the sibling `fuzzypickles`/`hydra`/`beerssh` trees -- brief in [gui/project.md](gui/project.md). Under it sit three C directories: a shared frontend layer, the remote protocol with Monocypher, and an agent that terminates it on the netcfgd host. **The daemon does not change**: design §11.3 already says a remote path is an ordinary unprivileged socket client, not a new authority layer, which is also what keeps the core's dependency budget and `forbid(unsafe_code)` intact. Feasibility, and what does and does not carry over from the sibling's protocol, in [docs/remote-access-feasibility.md](docs/remote-access-feasibility.md). |
| **M9** | **RESTCONF — last** | `netcfgd-restconf`: `ietf-interfaces`/`ietf-ip` mapping plus a netcfgd augment module, hooks read-only. Full NETCONF (SSH/XML) only if sites ask. |

**The M4 freeze's four inert features are all closed**, after M6 rather than at M4 — the schema had to carry them before the freeze, the behaviour did not. Policy routing rules, `ipv6_token` and the ethtool offloads are netlink; access points are hostapd, configured by a generated file under `/run` ([0026](docs/decisions/0026-an-access-point-is-a-file-hostapd-reads.md)). What is still recognised and not applied is the half of the `ethtool` block that needs a physical NIC to exercise, and `ncfg plan` names those fields individually.

**Access points carry a station list**, which is the single-host half of the Ubiquiti-style roaming [0036](docs/decisions/0036-the-shim-is-not-the-roadmap.md) wrote down: forcing a client onto one access point means every other access point refusing it. `access_control { deny = [..] }` or `allow`, never both, because hostapd reads one file or the other ([0039](docs/decisions/0039-a-station-list-is-one-list.md)). Changing the list still needs a restart, which for this feature is the wrong answer — converging it over hostapd's control socket instead is the next piece, and the record says why.

**A WireGuard tunnel, a bridge, a bond and a VLAN are themselves in the shim**,
the four link kinds to stop being `GENERIC` — each on the same terms: NM defines an
interface for it, and netcfgd can answer every property on that interface from
what it already observes. WireGuard needed 0054 first; a bridge and a bond
needed nothing, because a `Slaves` list is the `master` field on every other
link read from the other end. **That is also the rule for what has not left**: an IP tunnel's interface wants
thirteen properties and netcfgd can answer eight, and adding the other five to the
model to satisfy a shim is the direction constraint 6 forbids
([0077](docs/decisions/0077-a-type-leaves-generic-when-every-property-is-answerable.md)).
The VLAN did leave, once 0059 and 0060 gave the planner its own reasons to observe
an id and a parent. Its `interface` block is deliberately *not* a connection
profile, which is the radio rule read twice: an `802-3-ethernet` profile named
`wg0` is a thing in every client's list that is not an ethernet, and NM's own
WireGuard profile carries the peers and the private key, which this shim will
not project.

**And netcfgd shows who is connected.** `ncfg wifi clients` and a fifth TUI pane list the stations associated with an access point, read back over hostapd's control socket ([0040](docs/decisions/0040-a-station-list-needs-a-station-list.md)). It is a live query rather than part of the observation, because there is no desired station list to reconcile against. The two halves are shown as one thing: a station that is on the deny list *and* connected is marked, which is 0039's restart gap made visible rather than silent. There is no hostname — hostapd knows addresses, and netcfgd runs no DHCP server to learn names from.

**Consequence of M9 being last, stated plainly:** multi-host management arrives at the very end, because conforming to RESTCONF *is* the multi-host answer (design doc §11.1). That is a deliberate choice — this is a single-host tool first, and nothing before M9 should be shaped by fleet considerations.

---

## 8. Decisions that were blocking implementation

All six are answered. Each has a record under `docs/decisions/` carrying the reasoning, the consequences and the alternatives that lost; those records are the reference, and this section is the summary. A decision is changed by writing a superseding record, not by editing the one that stands.

| # | Question | Answer | Record |
|---|---|---|---|
| 1 | Native syntax shape | **Blocks.** What transfers from netifrc is vocabulary, not syntax. The compat front end and `ncfg convert` were dropped in [0019](docs/decisions/0019-no-importers-for-config-stores-that-rewrite-themselves.md). | [0001](docs/decisions/0001-native-config-syntax.md) |
| 2 | Route protocol constant | **110** (`0x6e`), used for both `rtm_protocol` and `IFA_PROTO`, defined once in `netcfgd-model`. Minimum kernel 5.10; `IFA_PROTO` (5.18+) detected by read-back, never by version, with the `/run` fallback below that. | [0002](docs/decisions/0002-object-ownership-tagging.md) |
| 3 | Nano tier at all | **No.** Re-decided at M5 against the measurement 0003 asked for: the compiler is 193 KB and decoding a compiled document is 283 KB, so nano would be larger than embedded and less legible. | [0021](docs/decisions/0021-no-nano-tier.md), supersedes [0003](docs/decisions/0003-nano-tier.md) |
| 3b | Masquerade / netfilter | **One nftables table, `netcfgd`, NAT only.** Never filtering, never a table it did not create. Amends 0009, whose objection was iptables-shaped. | [0022](docs/decisions/0022-netcfgd-may-own-one-nftables-table.md) |
| 4 | Built-in DHCPv4 | **No.** Delegate to dhcpcd/udhcpc. The `Builtin` backend variant stays in the schema — unimplemented but recognised — because adding it after the M4 freeze is a major version bump. | [0004](docs/decisions/0004-dhcpv4-client-sourcing.md) |
| 5 | Vocabulary | **`desired`/`observed`.** Decided by constraint §1.6: adopting NMDA's `intended`/`operational` would be justified solely by an adapter's convenience. `netcfgd-restconf` translates at its own boundary. | [0005](docs/decisions/0005-state-vocabulary.md) |
| 6 | `addressing` list semantics | **Composition, with seven rules** covering multiplicity, what order is and is not for, metric derivation from list position, DNS merge, `LinkLocal` coexistence, the empty list, and per-source reconcile behaviour. | [0006](docs/decisions/0006-addressing-list-semantics.md) |

Two of these carry work that has to happen at a specific time rather than whenever it is convenient:

- **The `Builtin` DHCP variant must exist in the schema before M4** (§7), because §2 has consumers reject documents containing fields they do not recognise.
- **Per-address source attribution in `/run`** is needed by both the pre-5.18 `IFA_PROTO` fallback (0002) and rule 7 of the addressing semantics (0006). It is one mechanism with two consumers, and the second should be known about before the first one's design is fixed.

The design doc's remaining open questions (§19.2) are not blocking and can wait.

---

## 9. Working in this repo

### Code style

Three rules, applying to every crate in the workspace — pure core, netlink, binaries, backends and adapters alike:

- **`snake_case`, not `camelCase`,** for identifiers this project defines. Rust's own lints give most of this for free; what they do not give is the rest of the rule — no abbreviations, and one word per concept everywhere. Model field names become JSON keys, `/run` filenames and the dotted paths in a `Reason`, so a name invented inside a struct ends up in somebody's grep and can no longer be changed.
- **Tabs for indentation, spaces for alignment** — one tab per nesting level, spaces after the tabs for anything lined up within a line, so alignment survives at any tab width. No tab width is prescribed.
- **Lowercase filenames.** `snake_case.rs` for modules, kebab-case for prose, except where a tool insists otherwise (`Cargo.toml`, `README.md`).

Source, comments and commit messages are **ASCII**; write `--` where prose would use an em dash. Markdown documents are exempt and this one already is. That governs the repository, not the wire — an SSID is arbitrary octets (§2.1) and the parser must keep treating it that way.

**Full detail is in `code-style.md` at the repo root**, including why `rustfmt` *is* used here when the sibling C and Python projects ban their formatters: `hard_tabs` is a stable option and the default block indent style leaves nothing to align, so the rule survives the tool. `rustfmt.toml` is load-bearing — dropping `hard_tabs` converts the entire tree to spaces on the next `cargo fmt` and buries whatever change it rode in on.

### Build and commit conventions

- **`cargo fmt --check` and `cargo clippy -- -D warnings` before committing**, alongside the §6 gates. They are cheap and they are the two that produce noise in someone else's diff when skipped.
- **Kernel commit format**, stated in full in `code-style.md` §8 and in the global source it copies. The subject is `subsystem: summary`, imperative, no trailing period, 75 columns, where the subsystem is the crate or adapter with a slash for nesting — `netcfgd-plan:`, `adapters/nm:`, `tests/live:`. Body is prose wrapped at 75 explaining *why* the change is right and what was learned making it — including wrong turns, tests that passed for the wrong reason, and numbers that turned out to be guessed. `git diff` already lists what changed.
- **A trailer naming an artifact is content; one naming a person is theirs.** `Fixes:` and `Link:` point at a commit or a URL, assert nothing about anybody, and may be written freely. `Signed-off-by:`, `Reviewed-by:` and `Tested-by:` are statements a person makes about their own involvement, and are added by that person. Tooling or assistant attribution is refused outright, by `tools/hooks/commit-msg` as well as by the rule.
- **No docs-only commits.** Documentation rides along with the code commit it describes. Folding an accumulated session's findings back into this file is the standing exception.
- **Stage named paths; never `git add -A`.** That is the mechanism by which local editor state, scratch files and untracked notes end up in history. `.gitignore` covers the predictable cases and is not a substitute for reading `git status --short`.
- **Nothing containing real secret material is committed** — not in fixtures, not in test data, not temporarily. §2 makes the desired-state document secret-free by construction; the repository holds to the same rule, and a test fixture is the easiest place to forget it.

Changing any of the above is a convention change: raise it rather than adjusting the default in passing.

### `situ` against the control socket, and why the answer splits

Re-evaluated 2026-08-07, while writing `docs/socket-protocol.md`, and the
answer changed on one half since `gui/project.md` §6.1 last looked. **situ has
grown text-protocol support** — `delimited-member`, `unbounded-scan`,
`scanned-predecessor`, with HTTP as its worked example — so a line ending at
`\n` is now something it can describe.

**The framing: yes in principle, and it validates a decision already taken.**
situ's `unbounded-scan` rule says a delimited member with no cap on the scan
takes an effect on read. That is `MAX_LINE` exactly: its model would have
*predicted* the bound this protocol needs, rather than the bound being noticed
because somebody thought about a hostile client. Worth recording even though
nothing changes, because a tool that derives a constraint you reached by
judgement is a tool worth trusting on the constraint you have not reached yet.

**The payload: no, and not for a reason that will age.** situ describes data
that already has a binary representation. A JSON object has no byte layout to
pin — members may be in any order, whitespace is insignificant, escaping
varies — and the protocol makes non-canonicality a *rule* rather than an
accident, because nothing hashes a socket message. Nearly every member would
come back `canonical := NonCanonical`, which is situ correctly reporting that
there is nothing here for it to be exact about. A schema pinning this
encoder's bytes would pin the encoder rather than the contract, and a second
implementation held to it would be wrong the first time serde reordered a
field.

**And the payload already has the mechanism a self-describing format wants**:
a witness generated from the daemon's own types. situ's value is exactness
about bytes; the witness's is completeness about shapes. They answer different
questions, and the socket needs the second. `wire/`'s binary frame is where
situ is the right tool here, unchanged from §6.1.

### `fmake` against `client/` and `gui/`, and why neither moved

Evaluated 2026-08-04, by running it rather than reading about it. `fmake` builds C and C++ from an unannotated tree, and both C directories here are the shape it is for: `client/` is an 89-line hand-written Makefile, `gui/` is qmake.

On a copy of `client/` it needed **no configuration at all** — it found the two sources and the `main()` in `tests/client_test.c`, compiled all three and linked a binary. That part is as advertised.

It is not adopted, for one structural reason and three local ones:

- **It builds programs, not archives.** `client/`'s entire output is `libncfg_client.a`, which `gui/` links; `fmake` linked the library sources *into* the test binary instead, and has no option to emit a static library. That alone decides it.
- `.build-flags` would be lost. It exists because a `make SANITIZE=1 test` followed by a plain build in `gui/` linked a sanitized archive into a binary with no sanitizer runtime — forty lines about `__asan_report_store1` and no clue why. A stamp file that objects depend on is a project-specific fact, not something an unannotated builder can infer.
- `DEBUG` and `SANITIZE` are checked for being *set*, never for a value, deliberately and identically to the sibling projects.
- `make test` runs the binary with an argument — `../docs/schema/socket.json`, the daemon's own witness — which is the whole point of that test.

`gui/` is not a candidate at all while Qt needs `moc`.

**What the check was worth anyway:** it sent someone to read `client/Makefile` against the dependency rules the family treats as load-bearing, and it holds — `%.o: %.c $(HEADERS)` and `tests/client_test: … $(HEADERS)` make every object *and the test binary* depend on both headers explicitly, so the stale-object-versus-library ABI trap cannot happen here. Verified by touching a header and watching the test binary rebuild. The first measurement of that said it did **not** rebuild, and was wrong: `stat` reports whole seconds, and the rebuild landed inside one. Nanosecond timestamps settled it.

### Verifying — the method, which has earned its keep

`make check` is the desk gate and `make live` is the one that finds things. The live suite runs each script in its own network namespace (`unshare -rn`), against a real kernel, with `NCFG_LIVE=1` turning skips into failures — without that variable a missing tool looks exactly like a passing suite.

**Prove every new gate can fail.** Break the thing it guards, watch the named check go red, restore. This has caught a long run of checks that passed for the wrong reason: a `make packaging` check that matched nothing, an unsafe-policy gate that globbed half the tree, a `rows <= 24` assertion that could not fail, a "foreign NAT rule survived" check that passed because the *kernel* refused the delete rather than the planner, and a `tui.py` assertion that pressing `w` shows "no scan" — which passed for as long as the pane existed, because the pane read a field name the daemon has never sent. A gate nobody has seen fail is not evidence.

Five corollaries, every one of them paid for, and every one the same disease in
a disguise that took a while to recognise -- which is why they are written out
separately rather than merged. A sixth is in section 10, because it is about
what a witness catches rather than about what a test does.

- **A check expecting "nothing there" is satisfied by the feature being broken.** Whenever a check asserts an empty or negative state, ask what makes the populated case appear at all, and assert that instead.
- **Watch for a check that passes because of a different protection than the one under test.** Breaking the `InQueue` arm of the NM shim's bus-name claim changed nothing, because `DoNotQueue` makes the refusal arrive as an `Err`.
- **A guard clause no test can make fail is untested code, not defence in depth.** Three shipped and were removed: a `WireGuard` kind check the observation already guaranteed, a `#`-comment branch the key match already handled, and a `>`-prefix skip in the OpenVPN management client that reading-until-an-answer already covered. Apply the break-it method to guard clauses, not only to tests — and where the guarantee is worth keeping, pin it with a test so it survives however the code is later written.
- **A negative check needs its positive, even when the negative is the interesting half.** The modem monitor's drop detection was checked by dropping the bearer; one character wrong in the label it matches makes it decide the bearer is down on the *first* poll, which satisfies that perfectly. The missing assertion was that it stays up while the bearer is up.
- **A gate that cannot see part of the tree enforces nothing there.** The `ascii` gate covered neither `helpers/` nor `adapters/` and filtered by extension, so an installed script with none was invisible twice over. The schema witness could not see a new enum variant at all, twice — a witness is a *sample* and a sample cannot notice a variant nobody put in it. Both now fail to compile rather than fail to notice. The third instance was worse and is the one to remember: **`Observed` had no witness at all**, so a field added to the type the control socket actually sends moved nothing — and `socket.json`'s test said in a comment that the payload types were "pinned by their own crates", which was simply untrue. A sentence claiming coverage is not coverage, and it reads exactly like coverage in review.

**Prefer a real kernel and a reference tool over fixtures.** Every netlink bug here was found by writing to a kernel and reading it back, never by reading the encoder more carefully. Cross-check against `tc`, `ip rule`, `ip token`, `nft`, `nmcli`, `hostapd` — a round trip through netcfgd alone proves nothing when the same mistake is made in both directions.

Three techniques make that reachable without root or a clean machine:

- An uninstalled reference tool: `apt-get download <pkg>` then `dpkg-deb -x`. That is how the hostapd renderer is checked against a real hostapd 2.10 on a machine with no radio and no hostapd package — it validates its configuration *and* its ACL file before touching a driver, and names the line it dislikes.
- A tool that cannot be *run* at all still answers through `apt-get source <pkg>`. Reading hostapd's `src/ap/ctrl_iface_ap.c` changed the station parser twice over what `strings` implied. Guessing a wire format from `strings` is a step above guessing; reading the implementation is a step above that.
- **Every live script takes its working directory from `${TMPDIR:-/tmp}`.** All 36 of them, in one pass. They hardcoded `/tmp`, which made the suite unrunnable whenever that filesystem was full — and a 16 GB tmpfs shared with other work is full often enough to matter. The failure it produced was the wrong one twice over: unit tests failing with `StorageFull` in the two places that happened to exercise the change under review, and the live suite unable to start at all. **A suite that can only run in one directory cannot run beside anything else**, and the operator running it is who should choose where. `TMPDIR` rather than a new variable of our own, because every language runtime already honours it — the Rust tests picked it up with no change at all.
- **The C client test takes `TMPDIR` too, and had to grow a check to do it.** Its socket paths were `/tmp/ncfg-client-test-<pid>.sock`, and its buffer was already sized from `sun_path` with a comment saying why — but `snprintf` truncates silently, and **a truncated unix socket path is not an error, it is a different path** that two tests could then share. A hardcoded prefix always fit, so nothing had ever needed to look; an operator's `TMPDIR` carries no such guarantee. It refuses now, by name, and the binary exits 1 rather than running on a path it did not build. That is the general shape: **taking a value from the environment turns an invariant into an assumption, and the assumption needs a check the literal never did.**
- **Isolating the suite made its litter visible.** With the whole run under one directory of the operator's choosing, what it leaves behind is countable for the first time, and it was leaving four directories per run: `roam.sh` staged a datagram sender's socket in a fresh `tempfile.mkdtemp()` per event and never removed it. Nobody had seen it in six months of runs because `/tmp` is where everything else's litter is too. The check is one line — count what is left under `TMPDIR` after `make live` — and it is worth running occasionally rather than gating.
- A D-Bus client redirects to a private bus: `dbus-daemon --session --print-address --fork`, exported as **`DBUS_SYSTEM_BUS_ADDRESS`**, which GDBus honours in place of the system bus. That is how `tests/live/nm.sh` drives a real `nmcli` against the shim without touching the NetworkManager running the laptop.

**Fake only what cannot exist, which is a radio — never the protocol.** `fake_supplicant.py` and `fake_hostapd.py` speak the real `wpa_ctrl` wire format with replies copied from upstream source; the real daemons are driven elsewhere, which is what would catch a parser changing its mind. Anything needing a real association needs `mac80211_hwsim` and therefore real root: `sudo sh tests/live/hwsim.sh`.

**The suite runs on Alpine too** ([0100](docs/decisions/0100-kill-0-calls-a-zombie-alive.md)): musl, busybox `ash`, in a container whose pid 1 does not reap. With the packages Alpine has — including hostapd and wpa_supplicant 2.11, both newer than Debian's — **every script that can run there passes** ([0103](docs/decisions/0103-a-check-that-asserted-the-machine-rather-than-the-code.md)); the rest skip on packages the image lacks. **`slaac.sh` was reported as a second failure and is not one** — three scripts (`slaac.sh`, `dhcpcd.sh`, `pppoe-session.sh`) make their own namespaces and the Makefile runs them *bare*, so a sweep that wrapped every script in `unshare -rn` alike broke one of them and read the breakage as a defect. Run correctly it passes. `tunnel.sh` was the third and is closed ([0102](docs/decisions/0102-a-test-fixture-with-a-deprecation-deadline.md)) — its own `.ovpn` was a static-key configuration that openvpn 2.7 refuses and 2.8 removes, so it drives a real TLS peer now and passes on 2.6.14 and 2.7.5 alike. That combination is the hostile one and is worth keeping: it is where `kill -0` was caught calling a zombie alive.

**35 of the 36 also pass as real root, in a privileged `debian:trixie` container** — every script the ordinary run skips for want of a package or a privilege, run with the package and the privilege. `ap.sh` drives a real hostapd, `wifi.sh` a real wpa_supplicant, `nm.sh` a real NetworkManager, `delegation.sh` a real kea-dhcp6-server. Three packages had to be found by running it rather than by reading: `libtinfo-dev` (the build will not link without it), `python3-gi` (`fake_agent.py` imports `gi.repository`, and without it two `nm.sh` checks fail with a traceback rather than a skip) and `systemd`, for the `busctl` three `nm.sh` sections need to read properties.

**The thirty-sixth is `hwsim.sh`, and it did not run.** `mac80211_hwsim` creates its radios in the network namespace the module is loaded from, which is the host's and not the container's, so the script finds no new phys and stops on its own precondition. Reaching it means `--network=host`, which is the isolation the container was for. The module *is* loadable from the container — that much was checked — and the script's own refusal to touch a module it did not load is what makes it safe to try later.

**So `-P` is not verified against a running hostapd** ([0110](docs/decisions/0110-an-access-point-that-died-stayed-running-forever.md)). `ap.sh` proves netcfgd writes a configuration a real hostapd accepts and cannot go further, because a dummy has no radio and hostapd exits before it listens — so nothing in the suite has yet started a real hostapd with the flag. What holds it up is hostapd 2.10's own usage text, read out of the binary, and a unit test on the argument list. `hwsim.sh` is the only thing that would close it, and it is the one script that cannot run without real radios.

**`make live` exits 0 on both distributions, repeatably** — three consecutive full runs each, no failures in any. Debian: 38 passing, no failures, two skips (`hwsim` wants `mac80211_hwsim`, `delegation` wants `odhcp6c`). Alpine: **36 passing**, no failures, and three honest skips — `mac80211_hwsim` is not in the kernel, `pppoe-server` is not in Alpine's ppp packages, and `odhcp6c` is not packaged. `dhcpcd.sh` runs there now on the same dnsmasq fallback `dhcp.sh` uses. Getting both green took nine blockers, each hiding the next, and two were defects in netcfgd rather than in the suite. `dhcp.sh` used to stop the Alpine run — busybox there has `udhcpc`/`udhcpc6` and no server — and **falls back to dnsmasq now**, which found a defect in netcfgd rather than merely unblocking a script ([0108](docs/decisions/0108-the-client-never-asked-for-the-search-list.md)): **udhcpc does not request option 119 and netcfgd never asked it to**, so search suffixes reached netcfgd only from `busybox udhcpd`, which pushes unrequested options. Against dnsmasq, ISC dhcpd or a router, 0067's feature silently received nothing. It passes `-O search` now. The script picks its own namespace, because dnsmasq drops privileges and `unshare -rn` forbids that, so the Makefile runs it bare.

The packages are `cargo rust ncurses-dev make git iproute2 python3 util-linux procps busybox-extras openvpn openssl hostapd wpa_supplicant dnsmasq dhcpcd ppp ppp-pppoe wireguard-tools radvd iw kmod py3-dbus py3-gobject3 networkmanager networkmanager-cli dbus` — `networkmanager-cli` separately, because `nmcli` is not in `networkmanager` there and `nm.sh` skips without saying which package. Two apparent failures in the first sweep were the harness rather than the tree: the Rust live binaries were invoked without the `$binary` the Makefile computes, and a container without `wpa_supplicant` turned all twelve supplicant tests into failures because `NCFG_LIVE=1` makes a skip fatal.

**Know what an ordinary `make live` skipped.** Three scripts need real root — `hwsim.sh` loads a module and moves a phy between namespaces, `pppoe-session.sh` opens `/dev/ppp`, `delegation.sh` binds ports 546 and 547 — and `make live` invokes each of them either way, so an unprivileged run prints three skips and a green suite. Three more skip on a package a machine may not have: `tunnel.sh` wants `openvpn`, `ap.sh` wants `hostapd`, `dhcpcd.sh` wants `dhcpcd` — and that last one skips for a second reason too, because dhcpcd drops privileges to an unprivileged user and a `unshare -rn` namespace has one uid in it. It makes its own namespaces for that reason, and an unprivileged machine needs `newuidmap` and a range in `/etc/subuid` before it can run at all. That is six scripts saying nothing, and the skip lines are the only place it is written down. **A privileged container closes all six** and does not touch the machine's own network — `docker run --rm --privileged -v $PWD:/repo -w /repo debian:trixie`, plus the packages each header names. A container also needs `libncursesw6`, which is not obvious from anything: the daemon links ncurses for the TUI behind a default-on feature ([0025](docs/decisions/0025-the-audited-crate-is-the-libc-boundary-not-netlink.md)), so a bare image gets `error while loading shared libraries` and a test that looks like a daemon which will not start.

**Doing it found four defects, all in the suite rather than in netcfgd.** `delegation.sh`'s own build recipe stopped at `None of the required 'json-c' found` on a clean trixie. `hwsim.sh` **failed** rather than skipped where a kernel has no `mac80211_hwsim`, aborting the suite at the one moment somebody is running it properly — and the first repair of that asked `$PATH` rather than the machine, which skipped a machine that can run it. And `hwsim.sh` passed while leaving `netcfgd` and both supplicants running, because it killed by namespace and the background job's subshell is not in one; the run that showed it was still holding them ten minutes later, with the pipeline reading its output waiting on an end-of-file that could not arrive. None of the four is reachable without root, and three of them are the kind that leave a green suite.

**If a regression would make a test hang rather than fail, wrap it in `timeout`.** A stuck suite reports nothing, which is worse than a red one.

### Known incompatibilities to carry forward

- **A netifrc `preup` that checks link state deadlocks under netcfgd's ordering.** Rule 6 runs `pre_up` before `link.up`, and the kernel returns `EINVAL` for `carrier` on a down interface, so `mii-tool`/`ethtool` checks cannot work there — and net.example's canonical `preup` aborts on "no link", which then prevents the bring-up that would have produced the carrier. The ordering stays. The warning was to have lived in `ncfg convert`, which [0019](docs/decisions/0019-no-importers-for-config-stores-that-rewrite-themselves.md) dropped, so the incompatibility is documented and nothing converts. [0011](docs/decisions/0011-preup-runs-before-the-link-is-up.md).
- **A supplicant must hold no state of its own.** wpa_supplicant runs with no persistent configuration and `update_config=0` set explicitly, and every network arrives over the control socket ([0015](docs/decisions/0015-the-supplicant-holds-no-state.md)). iwd cannot be driven this way — it writes its own network database during connections and has no stateless mode — which is what blocks it, rather than the D-Bus cost ([0014](docs/decisions/0014-wpa-supplicant-is-the-floor-not-the-fallback.md)).
- **netcfgd will never implement key management or EAP.** Permanently delegated, affirming design §1.5. Scan and BSS selection *could* become netcfgd's, and [0016](docs/decisions/0016-which-half-of-a-supplicant-could-ever-be-ours.md) records the shape and the cost — pinning a BSSID defeats 802.11r fast transition, so it buys explainability and spends roaming quality.
- **netcfgd does not gate addressing on carrier.** A link is brought up and addressed whether or not a cable is present. The `carrier` hook reports; nothing defers. Noted as a gap in 0011, not scheduled.
- **hostapd reads its configuration once, at startup.** There is no reload that keeps clients associated, so changing an `access_point` block — an SSID, a channel — means restarting hostapd, which deauthenticates everyone on the radio. The **station list is the exception**: it converges over the control socket with `DENY_ACL`/`ACCEPT_ACL` `ADD_MAC`/`DEL_MAC`, no restart and no `DEAUTHENTICATE` ([0041](docs/decisions/0041-a-station-list-converges-over-the-control-socket.md)). Three things in hostapd 2.10's source decided that shape, and each would have been a defect taken from the documentation: `DENY_ACL ADD_MAC` **disconnects the station itself** (`hostapd_disassoc_deny_mac`); `SET deny_mac_file` **appends rather than replaces**, so re-pointing hostapd at the regenerated file would leave every past entry denied forever; and `hostapd_check_acl` **consults the accept list first and the deny list second whatever `macaddr_acl` says**, so the list the policy does not name is not inert and is converged to empty too.
- **`macaddr_acl` is the one field that cannot converge in place.** It is settable over the socket, but nothing disassociates on the change and nothing reports it back, so netcfgd would be converging a value it could never confirm — and converging the *lists* without it would apply a `deny` → `allow` edit as an open network. So netcfgd records the policy it started hostapd with, as a `# netcfgd policy: deny` line in the generated station list that `hostapd_config_read_maclist` skips, and a changed policy restarts the access point with a warning saying what that costs. The record has to sit at column zero and fit hostapd's 128-byte `fgets` buffer; a longer line is split, parsed as an address, and takes the access point down at startup. Checked against a real hostapd in both directions.
- **~~Nothing notices that an access point's *other* configuration changed.~~ Closed** ([0052](docs/decisions/0052-a-daemon-is-compared-to-what-it-was-started-with.md)), passphrase included. The observation reads back what hostapd was started with, and an edited SSID, channel or stated band restarts it with the deauthentication warning. The secret is compared **in the observer**, which is the one place both halves are in hand, and what travels is a boolean -- the value is in neither the document nor the observation, and must not be in either. Two limits are left and both are deliberate: a **band the document does not state** is not compared, because an absent `band` means "work it out from the channel" and comparing what hostapd worked out would restart the radio on every reconcile; and a daemon **netcfgd did not start** has no record to compare against at all, which 0053 names as the next thing of this shape.
- **`ieee80211r` is absent from Debian's hostapd.** Checked directly: not in the binary, and its parser rejects the option. OpenWrt's build generally includes it. So 802.11r fast transition is a per-distribution packaging question before it is a netcfgd feature, and any support has to detect it rather than assume — as [0026](docs/decisions/0026-an-access-point-is-a-file-hostapd-reads.md) handles hostapd's other optional pieces.
- **There is no client hostname to show.** hostapd knows hardware addresses; a friendly name would have to come from DHCP leases, and netcfgd runs no DHCP server. `ncfg wifi clients` shows a MAC rather than inventing a label.
- **`wwan_hwsim` cannot test a modem protocol, which is what decided the modem design.** Read out of the running kernel's source: one `wwan_create_port` call, `WWAN_PORT_AT`, and its emulator does not parse commands — it looks for `A`, then `T`, echoes the line and appends `OK`. The core knows `MBIM`, `QMI`, `QCDM`, `FIREHOSE`, `XMMRPC` and `FASTBOOT` and the simulator creates none of them. So an MBIM backend would have been the first thing here with no live test, and [0044](docs/decisions/0044-the-modem-helper-is-contained-the-way-an-adapter-is.md) supersedes [0043](docs/decisions/0043-mbim-is-ours-and-the-quirks-are-a-table.md) on that basis.
- **A stopped daemon must not keep its secret.** hostapd's generated configuration carries the passphrase in the clear — it has no indirection for one — and `stop` used to leave it in `/run`. Now removed, whether or not the daemon answered, since a hostapd that *died* is exactly the case where nobody comes back to tidy up. The check had to move to `acl.sh`: `ap.sh`'s hostapd never starts (a dummy has no radio), so nothing is ever stopped there and the check could not fire at all.
- **`pppd` cannot be told to negotiate an address and not apply it.** `noip` disables IPCP and IP communication entirely; there is no "negotiate, let somebody else configure". So OpenVPN and PPPoE cannot be made symmetric about addressing, which is what [0047](docs/decisions/0047-a-tunnels-address-stays-with-its-daemon.md) turns on — and routes, where `--route-noexec` and `nodefaultroute` both exist, are the half where symmetry is available and worth having.
- **A tunnel that is not up was dialled twice, since PPPoE was written.** Both the link-attributes pass and the contents pass called `plan_ppp_session`, so every apply of a session that had not come up ran `pppd` twice — and the fixture covering it asserted the action was *present* rather than how many there were. Found by adding a second tunnel type and watching the fake daemon get invoked twice; fixed for both, with the count now pinned.
- **A `link.up` on a device that does not exist yet fails first, and takes the tunnel with it.** It sorts before the `backend.start` that would have created the device, so the apply stops and the tunnel never comes up at all. That is why a tunnel with no link plans *only* the dial — a rule PPPoE already had and OpenVPN had to be taught.
- **`openvpn --help` lists 253 top-level options**, against hostapd's couple of dozen. That number is why netcfgd generates hostapd's configuration ([0026](docs/decisions/0026-an-access-point-is-a-file-hostapd-reads.md)) and references OpenVPN's ([0046](docs/decisions/0046-the-ovpn-file-is-the-operators.md)) — the same question answered opposite ways because the surface differs by an order of magnitude. A `.ovpn` is also a thing an operator is *given* rather than a rendering of an intent netcfgd holds, which is the `EapConfig` `ca_cert` treatment X.509 material already gets.
- **OpenVPN has a unix-socket text control protocol too** — `--management <path> unix`, with `signal SIGTERM` to stop it. That is the third daemon of this shape after `wpa_supplicant` and `hostapd`, and it is a *stream* socket where `wpa_ctrl` is a datagram one, so the client is new code rather than a reuse.
- **A scope with no mode of its own was dropped at delivery, silently.** `dns = "9.9.9.9"` on an interface compiles to a policy whose mode is `none` — the line says nothing about delivery — and the executor dropped such scopes while the plan reported applying them. An operator wrote a nameserver down and netcfgd ignored it, with nothing failing and nothing warning. Older than the modem work and found by merging the planner's and the executor's two copies of the scope list into one, which is the same class of defect `make executor-policy` exists to prevent. The mode was never a per-interface choice — `netcfgd-dns` refuses a delivery whose scopes disagree about it — so `none` on a scope with something to deliver can only mean "not stated", and it now inherits.
- **The interface report is a contract, and `docs/interface-report.md` is it.** `key=value` lines under `/run/netcfgd/reported/<interface>`, not JSON, because a writer is very often a shell script — wrapped around `umbim` or `mbimcli`, or handed its values in the environment by `openvpn` — and a shell script that must emit valid JSON is one that will one day emit invalid JSON. Unknown keys are ignored *as a promise*, so a writer can report `mtu=` before netcfgd knows what to do with it. Changing what the parser accepts changes what somebody else's script has to write. The modem's name came off the path, the document, the `AddressSource` variant and the config word together, because [0047](docs/decisions/0047-a-tunnels-address-stays-with-its-daemon.md) says doing half of it leaves two names for one idea; `config = "reported"` is the only spelling accepted.
- **Modem support must not require D-Bus, because avoiding D-Bus is why people are here.** Design section 1 opens on NM pulling "D-Bus, polkit, glib, ModemManager [...] absurd on a server, a container, or an embedded box", and [0044](docs/decisions/0044-the-modem-helper-is-contained-the-way-an-adapter-is.md) briefly wrote off the 16 MB router without noticing it had written off the target. [0045](docs/decisions/0045-the-contract-is-the-decision-and-the-helper-is-plural.md) fixes it: the `/run` contract is the decision and the helper is plural. Verified — OpenWrt's `umbim` is `+libubox +kmod-usb-net-cdc-mbim +wwan` with no glib and no bus; Debian's `mbimcli` links `libmbim-glib`, `glib`, `gio`, `gobject`, `libc` and neither `libdbus` nor `libsystemd`, and has `--connect` and `--query-ip-configuration`. Its lack of machine-readable output is the honest cost, and it lives inside the helper.
- **D-Bus is not free, and the client library is the cheap part.** `libdbus-1-3` is 445 KB and pulls `libsystemd0`; a bus daemon has to be *running*, and it drags an XML parser, SELinux, AppArmor and audit — `dbus-broker` depends on `systemd-sysv` outright. In Rust, `netcfgd-nm`'s lockfile is 99 crates against the core's 12. What makes it affordable is not the size but the **containment**: a separate workspace with its own lockfile, which `make nm-containment` proves the core does not link. That wall, not the direction of the arrow, is what 0014 was really protecting.
- **ModemManager's only door is the system bus.** Not systemd: Debian's build does link `libsystemd` and `libpolkit`, but both are upstream build flags a distribution could turn off. D-Bus is not a flag -- there is no unix socket, no control file, nothing else -- so a modem backend built on it would put a D-Bus client *southbound*, on the daemon's side of the wall `make nm-containment` enforces. Decision 0014 declined iwd on the same sentence. [0043](docs/decisions/0043-mbim-is-ours-and-the-quirks-are-a-table.md), superseded by [0044](docs/decisions/0044-the-modem-helper-is-contained-the-way-an-adapter-is.md).
- **MBIM and QMI are not one thing.** `libmbim-glib4` is 920 KB and needs libc and glib; `libqmi-glib5` is 4667 KB, and QMI is Qualcomm's while MBIM is published by the USB-IF and is what Windows drives a modem with. 0036 called them jointly "large", which was wrong about half of it and is why the fork looked closer than it was.
- **A stranded credential is one netcfgd cannot get back, not one it can see.** The rule that stops a plan is narrow on purpose ([0042](docs/decisions/0042-only-a-key-nobody-can-revoke-stops-a-plan.md)): a WireGuard private key is loaded into the kernel by netcfgd, readable back verbatim by root, and revocable only by every peer's administrator. Everything else the model carries is either revocable at one place the operator controls, or is a copy of material that stays in the secrets directory whichever policy is chosen — so refusing over it would ask somebody to decide something their decision cannot affect.
- **A default route is spelled `default` in both families, because that is all the kernel says.** A netlink dump carries no destination for a v4 or a v6 default route alike, so a desired `::/0` matches nothing observed: netcfgd added `::/0` and deleted `default` on every reconcile, forever, with both halves succeeding. It had shipped with the modem work and no fixture could see it — the harness's executor copies the destination it was handed into the observation, so both sides agreed. Only a real kernel normalises. The same rule now covers a report, which may say `default`, `0.0.0.0/0` or `::/0` and gets one spelling back.
- **`--script-security 2` is the difference between a tunnel that reports and one that silently does not.** OpenVPN 2.6 defaults to `SSEC_BUILT_IN`, which runs no user script at all; it says so once at verb 1 and then reports nothing forever. Nothing fails, nothing warns, and the routes simply never arrive.
- **`redirect-gateway` for IPv4 does not survive `--route-noexec`, and openvpn will not say it was asked for.** The `0.0.0.0/1` pair is added inside `add_routes`, which the flag skips, and the `redirect_gateway` variable is set in the same skipped branch. The IPv6 half *does* survive, because those four prefixes join the option list before the route list is built. Measured both ways against a real openvpn 2.6.14. The local answer is `routes = "default"` in the document, which is visible, ranked by `preference` and withdrawn with the tunnel — [0048](docs/decisions/0048-a-tunnels-routes-arrive-through-the-report.md).
- **An operator's `.ovpn` that sets its own `--route-up` loses it.** netcfgd's argument comes after `--config` and wins, and nothing can warn about it without reading the file — which [0046](docs/decisions/0046-the-ovpn-file-is-the-operators.md) forbids.
- **A scope states a DNS mode only to override, and the capability check used to forget that.** `global { dns { dns_mode = "dnsmasq" } }` with `interface vpn0 { dns { domains = [..] } }` was refused as "mode none cannot express routing domains" — naming a mode nobody wrote and no delivery would use — so the only way to split DNS down a tunnel was to repeat `dns_mode` in every interface block, which is a second place for the host's resolver to be stated and disagree. The compile-time twin of the delivery defect `dns::inheriting` fixed, and found the same way: by writing the config the documentation recommends.
- **A reported nameserver is gated more narrowly than a reported route.** netcfgd having started the writer is enough for a route and is deliberately not enough for a resolver ([0049](docs/decisions/0049-a-server-may-name-resolvers-not-where-queries-go.md)). Anyone touching one gate should read why the other one differs before making them agree.
- **pppd hands the `ip-down` call the same environment as the `ip-up` call.** `IPLOCAL`, `DNS1` and `DNS2` all stay set; what it unsets is `OLDIPLOCAL` and `CONNECT_TIME`. A single script deciding "up or down?" from its environment cannot, which is why netcfgd generates two.
- **The rp-pppoe plugin opens `/dev/ppp` when it is loaded**, part-way through pppd's option parsing. So an unprivileged pppd never reaches the options *after* the `plugin` line, and "no unrecognized option" on a whole options file is a check that passes because nothing was parsed. `tests/live/ppp.sh` checks netcfgd's own options with the plugin line removed, and names the plugin's own as the part it cannot reach.
- **`pppoe-server` looks for its plugin at `/etc/ppp/plugins/rp-pppoe.so`,** and Debian ships it under `/usr/lib/pppd/<version>/`. The default therefore fails *inside the server's own forked pppd*, where a client sees a session that connects and then never starts IPCP; syslog is the only place that says why. `-g` names the path.
- **dhcpcd's own hooks run for every family, and `-C` is how you silence one.** A `DHCPv6` lease's `20-resolv.conf` rewrites `/etc/resolv.conf` exactly as a `DHCPv4` one does — measured against a real dnsmasq — so a client netcfgd starts for `dhcp6` needs `-C resolv.conf` where the `dhcp` client gets `-c` ([0072](docs/decisions/0072-dhcpcds-own-hooks-are-replaced-or-silenced.md)). `-C <name>` matches `<name>`, `NN-<name>` and `NN-<name>.sh`, which is in `dhcpcd-run-hooks` and not in the manual page. `30-hostname` reads `$new_dhcp6_fqdn` too, so the hostname path exists on that family; option 39 is not in Debian's request list and nothing here could make it fire.
- **dhcpcd's pid file carries the family it was started with, and `-k` has to name the same one.** A client started `-4` writes `<rundir>/<iface>-4.pid`; `dhcpcd -k <iface>` looks for `<iface>.pid`, prints "dhcpcd is not running" and exits 1 — which is also exactly what a machine whose client is udhcpc says, so netcfgd ignored the status and could not stop the client it prefers ([0070](docs/decisions/0070-a-client-is-stopped-the-way-it-was-started.md)). Also: **dhcpcd will not run under `unshare -rn`.** It drops privileges to an unprivileged user and a namespace with one mapped uid has nobody to become, so a live test needs real root or `unshare --map-root-user --map-auto`, which wants `newuidmap` and a range in `/etc/subuid`.
- **dhcpcd cannot report a delegated prefix to a script**, and never could. `$new_delegated_dhcp6_prefix` is the addresses it derived from one, filled from `ap->delegating_prefix` in `dhcp6.c`, and only on an interface it delegated to. `$new_dhcp6_prefix` — which netcfgd's hook read for years — is not a dhcpcd variable at all.
- **`kea-dhcp6` binds before duplicate address detection finishes and fails.** "Cannot assign requested address" on a link-local it can see with `ip addr`; the address is tentative for about a second after the link comes up. Anything starting a DHCPv6 server right after `ip link set up` has to wait for DAD.
- **The outer `IFLA_LINK` is not where every kind takes its parent.** A VLAN and a macvlan read it there; a tunnel reads `IFLA_GRE_LINK` or `IFLA_IPTUN_LINK` and a VXLAN reads `IFLA_VXLAN_LINK`, both inside their own nest. netcfgd sent the outer one for all of them, so `parent = "base0"` on a tunnel or a VXLAN produced a device with no underlay at all and a successful apply ([0060](docs/decisions/0060-a-parent-is-one-word-and-two-attributes.md)). **A VXLAN is also the only kind that does not report its parent in the outer attribute**, so the reading half is split the same way the writing half is.
- **A geneve tunnel has no underlay interface.** No attribute for one in its family, and `ip` offers no `dev` either, so a `parent` on one could only be dropped -- it is a compile error now.
- **A VXLAN with no `port` in the document gets 8472, not 4789.** The kernel's default is the pre-standard port; `ip` defaults to the IANA one. Both are "whatever was chosen" as far as netcfgd is concerned, which is correct by the rules and is still a footgun: a host configured with netcfgd and one configured with `ip link add` will not talk unless the document says `port = 4789`. Not changed silently -- a default that differs from the kernel's belongs in a decision record, not in a patch.
- **A tunnel change must carry the whole `INFO_DATA` nest, because GRE and the ip tunnels reset what it omits.** A request carrying only `IFLA_GRE_REMOTE` leaves the tunnel with no local address, no TTL and no key — `ipgre_netlink_parms` fills a zeroed struct from whatever arrived — and an `ip6tnl` loses its encapsulation limit, a field netcfgd does not even model. geneve and VXLAN are the opposite and keep what a request leaves out. So netcfgd sends the nest creation would build, and the two rules cost it nothing either way ([0058](docs/decisions/0058-a-change-carries-the-whole-nest.md)).
- **The fallback tunnel devices refuse every change.** `gre0`, `gretap0`, `tunl0`, `sit0`, `ip6tnl0` and `ip6gre0` exist in every network namespace once their module is loaded, and `ip_tunnel_changelink` answers `EINVAL` for anything asked of one. An operator who names an interface after one gets a failing apply. Not special-cased: nothing in the dump marks a fallback device, only six names that are a module's convention.
- **A GRE key of zero is a key, and the value cannot say so.** The kernel emits `IKEY` and `OKEY` for every GRE tunnel, zero included; the `GRE_KEY` bit in `IFLA_GRE_IFLAGS` is what says whether they mean anything. Reading the flag is what stops a document asking for `key = 0` from differing from itself on every reconcile.
- **A macvlan cannot be moved into or out of `passthru`, and its parent cannot be moved at all.** `macvlan_changelink` refuses the `passthru` transition in either direction with `EINVAL`; an `IFLA_LINK` naming a different parent is accepted and silently ignored. The other three modes move freely on a live device.
- **A VXLAN refuses its `port` on presence rather than on difference.** Restating the port it already has fails the whole message with `EOPNOTSUPP`, so a change built from creation's nest could never correct an endpoint. Its `id` is refused only when the value differs, and a group address in the other family is refused by name.
- **iproute2 prints the same protocol tag in two bases.** A route shows `proto 110` and an address shows `proto 0x6e`. The obvious assertion fails on a perfectly correct address.
- **`accept_ra=1` means "accept unless this interface forwards".** A host in an environment that starts with forwarding on ignores every router advertisement, and `ip addr` shows nothing that explains it. `accept_ra=2` is the other way to say it. netcfgd writes that value itself now, where a document asks for `slaac` and the advertisement would otherwise be ignored ([0073](docs/decisions/0073-a-document-that-asks-for-slaac-makes-the-kernel-listen.md)) — and **a DHCPv6 client is not affected**, measured: `dhcpcd -6` solicits routers itself and took a lease on an interface with `forwarding=1` and `accept_ra=1`.
- **A host fills in the bottom 64 bits of an advertised prefix itself**, so the address is `2001:db8:1234:0:...` and a grep for `2001:db8:1234::` matches nothing. `proto kernel_ra` is the kernel saying where an address came from, and is the thing worth asserting.
- **A backend's *device* may not exist while the backend is running.** openvpn creates its `tun` seconds after starting, and a tunnel still negotiating has none at all — so anything planned from an interface's contents is skipped for exactly the tunnels that need it. The stale-configuration check for a `.ovpn` is a top-level pass for that reason, and the live test is what said so while every unit test passed.
- **The kernel's `SET_DEVICE` is a partial update and netcfgd used to send the whole device.** An attribute that is absent is left alone and the peer list is replaced only under `WGDEVICE_F_REPLACE_PEERS`, which is how `wg set wg0 listen-port` changes a port without touching a peer. A comment in `netcfgd-sys` said WireGuard "has no partial update that netcfgd wants", true while the only caller was link creation and false the moment there was a second.
- **A MAC-based allow list is policy, not security.** An address is asserted by the station and changed with one command. It keeps honest devices off a network and stops nobody who does not want to be stopped; anything that must be secure belongs in `wifi { .. }` where the key material is.

---

## 10. Where this is now, and what to pick up next

Kept current deliberately: this is the section to read after a break, and the one to rewrite rather than append to.

### State

**Read this first after a break, and rewrite it rather than appending to it.**
Last rewritten after **M8's first client was built outside this workspace**, which
turned out to be the most productive protocol review this project has had.
Appended to since, most recently by a run of six control-socket findings
(0109-0114) whose lessons live in *Things that are true and non-obvious* rather
than here.

`client/` and `gui/` are a C library and a Qt Widgets window speaking the pinned socket
([gui/project.md](gui/project.md)), and writing them against `docs/schema/` rather
than against the Rust types found three things nothing here could have:

- **`Request::Reload` had been in the protocol, the witness and the authorisation
  table since M2, and no shipped client could send it.** `ncfg reload` exists now,
  and exposing it found the daemon answering a rejected config with `ok`
  ([0081](docs/decisions/0081-a-request-nobody-can-send-is-not-a-feature.md)).
- **Every operation had two names.** A plan serialised its op as serde's
  `snake_case` of the variant, a journal stored `Op::name()`, and nothing saw both
  until a GUI drew a plan above the journal its apply returned. The tags are the
  names now ([0082](docs/decisions/0082-one-operation-has-one-name.md),
  [0083](docs/decisions/0083-the-tag-is-the-name.md)) -- and that turned up
  `ncfg tui` having rendered the wrong word since it was written.
- **The TUI's tests told it what the daemon sends.** Hand-written fixtures, in the
  last crate not reading `docs/schema/`, and wrong twice over. They read the
  witness now.

Before it, ten pieces of work on the laptop list, every one of them
started by asking what an operator would actually hit rather than what the roadmap
said next. The tenth was one line on that list -- "the dhcpcd script has never been
run by dhcpcd" -- and running it found three defects rather than the nothing a test
gap usually finds. **netcfgd could not stop a DHCP client**, in two different ways:
a dhcpcd, because the pid file carries the address family and the stop did not name
it ([0070](docs/decisions/0070-a-client-is-stopped-the-way-it-was-started.md)); a
DHCPv6 client, because `stop_backend` had no arm for one at all
([0071](docs/decisions/0071-a-client-with-no-socket-is-stopped-by-the-pid-it-wrote.md)).
And **a DHCPv6 lease rewrote `/etc/resolv.conf`** behind netcfgd, which is 0066's
contention on the family nobody had run
([0072](docs/decisions/0072-dhcpcds-own-hooks-are-replaced-or-silenced.md)).
None of the three could have been caught by anything here: nothing had ever run a
real dhcpcd, and the test that runs a real odhcp6c stopped it with `pkill`. Before
them:
four config keys that compiled and did nothing
([0061](docs/decisions/0061-a-key-that-compiles-does-something-or-says-it-does-not.md)),
**rfkill** — a radio that is switched off looked exactly like a network that would
not associate, and checking it put the first real wifi hardware under test here
([0062](docs/decisions/0062-a-blocked-radio-is-reported-and-not-unblocked.md)) — the
**`down`, `lease` and `carrier` hooks** (0063, 0064, 0068), **DHCPv4 with busybox**,
which had never worked at all
([0065](docs/decisions/0065-udhcpc-needs-a-script-and-netcfgd-writes-it.md)), **what
a lease says about names** (0066, 0067), and **joining a network without an editor**
([0069](docs/decisions/0069-adding-a-network-is-writing-a-file.md)).
Nearly every one found a defect older than the work itself — including netcfgd
overwriting a working `/etc/resolv.conf` with an empty one, up hooks running on
every reconcile, and a DHCP fallback that got a lease and configured nothing.
Before it, the session that **closed**
[0057](docs/decisions/0057-a-link-kind-is-compared-like-a-daemon.md)'s list and
found that a VXLAN's and a tunnel's parent had never reached the kernel at all
([0060](docs/decisions/0060-a-parent-is-one-word-and-two-attributes.md)):
every link kind's own settings are now compared against what the kernel holds,
the VLAN last and by the only route the kernel allows — deleting the interface
and making it again
([0059](docs/decisions/0059-an-interface-is-remade-when-the-kernel-will-not-change-it.md)).
It is the last answer to the question the sessions before it kept finding new
places to ask: **is what is running still what the document says?** What follows
is organised by subject, not by the order it was built in.

**Milestones.** M1–M6 are done. M7's NetworkManager shim has tiers 1 and 2
complete and tier 3 bounded rather than built — and **tier 3 bounds the shim,
not netcfgd** ([0036](docs/decisions/0036-the-shim-is-not-the-roadmap.md)),
which is the single easiest thing in this repository to misread. VPN, modems and
complete wifi are wanted in netcfgd and will simply not be projected through
NM's interfaces.

**The M4 freeze's inert features are all closed**, router advertisement last.
Everything the model carried and nothing implemented now has an implementation
and a test that ran against the real daemon.

#### The reporting contract

`/run/netcfgd/reported/<interface>`, `key=value` lines, documented for somebody
who has never read this source in
[docs/interface-report.md](docs/interface-report.md). Something that is not
netcfgd brings an interface up and writes down what the far end gave it;
netcfgd reads that file and treats it as it treats a lease. It is not a modem's,
though a modem helper wrote the first one — the name came off the path, the
document, the model variant and the config word together, because doing half of
it leaves two names for one idea
([0047](docs/decisions/0047-a-tunnels-address-stays-with-its-daemon.md)).

Four keys: `address`, `gateway`, `route`, `dns`. There will not be one for a
routing domain
([0049](docs/decisions/0049-a-server-may-name-resolvers-not-where-queries-go.md)):
a resolver is information netcfgd could not have had, and *which names use it*
is a decision about where every query on the machine goes, which a remote server
does not get to make by connecting.

**Two gates, and they differ on purpose.** A route is installed when the
document asks for `reported` addressing *or* when netcfgd started the writer —
a tunnel reports through a script netcfgd generated, run by a process netcfgd
started. A **nameserver** needs more: the addressing must come from the report,
or the interface must have a `dns` block. A route down a tunnel goes down that
tunnel; a nameserver changes where names resolve for the whole machine. Anyone
finding the two disagreeing should read 0049 before making them agree.

#### What netcfgd runs, and what it leaves alone

**Cellular** works end to end and nothing in it is netcfgd's protocol: a helper
connects the bearer and writes a report, netcfgd installs what it says and
withdraws it when the report empties. The helper is deliberately plural
([0045](docs/decisions/0045-the-contract-is-the-decision-and-the-helper-is-plural.md))
— `helpers/netcfgd-modem-mbim` is a reference, and `umbim` or ModemManager are
equally valid writers. netcfgd never speaks MBIM, QMI or D-Bus
([0044](docs/decisions/0044-the-modem-helper-is-contained-the-way-an-adapter-is.md)).
Nothing here has met hardware.

**An OpenVPN tunnel**: netcfgd owns the lifecycle and never reads the `.ovpn`
([0046](docs/decisions/0046-the-ovpn-file-is-the-operators.md)) — 253 top-level
options against hostapd's couple of dozen, and a file an operator is *given*
rather than a rendering of an intent netcfgd holds. The address stays with the
daemon as a DHCP lease's does; the **routes** are netcfgd's, through
`--route-noexec` and a generated `--route-up` script, with a metric from
`preference` so a tunnel can be ranked against a wired link
([0048](docs/decisions/0048-a-tunnels-routes-arrive-through-the-report.md)). The
one thing openvpn will not report is IPv4 `redirect-gateway`; the local answer
is `routes = "default"` in the document, and `tests/live/tunnel.sh` checks that
recommendation rather than leaving it as advice.

**A PPPoE session** dials and now hangs up — it could not until something
dialled one. pppd has no control socket, so netcfgd reads the pid file pppd
wrote for the interface and checks `/proc/<pid>/cmdline` names the options file
netcfgd generated before signalling anything, which is a stronger claim than
"not by name" rather than an approximation of it. `usepeerdns` is on, because
the belief that kept it out — that it rewrites `/etc/resolv.conf` — was wrong;
it writes pppd's own file, and what it is for is `DNS1`/`DNS2` in a script's
environment. Two generated scripts, not one: pppd hands the `ip-down` call the
same environment as the `ip-up` call.

**An access point** is a file hostapd reads
([0026](docs/decisions/0026-an-access-point-is-a-file-hostapd-reads.md)), with a
station list that converges over the control socket without deauthenticating
anybody ([0041](docs/decisions/0041-a-station-list-converges-over-the-control-socket.md))
and a live client list that makes it usable
([0040](docs/decisions/0040-a-station-list-needs-a-station-list.md)).

**A router advertisement** is the same bargain: netcfgd renders radvd's
configuration and radvd sends the packets. `advertise { prefixes = ["@pd:wan0"] }`
on the LAN. odhcpd is refused by name rather than handed radvd's file.

#### The router story, end to end

`config = "dhcp6 pd_length 56"` on the WAN and `@pd:wan0=::1/64` on the LAN: the
ISP delegates, odhcp6c reports through the hook netcfgd generated, netcfgd
derives the address, radvd advertises the prefix, and a host on the LAN
configures itself
([0051](docs/decisions/0051-the-request-half-of-a-delegated-prefix.md)).
`tests/live/delegation.sh` runs all of it against a real kea, a real odhcp6c and
a real radvd.

**Prefix delegation is odhcp6c's.** dhcpcd cannot report a prefix to a script at
all — its `$new_delegated_dhcp6_prefix` carries the addresses it *derived*, which
is the deriving decision 0009 makes netcfgd's — so a document asking dhcpcd for
one is refused by name
([0050](docs/decisions/0050-a-delegated-prefix-is-odhcp6cs-to-report.md)).
odhcp6c is not packaged for Debian and builds from source in two minutes;
`delegation.sh`'s header says how.

**And when the ISP renumbers, everything derived from the prefix moves** — the
LAN's address and what is being advertised. That is a reload for radvd, which
re-reads on `SIGHUP`, so nothing on the wire is disturbed.

#### Is what is running still what the document says?

The question this project keeps finding new places to ask. Five kinds of answer
now exist, and the shape of each is worth knowing before adding a sixth.

**A supplicant is checked the same way, and that took a pid file**
([0080](docs/decisions/0080-a-socket-outlives-the-process-that-bound-it.md)): it is
reached through a control socket, and a socket outlives the process that bound it.
The *start* path had the same bug — it treated the socket as proof of a running
supplicant, so a killed one could not be replaced at all. hostapd is left out on
purpose, because nothing here can start a real one.

**And it stops trying after five**
([0079](docs/decisions/0079-netcfgd-stops-restarting-what-will-not-stay-up.md)),
which is the defect the paragraph below introduced and the same session closed: a
daemon that dies as fast as it is started produced 181 starts in twelve seconds on
an interface set to `reconcile`. The count is of consecutive starts that did not
lead to a live process, cleared the moment one is seen running — so a flapping
daemon is still restarted indefinitely, and one that never comes up is not.

**A daemon netcfgd started may simply be gone**, and until
[0078](docs/decisions/0078-a-record-is-a-memory-and-a-process-is-a-fact.md)
nothing looked: `running` came from netcfgd's own record in `/run`, so a tunnel
killed by the OOM killer left a document saying it should be up, a machine where
it was not, and a reconciler reporting convergence. The observation checks the pid
now — for the backends netcfgd holds one for — and the planner restarts what has
gone. **A kind with no handle is left alone**, which is `None` is not `false`
deciding a design for the third session running: a `DHCPv4` client may be dhcpcd,
whose pid file is in its own compiled run directory, and reading "no file" as "not
running" would start a second dhcpcd beside a live one on every machine that uses
one.

**A daemon netcfgd started** is compared against the file netcfgd generated for
it ([0052](docs/decisions/0052-a-daemon-is-compared-to-what-it-was-started-with.md),
[0053](docs/decisions/0053-a-file-netcfgd-does-not-read-can-still-be-hashed.md)).
An edited SSID, channel, band, passphrase, advertised prefix or `.ovpn` is
noticed. The act differs by daemon and that difference is not cosmetic: radvd
reloads and costs nothing, hostapd restarts and every station is deauthenticated,
which the plan says in those words.

**A kernel object netcfgd configured** is compared against what the kernel
reports ([0054](docs/decisions/0054-a-kernel-object-is-compared-like-a-daemon.md),
[0057](docs/decisions/0057-a-link-kind-is-compared-like-a-daemon.md),
[0058](docs/decisions/0058-a-change-carries-the-whole-nest.md)). This is
where 0053 guessed wrong — it expected the next gap to be a backend netcfgd does
not start, and it was a **WireGuard device**, which netcfgd creates itself.
Everything that makes one a tunnel went over generic netlink inside
`link.create` and never again, so an edited listen port did nothing and **a peer
deleted from the config kept its access** while `ncfg apply` said there was
nothing to do: a wrong answer shaped like a completed revocation. The same was
true of every other link kind's own settings; a bridge, a bond, a macvlan, all
seven tunnel kinds and a VXLAN are closed now.

**What a kind will take is per attribute, and asking is the only way to know.**
Fourteen attributes across seven families answer four different ways — taken,
refused loudly, refused *silently*, and taken only in some directions. A
macvlan's mode moves among three of its four modes and is refused in either
direction between one of those and `passthru`; a VXLAN refuses its `port`
**whenever the request mentions it**, at the value it already has. So what
netcfgd sends is the whole nest its own creation would build, minus exactly the
attributes the kernel refuses on a device that exists — which is what leaves an
edited endpoint applicable while the id beside it is only reported.

**And the families disagree about what a request leaves out.** GRE and the ip
tunnels **reset** every attribute a change omits; geneve and VXLAN keep them.
That is why the nest goes whole rather than one field at a time, and it is a
measurement `ip` actively hides — see the entry under "true and non-obvious".

**A secret netcfgd loaded** is compared by *digest*
([0055](docs/decisions/0055-a-secret-can-be-hashed-too.md),
[0056](docs/decisions/0056-a-peers-secret-is-recorded-per-peer.md)). 0054 said a
rotated WireGuard key needed curve25519; it does not. The question is not what
public key a private one derives but whether the secret has moved since netcfgd
loaded it, and netcfgd answers that by recording `sha256` of what it handed the
kernel, at 0600 under `/run`, and hashing the store again on the next
observation. 0053's trick played on a secret rather than a file: it hashed bytes
it was forbidden to *interpret*, this hashes bytes it is forbidden to *keep*.
Every secret a WireGuard device holds is covered, the peers' preshared keys
included, recorded per peer and keyed by the public key — the only name the
kernel and the document share.

**Safe because of what the secret is, not because the technique is safe.** A
WireGuard key is 32 octets of kernel randomness with no dictionary behind it. A
*passphrase* is the opposite, which is why an access point's is still compared in
memory and written down nowhere. Anyone reaching for the digest on a third secret
has to make that argument again.

Three rules hold across all five, and every one was paid for:

- **The comparison goes where both halves already are.** A secret and an unread
  file cannot reach a pure planner, so those comparisons happen in the observer
  and only a boolean travels.
- **`None` is not `false`.** No record, an unresolvable secret, an unreadable
  file and a device netcfgd did not configure are all "could not check", and
  nothing is restarted, rekeyed or replaced on one.
- **What the document does not state is not compared.** An absent band, listen
  port or forward delay means "whatever was chosen", and comparing it against
  what *was* chosen rebuilds the thing on every reconcile. This mistake has now
  been made and caught three times.

**And where the kernel will not change a thing at all, the interface is remade.**
A VLAN's id and tag protocol are set at creation and `vlan_changelink` ignores
them afterwards, which is the kernel's worst answer: it takes the request and
does nothing. So the planner deletes the interface and makes it again, and the
passes below it put back everything that went with it — addresses, routes, the
client that was leasing, the members that were enslaved — because they run
against an observation the doomed interface is no longer in
([0059](docs/decisions/0059-an-interface-is-remade-when-the-kernel-will-not-change-it.md)).
An interface that exists as an entirely *different kind* takes the same road; that
was silent too, and worse, because netcfgd brought somebody else's device up and
called the network configured.

**Only a link netcfgd created is ever thrown away.** This is the one destructive
thing in a plan, and the ownership rule that governs addresses and routes governs
it: a link netcfgd has no record of creating gets a sentence and is left alone. A
guard refuses the whole sequence, delete and backend stop together, rather than
half of it.

**Nothing on that list is silent any more.** A macvlan's and a VLAN's parent were
the last of it, and they are remade like a VLAN's id
([0060](docs/decisions/0060-a-parent-is-one-word-and-two-attributes.md)) — while a
VXLAN's and a tunnel's move in place, because a parent is one word in the document
and two different attributes to the kernel.

#### What the config says and what happens

**A key that compiles does something, or the plan says it does not**
([0061](docs/decisions/0061-a-key-that-compiles-does-something-or-says-it-does-not.md)).
The `ethtool` block has said which of its fields are inert since it landed, and
that is why nobody has ever been confused by it. Four keys had no such sentence:
two are now implemented (`slaac privacy prefer_temporary`, which writes
`use_tempaddr` per interface, and `hostname = "name"`, which sets the running
hostname), and two are reported with the reason (`hostname = "dhcp"` needs a lease
netcfgd never sees; `portal_check` would need netcfgd to fetch a hard-coded URL,
which is the operator's decision and not a default).

**And `config = "slaac"` now makes the kernel listen**
([0073](docs/decisions/0073-a-document-that-asks-for-slaac-makes-the-kernel-listen.md)).
`accept_ra` defaults to "accept unless this interface forwards", so SLAAC on a
router's WAN — or in a container, which usually forwards — obtained no address at
all while `ncfg apply` reported success. netcfgd writes `2` where an advertisement
would otherwise be ignored and nowhere else, so an ordinary laptop has no sysctl
written and no line in its plan; an interface that stops asking gets the kernel's
default back, and one netcfgd never wrote is left alone, `0` included. The reading
is two files — the value means nothing without the interface's IPv6 forwarding —
so both halves are combined in the observer and only the answer travels. The write
goes **before** `link.up`, because the kernel does not solicit a router on an
interface whose advertisements it would ignore — written afterwards, the address
waits for the router's own timer. And the warning that used to tell an operator to
set the sysctl by hand is gone: it was true when written, false the moment this
landed, tested by nothing, and it read the *document's* `forwarding` field, so it
never fired for a container that forwards without being asked.

**All eleven hook phases fire**, and the machinery that made a phase which
*cannot* say so in the plan is still there for the next one added. `pre_up` and
`post_up` were the first two. `up` is the newest
([0076](docs/decisions/0076-the-up-hook-is-the-moment-a-link-is-live-and-bare.md)),
and it earns a phase of its own by having a moment of its own: the link is up and
nothing is addressed. **The addressing waits for it**, which is what makes that a
fact rather than emission order — and the price, a slow hook delaying the
addresses, is in the phase's documentation rather than left to be discovered. The
warning that lists which phases fire now reads the list instead of naming two by
hand; it had said "only `pre_up` and `post_up`" since before `down` landed. `down` and `post_down` joined them in
[0063](docs/decisions/0063-the-down-hooks-run-before-the-interface-goes.md), where the
ordering is the whole point: teardown is the *last* thing in a plan, so a teardown hook
runs while the interface still has its addresses and routes — which is what lets it
unmount a share. `pre_down` joined them in
[0096](docs/decisions/0096-taking-an-interface-down-is-more-than-one-moment.md), which
gave disabling an interface the five steps the phase names describe: `pre_down` while
everything still works, `addr.del` for what netcfgd installed, `down` with the
addresses gone and the link still up, `link.down`, `post_down` with nothing left to
stop. **`down` moved** in that change — it used to run before netcfgd removed anything,
because netcfgd removed nothing — so a `down` hook that needs to reach the network
belongs in `pre_down` now.

**`lease` and `carrier` are the two event phases**, and they share one mechanism.
`lease` fires on an address netcfgd did not install
([0064](docs/decisions/0064-a-lease-is-an-address-netcfgd-did-not-install.md)), which
is the only way netcfgd can know a lease arrived — it never sees DHCP. `carrier` fires
when the cable comes or goes
([0068](docs/decisions/0068-a-carrier-hook-fires-where-the-cable-matters.md)), which
nothing else reported, and *where* it goes in the plan depends on which way it went:
gained after the addressing, because a script that reacts by connecting somewhere
needs the network to work; lost early, before the teardown withdraws anything.
`NCFG_REASON` is `up` or `down`, and the first observation fires it, which is what
`ifplugd -i` does.

**One `/run` record serves both**, and every event phase after them: `hook_state`,
keyed by interface and phase, is what makes an event hook fire once per event rather
than once per reconcile. It was the lease's alone for two commits until `carrier`
arrived wanting the same thing with a different value in it, which is the signal to
generalise rather than duplicate. It is written whether or not the script succeeded,
because a hook that kept the plan non-empty would be a plan that never converges.

**And the up hooks now fire only when netcfgd is bringing the interface up.** They
were unconditional, so a converged interface ran them on **every apply** — the
second plan was never empty, against §4 — and a *disabled* interface ran them too,
in a plan that went `pre_up`, `link.down`, `post_down`, `post_up`. Both were found
by putting hooks in front of a real kernel, and neither was visible to the
idempotence gate: the one fixture with hooks called `plan` and `simulate` by hand
instead of going through `settle`.

**`Device.match` is unreachable from the config**, and that is now written down
rather than looking like a feature: the model carries `mac`, `path`, `driver` and
`name_glob`, and the language has no syntax for any of them, so an operator who
tries gets a compile error. Implementing it means reading a driver name and a
device path out of `/sys`.

#### DHCPv4, which nothing had ever driven

**A lease's nameservers and search suffixes reach the resolver through the report
contract**
([0066](docs/decisions/0066-a-lease-reports-its-nameservers.md)). Both clients run a
netcfgd-generated script that writes `dns=` into `/run/netcfgd/reported/<iface>`, and
0049's existing gate delivers them to an interface that asked with an empty
`dns { }` block. No new mechanism and no new gate: only the reporting half 0049 left
for later, so a modem, a tunnel and a lease all arrive the same way.

**A search suffix is not a routing domain**, which is 0049 split in two
([0067](docs/decisions/0067-a-suffix-is-not-a-routing-domain.md)). It refused
`dhcp-option DOMAIN` as authority over where queries go; on the wire that option is
usually the weaker thing — what to append to a bare name. So `search=` is a report
key now, under the *same* gate as a server, and the argument is what makes it safe:
if you took the network's resolvers they already answer everything, so appending a
suffix adds nothing; if you kept your own, a lease that could set the search list
would make `wiki` resolve as `wiki.evil.example` through your trusted resolver. The
gate keeps the two together. A routing domain is still refused and still has no key.

**It was worse than a missing feature.** With the mode the first-run guide
recommends, netcfgd overwrote a working `/etc/resolv.conf` with a file containing one
comment and no nameservers — measured — while the plan said `dns.apply` and warned
only that it could not be undone. A delivery with no servers in it now says so, and
where a report offered some, it names the interface and the one-line fix.

**And dhcpcd had been fighting netcfgd for that file all along.** Its own
`20-resolv.conf` hook writes `resolv.conf`, so on any machine where netcfgd's DNS
mode owns it, both wrote and whichever ran last won. `-c` replaces dhcpcd's hook
directory, which ends that — and stops `30-hostname` taking the hostname from a
lease, which 0061 had refused in the config while dhcpcd did it anyway.

**netcfgd generates the script busybox `udhcpc` needs**
([0065](docs/decisions/0065-udhcpc-needs-a-script-and-netcfgd-writes-it.md)). Before
that it invoked the client with no `-s`, and busybox has no configuration step of
its own — so on a machine with busybox and no dhcpcd, `config = "dhcp"` obtained a
lease and configured nothing while the plan reported success. Two more halves of the
same defect: the client could not be *found* on Debian, which packages busybox as one
binary with no `udhcpc` symlink, and it could not be *stopped*, because `dhcpcd -k`
does nothing to a udhcpc and there was no pid file to find one by.

The script does what dhcpcd does and no more — the address and the default route,
untagged, so the lease is the client's under either client and the `lease` hook needs
no case for both. It leaves the MTU alone (the document owns it), leaves
`resolv.conf` alone (netcfgd's DNS backend owns it), and removes **only the address
it added**, where a stock `deconfig` flushes the interface and would take a static
address with it.

**All three survived because nothing in the suite had ever driven a v4 client.**
`tests/live/dhcp.sh` now does: `busybox udhcpd` on the far end of a veth pair, a real
DISCOVER/OFFER/REQUEST/ACK, and netcfgd's own script putting the address on. It needs
no package a machine with busybox does not already have.

**And now the other client is driven too, which found the same defect again**
([0070](docs/decisions/0070-a-client-is-stopped-the-way-it-was-started.md)).
`tests/live/dhcpcd.sh` runs a real dhcpcd against the same busybox server. 0065 had
fixed "a udhcpc cannot be stopped" and left standing, unnoticed, that **a dhcpcd
could not be stopped either**: its pid file carries the family it was started with,
`dhcpcd -k <iface>` looks for the name without one, and "dhcpcd is not running" is
also what a machine whose client is udhcpc says — so the status could not be checked
and was not. Dropping `config = "dhcp"` reported a stopped backend while a real
client kept the address and went on renewing the lease. One constant now names the
family for both the start and the stop, and a unit test reads the start arguments and
asserts the stop agrees.

**And a tunnel that had not finished starting could not be stopped either**
([0074](docs/decisions/0074-a-daemon-that-cannot-answer-is-still-running.md)),
which is the third instance in one session of one question. `--daemon` returns at
the fork and the management socket is bound by the child a moment later; a stop in
that window found nothing listening, said so, and left the daemon holding the
link. netcfgd passes `--writepid` now and falls back to the pid when the socket
does not answer — checking `/proc/<pid>/cmdline` against *this tunnel's socket
path* rather than the interface name, because `vpn0` is a string an unrelated
command line could contain.

**The pattern is worth stating once**: netcfgd could stop the daemons it could
reach, and had no answer for the ones it could not. A dhcpcd under a pid file name
it did not expect, a DHCPv6 client with no arm at all, a tunnel that had not
finished starting.

**The DHCPv6 half was worse and is closed too**
([0071](docs/decisions/0071-a-client-with-no-socket-is-stopped-by-the-pid-it-wrote.md)).
`stop_backend` answered `Dhcp6` with "not implemented in this build", so dropping
`config = "dhcp6"` was a *failed apply* with the client still holding the lease.
dhcpcd takes `-6 -k`; odhcp6c has no control socket, no `-k` and no `-x`, so netcfgd
tells it where to write its pid and stops it by that — sharing udhcpc's one function
rather than growing a second copy of it. A stopped odhcp6c releases the delegation,
calls its script once more with nothing bound, and the prefix file empties itself,
which is the path the hook's own comment described and nothing had run.
`delegation.sh` used to tear down with `pkill -f odhcp6c` and a truncated prefix
file — the test doing by hand the two things netcfgd could not do, which is how it
stayed hidden through every green run.

**And dhcpcd was fighting netcfgd for `resolv.conf` on the other family too**
([0072](docs/decisions/0072-dhcpcds-own-hooks-are-replaced-or-silenced.md)). 0066
ended that contention for `DHCPv4` by replacing dhcpcd's hook directory; the
`DHCPv6` client got nothing, so a `dhcp6` lease rewrote the file netcfgd owns —
measured, against a real dnsmasq. It is silenced now rather than given netcfgd's
script, and the reason is the report rather than dhcpcd: `/run/netcfgd/reported/`
is one file per interface, written whole, so two clients on one interface would
clobber each other's `dns=` lines on every renewal. What dhcpcd does about its own
hooks is a type with two arms now, and no third one meaning "nothing".

**The test runs dhcpcd once with its own hooks first**, which is what makes the rest
of it mean anything: without `-c`, a lease sets the machine's hostname to
`leased-name.lan.example` and rewrites `/etc/resolv.conf` — both measured, in a UTS
namespace and behind a bind mount so neither reaches the machine. Only then is
"netcfgd's hook left them alone" worth asserting. It is also the first check here
that `preference` reaches a lease's default route, which it can only do through
`dhcpcd -m`: netcfgd does not install that route, the client does, and busybox has no
equivalent.

#### The radio, and what netcfgd will not switch

**A blocked radio is named, with the remedy for the switch that blocked it**
([0062](docs/decisions/0062-a-blocked-radio-is-reported-and-not-unblocked.md)).
`ncfg status` prints a line when the radio is off, `ncfg explain interface` says so
before the addresses — a blocked radio has none — and a plan gives the remedy,
which differs: a soft block clears with `rfkill unblock wifi` and a hard block is a
physical switch nothing in software will move.

**netcfgd will not unblock one.** It could — clearing a soft block is an 8-byte
write to `/dev/rfkill`, no `unsafe` and no privilege beyond group `netdev` on
Debian. It does not, because a soft block is somebody's deliberate act: the
aeroplane switch, the function key, the desktop's toggle. A daemon that reads "wifi
off" as a state to correct turns the radio back on in a cabin because a config file
mentions a network. The same rule as `Ownership::may_remove`, applied to a switch.

**A laptop has two `wlan` switches and only one of them is the card's.** The Dell
this was measured on reports `dell-wifi` beside `phy0`; netcfgd reads the phy's own,
because that is the one the driver obeys. Whether blocking the platform button
propagates to the phy is **not measured** and is written down as unknown — finding
out means switching off the radio of the machine running the test.

#### Storing a credential

**`ncfg secret set NAME` writes the file a `@secret:` reference points at**
([0075](docs/decisions/0075-a-secret-is-stored-by-a-command-that-never-shows-it.md)),
with echo off and at 0600, and says which blocks refer to the name — or that
nothing does yet, which is how a typo is caught at the moment it is made rather
than as "no such secret" from a backend an hour later. An existing secret is
refused rather than replaced unless `--replace` says so: one of the things this
stores is a WireGuard private key, which nobody can get back. There is no `get`,
and asking gets a sentence explaining why rather than an unknown-subcommand error.

The prompt is 0069's, *moved* rather than copied — both commands call one reader,
and breaking it shows the value in the transcript of both. Design section 3.3 had
specified this command since before there was a compiler; the help pointed at it
while it did not exist, which is 0061's disease in a help string and is now two
diagnostics that point at something real.

#### Joining a network

**`ncfg wifi add SSID` writes the config file, and the daemon is not involved**
([0069](docs/decisions/0069-adding-a-network-is-writing-a-file.md)). It cannot be:
`netcfgd.service` mounts `/etc/netcfgd` read-only and nothing in the protocol writes
configuration — which is the shape 0030 settled when the NetworkManager shim needed
the same thing. So a client writes one `network` block into
`conf.d/wifi-<id>.conf`, the passphrase into `secrets/<id>` at 0600, and the daemon
notices by inotify. Forgetting a network is `rm` on that file.

**The passphrase is never an argument**, because `ps` shows one to every user on the
machine and the shell writes it to a history file. On a terminal it is prompted for
with echo off — a new `EchoOff` guard in `netcfgd-sys::term`, next to `is_terminal`
for the reason that module exists: constraint 4's crate is where the libc boundary
lives, not where netlink lives. The termination signals are blocked for exactly as
long as echo is off, so `^C` aborts *after* the terminal is restored rather than
instead of it. On a pipe it is one line of standard input, which is what makes the
command scriptable.

**What it writes, it reads back**: the whole configuration is compiled again through
the daemon's own loader, and if the result does not compile or does not contain the
network asked for, both files are removed and the compiler's diagnostic is the error.
A generated file that does not compile takes every other interface with it.

**An id is a label, a filename and a secret name at once**, so the strictest of the
three wins — no quote, no backslash, no control character, no `/` and no `..`, the
last two because a secret's name is a path under `secrets/`. An SSID that fails is
refused with the fix: `--id` gives a plain label and the SSID is kept exactly, as
hex, which is the mechanism the DSL already had.

#### Roaming, which is how wifi always worked

An ESS is several access points sharing one SSID, and a station picks whichever
it hears best. netcfgd could not ask for it
([0089](docs/decisions/0089-a-station-picks-the-loudest-access-point-and-netcfgd-must-say-so.md)):
`wpa_supplicant` roams within a network block by itself but **only while a
`bgscan` module is asking it to look**, and nothing here set one — grepped, in
every crate and every test. So every netcfgd station re-selected only after the
link had gone, which is roaming by first losing the network.

`roam { signal = -68; interval = 20; slow_interval = 240 }` on a network, with
`-70`/`30`/`300` as the defaults. **Intent, not a module name**: the operator
says how weak is weak and how often to look, and the backend renders
`bgscan="simple:..."` the way it renders everything else. Off unless asked for,
because a background scan costs airtime and a router with a radio does not move.
Pinned or roaming and never both — `bssid` and `roam` are two different requests,
and the check sits where the whole network is known rather than inside the `wifi`
block, since one is a network key and the other is not.

Measured against a real `wpa_supplicant` 2.10, and the question is sharper than
it looks: netcfgd writes no config file for a station, it sends `SET_NETWORK`.
A key the file parser takes is not necessarily one the socket takes, and the
failure would be roaming silently off with the daemon reporting success.

~~**Still missing:** an access point identified *only* by BSSID.~~ **Done**
([0090](docs/decisions/0090-a-network-may-be-named-by-its-access-points.md)).
`bssid` takes one address or a list: **one pins, several choose**, which are
different keys to `wpa_supplicant` (`bssid` refuses everything else,
`bssid_accept` limits selection and picks by signal) and rendering a list as a
pin would join one and never move. That also corrects 0089 by half — a *pin*
contradicts a roam policy, a *list* does not, and "any of these, whichever is
loudest" is exactly what an operator who listed their site wants.

`ssid = "@bssid"` says the name is not the operator's to state, and netcfgd
reads it off `SCAN_RESULTS` before configuring. **That is arithmetic, not
convenience**: `wpa_supplicant`'s wildcard-SSID example is annotated "plaintext
APs only", because WPA derives its key from the passphrase *and* the SSID. No
`SCAN` is issued — a scan costs seconds and interrupts traffic, and this runs
inside an apply — so an access point that is not in the last results is reported
as unseen, with its address in the message. Addresses that advertise different
names are refused: two networks, and one passphrase cannot be right for both.

The `roam` hook still does not fire (0084).

#### What a client may do, asked once

`hello` reports the control tiers a connection satisfies
([0092](docs/decisions/0092-a-client-is-told-what-it-may-do.md)). Before it, the
only way for a client to learn what an operator was allowed to do was to try it
and read the refusal — so a window offered an apply button whose first effect was
a no, which is what `gui/project.md` §4 asks against.

**Three independent answers, not a level.** 0013's tiers are group memberships:
a machine may grant `admin` to a group somebody is in and `wifi` to one they are
not, so reporting a maximum would claim a permission they do not have. The gate
is that `granted` agrees with `check` for every tier and every peer — two
answers to "may I" is exactly what this would otherwise create.

A daemon too old to answer grants nothing, and the GUI reads that as *permitted*
rather than as denied. Stated in the code, because the instinct is the other way:
being refused explains itself and a greyed-out button does not.

#### Explaining it

`ncfg explain` follows the indirections. An address the document named by
reference — a report, a delegated prefix — says which file the value came from,
so the next question has somewhere to go. An interface says which backends are
running, what they were started with, and whether anything behind them has
moved. `ncfg status` and the TUI's device pane both mark what was *reported* and
not applied, which is the difference between "the network gave us nothing" and
"netcfgd has not acted on it".

#### Credentials and the schema

Walking away from a device is decided rather than defaulted: `managed = false`
on a device holding a **WireGuard private key** stops an apply with its own exit
code until the operator says which they meant
([0042](docs/decisions/0042-only-a-key-nobody-can-revoke-stops-a-plan.md)) — the
one credential that is both irrevocable from this host and something the
operator's choice can change.

The schema version is pinned at 1.0 until the first release
([0038](docs/decisions/0038-versioning-starts-at-the-first-release.md)). What
does the work is the **four** witnesses under `docs/schema/`, which move on every
change and need a deliberate `make schema-bless`. Two of them are new:
`observed.json` and `plan.json` are the other things a `Status` response carries,
and nothing had ever pinned either while the socket witness claimed in a comment
that something did.

All four are exhaustive now rather than sampled: each goes through a match that
stops the file compiling when a variant appears, and the payload-heavy socket
responses carry an *empty* payload — enough to pin the tag and the framing, with
the contents left to the witness that owns them.

#### A second implementation is a protocol review

`client/` is the first consumer of netcfgd's socket written outside this
workspace, and building it found three defects in the *protocol* rather than in
itself. None was reachable from here, and the reason each hid is the same: every
program that read a plan had been written in the same workspace as the program
that wrote it.

**A request nobody can send is not a feature.** `reload` was pinned, authorised
and handled, and no client offered it. Nothing was red because nothing compared
the two lists; the daemon reloads by inotify, so the gap was not in the
behaviour but in the *answer* -- a config that does not compile said so to the
log while the person holding the editor was told nothing. Exposing it found the
socket answering from `state.diagnostics` where the truth was in the event, so a
config a revert had rejected got "reloaded; the configuration compiles"
([0081](docs/decisions/0081-a-request-nobody-can-send-is-not-a-feature.md)).

**Two names for one operation, invisible from inside.** The plan's op tag was
serde's `snake_case`; the journal's was `Op::name()`; `ncfg plan` printed the
second and `ncfg plan --json` emitted the first. It took a screen showing a plan
above a journal to put `link_create` four lines from `link.create`. The repair
was a field first ([0082](docs/decisions/0082-one-operation-has-one-name.md)) and
then the rename it recorded as somebody's to authorise
([0083](docs/decisions/0083-the-tag-is-the-name.md)) -- which found `ncfg tui`
drawing the snake tag since the day it was written, with a hand-written fixture
asserting the dotted one and passing.

**And the rename traded one risk for a subtler one**: two lists of forty-seven
strings with nothing making them agree. The gate that forces them earned itself
on its first run, on the one unit variant among forty-eight that the mechanical
edit had skipped.

#### What the gates have been worth lately

Several sessions in a row have found more in the *tests* and in the measurements
than in the code, and the patterns are worth carrying rather than rediscovering.

**The most productive question came from outside the roadmap.** "What is missing
for this to be a daily driver on a Debian laptop?" found four config keys that
compiled and did nothing, a DHCPv4 fallback that obtained a lease and configured
nothing at all, netcfgd overwriting a working `/etc/resolv.conf` with an empty
one, dhcpcd's own hooks fighting netcfgd for that same file, and up hooks running
on every reconcile against the brief's own words. Not one of those was on any
list, and no gate was red for any of them. **Ask what an operator hits, not what
the milestone says next** — and when the answer is a list, take it one item at a
time with a decision record each, because six of the ten items found a defect
older than the work itself. The tenth is the cleanest example of why the list is
worth finishing rather than skimming: it was written down as a test gap — "the
dhcpcd script has never been run by dhcpcd, and a machine with the package would
close this in one run" — and running it found that the client could not be
stopped at all.

**Asking the kernel beat reading the previous session's table.** 0057 wrote down
seven measurements and told the next session to ask again; asking corrected two of
them and turned up the question nobody had asked at all — what happens to the
attributes a change request leaves out. Two of the answers would have shipped as
defects: a macvlan mode netcfgd would refuse to move, and a VXLAN whose endpoint
could never be corrected because the nest carried a port the kernel refuses to
see. The session after it found its own defect the same way — not from a test, but
from asking what *else* would fall into the safe direction of a new comparison,
which is how an interface existing as the wrong kind turned out to be invisible.

**A gate can be blind because its input does not contain its subject.** Past ten
instances now, across four sessions, and the disguise changes every time. The
plan-idempotence gate had never seen a document with a hook in it. A fixture
asserted a hook ran *after* the addressing, which list order gives for free. A
live carrier test plugged the cable in on an interface that already had its
address, so the ordering could not fail either way. An rfkill field said where a
value came from and was filled in from the variable the search *started* with. And
no test had ever passed a global option before a positional one, which is why two
copies of "which flags take a value" had drifted apart unnoticed. A check about a
thing has to contain the thing, with a value that is not the default. Its mirror
image turned up in the same run: `wifi add`'s rollback cannot be reached by *any*
input, every invalid block being refused earlier by name, so only a patch that
rendered the block without its closing brace could tell whether it worked. Where
input cannot reach a check, a patch can, and until one has, it is a comment.

**And the suite has been run as root**, in a privileged container, which is still
the only way three of the scripts run at all. All three pass. Getting there found
four defects, every one in the suite and three of them leaving a green run
behind: a build recipe that does not build, a preflight that failed where it
should skip, its repair which then skipped where it should run, and `hwsim.sh`
passing while leaving a root `netcfgd` and two supplicants alive. The socket
witness had the hole its own comment claimed to cover, too — three responses were
pinned by nothing anywhere, and all three lists now go through an exhaustive
match.

### What would prove it

The status line calls this a proof of concept. That is only meaningful with a
bar attached, or it never graduates — so this is the bar, and every entry is
something that has **never been done**, not something that failed.

**Passing the suite does not count**, and the reason is the whole point. 696
unit tests and 37 live scripts is a lot of evidence, and the live ones drive a
real dhcpcd, dnsmasq, hostapd, openvpn and wpa_supplicant. But the radio is
`mac80211_hwsim`, several daemons are fakes, and every run has been x86_64. The
tests are *disciplined* and not yet *validated against reality*, which is a
different property and the one this list is about.

- **Nobody has run netcfgd against a real radio.** Association is proven end to
  end against virtual radios; a real card, real drivers and real firmware have
  never been tried. `docs/first-run.md` says so at the top and calls step 5 the
  least proven thing in it.
- **Nobody has used it as their machine's network configuration.** Not a day, on
  hardware they depend on, with the failure modes that only appear when a
  machine moves between networks.
- **It has never run on the class of device it was designed for.** The design's
  §10 wants an OpenWrt-class device and §10.2 budgets `netcfgd-embedded` at
  ≤ 1 MB; the install measures 2.3 MB, and there is no cross-compile target in
  the `Makefile` at all, so mips and arm have not merely failed, they have not
  been attempted. §10.2 already says what to make of that — those are
  "**budgets to validate, not measurements**" — which is this section's framing,
  written into the design before any code existed and then lost from the brief.
- **The modem path has never met hardware** — Next item 1, written entirely
  against a fake copied from libmbim's own output.
- **Suspend and resume have never been exercised**, per item 3, and it is the
  most-travelled path a laptop has.
- **systemd-networkd detection has never been run against systemd-networkd.**
  Written from its documented layout, unlike the NetworkManager path, which was
  checked against a running one.

Two things follow from this list, and both change what to work on.

**The bar and any future rewrite want the same work.** A rewrite is a
translation problem when the semantics are settled and the tests are accurate,
and a design problem when they are not — so every item here is simultaneously a
graduation criterion *and* the prerequisite for a rewrite ever being a safe
thing to attempt. There is no tension between proving this and refining it
later; there is a sequence, and this is the first half of it.

**The clients are the blocker, which is why item 5 outranks its number.** Every
entry above needs somebody living with netcfgd on real hardware, and today the
interface for that is `ncfg` plus a five-pane TUI, against a GUI that is a
three-tab viewer and a shim whose value assumes a NetworkManager applet the
operator does not have. **Nothing else on the list can start until the tools to
evaluate it exist.**

### Next, roughly in order

**This list is down to what is blocked, what was refused, and one thing nobody
has looked at.** Item 4 is closed in full, item 2 is half done and half refused
with a reason
([0077](docs/decisions/0077-a-type-leaves-generic-when-every-property-is-answerable.md)),
and item 1 has needed hardware since it was written. **Item 3 reopened**: every
defect on the laptop list is closed, and then suspend/resume was added to it —
the one entry that came from asking what a laptop does rather than from
something going wrong. It needs a real laptop, so it is blocked the way item 1
is, and unlike item 1 nothing has been written for it yet.

**Item 5 is the top of this list regardless of its number, and the only entry
not blocked on anything.** The clients are behind what already sits underneath
them, and the operator this was written for has no NetworkManager applet — so
the shim, which the roadmap treated as the desktop answer, is not the fallback
that reasoning assumed. It ranks first because *What would prove it* cannot
start without it: every remaining item on that bar needs somebody living with
netcfgd on real hardware, and the tools to do that are what item 5 is about.
**Build the clients, then evaluate, then refine.**

**Item 6 is the wall a first evaluation hits**, and it arrived from somebody
asking whether the thing was ready rather than from any gate: a default install
refuses its own client and misdiagnoses why.

**Item 7 is a feature that does not exist rather than work that stalled**, and
it is the first entry here to arrive from asking what a network daemon ought to
do rather than from a defect or a measurement: nothing in netcfgd ever asks
whether a link it prefers actually reaches anything.

Where the last six pieces came from instead, in order: **a live flake nobody had
chased to the end**, and then each fix exposing the next
([0109](docs/decisions/0109-a-daemon-that-does-not-answer-has-not-stopped.md)
through [0114](docs/decisions/0114-one-second-is-one-constant.md)) — a stop that
reported success without asking, an access point that could never be noticed
dead, a deadline that stalled the whole machine, a watcher talking to netcfgd's
own sockets, a contract that created the artefact it warns about, and a
dismissal written in a sentence that turned out to be wrong. Four of those six
were found by **re-reading something this document already said** and measuring
it rather than believing it. That is the seam worth working when the list is
empty: the notes that say what *would* happen, the reasons for a deferral, and
the sentence that disposes of an alternative in half a line.

1. **Run the modem path against a real modem.** Everything is written and
   nothing has met hardware: `helpers/netcfgd-modem-mbim` drives `mbimcli`
   against a fake whose output is copied from libmbim's own `g_print` calls.
   What no test can reach is a modem that does not behave — the 43 vendor
   plugins ModemManager carries are the measure of how common that is
   ([0043](docs/decisions/0043-mbim-is-ours-and-the-quirks-are-a-table.md)).
2. ~~**The shim's remaining device types, which have everything they need now.**~~
   **Half done, and the other half is refused with a reason**
   ([0077](docs/decisions/0077-a-type-leaves-generic-when-every-property-is-answerable.md)).
   A **VLAN** is a `.Device.Vlan` now: libnm asks for four properties and netcfgd
   observes all four, the id and the parent only because 0059 and 0060 needed them
   for the planner — constraint 6 in the direction it is meant to run, with no
   model change. An **IP tunnel stays `GENERIC`**: libnm asks for thirteen and
   netcfgd observes eight, with no encapsulation limit, flags, flow label, fwmark,
   path-MTU-discovery bit or TOS anywhere in the observation *or* the document.
   The item above was written from what netcfgd happens to observe rather than
   from what libnm asks for, which is the lesson: **a type leaves `Generic` when
   *every* property on the interface is answerable, not the ones somebody listed.**

3. **What a laptop still wants, in the order it will bite.** Settled so far: the
   four inert config keys (0061), rfkill (0062), the `down` and `post_down` hooks
   (0063), the `lease` hook (0064), DHCPv4 with busybox (0065), a lease's
   nameservers and search suffixes (0066, 0067), the `carrier` hook (0068) and
   joining a network without an editor (0069), an enterprise network from the
   command line (0087) and the rfkill event stream (0093). **What is left is one item, and it is the
   first that was never a defect report**: every entry below it is closed, ten of
   the fifteen found a defect older than the work itself, and suspend/resume is
   here because somebody asked what a laptop does that this tree has never
   simulated — not because anything went wrong:

   - ~~**dhcpcd's generated script has never been run by dhcpcd**~~ — **closed**
     ([0070](docs/decisions/0070-a-client-is-stopped-the-way-it-was-started.md)),
     and it took one run on a machine with the package, as predicted. What it found
     was not in the script: **netcfgd could not stop a dhcpcd at all**, because the
     pid file carries the family and the stop did not name it. `tests/live/dhcpcd.sh`
     drives a real one now.
   - ~~**A DHCPv6 client is not stopped at all**~~ — **closed**
     ([0071](docs/decisions/0071-a-client-with-no-socket-is-stopped-by-the-pid-it-wrote.md)).
     dhcpcd takes `-6 -k`, the family being 0070's rule with a parameter; odhcp6c
     has no socket and no `-k`, so it is told where to write its pid and stopped by
     it, sharing udhcpc's one function rather than a second copy of it.
     `delegation.sh`'s teardown used to be `pkill -f odhcp6c` and a truncated
     prefix file — the test doing the two things netcfgd could not — and is an edit
     to the document now.
   - ~~**dhcpcd's own hooks still write `/etc/resolv.conf` from a DHCPv6 lease**~~
     — **closed**
     ([0072](docs/decisions/0072-dhcpcds-own-hooks-are-replaced-or-silenced.md)),
     and measured before it was fixed: a real dnsmasq, a real `dhcpcd -6`, and
     `nameserver 2001:db8:44::53` in the file netcfgd owns. The v6 client is
     *silenced* (`-C resolv.conf -C hostname`) rather than given netcfgd's script,
     because the report is one file per interface and two clients on one interface
     would clobber each other's `dns=` lines on every renewal. ~~What a v6 lease
     says about names therefore still reaches nothing~~ — **closed**
     ([0086](docs/decisions/0086-two-clients-on-one-interface-need-two-files.md)),
     and the fragment directory that record named is what it took. `reported/` is
     still one file per interface and still the documented contract, with one
     writer by construction; `reported.d/<interface>/<source>` is where netcfgd's
     *own* generated writers go, because netcfgd starting a second client on one
     interface is a situation only netcfgd creates. **A v6-only network resolved
     nothing at all** until this — dnsmasq sent it, dhcpcd received it, and the
     hook that would have used it was the one 0072 silenced. It also deleted
     `DhcpcdHooks`: with the v6 client given a script, nothing constructs
     `Silence`, so every dhcpcd netcfgd starts gets `-c` and there is no argument
     for one that does not.
   - ~~**One hook phase still does not fire**~~ — **every phase fires**
     ([0096](docs/decisions/0096-taking-an-interface-down-is-more-than-one-moment.md)).
     `pre_down` was the last, and building it found that the fix was bigger than
     a hook: netcfgd's plan for disabling an interface was `link.down` alone, and
     `link.down` **flushes IPv6 and leaves IPv4 behind**, so a disabled interface
     kept a stale address netcfgd still recorded as its own — in one family and
     not the other. The teardown a `pre_down` hook needs and the fix for that
     address are one change. `portal` was the one before
     ([0095](docs/decisions/0095-a-portal-check-fetches-the-operators-url.md)),
     which also closed the last of 0061's inert keys: `portal_check` is an
     operator's `http://` URL rather than a boolean, netcfgd has no default,
     and `https` is **refused** because a portal detects by intercepting and
     TLS exists to stop interception — an `https` probe reports no portal on
     exactly the networks it is for, which is 0061's own example corrected. `roam` was
     the third and now fires
     ([0091](docs/decisions/0091-a-roam-is-something-the-supplicant-tells-netcfgd.md)),
     from a watcher thread attached to each radio's control socket. **Push, not
     poll, and that was worth re-checking rather than inheriting**: netcfgd asks
     a station nothing during an observation, so the alternative meant a
     `STATUS` round trip per radio on every netlink event — and it could still
     miss a station that moved and moved back between two of them. Unlike
     `drift` it is *not* de-duplicated: drift is a condition that persists and a
     roam is a thing that happened, so a station that moved back and forth
     moved twice.
     `drift` was the fourth and now fires
     ([0084](docs/decisions/0084-the-drift-hook-fires-where-nothing-is-applied.md)),
     and it is the only one of the eleven that is **not a plan action**: under
     `on_drift = "report"` netcfgd applies nothing, so a planned hook would never
     run and the policy whose entire purpose is "tell me, do not touch it" would
     tell nobody. It fires from the daemon at detection, once per drift rather
     than once per netlink event — measured, because without that guard three
     unrelated link add/deletes turn one hook run into seven.
     `up` was the fifth and fires
     ([0076](docs/decisions/0076-the-up-hook-is-the-moment-a-link-is-live-and-bare.md)):
     the one moment where the link is live and nothing is addressed, which is
     what `pre_up` cannot see and `post_up` is too late for. 0063's machinery for
     reporting a phase that *cannot* fire stays, and the test that a config using
     all eleven draws no warning now fails if a twelfth is added unwired.
   - ~~**`ncfg secret set NAME` does not exist**~~ — **closed**
     ([0075](docs/decisions/0075-a-secret-is-stored-by-a-command-that-never-shows-it.md)).
     The value is never an argument, never echoed, and the file is 0600 from the
     moment it exists; an existing secret is refused rather than replaced unless
     `--replace` says so, because one of the things it stores is the key 0042
     calls irrecoverable. It also says which blocks refer to the name, which is
     what turns a typo into a sentence instead of a backend failing an hour later.
     0069's prompt *moved* rather than being written twice, and the two
     diagnostics that pointed elsewhere now point at the command — which is what
     the item was really about. **Nothing forgets a network** either: `rm` on the
     file is the whole of it, and an `ncfg wifi forget` would take the secret with
     it the way the shim's delete path does.
   - ~~**An enterprise network cannot be added from the command line.**~~ —
     **closed**
     ([0087](docs/decisions/0087-an-enterprise-network-is-a-form-and-a-flag-list-can-hold-it.md)).
     "A form and not a flag list" was the right diagnosis and the wrong
     conclusion: the form part is that *which* fields are needed depends on the
     method, and that is expressible as refusals — TLS presents a certificate,
     the other three present a password, and every method needs an identity.
     The prompt follows the method too, because a PEAP password typed into a
     prompt saying "passphrase" is a network that never joins. What it found is
     the better half: **netcfgd could not configure an EAP network that pinned
     no CA certificate**, because the compiler pushed a `Diagnostic` — the only
     severity it has, and fatal — under a comment reading "Not an error". 0017
     had rejected exactly that behaviour and 0008's model has `ca_cert :
     string?`. It is a plan warning now. `dot1x` on a wired port is still an
     editor job, and is a smaller one: no SSID, no priority, no hidden flag.
   - ~~**`accept_ra` is unmanaged**~~ — **closed**
     ([0073](docs/decisions/0073-a-document-that-asks-for-slaac-makes-the-kernel-listen.md)).
     The kernel's default means "accept unless this interface forwards", so
     `config = "slaac"` on a router's WAN — or in a container, which usually
     forwards — obtained no address while the apply reported success. netcfgd
     writes `2` where an advertisement would otherwise be ignored, nowhere else,
     and hands it back only where it wrote it. `tests/live/slaac.sh` drives a real
     advertisement from a real dnsmasq.
   - ~~**Nothing reads `/dev/rfkill`'s event stream**~~ — **closed**
     ([0093](docs/decisions/0093-a-switch-being-flipped-is-not-something-to-wait-for.md)),
     and this was the last item on the laptop list. *Blocking* a radio usually
     takes the interface down, so netlink reported it; **unblocking** one
     produced nothing at all until something else happened, so a machine could
     sit with a working radio and a plan still saying it was off. A watcher
     reports `KernelChanged` — the same answer netlink gets, because what
     changed is something an observation already reads. Read-only
     structurally: the write path on that device blocks every radio, and not
     opening for writing is how 0062's "report, do not overrule" stays a
     property of the code.

4. ~~**The "is it still what the document says?" question has one open corner
   left.**~~ **Closed — every corner of it has an answer now.** Daemons, kernel objects, secrets, unread files and now *whether the
   process is there at all*
   ([0078](docs/decisions/0078-a-record-is-a-memory-and-a-process-is-a-fact.md))
   all have an answer. Twice this list has predicted the next one and been wrong —
   0053 guessed at a backend netcfgd did not start, and the answer was a WireGuard
   device it creates itself; then the question turned out not to be about
   configuration at all, but about a pid. What is genuinely left:
   - ~~**a supplicant and an access point are not liveness-checked**~~ — the
     supplicant is, in both senses: alive
     ([0080](docs/decisions/0080-a-socket-outlives-the-process-that-bound-it.md))
     and **answering**
     ([0098](docs/decisions/0098-a-supplicant-that-bound-its-socket-and-stopped-answering.md)).
     0085 recorded the second as "a real piece of work rather than a line", and
     re-measuring rather than believing that is what closed it: `connect_within`
     already pings inside the connect with the deadline as a parameter, and
     `netcfgd-observe` already depends on a backend crate for exactly this shape
     of question. A wedged supplicant has a live pid, a socket on disk, and looks
     from every other angle exactly like one that has not associated yet. The
     first half
     ([0080](docs/decisions/0080-a-socket-outlives-the-process-that-bound-it.md)):
     `-P` gives it a pid file, and that turned up a second defect hiding behind
     the first — the *start* path also treated the socket as proof, so a plan that
     had correctly decided to start one found the dead supplicant's socket and did
     nothing. ~~**hostapd is deliberately left out**~~ — **closed**
     ([0110](docs/decisions/0110-an-access-point-that-died-stayed-running-forever.md)).
     The reason it was left out — nothing here could run it, because `ap.sh`'s
     hostapd never starts on a dummy and a real radio needs `hwsim.sh` and real
     root — was true when 0080 wrote it and stopped being true when 0109 needed
     a fake hostapd in a particular state and produced one with a signal. An
     access point was the **one backend netcfgd could never notice had died**:
     `running` came from the record, `backend_pid_file` had no arm for it, so
     nothing ever contradicted the record. A hostapd that crashed stayed
     `running: true` for as long as netcfgd was up, the planner had nothing to
     do, and 0079's restart could not fire. It takes `-P` now, the fake takes a
     `--pidfile` to match, and `acl.sh` kills one with `SIGKILL` so that every
     artefact says it is there except the pid;
   - ~~**a daemon that is alive and wedged still counts as running**~~ — **closed**
     ([0085](docs/decisions/0085-a-daemon-that-does-not-answer-is-not-running-well.md)),
     and it was not a missing check. netcfgd has asked hostapd for its station
     lists on every observation since 0052, under a one-second deadline, and
     **threw the failed round trip away** — the answer was computed every time
     and `running: true` went on the socket over the top of it. `answering` is
     an `Option<bool>` beside `running`, separate for 0078's reason: one is a
     fact about a process and the other is a fact about behaviour. It is a
     warning and deliberately **not a restart** — netcfgd cannot tell a wedged
     daemon from a slow one, and `acl.sh` has already seen a *healthy* fake miss
     that deadline under load, so acting on the reading would take working
     access points off the air on busy machines. Supplicants answer it too
     ([0098](docs/decisions/0098-a-supplicant-that-bound-its-socket-and-stopped-answering.md)),
     and each kind that gains a round trip gains its own noun in the warning in
     the same change — "the backend on wlan0" is the least useful true thing
     available on a machine running both;
   - ~~**restarting is unconditional**~~ — **closed in the same session, because
     it was a live defect rather than a future concern**
     ([0079](docs/decisions/0079-netcfgd-stops-restarting-what-will-not-stay-up.md)).
     Measured rather than reasoned about: a daemon that lived half a second, on an
     interface set to `reconcile`, went from 1 start in twelve seconds before 0078
     to **181** after it. netcfgd tries five times and then stops and says so. What
     it deliberately does *not* stop is a daemon that comes up and dies later —
     each of those is a real event and restarting is the right answer.
   - **Suspend and resume have never been designed for or run.** Closing the lid
     is the most-exercised path a laptop has and the only item here that arrived
     by *asking what was missing* rather than by a defect: nothing in the tree
     mentions suspend or hibernate at all, the only `resume` in it is a partial
     plan being re-run, there is no test, and no record says it was considered
     and dismissed. **Absence of a finding here is absence of looking, not
     evidence of working.**

     Much of what it needs exists by construction, which is why this is a
     verification item rather than a feature. A resume brings the link down and
     up, so netlink reports it; the loop has a five-second backstop for anything
     netlink does not say; the rfkill watcher catches the hardware block many
     laptops apply across a suspend; and the confirm window is an absolute
     `deadline_epoch` in `/run/confirm.json` rather than a monotonic timer, so it
     keeps running while the machine is asleep instead of freezing — the trap a
     `CLOCK_MONOTONIC` deadline would have walked into, since that clock does not
     advance across a suspend and `CLOCK_BOOTTIME` is the one that does.

     What that same design does next has not been decided. A window armed before
     an eight-hour suspend is long expired on resume, so the first observation
     after the lid opens **reverts a change the operator has been living with all
     night** — defensible, since unconfirmed means revert, and surprising enough
     that it should be a decision rather than a consequence. Wall-clock also means
     the resume-time NTP correction a laptop usually takes can move the deadline
     under a window that is still open.

     Worth measuring specifically, in the order it will bite: whether a lease that
     expired during the suspend is renewed or silently stale; whether the
     supplicant is still associated and, if not, how long netcfgd takes to notice;
     whether the rfkill watcher's blocking read survives the suspend or returns an
     error nothing handles; and what the confirm window does across the lid.
     `tests/live/` cannot suspend a machine, so the first three want a real laptop.

     ~~The fourth was a unit test on a clock somebody moves~~ — **done**, and it
     needed a seam before it needed a test. `expired` and `remaining` read
     `SystemTime::now()` *inside* the comparison, so neither "the machine slept
     through the window" nor "something moved the clock" could be expressed at
     all; `expired_at` and `remaining_at` take the clock as an argument and the
     original two delegate. **The unreachable case, not the unimportant one** —
     which is worth remembering the next time a gap looks like nobody caring.
     The window closes across a sleep, and the wall-clock cost is pinned beside
     it: stepped back an hour, a window with 60 seconds left has an hour and a
     minute. Neither is asserted to be *right*, because that is the decision
     above that nobody has made.

5. **The three UIs, and the one of them that is a prototype.** Two gaps found by
   building the tree rather than reading it, and one correction to who the
   clients are *for*.

   - **The GUI is far behind its own client library.** `gui/` builds cleanly
     (`cd gui && make` against Qt 6) and offered **three tabs — devices, plan,
     events — and three actions: `device`, `up`, `down`**, while `client/`
     underneath it already implemented apply, confirm, revert, plan-of, monitor,
     tiers and hello. The window was never blocked on plumbing, so the cheapest
     real progress is spending what is already there.

     **A wifi tab is the first of that spent** — scan, join, disconnect, and a
     radio's current state, in the TUI's vocabulary so that the two clients name
     one thing once. The wireless half of `client/` did not exist either and was
     written with it: the C library had no wifi call at all, only the generic
     request, so the models went below the seam where 0116 and `gui/project.md`
     section 3 both say they belong. **Which links are radios moved down with
     them**, because "is this a radio" is not a visual question — though it is
     now the same heuristic in two languages, which is exactly the drift 0116
     names and does not yet fix.

     What it still cannot do is **add** a network, and that is a boundary rather
     than a gap: the socket has no request for it, because 0013 puts joining a
     known network in the `wifi` tier and 0069 makes adding one *writing a file*.
     So no passphrase is entered and none can be read back (0029, 0031), and an
     access point with no `network` block is listed, greyed, and given no join
     button rather than a refusal after the fact.

     **And this is the blocker for daily-driving, with a real decision under
     it.** `ncfg wifi add` writes `conf.d/wifi-<id>.conf` at 0644 and a secret
     at 0600 into the config directory, which is root's. A GUI running as the
     desktop user cannot do that, and the socket deliberately offers no way to
     ask the daemon to. So an operator can join networks somebody already wrote
     config for and no others -- which on a laptop means every new café needs a
     terminal. The options are not obviously ranked and each gives something
     up: a privileged helper (a polkit-shaped dependency constraint 3 avoids),
     an `admin`-tier socket request that writes config (making the daemon an
     editor of its own authority, against constraint 1), or the shim's route,
     where a privileged adapter already accepts exactly this from a desktop
     ([0030](docs/decisions/0030-a-gui-is-an-editor-of-config-files.md)) and
     netcfgd's own GUI would be the odd one out. **Settled in
     [0117](docs/decisions/0117-adding-a-network-is-a-typed-request-not-a-written-file.md)**:
     an `admin`-tier `wifi_add` carrying typed fields, never config text and
     never a path, because a config file may name a hook whose `run_as`
     defaults to root — so the cheapest option, a group-writable config
     directory, is group-writable root code execution and the obvious answer is
     the one that quietly grants the most. **Built**, with the renderer, the
     paths, the id validation and the compile-it-back check moved to
     `netcfgd_host::wifi_profile` so there is one writer.

     The move immediately justified itself. The round-trip check compared the
     enterprise fields one by one; a first pass at sharing it kept only "a
     network with this id exists", and the test whose own comment says breaking
     that comparison leaves every other test green is what caught the loss.
     Validation lives **inside** the writer rather than in its callers, because
     with a socket request the caller is a remote client and an id is joined
     onto a directory twice. Driven against a real daemon: a network written
     with an `@secret:` reference and the credential at 0600, a duplicate
     refused, and `../../../tmp/pwned` refused with nothing written.

     ~~**What is left is the clients.**~~ **Done.** `ncfg_client_wifi_add` takes a
     typed `ncfg_network_t` and is the only call in that library carrying a
     secret -- it wipes its request buffer through a volatile pointer, because a
     plain `memset` to a local about to leave scope is a write a compiler may
     drop. The GUI's dialog opens from a selected scan row, so the SSID is the
     exact octets the radio saw rather than something retyped: a network whose
     name does not render as text is precisely the one somebody types wrongly.
     The passphrase field is `Password` echo and is cleared before the dialog
     closes, and `add` is offered only for a row with no `network` block --
     the mirror of `join`, which is offered only for a row that has one.

     Driven against a real daemon: a secured network written with `@secret:` and
     its credential at 0600, an open network written with **no secret file at
     all**, a duplicate refused by name, and an SSID of `cafe\0` keeping its hex
     because the label cannot carry the trailing NUL.
   - ~~**M8's tray applet does not exist.**~~ — **written**, and it is the one
     thing a GUI gives that `ncfg` and `ncfg tui` structurally cannot: an
     answer to "am I on the network" costing no window and no command, on a
     desktop that has no NetworkManager applet to fall back to. State at a
     glance, disconnect, show, quit. **It does not scan** -- a scan blocks for
     seconds and transmits probe requests, and doing that because somebody
     opened a menu would be wrong twice -- and it offers nothing needing the
     admin tier, because a menu is the wrong place to change a machine without
     showing the plan first. Absent tray, `create()` returns nothing and the
     window behaves as it always did; `--tray` on a desktop without one
     complains on stderr and shows the window, which is the daemon's own
     convention rather than a modal that blocks startup on the machines least
     likely to have somebody in front of them. The icon is painted rather than
     shipped, so the tree still has no image assets.

     **Unverified: the icon itself.** It compiles, the no-tray path runs
     against a real daemon, and the `--tray`-without-a-tray path was measured.
     Nothing here has a status-notifier host, so the menu, the refresh and the
     disconnect have never been drawn or clicked. That wants the same laptop
     the rest of *What would prove it* wants.
   - **The shim is not the fallback it was assumed to be.** The reasoning that
     tier 1 and 2 cover a desktop assumes the operator *has* an NM applet, and
     this one does not — the current tool is `nmtui`. So **`ncfg tui` is the
     surface that matters**, `netcfgd-nm` is worth much less than its
     completeness suggests, and 0036's ceiling means no NM client will ever drive
     a VPN, a modem or an access point anyway. Weight the native clients
     accordingly.

   **Design them against `fuzzypickles`, which has the same three apps and
   solved the layering.** Its `cli/`, `tui/` and `gui/` all sit on one C
   `client/`, and its `tui/Makefile` states the rule outright: *"Deliberately
   thin: everything non-visual lives in client/, shared with the others."*
   netcfgd has the same four directories and does **not** follow that rule --
   `ncfg` and `ncfg tui` are Rust inside `crates/netcfgd-cli`, and only the GUI
   uses the C `client/`. **Two implementations of one socket protocol**, which is
   the shape that produced [0082](docs/decisions/0082-one-operation-has-one-name.md)
   and [0083](docs/decisions/0083-the-tag-is-the-name.md) when a plan and a
   journal disagreed about what an op was called, and the shape section 10
   already records under *two lists of the same thing have already drifted*.

   What is **not** settled, and is a decision rather than a task: the Rust CLI
   shares `netcfgd-model` and `netcfgd-proto` as types, which a C client cannot,
   and constraint 7 wants `ncfg plan` in the smallest build. Rewriting `ncfg` in
   C to match the sibling would trade a real property for symmetry. The
   harmonisation worth having may be the *shape* -- three thin apps, one
   vocabulary, nothing non-visual in a view -- with both clients pinned against
   `docs/schema/socket.json`, which is the witness that already catches this
   class of drift. **Raise it before building it**: this is a cross-project
   design question, and `harmonization.md` is explicit that extracting or
   aligning shared technology is its own deliberate piece of work rather than
   something done while in one repo. **`make conformance` is the first half of
   the prerequisite 0116 names** — it diffs what the two clients extract from
   one witness, so the vocabulary they share is checked rather than promised.
   The protocol *specification* is still missing, and remains what a third
   implementation would need. **Settled in
   [0116](docs/decisions/0116-a-client-that-needs-the-model-is-rust.md)**: the
   shape harmonises, the language does not, and the dividing line is the model
   — `ncfg` needs the compiler and planner locally so constraint 7 keeps it
   Rust, while `ncfg tui` is a pure socket client and a *new* socket-only client
   should prefer C over `client/`. The TUI is deliberately not moved.

6. **A default install refuses its own client, and says the wrong thing about
   why.** Every tier defaults to root
   ([0013](docs/decisions/0013-three-things-a-caller-may-be-allowed-to-do.md)),
   the socket's mode follows the policy, so a desktop user opening the GUI is
   refused — and was told `Permission denied. Is the daemon running?`, which
   sends them to `systemctl` and the journal for something that is in a config
   file. **The diagnostic is fixed** in both clients, and the Rust one had the
   sentence written four times, three of them terse: one diagnostic in four
   places is one that is right in at most one of them, and this was wrong in all
   four for the case that matters.

   **What to do about the wall itself is
   [0118](docs/decisions/0118-two-ways-to-be-allowed-and-one-of-them-is-visible.md),
   decided and unbuilt.** Two ways to be allowed: a reserved group the packages
   create empty, and an administrator mode in the client on KDE 3.5's pattern —
   read-only until the operator authenticates as root, **surrounded by a red
   frame while it is live**, editing the `control` block and nothing else. The
   frame is the argument: polkit prompts per action and leaves nothing on screen
   saying whether you are privileged *now*, and a mode is a thing you can look
   at. It does not contradict 0117's refusal of a privileged helper, because
   that refusal rested on `wifi_add` being strictly better — and you cannot ask
   the daemon for permission to ask the daemon, so the option that lost on merit
   there wins here on necessity.

7. **An uplink is chosen by carrier, and nothing ever asks whether it works.**
   netcfgd has **no reachability probe and no probe-driven failover**, and this
   is a gap rather than a decision — no record refuses it, and the words
   `failover`, `mwan` and `dead gateway` appear nowhere in the tree. The only
   `ping` in it is `wpa_supplicant`'s control-socket `PING`, which asks whether
   a *daemon* is answering, not whether a *route* works.

   What exists is adjacent and is not this. **`preference` ranks uplinks and
   switches on carrier**, which is what a laptop wants when a cable is unplugged
   and useless when the cable is plugged into a switch that has lost its own
   uplink — the carrier is up, the link is dead, and netcfgd keeps preferring it.
   **`portal_check`** fetches a URL **once**, when the interface becomes
   addressed, and fires the `portal` hook; it is captive-portal detection, not a
   repeating health check, and its result feeds a hook rather than the planner.
   Hooks are **outputs**: an `on carrier` hook can run `curl` today and has no
   way to tell the reconciler what it learned. That missing direction is the
   feature.

   It earns its place on the constraints rather than despite them. Constraint 9
   asks whether something is common real-world networking, and dual-WAN failover
   is one of the most-installed things on an OpenWrt box; constraint 6 asks
   whether a local operator would want it in their own file, and "use the cable,
   but fall back to LTE when it stops reaching anything" is exactly that. It
   needs no new dependency: netcfgd already runs as root and already executes
   hook programs, so an arbitrary checker — `ping`, `curl`, `wget`, a script —
   costs nothing the hook runner does not already pay.

   **The shape that fits this architecture: a probe result is an observation,
   never desired state.** The config says what to prefer and under what
   condition; the probe outcome joins observed state beside carrier and address;
   the planner does what it already does with a difference between the two. That
   keeps §2's determinism intact — the *document* stays byte-identical from the
   same config, and only the observation moves — and it means `ncfg plan` can
   explain a failover in the same sentences it uses for everything else, which
   is the product.

   Four things to get right, and they are where every implementation of this is
   wrong first:

   - **Hysteresis is the feature, not a refinement.** A probe-driven failover
     that flaps is worse than none, because it moves the default route under
     live connections. It needs consecutive-failure and consecutive-success
     counts and a hold-down, and those belong in the config where an operator
     can see them, not as constants.
   - **A reachability probe is the opposite of `portal_check`, and conflating
     them is a bug.** [0095](docs/decisions/0095-a-portal-check-fetches-the-operators-url.md)
     makes portal detection plain `http://` **because** a portal intercepts and
     TLS prevents exactly that. A reachability probe wants the opposite
     guarantee — that it reached the real destination — so it wants TLS, or a
     known response, or both. Two questions that look alike and want contrary
     transports.
   - **It changes the route the operator may be connected through**, which is
     the hazard commit-confirm exists for, except netcfgd initiates it. Whether
     an automatic failover arms a window, and what reverting one would even
     mean while the probe still fails, is a decision to make before the code.
   - **An exit status is the contract.** `ping`, `curl -f` and a custom script
     already agree that zero means reachable, which is why an arbitrary program
     works here at all -- and it is the same shape as `HookRef`, so the probe
     should be a reference with a hash and a timeout rather than an inline
     command line (§2.2).

Longer-range direction is in [0036](docs/decisions/0036-the-shim-is-not-the-roadmap.md) and governed by constraint 9: VPN's second half (ipsec, where strongswan and libreswan disagree about nearly everything), complete wifi as configuration surface over `wpa_supplicant`/`hostapd`, teaming stays dropped in favour of bonding, Open vSwitch is out, and SNMP switch management is a fleet-tree concern rather than a single-host one. [0115](docs/decisions/0115-the-way-back-in-is-not-ours-to-configure.md) closes the other half of that question and one next to it: serving SNMP is refused because M9 already picks RESTCONF as the northbound answer, and **IPMI is refused because a BMC is the way back into a machine you have locked yourself out of** — netcfgd cannot tell a BMC setting it made from one the BIOS screen made, and a bad change to the way back in survives the reboot that would otherwise undo it. It passes constraints 3, 6 and 9, which is why it needed a record rather than a sentence.

### Things that are true and non-obvious

- **A warm-up that runs before the thing it warms is not a warm-up.** `acl.sh` sent one round trip nobody read, at the end of `start_fake` — which runs before `seed_run_state`, so netcfgd did not yet believe an access point was running, never read an ACL, and never touched the fake. It missed the one moment it existed for, the Python interpreter's first reply. Moving it after the run state was not enough either: the configuration is written later still, and a plan with no configuration says so and reads nothing. It waits for [0085](docs/decisions/0085-a-daemon-that-does-not-answer-is-not-running-well.md)'s warning to stop being true now, which is netcfgd itself reporting that the read succeeded inside the real one-second deadline. **A readiness check should assert readiness, not perform an action and hope.**
- **`ncfg apply` returns when netcfgd has sent a command, not when the other end has logged it.** Checks that read a fake's log immediately after an apply are reading a file the fake has not reached yet, which is a race that only opens under load. The assertions that a command *did* arrive wait for it; the ones that it did **not** must never wait, because there is nothing to wait for and the wait would cost its full bound on every run.
- **A reason not to do something has a shelf life, and nothing tells you when it expires.** 0080 left hostapd out of the pid-file liveness check and said why: nothing in the tree could produce a hostapd in a state worth checking. That was true, and it stopped being true the moment [0109](docs/decisions/0109-a-daemon-that-does-not-answer-has-not-stopped.md) needed a hostapd that was running and silent and made one by signalling the fake. Neither change knew about the other, and the item sat on the list reading "deliberately left out" with a reason that had quietly become false — while **an access point was the one backend netcfgd could never notice had died** ([0110](docs/decisions/0110-an-access-point-that-died-stayed-running-forever.md)). A deferral is worth re-reading rather than re-trusting, and the trigger is not a schedule: it is any change to the thing the reason was about.
- **A readiness wait that does not clear its marker can match the previous run's output.** `acl.sh` launched its fake with `> fake.log` and waited for `ready` to appear there — but the redirect is opened by the *child*, after the fork, while the wait runs in the parent, so the first `grep` can match the **previous** fake's `ready` and return before the new process has run a line. Harmless for as long as nothing downstream needed the new process to have done startup work; the moment it wrote a pid file, three runs in eight failed and the failure moved from check to check depending on which section lost the race. **And the instrumentation kept curing it** — every diagnostic cost a few milliseconds of startup and the failure vanished, six and eight clean runs against three in five without. A bug that disappears when watched is telling you it is about *when*, which is worth reading as a clue rather than answering with a bigger sample.
- **A dismissal in a sentence is a claim — the third time, and the tell has not changed.** 0112's sweep disposed of two remaining callers in half a line: "`ncfg wifi` is an operator's command where a scan legitimately takes that long, and `populate_supplicant` talks to a supplicant it has just started." The second half was reasoning. `populate_supplicant` runs inside `start_backend` on the apply path, and "just started" only proves the supplicant answered *one* `PING` — measured against a fake that answered it and then nothing, **every command after the connect timed out at ten seconds flat**. Against a real `wpa_supplicant` those same commands answer in **0.07–0.13ms**, four orders of magnitude inside a one-second deadline, so there is no busy supplicant the shorter one can fail ([0114](docs/decisions/0114-one-second-is-one-constant.md)). After 0079 and 0111 the tell is unmistakable: **a claim about what would happen, written in the calm voice of something already checked.**
- **A break that leaves the behaviour intact reads exactly like a test that cannot fail.** Verifying the gate above, the first break — setting the client's `timeout` field back to the default — did not turn it red, and the honest reading was not "the test is weak" but "the break missed". The blocking is `recv` honouring the socket's *read timeout*; `self.timeout` governs only the deadline that skips unsolicited events. Two mechanisms, one of which looks like the one that matters. Breaking `set_read_timeout` fails it with `waited 10.120029335s`. **When a break comes back green, suspect the break before the gate.**
- **A contract can create the artefact it warns about.** `docs/interface-report.md` tells every writer to stage the file in the report directory and `rename(2)` it over the target, "because netcfgd may read at any moment and a half-written file is a file it will believe" — and the same directory is not negotiable, since a rename is atomic only within one filesystem. So the contract *requires* the half-written file to sit in the directory netcfgd reads, then never said what to call it, and the reader took every entry as an interface name. Measured: a report for an interface called `.eth0.tmp.1234` carrying a nameserver out of a file still being written. **netcfgd's own four generated writers staged at `<report>.tmp`**, so the product created the artefact its own reader misread, on every lease renewal. A leading dot now, and readers skip anything dotted — a `.tmp` suffix rule would have silently dropped the report of a VLAN legitimately named `eth0.tmp`, which is the same defect pointing the other way ([0113](docs/decisions/0113-the-file-the-contract-hides-is-in-the-directory-it-reads.md)). **The document described what writers must do and never described what netcfgd would then see.**
- **A fixture being right is not the product being right.** `report.sh` had staged its report under a leading dot since it was written, with a comment quoting the contract — while the writers netcfgd generates did not. A test more careful than the code it exercises never fails: it is testing its own good manners. The window it politely closed is the one the product left open on every machine.
- **A directory listing is an interface, and this one had no schema.** The roam watcher rescans `wpa_supplicant`'s control directory for radios it is not yet attached to, and took **every entry** as an interface name. Not every entry is one: a datagram client has nowhere to be replied to unless it binds an address of its own, and netcfgd binds it *in that same directory* — so the daemon's own in-flight connections sit in the listing beside the supplicants. Connecting to one blocks for the whole timeout, because the far end is a live process that is not a server (measured: three `PING`s in twenty-five seconds, one per timeout, forever) — and **the `PING` is delivered into that client's reply queue**, where it is not an event, so `request` can hand it back as the answer to a command it really sent. Everything else netcfgd reads has a shape it checks; a `read_dir` looks like it needs none ([0112](docs/decisions/0112-not-everything-in-the-control-directory-is-a-radio.md)).
- **Break the gate and read *which* assertion fires.** Twice in two days a gate passed while testing nothing: `start_fake`'s warm-up matched the previous fake's `ready` (0110), and a unit test whose subject was never constructed — `connect_within` checks the remote exists *before* it binds, so with no server socket there was no reply socket to observe and the loop over what was seen ran zero times. Both looked exactly like passing tests. What catches this is not reading the test, it is breaking the thing it guards and checking that the failure message names the property you meant.
- **An open note is a claim, and claims get measured — this is the second time.** 0109 ended with a paragraph explaining why a stop's ten-second timeout was being left alone: true about the design, right about the precedent, and wrong in the one clause that could have been checked in ten minutes ("so it does not hold the reconcile loop"). It does. A failed stop is retried on the next reconcile, and the reconcile loop is what runs it — so with a wedged access point recorded, **pulling the cable took 12.2 seconds to switch to wifi against 106ms with nothing wedged**, the carrier event sitting behind a `PING` in a stop for an unrelated interface. That is the stall 0085 measured at 10.2s on the ACL read and cured with a deadline; the read got one and the stop kept a default sized for `SCAN_RESULTS`. One second now, both stops, 3.0s wedged ([0111](docs/decisions/0111-a-stop-is-not-a-scan.md)). Same shape as 0079's "a backoff needs state that needs a home", and **the tell is the same both times: a note that says what *would* be needed rather than what is happening now.**
- **A daemon that does not answer has not stopped, and netcfgd said it had.** The flake above did not go away entirely: one run in ten still failed the check that stopping an access point asks hostapd to `TERMINATE`, with the apply reporting `ok backend.stop` and the fake's log holding six bytes -- `ready`, and nothing sent to it. Producing the state deliberately rather than waiting for load to produce it (`SIGSTOP` on the fake: a hostapd that is running, has its socket bound, and does not answer) made it deterministic and showed three wrongs at once. **The operator is told the access point stopped while it is still on the air**, `ncfg apply` exits 0, and **the run state comes back with no backend in it**, so nothing will ever try again. One line: `Err(_) => Ok(())`, under a comment justifying it that is true and does not cover it -- "nothing listening" is about a socket that is *not there*, and `connect` opens with a `PING`, so a wedged daemon fails there rather than at `TERMINATE`. Absence and silence are separate answers now, decided by one function shared with the identical shape in the supplicant stop, and a failed stop is fail-stop -- which leaves the backend recorded, so a re-run retries ([0109](docs/decisions/0109-a-daemon-that-does-not-answer-has-not-stopped.md)). **When a race is a state rather than a timing, produce the state**: saturating twelve cores gave one failure in ten and a log that could be read two ways; `SIGSTOP` gave it every time in eleven seconds with nothing to interpret.
- **"The apply did not converge" was the wrong reading, and the diagnostic that produced it was taken at the wrong moment.** `acl.sh` under heavy load looked like netcfgd failing to apply an `access_control` action; the wedged-daemon warning was absent, which seemed to rule out the one-second ACL deadline. It did not: the warning was sampled *after* the failure, by which time the fake had warmed up and was answering. The real cause was a section that restarts the fake and goes straight into a measured apply **without any `write_config`** — so a warm-up attached to `write_config` never ran there, and the coldest process in the script was the one nobody warmed. Warming after `seed_run_state` as well took it from five failures in eight to one. **A diagnostic taken after the fact describes the state afterwards, which is not the state that failed.**
- **A trap that kills a daemon and then removes its directory races the process it just signalled.** The daemon writes a pid file, a socket or a log on the way out, `rm -rf` reports "Directory not empty", and **a non-zero exit from a trap fails the whole run with every check above it passed** — a verdict line saying "all checks passed" immediately above `make: *** Error 1`. It stopped `make live` from three different scripts and on *both* distributions, so it is not busybox's rm being fussy. Every cleanup that signals something now retries the removal for five seconds and says so if the directory outlives that. Swept by pattern across 23 scripts rather than one at a time, because the ones not yet bitten are the point.
- **The absence of a message can be the evidence, and an extractor that only looks forward throws it away.** A failing suite run reported `expected: eth-lan, actual:` with nothing — and the informative part was that **no timeout diagnostic appeared above it**, which proved the wait had *succeeded* and the check's own second read caught a gap while the daemon reinstalled the routes. The container harness was showing only the lines after a `FAIL`; it keeps the whole log now. **Wait-then-assert samples twice**: collapse them so the wait reports its own outcome and there is no second read to disagree with the first.
- **A counter-proof has a premise, and a machine can falsify it.** `dhcpcd.sh` runs dhcpcd without netcfgd's silencing to show its hooks would otherwise rewrite the resolver file — but `20-resolv.conf` opens with *"Support resolvconf(8) if available"* and hands off when one exists, writing nothing. So the check reported an untouched file as though netcfgd's silencing had failed. It passed with dhcpcd alone and failed with the suite's full package set, which pulls in **openresolv**: deterministic both times, and read as a flake until the package owning `/usr/sbin/resolvconf` was looked up. Both counter-proofs check their premise now.
- **A test with one implementation of its scenery is testing that implementation too, and does not say so.** `dhcp.sh`'s DHCP server was `busybox udhcpd`, which pushes every configured option whether the client asked or not. Adding dnsmasq as a fallback -- for an unrelated reason, to let the script run on Alpine -- cost four checks and exposed the cause: **busybox `udhcpc` does not request option 119, and netcfgd passed no `-O`**, so against any server that honours the request list the search suffixes never arrived. Option 15 is in the default list, so a single domain always did, which is what made it look like it worked. Nothing was wrong with the code that reads a search list or the code that delivers it; the gap was in what netcfgd asked the network for ([0108](docs/decisions/0108-the-client-never-asked-for-the-search-list.md)). Third instance of this shape, after `tunnel.sh` against openvpn 2.7 and the fake supplicant against 0080.
- **Targeted sampling beats whole-suite sampling by two orders of magnitude, and can exonerate an operation.** A once-seen failure in `nm.sh`'s static-profile checks would have taken hours to chase at ~30 seconds a run and 44 clean runs already spent. Hammering the one operation inside a single run -- 60 add-and-delete cycles per run -- gave samples at a hundred times the rate. **660 of them: 240 quiet; 240 with every core three to four times oversubscribed and netcfgd re-reading its configuration ~1850 times per run; and 180 under sustained disk writeback of 80-140 GB per run with tmpfs churn beneath it. None failed.** Combined with reading the handler -- `AddConnection` calls `store::write` synchronously, before it replies, so there is no queue race to have -- that is enough to say the operation is sound and stop, rather than inventing a fix for a mechanism nobody has seen. **A negative result needs its conditions proved too**: the first hostile run reported nothing but a clean count, which is what a run whose load never started also reports -- so the load average, the completed reload count, the megabytes written and the `MemAvailable` low-water mark are printed beside the verdict. Worth knowing before repeating it: `/tmp` here is tmpfs, so pressure on the directory the test writes to is *memory* pressure and not disk, and the two have to be applied separately.
- **One action that always fails silently skips every action ordered after it, including unrelated ones.** Execution stops at the first failure by design (section 4), and `nm.sh`'s fixture guarantees a failure: the `Prompted` network references a secret that does not exist, because the secret-agent tests need it to. `dns.apply` is ordered after `backend.start radio0`, so the global nameservers were never delivered and a panel correctly showed none -- presenting as three unrelated panel checks failing together, about two runs in ten. Section 4 also gives the remedy it was not using: the remainder is re-runnable, and one further `ncfg apply` delivered it every time, where ten seconds of waiting never did. **A test that asserts on what was applied has to establish that it was applied.**
- **A test double that stops running is invisible to every gate this project has.** `fake_agent.py` was left referring to a function deleted in the same commit, raising `NameError` before it registered, and `make check`, `make style` and `make adapters` all passed -- none of them runs a live script. The live run that would have caught it had been done before the cleanup rather than after. This is `build-and-commit.md`'s "never conclude a test passes from a build step that did not run it", in the form where the thing that did not run is a fixture rather than a test binary.
- **You cannot ask the caller a question while it waits for your answer.** The NM shim asks a secret agent for a passphrase from inside `ActivateConnection`, before returning — and nmcli registers a secret agent of its own for `connection up`. When the shim asked *that* one, nmcli could not answer until the call it was blocked on returned, and that call was waiting for the answer. A circular wait unwinding at GDBus's 25-second default, intermittent because it depended on which agent the list yielded first. Real NetworkManager avoids it structurally: it returns the active-connection path first and asks during the asynchronous activation, by which time the caller is free ([0107](docs/decisions/0107-you-cannot-ask-the-caller-a-question.md)).
- **A stall that stops happening when you add a `println` needs a recording that costs no syscall.** Two guesses at this bug were wrong, and the second could not even be tested: `eprintln!` checkpoints in the handler produced eighteen clean runs against something that had reproduced twice in four. An in-memory ring — monotonic timestamp plus `&'static str`, dumped afterwards by a watchdog thread — did not perturb it, and localised the wait to a single line on the fifth run. **Prove the instrument before trusting it**: an injected eleven-second sleep showed the watchdog firing and the gap appearing where the sleep was.
- **A guard set to the same number as the thing it guards will hide it.** `nm.sh` wrapped an activation in `timeout 25`; GDBus's default method-reply timeout is also 25 seconds. Two timers racing, and when the guard won it killed nmcli and destroyed the only output worth reading — so an intermittent failure presented as "the test's timeout fired" rather than "the shim never answered". Moved off that number, the slow case says what it is: nmcli printed nothing but a version warning and the agent's log stops at `registered`, so `ActivateConnection` returned no reply at all and the agent was never asked for a secret ([0106](docs/decisions/0106-two-twenty-five-second-timers-racing.md)). A stall, not slowness — raising a timeout cannot fix a reply that never comes.
- **The shim asks an agent for a secret from inside a D-Bus method handler**, which is the re-entrancy hazard its own job queue exists to avoid for registering objects and emitting signals. The secret bridge (0031) makes a third call of that shape without going through it, and an intermittent no-reply unwinding exactly at the default timeout is what that looks like from outside. Diagnosed, not yet fixed.
- **sysfs is not filtered by network namespace unless it is remounted, so `/sys/class/net` lies inside `unshare -rn`.** It still lists the *host's* interfaces, while netlink — which is namespaced — does not: `/sys/class/net/wlp0s20f3` exists and `ip link show wlp0s20f3` fails, in the same shell. `rfkill.sh` discovered its radio by walking `/sys/class/net/*/phy80211/name`, so inside a namespace it found a radio that is not there and then failed because netcfgd, observing through netlink, correctly reported no such interface. **Discovery that must agree with netcfgd has to ask what netcfgd asks.** The Makefile runs that script bare and says why; the failure only appears when somebody runs it under `unshare -rn` anyway, and reads as a broken feature rather than a wrong invocation.
- **A flaky test cannot be bisected one run at a time, and will happily produce a narrative.** Two single-run passes over `nm.sh`'s history produced a confident, detailed, wrong story — a named culprit commit and a "gradual erosion" across forty commits — and every number in it was real. Sampling five runs per commit gave a different answer: **one** commit, consistently seven failures, its parent consistently clean. The remedy is not care, it is sampling; the wrong version was produced while being careful.
- **A test double is a claim about the real component, and nothing enforces it stays true.** [0080](docs/decisions/0080-a-socket-outlives-the-process-that-bound-it.md) correctly stopped treating a control socket as proof a supplicant is running — the proof is a pid file whose own path appears in the process's command line. `fake_supplicant.py` offered a socket and nothing else, so netcfgd rightly decided nothing was running and started a **real** `wpa_supplicant`, which bound the same socket and answered scans from a radio that does not exist. Seven wireless checks read blank for as long as 0080 has been in the tree ([0105](docs/decisions/0105-a-fake-that-stopped-being-believable.md)).
- **`TERM` is unset in every container and most CI runners, and a pty test that inherits it fails fourteen ways for no reason of its own.** `tui.py` opens a pty it controls and decodes xterm's sequences by hand, then handed the child whatever `TERM` the caller happened to have. On a desk that is `xterm` and everything works; in a container ncurses cannot initialise at all. The terminal a test emulates is a property of the test — it sets `TERM=xterm` itself now. Found by running the full suite in a container for the first time, which is also the only way it could have been found.
- **A daemon watching the config directory reconciles alongside your explicit apply, and a test that then changes kernel state by hand is racing it.** `qdisc.sh` sets a foreign qdisc to prove netcfgd leaves it alone, while the daemon still had a reset pending from the previous config change — planned when netcfgd *did* own that qdisc, and correct when planned. Landing late, it wipes the foreign one and the check reports netcfgd resetting somebody else's queueing. Seen once in a full `make live`, not reproducible in twelve standalone runs across two machines. The setup establishes its precondition by retrying now, rather than assuming it; a sleep would only have made it likely.
- **A requirement quoted without its scope is a requirement invented.** Design §10.4 reads *"target < 4 MB RSS steady-state **for nano**"*, and [0021](docs/decisions/0021-no-nano-tier.md) dropped the nano tier — a qualifier three words long, in the same sentence, which survived being copied into a Makefile comment, two decision records and this file in a single session. The measurement was correct every time; nobody checked what the number was *for*. `size-budget.txt` had carried exactly that distinction since M5 and the RSS gate had not.
- **RSS is mostly somebody else's text, and which C library you use moves it by a third.** netcfgd peaks at ~4.2 MB on glibc and **~2.9 MB on musl** — the platform the size posture targets and the one the apk ships — for the same work. `RssAnon`, what netcfgd actually allocated, is ~520 kB against ~205 kB: glibc's allocator arenas are most of that difference. Pss is little over half of VmHWM either way, because the rest is text shared with every process on the machine. A footprint gate that prints one number invites the reading that number cannot support, so `make rss` prints three and pins the pessimistic one ([0104](docs/decisions/0104-the-four-megabytes-belonged-to-a-tier-that-was-dropped.md)).
- **A check can assert a fact about the machine while reading as a fact about the code.** `ppp.sh` demanded that pppd fail with a message naming `/dev/ppp` — true where the device is out of reach, which is an ordinary desk. Where it *is* present, real root or the privileged container this suite is meant to run in, pppd parses netcfgd's whole options file and **accepts it, exiting 0** — and the check called that a failure. Green on the machine in front of you, red wherever the thing under test is actually available: the third instance of that shape in one session, after `tunnel.sh` and `openvpn.sh`. The script now says which world it is in and asserts the stronger thing where it can ([0103](docs/decisions/0103-a-check-that-asserted-the-machine-rather-than-the-code.md)).
- **"0 failed" is not "all checks passed", and `set -e` is how they diverge.** Capturing pppd's exit status meant dropping the `|| true` that had swallowed it — and `set -e` then killed the script at that very line, in exactly the branch being added. The run reported zero failures having run almost none of the checks. `|| status=$?` is the shape; the lesson is that a summary counting failures cannot distinguish a clean run from an aborted one, so it has to look for the pass line.
- **How a live script must be invoked is knowledge that lived only in the Makefile, and a uniform sweep gets three of them wrong.** Most scripts run under `unshare -rn`; `slaac.sh`, `dhcpcd.sh` and `pppoe-session.sh` are invoked bare because they make their own namespaces — `unshare -rn` writes `deny` to `/proc/self/setgroups`, and dnsmasq and dhcpcd then cannot drop privileges. Wrapped, `slaac.sh` reported *"the router did not start"* and was written up as a failing feature on two distributions. It passes. The two that care now **detect** the case and skip with the reason, so the next uniform sweep is told rather than misled. A script that only works when invoked a particular way should say so when it is not.
- **A test fixture can have a deprecation clock on it, and nothing in the repository ticks.** `tunnel.sh`'s `.ovpn` used a pre-shared static key because that brings a tunnel up with no peer at all — the cheapest route to the moment netcfgd cares about. openvpn 2.7 refuses to start on such a configuration and 2.8 removes the mode, so on Alpine, which already ships 2.7, the only test driving a *real* openvpn failed 18 of 22 checks. Nothing in netcfgd changed and nothing would have warned: a fixture the upstream tool has stopped accepting is a test on its way to covering nothing, and it gets there by itself ([0102](docs/decisions/0102-a-test-fixture-with-a-deprecation-deadline.md)).
- **Both ends of a tunnel in one namespace makes the far endpoint a *local* address, and the kernel will not route via its own.** Giving the test's new far end the matching half of the point-to-point pair — which is what a real deployment looks like — produced `route.add ... via 10.8.0.2: Invalid argument (os error 22)` on six checks. The peer address was simultaneously on the far end's own interface. Nothing is sent through this tunnel, so the two ends are free to disagree about addressing, and putting the far end on a different subnet fixes it. **The control is what identified it**: those six looked like netcfgd defects until the original fixture was run on the same image and passed.
- **A fake on `PATH` fakes nothing if the code searches `sbin` first.** `openvpn.sh` exists so the daemon does not have to be installed: it copies a fake to `$work/bin/openvpn` and prepends it. netcfgd looks in `/usr/sbin`, `/sbin`, `/usr/local/sbin` and `/usr/bin` *before* `PATH` — correctly, since sbin is not on a non-root `PATH` — so on any machine with openvpn installed netcfgd ran the real daemon and **20 of the script's 45 checks failed**. Reproduced on Debian and Alpine alike; it was green here only because this machine lacks the package. The same disease as `tunnel.sh`'s, with the polarity reversed and therefore worse: `tunnel.sh` *skips* without the package, while this one never skips and simply reports the wrong thing. The other fakes are unaffected because they bind a control socket rather than replace a program ([0101](docs/decisions/0101-a-fake-on-path-does-not-fake-what-netcfgd-finds-in-sbin.md)).
- **A gate can be passed on its tolerance for a year, four kilobytes at a time.** `make size` was at 2.41% of a 3% band with 13 KB left, and no single feature had overspent — the linker pads to 4 KB pages, so a change smaller than a page is invisible to it and several hide inside one until they cross together. Five separate pieces of work landed in **+0 bytes** measured. Re-baselining meant building the release binary at six points across twenty-eight commits, because attributing drift by guess is how a budget file becomes fiction.
- **`kill -0` calls a zombie alive, and a zombie is what every daemon a test stops becomes when pid 1 does not reap.** A container's pid 1 is whatever the image was told to run, and a shell never reaps — so `openvpn.sh` reported netcfgd leaving a daemon behind on Alpine while netcfgd was right: its own check reads `/proc/<pid>/cmdline`, which a zombie does not have, so it is correct by construction. Seven scripts used `kill -0` and `delegation.sh` had already reasoned this out for itself without anybody sweeping the rest. **The direction that was found is the harmless one**: four scripts assert a process is *gone*, where a zombie is a loud false failure. Three assert one is *alive* — including "netcfgd left somebody else's pppd alone" — and there a zombie is a silent false pass on exactly what the check exists to catch, on any machine, no container needed ([0100](docs/decisions/0100-kill-0-calls-a-zombie-alive.md)).
- **A suite failing on a new platform reads like a port, and was a test bug.** netcfgd builds on musl and its 696 unit tests and 23 live scripts pass on Alpine under busybox `ash`. Not one line of the daemon changed. The way to tell the two apart was to run the same container with `docker run --init`: a reaping pid 1 turned five failures into five passes, which said the subject was never musl.
- **A redirection's failure is the shell's, and `2>/dev/null` on the command does not catch it.** `[ -n "$(tr -d '\0' < /proc/$pid/cmdline 2>/dev/null)" ]` prints `cannot open ...: No such file` from the shell itself when the process is gone — into the middle of a test's output. `cat "$f" 2>/dev/null | tr ...` does not. The working version already existed one file away and this copied the idea rather than the line.
- **A package that builds is not a package that works, and every metadata gate passes on one that installs to the wrong prefix.** Both the deb and the apk were installed and exercised in a clean container of their own distribution — binaries run, `ncfg plan` on an empty config says so rather than failing, the daemon starts and answers its socket, a real config produces a real plan, removal leaves the operator's configuration alone. The first Debian run failed usefully, on `libncursesw6` being absent: the *derived* `Depends` catching the exact trap this file already records for bare containers. It also exposed a defect in the test rather than the package — `dpkg -i ... | tail` hides the exit status, so the fallback never ran.
- **A footprint gate on a debug binary measures debug metadata, not the footprint.** `make rss` pinned `target/debug/netcfgd`, where an *unused* dependency edge added to a crate moved peak RSS by ~190 KB — while the release build stayed byte-for-byte the same size and its RSS did not move at all (4307 vs 4315 KB). A 51 MB debug binary's resident set is dominated by layout. It measures the release binary now, which `size` already builds. Two lessons and the second is bigger: an A/B run in two batches drifts by as much as the effect, so **interleave the measurements**; and the number the debug figure had been hiding is that the release daemon peaks at ~4.2 MB on glibc — which was then mis-cited against §10.4's nano target, see below.
- **A guard whose removal changes no output is not tested by the output.** The observation asks only a supplicant its record says is running; deleting that guard fails nothing, because the planner skips a stopped backend whatever the field holds. The cost is invisible and real — a round trip per pass to a process netcfgd believes is gone, which a socket outliving its process could even answer. The live check was named "is not asked, and not named" and verified the second half only. Where a guard exists to stop *work* rather than to change an answer, the gate has to look at the work: it counts the requests that reached the other process now.
- **A sentinel return value is a guard at every call site, and call sites do not all remember.** `push` returns `u32::MAX` for an action it declines to emit, under a comment saying nothing downstream can depend on it. Six of thirteen sites checked; seven fed the sentinel into one of five accumulators that all end up as somebody's `depends_on`, and two of those are reachable from a nine-line config — a guarded bridge member left the bridge's `link.up` and `addr.add` waiting on action **4294967295**. Downstream, `restrict` dropped both and said `needs action 4294967295, which belongs to another interface`, a sentence with two false claims in it. **Where the same check must happen at every call site, put it where the value is minted** — and treat a comment asserting a property as a claim to verify, not a statement of fact.
- **"Who reads this field?" is worth asking of anything the schema pins.** `depends_on` is in `plan.json`, in every client, and in 29 fixture assertions — and the *executor* does not read it: actions run in list order and stop at the first failure. One code path acts on it. A field can be pinned, documented, asserted on and structurally load-bearing in exactly one place nobody was looking at, which is where its defect will be. The question came out of a break that correctly passed, not out of a gate.
- **`ip link set dev down` flushes IPv6 and leaves IPv4 behind, so "the kernel cleans up" is true in one family and not the other.** netcfgd's whole plan for disabling an interface was `link.down`, which looks complete on a v6 machine and leaves a stale `10.x` address on a v4 one — an address netcfgd had installed and still recorded as its own, with nothing left to remove it. The asymmetry is real kernel behaviour and it was found by running the command and looking, while going to build something else entirely. **Where the kernel tidies up after you, check that it does so in every family**, or the daemon's idea of what it owns depends on which one the operator wrote.
- **An ordering assertion that reads positions in a list is not testing the dependency that produces them.** Actions execute in list order, so a fixture checking that `down` comes after `addr.del` passes on emission order alone — deleting the `depends_on` edge changes no position and no assertion can see it. The break that removed the edge came back **green** on a test written specifically for the ordering. §9 already says an unasserted edge is decoration; the lesson the break added is that a *positional* assertion looks exactly like an assertion on the edge and is not one. Assert the edge by name: this action's `depends_on` contains that action's id, and the phase before it does not.
- **Every interface that is up has a link-local, so "has an address" is true from the moment the link exists.** The portal check fires on an interface *becoming* addressed, and the first version asked whether it had any address at all -- which `fe80::` makes true immediately and permanently. The feature therefore fired once, at startup, and never again on any real machine, and it survived its first live run because the first probe is the one that works. **A transition test needs a condition that can actually go back**, and connectivity is not "has an address": it is having one that could reach something.
- **A config key can be compiled, carried, pinned in the witness, documented, and read by nothing.** `globals.confirm_default` was all five. `global { confirm = 90 }` produced a document field that no code path consulted, so an operator who wrote it believing every apply had a safety net had none -- silently, and with the key listed in project.md's own config surface as though it worked. 0061 closed four of these by reading the DSL against the code; this one was found by going to fix something else and asking where the number lived. **Being in the schema is not being read**, and the witness cannot tell the difference: it pins the shape of a field, not that anything consults it.
- **"Read what you know and ignore the rest" describes a record, not a stream, and the difference is a shift bug on a newer kernel.** `/dev/rfkill`'s header says the record may grow, which reads as an invitation to buffer bytes and cut them every eight. It is not: the kernel dequeues **one event per read** and copies as much of it as you asked for, so a generous buffer gets exactly one record and the surplus of a longer one belongs to that read. The stream reading would have kept the ninth byte and shifted every following event — visible only on kernels newer than the one it was written against. Opening the device and printing what came back settled it in a minute; the header could not have.
- **A probe that reads the first widget of a kind reads whichever was constructed first, which is rarely the one meant.** A headless check asked whether the devices table had caught up and read `findChildren<QTableWidget*>().first()` -- which is the *plan* pane's notes table, built earlier and empty on a converged machine. It reported "the window did not change" for a window that had changed correctly, and the obvious next move would have been to debug working code. Select a widget by something only it has: a header, an object name, a title.
- **"Not allowed" is the wrong guess when the answer is "could not tell".** A client asking an older daemon which control tiers it holds gets no answer, and the instinct is to grant nothing — which greys out every button against a daemon that would have permitted everything. The refusal path produces a sentence naming the tier that was needed and what to change; a disabled button produces silence. Where a permission check cannot be made, the failure that *explains itself* is the safer one, and that is not always the restrictive one.
- **A fake that refuses what the real thing accepts hides a defect in the fake, and the test that should catch it can pass by looking early.** `fake_supplicant.py` fails anything it does not model — deliberately, so an unmodelled command cannot look like success — and it did not model `ATTACH`. netcfgd attached, was refused, dropped the connection and reconnected on every pass, forever. The check counted one `ATTACH` and **passed**, because it looked before a second had happened. It asserts exactly one at the start *and* at the end now, which is the difference between "it attached" and "it attached and stayed". A count against a loop needs a second look later, or it is a check on timing.
- **A test that was already failing turns a break sweep into noise that reads like evidence.** One of three breaks looked like it caught two tests; the second had been red before any patch was applied, because a fixture helper's first argument is the SSID and the assertion wanted the id. Every break in the sweep then "caught" it. The real signal survived, but only by luck of the other failure being the right one — a sweep has to start from green, and each break should fail *one* test and be checked for which.
- **"Is there anything to do?" cannot be read off the action list once a refusal can be consented to.** A guard refusal usually means the plan has *no* actions -- the guard stops the ones it covers -- so a plan whose only content is a refusal has an empty action list. The GUI read "nothing to do" off that and disabled Apply on exactly the plan consent exists for (0088). Found by a headless probe that ticks a box and clicks a button; the headless run that already existed proves the window opens, which is a different claim entirely. **When a screen gains a way to act on something, re-check every emptiness test near it.**
- **A break that does not compile is not a break, and a harness grepping for `FAILED` calls it a pass.** §9 already warns that a break which silently fails to *apply* reads like a gate that works. This is the same disease one step later: the patch applied, `cargo test` failed to build, no line said `FAILED`, and the sweep reported the gate holding. A break harness has to treat a build failure as "not a break" — and the same run found the gap the break was aimed at, which is that a refusal was tested by calling the function that makes it rather than the command that reaches it. **A refusal nobody reaches is not a refusal.**
- **A comment can be exactly wrong about the code it sits on, and the code can contradict a decision record.** `// Not an error, because plenty of real deployments pin nothing` sat above a `Diagnostic` in a compiler whose only severity is fatal — so an EAP network that pinned no CA did not compile, which 0017 had rejected in as many words and 0008's model contradicted with `ca_cert : string?`. Three places agreed and the code was the fourth. Nothing was red, because no gate reads prose and no gate compares code against decisions. When a comment states a *property* ("not an error", "this is only advisory"), check that the mechanism has that property at all.
- **A negative assertion against the wrong file passes whatever the code does.** Two live checks in this session were written against the *system* `/etc/resolv.conf`, where netcfgd writes `$NCFG_RUN_DIR`'s copy. The positive one failed honestly and was found in a minute; the negative one — "netcfgd does not write this nameserver" — passed, and would have passed for a netcfgd that wrote it enthusiastically to its own file. A check that something did **not** happen is only as good as its aim, and it gives no sign when the aim is wrong. Both now name netcfgd's file with a comment saying why.
- **A stated gap with a shape is still a gap.** 0072 ended with "which is now a stated gap with a shape (a fragment directory) rather than an accident", and that sentence is accurate and reads like closure. What it was describing is a machine on a v6-only network resolving nothing. The same tone problem 0078's note had, and worth the same treatment: when a record names the fix, the fix is a piece of work, not a footnote.
- **A question already being asked, whose answer is discarded, looks exactly like a question nobody asks.** Section 10 carried "a daemon that is alive and wedged still counts as running" as work needing a new check. There was no new check: netcfgd had been asking hostapd something on every observation since 0052, under a deadline, and the failure branch was a `continue` with a comment explaining — correctly — why saying nothing about the *list* is honest. It was silent about the *daemon*, and nothing distinguished the two. The whole change is two assignments. Before building a check, grep for the round trip that would already have the answer.
- **An explanation of why a line is load-bearing, above a line that is not, is a gate that cannot fail.** The drift record was written to `/run` *and* into the in-memory observation, with a comment saying the second was necessary because the next check comes before the next `reobserve`. Breaking it changed nothing — `reobserve` reads the record back and does run first. The comment was wrong and confident, and the only reason anybody found out is that every part of the change was broken on purpose, including the parts that looked obviously right. The line went rather than the comment.
- **A break that correctly passes is a finding, not a failed break.** Renaming an op on the wire left the TUI's plan-pane test green, and that is right: the pane draws what the daemon sends, so pane and test moved together. "One operation has one name" is a different question and it fails one layer down, in `netcfgd-plan`. A break that does not fire is worth understanding before it is worth fixing -- the answer is either a blind gate or a gate whose subject is somewhere else, and the two look identical until you say which.
- **A fixture written from a second reading of the type repeats the first reading's mistake.** The wifi pane read `entries` where the daemon sends `access_points`, and the test written to stop that happening again was itself written from `ScanReport` rather than from the witness. It could not have caught the bug it was named after. Where a test exists because a field name was got wrong, the fixture has to come from the wire, not from a fresh look at the struct.
- **Two witnesses can both be necessary and neither sufficient.** `socket.json` pins the `status` and `plan` envelopes with every list empty; `observed.json` and `plan.json` hold the content with no envelope. A test wanting a realistic answer has to compose them -- which is a guess about the protocol unless something checks it, so the composition is asserted against the pinned envelope member by member. Worth knowing before writing the fourth witness.
- **If one thing here is going to be re-learned, it is §9's.** Every corollary under "prove every new gate can fail" was paid for by a gate that was green while the thing it guarded was broken. The worst-shaped instance so far was a gate that did not exist at all, with a comment saying it did.
- **A column that renders two things the same way cannot tell them apart, and neither can a check reading it.** `nmcli`'s TYPE column prints a *generic* device's `TypeDescription`, and netcfgd's type description is the kernel's link kind — so "the tunnel shows as `wireguard`" passed with the device-type mapping deliberately broken, because a generic device whose description is the word `wireguard` renders identically to a real one. The repair is to assert a value only the real thing can produce: a listen port the document chose, and the type as a *number* rather than as a rendered column.
- **A script that skips on a missing package is a script whose failures nobody sees.** `tunnel.sh` had been red on every machine with openvpn installed since 0067 landed, and green everywhere else because it skips without the package -- so the suite said nothing. What it was asserting is that a pushed `dhcp-option DOMAIN` shows up as a *declined* comment in the report; 0067 made it a `search=` suffix, and neither the check nor the doc comment above the code followed. Both are the same disease in two media, and the second one is the reason to grep prose when behaviour changes. The bucket of scripts that skip on a package needs running *deliberately*, on a machine that has it, or it is a bucket of tests nobody is running.
- **A live script piped into `head` leaves its work directory behind.** `trap ... EXIT INT TERM` does not catch `SIGPIPE`, and a shell killed by one runs no EXIT trap — so `sh tests/live/hooks.sh | head -20`, which is how a person reads output, leaks the directory that a plain run cleans up. Found by counting `/tmp` after a session of doing exactly that. Not swept across the scripts: adding `PIPE` to each trap is a one-word change and a thirty-file diff, and the leak only bites an interactive reader. Worth knowing before blaming a script's trap for a directory you find.
- **A note in "what is still open" is worth measuring before it is believed.** 0078 ended with "restarting is unconditional… a backoff needs state that needs a home", which reads like a design task for later. Measuring it took ten minutes and turned it into a live defect: 181 starts in twelve seconds, introduced by the change that wrote the note. The note was accurate and its *tone* was wrong, which is the failure mode — an open question written calmly enough that the next reader files it rather than checking it.
- **A record of what you started is a memory, and it ages.** `running: true` came out of `/run` and was never checked against the machine, so every "is it still what the document says?" answer this project had built compared *configuration* — a file, a kernel object, a secret — and none of them asked whether the process was there at all. A `kill -9` on a tunnel left netcfgd reporting a converged network with nothing behind it. The check is two file reads; the reason it took four decisions to get to is that the record reads exactly like an observation at the call site.
- **"It has everything it needs" is a claim about the *other* side's interface, and only that side can settle it.** The shim's remaining device types were written down as ready because netcfgd observed the properties somebody had listed. Reading libnm's own accessors said four for a VLAN and thirteen for an IP tunnel, of which netcfgd answers eight — so one shipped and one is refused with the six missing names in a test. A capability list assembled from what you have, rather than from what the consumer asks for, is a list that will be wrong in the direction that flatters you.
- **`/sys` in an `unshare -rn` test is the host's, and the interface under test is not in it.** A hook reading `/sys/class/net/<iface>/carrier` got "No such file or directory" for a device that plainly existed — sysfs is a mount, the mount is the machine's, and only netlink is namespace-correct without `unshare -m`. Every live script here that asks about a link uses `ip`, which is why this had never come up.
- **A check that counts lines is not counting runs.** `grep -c '^pre_up '` said "the hook ran once" until the hook grew a second `echo`, and then said twice. Count one specific line — the transcript is a record of what happened, not of how often.
- **A cleanup whose pattern matches nothing is a cleanup nobody has.** `openvpn.sh`'s trap ran `pkill -f "$work/fake_openvpn"`, and the fake is installed at `$work/bin/openvpn` -- so it matched nothing on every run since the file was renamed, and the correct pattern was sitting five lines further down in the same file, used mid-script. Nine daemons were found alive on the machine, the oldest 21 hours old, each holding its `/tmp` directory open. Nothing was red: a leaked daemon is invisible to every gate here. Two things follow -- name the pattern once so the two uses cannot drift, and treat "did this `pkill` actually kill anything?" as a question worth asking, because `|| true` swallows the answer.
- **~~And one daemon in about every other `openvpn.sh` run is not stopped at all.~~ Closed** ([0074](docs/decisions/0074-a-daemon-that-cannot-answer-is-still-running.md)), and it *was* a netcfgd defect: `--daemon` returns as soon as openvpn forks, the child binds its management socket a moment later, and a stop arriving in that window found nothing listening and called the tunnel stopped. It would not reproduce on an idle machine — ten runs clean — so the window was opened deliberately instead, and then `ncfg apply` printed `ok backend.stop vpn0` beside a daemon that was still running, followed by `nothing to do` forever. netcfgd now passes `--writepid` and falls back to that pid when the socket does not answer. **Do not read "unreproducible" as "not real": every reproduction was on a loaded machine, and the way to settle it was to make the timing explicit rather than to wait for it again.**
- **A test that cleans up by category misses what is not in the category.** `hwsim.sh` killed everything in its network namespace, which is netcfgd and both supplicants and is not everything it started: the subshell a background job forks stays in the initial namespace, holds the script's stdout, and keeps a reader of that pipe waiting after the script has exited. The test passed and left a root netcfgd running. Kill what you started by the handle you were given, and treat an enumeration as the second answer rather than the only one.
- **Ask the kernel what it will take, one attribute at a time.** Three link kinds, three answers: a bridge takes its settings on a live bridge; a bond takes `miimon` and refuses `mode` with `ENOTEMPTY` while it has members; a VLAN accepts an id and silently ignores it. The middle one also refuses the *whole* `RTM_NEWLINK`, so an attribute the kernel will not take stops its neighbours in the same message being set. A planner that assumes "observed differs, therefore set it" produces an apply that fails and a plan that repeats forever — or, in the VLAN case, one that reports a change nobody made.
- **A units conversion is invisible to a pure test.** The bridge fixtures build an observation in *model* units, so the divide between the kernel's hundredths of a second and the document's seconds is not on their path — removing it leaves all 139 of them green while every bridge differs from itself by a factor of a hundred. Only `links.sh` sees it, because there the observation comes from a real dump. Where a value crosses a unit boundary, the test that matters is the one on the far side of the boundary.
- **A fixture that does not exercise a field cannot see a comparison break on it.** Four times in one session, in four disguises. The live WireGuard test asserted "an unchanged device plans nothing" — the right check — with peers that had no endpoint, so it could not notice that the comparison replaced the peer list on every reconcile for any peer that had one. The nmcli check asserted the right column with a value two different devices render identically into. And a zero the kernel spells as absent had to be written *in a document* before anything noticed the document's side kept it. When a check is about a field, the input set has to contain that field with a value that is not the default.
- **A limit can be an artefact of the question rather than of the world.** 0054 wrote down that a rotated WireGuard key could not be noticed without curve25519, and project.md carried it as work needing "a plan for where that arithmetic lives". Both were true about *deriving a public key* and neither was true about the question anyone actually had, which is whether the secret moved. The rewrite cost a digest and no dependency. Worth asking of any limit stated in terms of a technique rather than in terms of an answer.
- **An op can be declared, frozen and pinned without anything emitting it.** `wg.set_device` and `wg.set_peers` were in the action taxonomy, in the `Op` enum and in `docs/schema/plan.json` from M4, and the executor answered both with "not implemented in this build" — because no planner path had ever produced one. A witness proves an op's *shape*; nothing in the repository was asking whether an op is reachable. Worth suspecting wherever a taxonomy was written before the code that fills it.
- **A comment is falsified by the commit after it, and nothing goes red.** Four places in one session said an access point's passphrase, SSID or channel was not compared — written true, left standing when the next commit compared them, and sitting directly above the code that does. Every gate stayed green because no gate reads prose. The habit that catches it is the one §10 already asks for: when a session closes a gap it earlier wrote down, grep for the sentence that wrote it down, not only for the code.
- **A record that defers something needs a forward pointer when the deferral is lifted.** 0050 has one to 0051 and it works; 0047 and 0048 deferred work the same session then did and had none, so a reader landing on 0047 from `docs/interface-report.md` — which links there — was told the rename had not happened. The body stays as written, because a decision is changed by superseding it; the `Status` line is where the pointer goes.
- **A witness built on an exhaustive match catches an addition by failing to compile, and the assertion beside it does something else.** Two of these witnesses claimed the assertion caught "an arm written with no sample added"; it does not, because neither the sample list nor the expected-name list would mention the new name and the two would agree. Tried it, then corrected the comments — and then, a session later, found the same false claim still standing in two *inline* comments in the file the correction was made in, because "all three" had counted the doc comments and stopped. What the assertion catches is a sample that went away or a name that moved, and nothing in Rust can enumerate a variant without a value of it — so the gap is stated where it is rather than assumed away. Overstating a gate is the same disease as not having one: both leave somebody trusting a check that is not running, and a correction is worth grepping for rather than counting.
- **A real daemon in a namespace is reachable more often than it looks.** OpenVPN's static-key point-to-point mode has no handshake, so a tunnel is up the moment the `tun` device opens — no server, no certificates, no second process. That is what made every claim about `--route-up`'s environment measurable rather than inferred, and `unshare -rn` plus `/dev/net/tun` is all it needs. The trick reached further than expected: a veth pair *is* an ethernet segment, so `pppoe-server` on one end and netcfgd's `pppd` on the other is a real PPPoE session, and the whole of DSL is testable without a DSL line. What that needs beyond the tunnel case is real root, which a privileged container supplies as well as `sudo` does. **Reach for this before writing another fake** — the session found an unimplemented hang-up on its first run, and no fake would have.
- **~~An interface that exists as the wrong kind is not recreated, and nothing says so.~~ Closed** ([0059](docs/decisions/0059-an-interface-is-remade-when-the-kernel-will-not-change-it.md)), in the commit after the one that wrote it down. A document declaring `mixup` as a macvlan, against a `mixup` that already exists as a dummy, planned `link.up` and nothing else — netcfgd brought somebody else's device up and called the network configured. It shared its remedy with the VLAN id, which is why one session did both. What is worth keeping from it is the measurement habit that found it: the finding came from asking what *else* would fall into the safe direction of the new comparisons, not from a test.
- **A `depends_on` edge with no assertion on it is decoration.** Actions execute in list order, so a fixture checking that a hook comes *after* the addressing passes on emission order alone — deleting the dependency changed nothing any test could see. It asserts the edge now as well as the position. The live test was blind to the same thing for a different reason: it plugged the cable in on an interface that already had its address, so the ordering could not fail either way. Both found by breaking the code and watching nothing happen.
- **A doc edit that silently does not apply is a lie that survives review.** Two paragraph edits to project.md in this run asserted their anchor, failed, and wrote nothing — so the section claimed "four of the eleven phases fire" for two commits after it was six. `make check` does not read prose, and neither does a diff you did not look at. Verify a documentation edit the way a gate is verified: grep for the new sentence afterwards.
- **`all` on an empty list is true, and that is a warning nobody asked for.** The check for "this DNS delivery has no servers" fired on every document that manages no DNS at all, because the scope list was empty and `all` said yes. Two existing fixtures caught it — both of them asserting that a converged plan warns about nothing, which is a cheap assertion to have in a lot of tests.
- **A break that silently fails to apply reads exactly like a gate that works.** Two runs in this session proved nothing: one patch did not match the source and its script had no assertion, so it built the unmodified tree and reported "all checks passed"; another had its restore skipped by `set -e` and left the tree broken for the *next* break, which then failed for the wrong reason. A break script needs to assert that it changed something, and to restore whether or not the test passed — the same discipline as the gates it is checking.
- **A gate that has never seen its subject is not a gate.** The plan-idempotence check has run on every fixture for milestones, and not one of them had a hook in it — the single fixture that did called `plan` and `simulate` by hand. So the up hooks being emitted unconditionally, which made every converged plan non-empty, was invisible to the exact gate that exists to catch it. When a feature has one test, check whether that test goes through the harness the others do.
- **The hash on a hook can only fail where the compile and the run are separated in time.** `ncfg apply` materialises the script microseconds before running it, so it is checking a hash of a file it just wrote; the daemon re-materialises whenever the config changes. What is left is a plan built from a *kernel* change against a document compiled earlier — drift, which is what §2.2 said the hash was for. Nothing had ever tested it, and the first attempt could not, twice, for these two reasons.
- **A field that cannot disagree cannot be wrong.** The rfkill observation reports which switch the flags came from, and the first version filled that in from the phy name the *search started with* rather than from the entry it found — so a search that picked the wrong switch still reported the right name. Breaking the search on purpose left every test green. The fix is one line and the rule is general: a field whose job is to say where a value came from has to be read from there.
- **`read_dir` order is the filesystem's, and a test that depends on it proves nothing.** Deleting the "is this the phy's own switch?" check left the unit test passing, because the fixture's two switches came back in whichever order the directory happened to hold them. Sorting made the failure deterministic — and made the real read deterministic too, which is worth having on its own.
- **The config surface is a feature list nobody audits.** Four keys compiled and did nothing, and the way they were found was reading the DSL against the code rather than reading the roadmap — a question from outside ("what is missing for a laptop?") did what no gate does. Two of them were *silent*; the other two turned out to be compile errors, which is honest by accident and worth telling apart from the first kind. The `ethtool` block has named its own inert fields since it landed and has never confused anybody, which is the whole argument.
- **A doc comment can recommend a feature that does not exist.** `HookPhase::PreUp`'s documentation sent the reader to `Up` and `Carrier` for the things `pre_up` cannot do. Neither has ever been fired by anything. The same session found nine of eleven phases inert — parsed, materialised into `/run` with a hash, and never run, which is the most feature-shaped nothing in the tree.
- **The place to look for a defect is the half nobody asked about.** The parent was being read for the shim's sake and the question was whether the model may grow a field. Asking instead "what does netcfgd currently *do* with a parent" found that two kinds never sent one to the kernel, in a code path that had been green for years -- the `parent` in the document, the `parent` in the plan and the successful apply all agreed, and the kernel had no underlay. Constraint 6's discipline of finding a local reason before adding a field for an adapter is what pointed at it, which is an argument for the constraint beyond the one it was written for.
- **A break that hits two protections proves nothing about either.** Disabling the recreation pass's ownership check by replacing `if !link.ownership.may_remove() {` also disabled `teardown_links`', because the line is identical in both -- eight fixtures went red and none of them said which protection had gone. The re-run with a unique anchor failed exactly one. Section 9 already warns about a check that passes because of a *different* protection; this is the same disease in the break rather than in the check.
- **A fake that leaves a field blank makes a loop look like convergence.** The fixture harness's simulated `link.create` produced an empty link with the right name, so a remade VLAN came back with no id at all -- and the second plan found nothing to compare and called that agreement. Every comparison 0057 to 0059 added was invisible to the idempotence gate for the same reason. The fake now fills in what the kernel would report about the device it just made, with the fields the document does *not* state deliberately left absent, because that is also what the kernel does.
- **A reference tool can hide the kernel's behaviour by being helpful.** `ip link set tun0 type gre remote X` keeps the tunnel's key and local address, which looks like the kernel merging a partial update. It is not: `ip` reads the device and refills every field before it sends anything. Forty lines of python sending one raw attribute said the opposite, and the design turned on which answer was true. Section 9's advice is to prefer a reference tool over a fixture, and this is its limit — a reference tool answers "what does this command do", and sometimes the question is "what does the kernel do".
- **A guard whose condition is a comparison needs the case where both halves moved.** The geneve VNI is left out of a change nest because the kernel refuses a *changed* one — and restating the VNI it already has is accepted. So the first live test, which edited the remote alone, passed with the omission deliberately removed: the nest carried the VNI, at the value the kernel already had, and nothing failed. What made the gate real was editing the VNI *and* the remote in one go, which is also the only case an operator would notice. The neighbour of section 9's input-set rule: a check on a difference has to contain the difference.
- **`make live` is where defects are found**, not `make check`. Nearly every real bug in the last several milestones came from a real kernel or a real reference tool, and several came from a test that had been passing for the wrong reason.
- **`acl.sh` failed once, unreproduced, and the cause is a real property.** Two policy-change checks went red in one `make live` and have passed on every run since, including under deliberate load. They need netcfgd to have read a running access point's ACL, and that read has a one-second deadline *on purpose* -- a wedged hostapd must not stall the reconcile loop. A Python fake's first reply on a loaded machine can cost more than that, at which point netcfgd correctly converges nothing. The fix is a warm-up round trip before anything is measured, never a longer deadline: the deadline is the behaviour, and the same script measures it two checks later.
- **`switch.sh` has now failed twice, in two different ways, and neither reproduces.** The second was a five-second `settle_to` deadline expiring on `the wired uplink wins while it has carrier` during a full `make live`; seventeen standalone runs and a second full-suite run of the same binary passed. That is the shape `acl.sh`'s note already describes — a deadline that is generous on an idle machine and is not the behaviour under test — so the fix, if it returns, is a longer settle for the *test* and never a change to the daemon. The first was: the socket appearing does not mean the first apply has finished — the daemon binds before it converges — so the veth peers are not guaranteed to exist when a script that waited on the socket uses them. The window is real, smaller than a `fork`+`exec`, and has never been caught open. The wait added there is not claimed as the diagnosis; what it does is report the failure with the daemon log instead of a message about permissions.
- **Size and RSS both ratchet, and RSS is noisy.** See §6. Raising either is a deliberate, reviewable edit with a line saying what it bought.
- **An observation that asks another process needs its own deadline, and the deadline has to cover the connect.** Reading a running hostapd's ACL put a control-socket round trip in the reconcile loop, which runs on every netlink event. A hostapd that is *wedged* — alive, socket bound, not answering — held a single `ncfg plan` for 10.2 seconds; a one-second deadline brings it to 1.0. The first attempt shortened nothing, because `Client::connect` opens with a `PING` and a timeout set on the returned client never covers it. Measured both times rather than reasoned about, and `tests/live/acl.sh` now keeps it measured.
- **Reading the daemon you are integrating with beats reading its documentation, and `apt-get source` is how.** Three separate design errors in 0041 came from believing the wpa_ctrl documentation and `strings` output; all three were settled in twenty minutes by reading `hostapd/ctrl_iface.c`. This is the third feature in a row where the source answered a question the documentation got wrong.
- **Two lists of the same thing have already drifted.** The CLI parsed its arguments three times: `parse_options` knew which flags take a value, a `positional` helper had its *own* copy of that list, and `explain` used neither and took arguments up to the first `--`. The copy was missing `--factory-dir` and `--strand-credentials`, so `ncfg wifi --factory-dir /d scan` read the directory as a subcommand and `ncfg explain --json interface eth0` found no subject at all. Nothing was red, because no test passed a global option before a positional one. One walk returning both cannot disagree with itself — and where a second list is genuinely needed, the test to write is the one that iterates it and asserts the other half agrees.
- **A defensive check needs a break to be worth its lines.** `wifi add` compiles what it wrote and removes it if that fails, and no input reaches that path: every way an operator can make an invalid block is refused earlier, by name. Rendering the block without its closing brace is what proved the rollback works — the command quoted `unclosed block \`network\`` with the file and line, and left both directories empty. A check that cannot be reached by input can still be reached by a patch, and until it has been, it is a comment.
- **A prompt that echoes is invisible to every test that drives a pipe.** A pipe has no `ECHO` to clear, so a passphrase prompt reading standard input passes identically whether the code turns echo off or not. Only a pty can say, which is why the second python test in the tree exists — and turning echo off has a matching hazard the TUI already paid for once: a process killed between clearing and restoring hands back a shell with echo off.
- **A test that does not pin which implementation it drives tests whichever one the machine has.** `dhcp.sh` is about the busybox client and never said so: netcfgd prefers dhcpcd, so on any PATH containing sbin — a root shell, the privileged container — it drove dhcpcd instead, and under `unshare -rn` that meant the *entire script* failing at the first apply for a reason having nothing to do with what it tests. It passed for years because an ordinary user's PATH has no sbin. The daemon now gets the machine's PATH with every directory holding a dhcpcd removed, and the first attempt at that — a PATH with busybox alone on it — broke the generated script, which needs `ip`. Where a fallback chain exists, a test of one link has to make the others unreachable.
- **The address arriving is not the hook having run.** dhcpcd installs the address itself and calls its hook afterwards, so a test that waits for the address and then asserts on what the hook did is a race — this one lost one run in three, in the *counter-proof*, which is the half that fails visibly. The other half is where it would have been silent: the checks that netcfgd's hook did not set the hostname and did not touch `/etc/resolv.conf` are satisfied by a hook that has not run yet. Waiting until the hook has demonstrably done its one job — written the report — is what makes both of them mean something. Same family as `switch.sh`'s note that the socket appearing does not mean the first apply has finished.
- **A test that tidies up by hand is hiding whatever cannot tidy itself.** `delegation.sh` ended with `pkill -f odhcp6c` and `: > "$prefixes"`, then checked that netcfgd reacted correctly — to a world the test had arranged. Both of those lines were things netcfgd could not do, and one of them was a *failed apply*. The assertion after them was fine; the step before it was not netcfgd's. Where a teardown in a test is a command rather than a configuration change, ask what would happen if the operator did it the way the documentation says.
- **The break that proves a gate can fail can prove the opposite instead.** Taking `-p` off odhcp6c's arguments left three of the new checks green: no pid file means the test reads `pid=0`, `/proc/0/cmdline` does not exist, so "is it still running?" answers no and "the pid file is gone" is true because there never was one. A missing input makes a *negative* check pass, every time, and it is the break rather than the test that says so. Read what a break turns green as carefully as what it turns red.
- **`kill -0` is not "is it running".** A daemonised process is reparented to init, and an init that does not reap — a container whose pid 1 is `sleep infinity` — leaves a zombie that `kill -0` reports as alive. `/proc/<pid>/cmdline` is empty for a zombie, which makes it the honest question and the same one netcfgd's own ownership check asks.
- **`[ -n "$x" ] && kill` in a cleanup trap eats the rest of the trap.** Under `set -e` an AND-list whose last command fails takes the function with it, so a `kill` of something already stopped means the `rm -rf` below it never runs. `dhcpcd.sh` left five work directories in `/tmp` before anyone looked, and it only bit there because that script stops its own server before exiting where the others leave theirs running. Nothing was red: a leaked temporary directory is invisible to every gate, and the only reason to look is habit. Looking properly then found the bigger one — `cargo test --workspace` left five directories in `/tmp` on every run, and 1252 had accumulated. That one wanted a `Drop` rather than a tidy-up line, because a test that panics never reaches its last line — and every other test module had written the same tidy-up line, so a *failing* test leaked one too. There is one `netcfgd-testdir::TestDir` now, used in fourteen places, and the measurement is the gate: a passing run leaks nothing and a deliberately failed test leaks nothing, where before it left a directory every time.
- **The kernel does not solicit a router on an interface whose advertisements it would ignore.** So `accept_ra` has to be written *before* `link.up`, not after: written after, the interface waits for the router's own unsolicited timer, measured at 14.2 seconds against a dnsmasq told to advertise every five and running to minutes on a real network. Nothing else in a plan cares where a sysctl goes, which is why this one had to be looked at rather than copied from `forwarding` and `use_tempaddr` -- and the assertion is on the *order of the two lines*, because the address still arrives eventually and every other check passes.
- **`-B` is a promise about readiness in some daemons and not in others, and only the daemon can tell you which.** hostapd 2.10 and wpa_supplicant both finish setting up -- interface, control socket, everything -- before the parent exits, so "nothing is listening" really does mean "nothing is running". openvpn's `--daemon` returns at the fork and does the work afterwards, which is the window [0074](docs/decisions/0074-a-daemon-that-cannot-answer-is-still-running.md) had to close with a pid file. All three measured with netcfgd's own invocations against the real binaries; the two safe call sites now say why they are safe, so nobody makes them symmetrical.
- **A daemon that drops privileges will not start in `unshare -rn`, and each one says so differently.** dhcpcd cannot become its own unprivileged user, because a single-uid namespace has nobody to become; dnsmasq cannot `setgroups`, because an unprivileged gid mapping writes `deny` to `/proc/self/setgroups`. Both exit before doing anything, and dnsmasq puts the reason in its log file and nowhere else — so it looks exactly like a router that is not advertising. `unshare --map-root-user --map-auto` fixes both, at the cost of `newuidmap` and a range in `/etc/subuid`; real root fixes both for free. Two daemons in two sessions, which is enough to expect a third.
- **A negative check with no event of its own needs a bound somebody measured.** "dhcpcd did not write that file" is satisfied by "has not written it yet", and there is nothing to wait for, because the whole assertion is that nothing happens. The answer that works is to wait twice as long as the counter-proof needed for the same exchange *in the same run on the same machine* — which scales with a loaded machine, where a sleep somebody guessed does not. That is also the only kind of wait this repository has that cannot be tuned into passing.
- **An exit status ignored for a good reason hides a defect of a different shape.** `dhcpcd -k` says "dhcpcd is not running" and exits 1, which is the ordinary answer on every machine whose client is udhcpc — so netcfgd could not check the status, and the *same* sentence appearing because the pid file's name was wrong was invisible. The two failures are indistinguishable from the outside, and only running the daemon showed which one was happening. Where a status is deliberately unchecked, the comment saying why is also the note saying what it can no longer catch.
- **Breaking a gate to prove it fails needs the artefact rebuilt.** Restoring a file from a copy can leave it with an *older* mtime than the broken build, and cargo then keeps the broken artefact — so the "restored" run silently tests the break. It looked like a new test failing for no reason. `touch` after restoring, or the whole break-it-and-watch-it-go-red method reports on a binary nobody has.
- **A floor of zero is not a floor, and the number that says so has to be measured.** The socket parser's randomised test asserts an acceptance rate the way `fuzzypickles` prints one -- so a mutation scheme that decayed into garbage cannot keep passing the does-not-panic half while testing nothing. Written with `accepted > 0`, and **that threshold passed a deliberately degenerate mutator**: replacing every seed with `?` bytes still scored 16.4%, because one mutation case builds its own frame and parses regardless of what it was given. Real seeding scores 33.4%. The floor is 25% because those two numbers were measured, not because 25 looked careful. The same run made a second weak assertion visible: checking that an over-long line is refused with `is_err()` passes when the bound is *deleted*, because `xxxx...` is not valid JSON either -- the refusal has to be asserted to name the limit, or the check is satisfied by the parser failing for an unrelated reason.
- **Writing the specification down found a defect that pointing at the witness could not.** The socket had a generated witness, a second implementation parsing it and a conformance gate diffing them, and all three were green — but nothing said in prose what the contract *was*, so nothing had ever asked whether the daemon rejects a request member nobody defined. It does not: `{"request":"status","bogus":1}` is **accepted**, while a payload struct carrying an unknown member is refused. The payloads are `deny_unknown_fields` and the `Request` enum cannot be, because serde does not support that attribute on an internally-tagged enum. So **the envelope does exactly what section 2 forbids for the document** — silent field-dropping — on the surface that reads untrusted bytes, and the strictness is on the inside where the bytes are already trusted. Found by measuring a sentence that was about to be written as fact, which is the whole argument for a specification: a witness pins what the daemon *does*, and only prose states what it *must*.
- **The conformance gate passed while comparing nothing, and the witness is why.** `make conformance` runs both client implementations over the same bytes and diffs what they extract — the first gate here that compares two *clients* rather than a client against the daemon. Its first version was **vacuous**, and the way that was found is the method: drifting the C renderer back to its old spelling did not turn it red. The witness carries **one** access point and it has a text name, so `hex:` and `(hidden)` — the two cases that had actually drifted — appear in `docs/schema/socket.json` nowhere at all. A comparison over data that does not contain the disagreement agrees perfectly. Fixed by asking both sides a fixed table of cases rather than only the witness's, after which the same break fails with `rust: display=hex:ff00ff` against `c: display=<ff00ff>`, and dropping the kind test from the C radio predicate fails with `rust: wireless=1` against `c: wireless=0`. **And the witness gap it exposed is closed**: `ScanEntry`'s `name` and `configured` and all four of `WifiState`'s optionals are `skip_serializing_if`, so a sample that filled every one of them pinned only the *present* form — the bytes the daemon actually sends for an unprintable SSID, an unconfigured network or a radio associated with nothing were pinned by nothing at all. The witness carries those shapes now, and the same break fails on a *witness* line rather than only on the table beside it. **No version bump: no type changed.** The bytes moved because the samples grew, which is the witness doing its job rather than the schema doing anything.
- **Three clients had three spellings for one fact, and one of them destroyed the fact.** An access point's name arrives three ways — text, present-and-empty for a hidden network, absent when the SSID is not UTF-8 — and each client had invented its own rendering. `ncfg wifi scan` said `hex:ff00ff` and drew a hidden network as a blank; the TUI said **`<not text>`**, naming the *condition* and throwing the network away, so two unprintable SSIDs became one row that no keystroke could tell apart; the GUI then added a fourth spelling. None of this was wrong enough to fail anything, because **no gate compares two clients** — the schema witness pins what the daemon *sends*, not what a screen makes of it. One renderer now, called by both Rust clients, with the C one holding the same words by comment until the socket has a specification ([0116](docs/decisions/0116-a-client-that-needs-the-model-is-rust.md)). The test that matters is the one asserting two unprintable networks do not render alike: it fails on the old wording with `left: "<not text>", right: "<not text>"`, which is the defect stated as an assertion. **A vocabulary is a thing that drifts, and nothing in this tree was watching it.**
- **A convention adopted in one file has not been adopted.** The kernel commit format was taken into `code-style.md` §8 and nowhere else, so §9 of *this* file went on stating the superseded rule — 72 columns, capitalised, no subsystem prefix, no trailers at all — for the forty-five commits that followed, while `tools/hooks/commit-msg` was enforcing 75 and the log itself had already switched. Two documents in one repository, both current, flatly contradicting each other, and nothing red: **no gate reads prose**, which this section already knew about comments and is no different about rules. What settled it was neither document but `git log`, where the practice was visible and unanimous — the tell being that a document describing what people do can be checked against what they did. The reconciliation deletes the restatement rather than correcting it, because a rule stated in two places is a rule that will drift again.
- **A gate that bails early has not run the checks below the bail.** The verifier for the message rewrite checked commit count first and returned on mismatch, so running it against the *original* history to prove it could fail reported only "289 != 265" and never reached the message rules. That looked like the gate firing and was the gate not firing — the same vacuous pass as a check over an empty file list, wearing the costume of a real failure. Neutralising the grouping so the loop actually ran gave the number that means something: **244 subjects with no subsystem and 132 over-length body lines on the original, 0 of each after**. A break that proves a gate works has to reach the assertion you care about, not merely turn the process red.
- **A heuristic is worth what it reproduces on work somebody already judged.** Choosing a subsystem prefix for 244 old commits was a guess until it was checked against the forty-five whose prefixes had been written by hand: 42 of 45, and the three misses were one shape — a one-line crate fix under a large test diff, where ranking by churn named `tests/live` instead of the crate the defect was in. Tests and packaging rank below code now, which took it to 44 of 45, and the last disagreement was genuine judgement rather than a rule. **Existing hand-made decisions are a labelled training set, and a mechanical rule that cannot reproduce them is not ready to be trusted on the cases nobody checked.**
- **A copy of a check is not the check.** The same verifier re-implemented `commit-msg`'s tooling-attribution pattern from memory and left out its scrubbing of the two names `.claude` and `CLAUDE.md` — so it flagged two commits, one of which was *the commit that taught the hook that difference*. The rule the hook encodes is narrow on purpose: those two names are unavoidable when a message says where the shared tooling lives, and neither is a plausible spelling of attribution. Reading the flagged message rather than trusting the flag is what separated "the message is wrong" from "the check is wrong", and it was the check. Where a gate exists, run *it*; a paraphrase of a gate is a second implementation that will disagree with the first.
- **A note written to stand alone stops making sense where it is folded.** Squashing the small `project.md` folds into the change each describes is what the no-docs-only rule asks for, and it broke three of them: a fold that opened "Two of them are pppd's behaviour" was pointing at a findings list only a standalone commit had, and after the merge the pronoun had no antecedent at all. The other twenty-one read fine, because they opened with a statement rather than a reference. **Prose that survives being moved is prose that names its subject**, and the ones that did not were repaired by naming it — with the replacement asserted rather than assumed, since an edit that silently matches nothing is the failure recorded two entries above.

---

## 11. Reference

The control socket's contract is **[docs/socket-protocol.md](docs/socket-protocol.md)** — what a client sends, what the daemon answers, and the ten things an implementation has to get right. It is the prose half of `docs/schema/socket.json`, and 0116's prerequisite for anyone writing a third client.

Full rationale, principles, comparisons, security model, migration paths and the northbound-adapter discipline are in **`netcfgd-design.md`** (v0.6). Read §2 (principles), §4 (architecture and the compiler/reconciler seam), §9.2 (the one-way rule) and §10 (embedded tiers) before making structural decisions.
