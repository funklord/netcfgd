# netcfgd — implementation brief

**Status:** pre-implementation. Nothing is built yet. This document is the working brief; `netcfgd-design.md` is the reference design and holds all rationale. Where the two disagree, this document wins for *what to build*, the design doc wins for *why*.

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
  confirm_default  : u32?             // seconds; commit-confirm default window
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
  portal_check : bool = false
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
  depends_on : [u32]
  inverse    : Op?           // None => irreversible; plan warns loudly
}

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
| RSS budget | `make rss`, `VmHWM` of the debug daemon. Design §10.4 wants < 4 MB; what is measured is the full tier, so this ratchets too. **It is noisy in a way the size gate is not** — five runs of an *identical* binary spanned ~600 KB — so the limit carries a full noise band above the observed peak, and the measurements are written down in the Makefile so the next person can tell drift from spread. A limit set at the measurement goes red on noise, and a red build nobody can act on teaches people to re-run it |
| Filesystem footprint | `find /etc/netcfgd` on a fixture install with no optional features used must match a build compiled without those features |
| Unsafe policy | `forbid(unsafe_code)` holds everywhere except `netcfgd-sys` |
| Supply chain | `cargo-deny`, `cargo-audit`, pinned lockfile, stated MSRV |
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
| **M8** | Desktop | GUI + tray applet; NM shim tier 2. |
| **M9** | **RESTCONF — last** | `netcfgd-restconf`: `ietf-interfaces`/`ietf-ip` mapping plus a netcfgd augment module, hooks read-only. Full NETCONF (SSH/XML) only if sites ask. |

**The M4 freeze's four inert features are all closed**, after M6 rather than at M4 — the schema had to carry them before the freeze, the behaviour did not. Policy routing rules, `ipv6_token` and the ethtool offloads are netlink; access points are hostapd, configured by a generated file under `/run` ([0026](docs/decisions/0026-an-access-point-is-a-file-hostapd-reads.md)). What is still recognised and not applied is the half of the `ethtool` block that needs a physical NIC to exercise, and `ncfg plan` names those fields individually.

**Access points carry a station list**, which is the single-host half of the Ubiquiti-style roaming [0036](docs/decisions/0036-the-shim-is-not-the-roadmap.md) wrote down: forcing a client onto one access point means every other access point refusing it. `access_control { deny = [..] }` or `allow`, never both, because hostapd reads one file or the other ([0039](docs/decisions/0039-a-station-list-is-one-list.md)). Changing the list still needs a restart, which for this feature is the wrong answer — converging it over hostapd's control socket instead is the next piece, and the record says why.

**A WireGuard tunnel, a bridge and a bond are themselves in the shim**, the
three link kinds to stop being `GENERIC` — each on the same terms: NM defines an
interface for it, and netcfgd can answer every property on that interface from
what it already observes. WireGuard needed 0054 first; a bridge and a bond
needed nothing, because a `Slaves` list is the `master` field on every other
link read from the other end. **That is also the rule for what has not left**:
`.Device.Vlan` wants an id and a parent the observation does not carry, and
adding them to the model to satisfy a shim is the direction constraint 6
forbids. Its `interface` block is deliberately *not* a connection
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
- **Commit subject: capitalised, imperative, no trailing period,** 72 columns. No conventional-commit prefixes, no type tags, no emoji. Body is prose wrapped at 72 explaining *why* the change is right and what was learned making it — including wrong turns, tests that passed for the wrong reason, and numbers that turned out to be guessed. `git diff` already lists what changed.
- **The message ends at its real content.** No trailers, no sign-offs, no tooling or assistant attribution (`Co-Authored-By:` for anything that is not a person, `Generated with ...` footers). The author field carries the attribution git needs.
- **No docs-only commits.** Documentation rides along with the code commit it describes. Folding an accumulated session's findings back into this file is the standing exception.
- **Stage named paths; never `git add -A`.** That is the mechanism by which local editor state, scratch files and untracked notes end up in history. `.gitignore` covers the predictable cases and is not a substitute for reading `git status --short`.
- **Nothing containing real secret material is committed** — not in fixtures, not in test data, not temporarily. §2 makes the desired-state document secret-free by construction; the repository holds to the same rule, and a test fixture is the easiest place to forget it.

Changing any of the above is a convention change: raise it rather than adjusting the default in passing.

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
- A D-Bus client redirects to a private bus: `dbus-daemon --session --print-address --fork`, exported as **`DBUS_SYSTEM_BUS_ADDRESS`**, which GDBus honours in place of the system bus. That is how `tests/live/nm.sh` drives a real `nmcli` against the shim without touching the NetworkManager running the laptop.

**Fake only what cannot exist, which is a radio — never the protocol.** `fake_supplicant.py` and `fake_hostapd.py` speak the real `wpa_ctrl` wire format with replies copied from upstream source; the real daemons are driven elsewhere, which is what would catch a parser changing its mind. Anything needing a real association needs `mac80211_hwsim` and therefore real root: `sudo sh tests/live/hwsim.sh`.

**Know what an ordinary `make live` skipped.** Three scripts need real root — `hwsim.sh` loads a module and moves a phy between namespaces, `pppoe-session.sh` opens `/dev/ppp`, `delegation.sh` binds ports 546 and 547 — and `make live` invokes each of them either way, so an unprivileged run prints three skips and a green suite. Two more skip on a package a netcfgd machine has no reason to have: `tunnel.sh` wants `openvpn`, `ap.sh` wants `hostapd`. That is five scripts saying nothing, and the skip lines are the only place it is written down. **A privileged container closes all five** and does not touch the machine's own network — `docker run --rm --privileged -v $PWD:/repo -w /repo debian:trixie`, plus the packages each header names. A container also needs `libncursesw6`, which is not obvious from anything: the daemon links ncurses for the TUI behind a default-on feature ([0025](docs/decisions/0025-the-audited-crate-is-the-libc-boundary-not-netlink.md)), so a bare image gets `error while loading shared libraries` and a test that looks like a daemon which will not start.

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
- **dhcpcd cannot report a delegated prefix to a script**, and never could. `$new_delegated_dhcp6_prefix` is the addresses it derived from one, filled from `ap->delegating_prefix` in `dhcp6.c`, and only on an interface it delegated to. `$new_dhcp6_prefix` — which netcfgd's hook read for years — is not a dhcpcd variable at all.
- **`kea-dhcp6` binds before duplicate address detection finishes and fails.** "Cannot assign requested address" on a link-local it can see with `ip addr`; the address is tentative for about a second after the link comes up. Anything starting a DHCPv6 server right after `ip link set up` has to wait for DAD.
- **A tunnel change must carry the whole `INFO_DATA` nest, because GRE and the ip tunnels reset what it omits.** A request carrying only `IFLA_GRE_REMOTE` leaves the tunnel with no local address, no TTL and no key — `ipgre_netlink_parms` fills a zeroed struct from whatever arrived — and an `ip6tnl` loses its encapsulation limit, a field netcfgd does not even model. geneve and VXLAN are the opposite and keep what a request leaves out. So netcfgd sends the nest creation would build, and the two rules cost it nothing either way ([0058](docs/decisions/0058-a-change-carries-the-whole-nest.md)).
- **The fallback tunnel devices refuse every change.** `gre0`, `gretap0`, `tunl0`, `sit0`, `ip6tnl0` and `ip6gre0` exist in every network namespace once their module is loaded, and `ip_tunnel_changelink` answers `EINVAL` for anything asked of one. An operator who names an interface after one gets a failing apply. Not special-cased: nothing in the dump marks a fallback device, only six names that are a module's convention.
- **A GRE key of zero is a key, and the value cannot say so.** The kernel emits `IKEY` and `OKEY` for every GRE tunnel, zero included; the `GRE_KEY` bit in `IFLA_GRE_IFLAGS` is what says whether they mean anything. Reading the flag is what stops a document asking for `key = 0` from differing from itself on every reconcile.
- **A macvlan cannot be moved into or out of `passthru`, and its parent cannot be moved at all.** `macvlan_changelink` refuses the `passthru` transition in either direction with `EINVAL`; an `IFLA_LINK` naming a different parent is accepted and silently ignored. The other three modes move freely on a live device.
- **A VXLAN refuses its `port` on presence rather than on difference.** Restating the port it already has fails the whole message with `EOPNOTSUPP`, so a change built from creation's nest could never correct an endpoint. Its `id` is refused only when the value differs, and a group address in the other family is refused by name.
- **iproute2 prints the same protocol tag in two bases.** A route shows `proto 110` and an address shows `proto 0x6e`. The obvious assertion fails on a perfectly correct address.
- **`accept_ra=1` means "accept unless this interface forwards".** A host in an environment that starts with forwarding on ignores every router advertisement, and `ip addr` shows nothing that explains it. `accept_ra=2` is the other way to say it.
- **A host fills in the bottom 64 bits of an advertised prefix itself**, so the address is `2001:db8:1234:0:...` and a grep for `2001:db8:1234::` matches nothing. `proto kernel_ra` is the kernel saying where an address came from, and is the thing worth asserting.
- **A backend's *device* may not exist while the backend is running.** openvpn creates its `tun` seconds after starting, and a tunnel still negotiating has none at all — so anything planned from an interface's contents is skipped for exactly the tunnels that need it. The stale-configuration check for a `.ovpn` is a top-level pass for that reason, and the live test is what said so while every unit test passed.
- **The kernel's `SET_DEVICE` is a partial update and netcfgd used to send the whole device.** An attribute that is absent is left alone and the peer list is replaced only under `WGDEVICE_F_REPLACE_PEERS`, which is how `wg set wg0 listen-port` changes a port without touching a peer. A comment in `netcfgd-sys` said WireGuard "has no partial update that netcfgd wants", true while the only caller was link creation and false the moment there was a second.
- **A MAC-based allow list is policy, not security.** An address is asserted by the station and changed with one command. It keeps honest devices off a network and stops nobody who does not want to be stopped; anything that must be secure belongs in `wifi { .. }` where the key material is.

---

## 10. Where this is now, and what to pick up next

Kept current deliberately: this is the section to read after a break, and the one to rewrite rather than append to.

### State

**Read this first after a break, and rewrite it rather than appending to it.**
Last rewritten after the session that **closed**
[0057](docs/decisions/0057-a-link-kind-is-compared-like-a-daemon.md)'s list:
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

The question this project keeps finding new places to ask. Four kinds of answer
now exist, and the shape of each is worth knowing before adding a fifth.

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

Three rules hold across all four, and every one was paid for:

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

**What is still silent**, so that nobody assumes otherwise: **a macvlan's
parent**, which the kernel also accepts and ignores. Same answer, same remedy,
and nothing has asked for it.

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

#### What the gates have been worth lately

Three sessions in a row have found more in the *tests* and in the measurements
than in the code, and the patterns are worth carrying rather than rediscovering.

**Asking the kernel beat reading the previous session's table.** 0057 wrote down
seven measurements and told the next session to ask again; asking corrected two of
them and turned up the question nobody had asked at all — what happens to the
attributes a change request leaves out. Two of the answers would have shipped as
defects: a macvlan mode netcfgd would refuse to move, and a VXLAN whose endpoint
could never be corrected because the nest carried a port the kernel refuses to
see. The session after it found its own defect the same way — not from a test, but
from asking what *else* would fall into the safe direction of a new comparison,
which is how an interface existing as the wrong kind turned out to be invisible.

**A gate can be blind because its input does not contain its subject.** Six
instances across two sessions now. The newest is the sharpest: a live check that
edited a geneve tunnel's *remote* passed with the protection against sending its
VNI deliberately removed, because restating the VNI the kernel already has is
accepted. Only editing both at once could see it. A check about a difference has
to contain the difference.

**And the suite has been run as root**, in a privileged container, which is still
the only way three of the scripts run at all. All three pass. Getting there found
four defects, every one in the suite and three of them leaving a green run
behind: a build recipe that does not build, a preflight that failed where it
should skip, its repair which then skipped where it should run, and `hwsim.sh`
passing while leaving a root `netcfgd` and two supplicants alive. The socket
witness had the hole its own comment claimed to cover, too — three responses were
pinned by nothing anywhere, and all three lists now go through an exhaustive
match.

### Next, roughly in order

1. **Run the modem path against a real modem.** Everything is written and
   nothing has met hardware: `helpers/netcfgd-modem-mbim` drives `mbimcli`
   against a fake whose output is copied from libmbim's own `g_print` calls.
   What no test can reach is a modem that does not behave — the 43 vendor
   plugins ModemManager carries are the measure of how common that is
   ([0043](docs/decisions/0043-mbim-is-ours-and-the-quirks-are-a-table.md)).
2. **The shim's remaining device types, which are now unblocked rather than
   forbidden.** `.Device.Vlan` wants an id and a parent, and `.Device.IPTunnel` a
   local and a remote; the observation carries the id and both endpoints because
   0058 and 0059 needed them for a local reason, which is the direction
   constraint 6 requires and the road a bridge, a bond and a WireGuard tunnel all
   took. **The parent is the piece still missing** for a VLAN, and it should be
   added for a local reason too or not at all — a macvlan's parent being silently
   ignored by the kernel is one, and is the last thing on 0057's list that nothing
   compares.

3. **Nothing else on the "is it still what the document says?" question is
   open.** Daemons, kernel objects, secrets and unread files all have an answer,
   and 0059 closed the last kind. The next thing of this shape, when it turns up,
   is likely to be a backend netcfgd did *not* start — which
   [0053](docs/decisions/0053-a-file-netcfgd-does-not-read-can-still-be-hashed.md)
   guessed at once already and was wrong about, so it is a suspicion rather than a
   plan.

Longer-range direction is in [0036](docs/decisions/0036-the-shim-is-not-the-roadmap.md) and governed by constraint 9: VPN's second half (ipsec, where strongswan and libreswan disagree about nearly everything), complete wifi as configuration surface over `wpa_supplicant`/`hostapd`, teaming stays dropped in favour of bonding, Open vSwitch is out, and SNMP switch management is a fleet-tree concern rather than a single-host one.

### Things that are true and non-obvious

- **If one thing here is going to be re-learned, it is §9's.** Every corollary under "prove every new gate can fail" was paid for by a gate that was green while the thing it guarded was broken. The worst-shaped instance so far was a gate that did not exist at all, with a comment saying it did.
- **A column that renders two things the same way cannot tell them apart, and neither can a check reading it.** `nmcli`'s TYPE column prints a *generic* device's `TypeDescription`, and netcfgd's type description is the kernel's link kind — so "the tunnel shows as `wireguard`" passed with the device-type mapping deliberately broken, because a generic device whose description is the word `wireguard` renders identically to a real one. The repair is to assert a value only the real thing can produce: a listen port the document chose, and the type as a *number* rather than as a rendered column.
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
- **Breaking a gate to prove it fails needs the artefact rebuilt.** Restoring a file from a copy can leave it with an *older* mtime than the broken build, and cargo then keeps the broken artefact — so the "restored" run silently tests the break. It looked like a new test failing for no reason. `touch` after restoring, or the whole break-it-and-watch-it-go-red method reports on a binary nobody has.

---

## 11. Reference

Full rationale, principles, comparisons, security model, migration paths and the northbound-adapter discipline are in **`netcfgd-design.md`** (v0.6). Read §2 (principles), §4 (architecture and the compiler/reconciler seam), §9.2 (the one-way rule) and §10 (embedded tiers) before making structural decisions.
