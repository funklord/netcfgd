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

Six corollaries, every one of them paid for. The first two were here before this
session; the rest are the same disease in disguises that took a while to
recognise, which is why they are written out separately rather than merged:

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

**Fake only what cannot exist, which is a radio — never the protocol.** `fake_supplicant.py` and `fake_hostapd.py` speak the real `wpa_ctrl` wire format with replies copied from upstream source; the real daemons are driven elsewhere, which is what would catch a parser changing its mind. Anything needing a real association needs `mac80211_hwsim` and therefore real root: `sudo sh tests/live/hwsim.sh`, which is the one part of the suite that cannot run unprivileged.

**If a regression would make a test hang rather than fail, wrap it in `timeout`.** A stuck suite reports nothing, which is worse than a red one.

### Known incompatibilities to carry forward

- **A netifrc `preup` that checks link state deadlocks under netcfgd's ordering.** Rule 6 runs `pre_up` before `link.up`, and the kernel returns `EINVAL` for `carrier` on a down interface, so `mii-tool`/`ethtool` checks cannot work there — and net.example's canonical `preup` aborts on "no link", which then prevents the bring-up that would have produced the carrier. The ordering stays. The warning was to have lived in `ncfg convert`, which [0019](docs/decisions/0019-no-importers-for-config-stores-that-rewrite-themselves.md) dropped, so the incompatibility is documented and nothing converts. [0011](docs/decisions/0011-preup-runs-before-the-link-is-up.md).
- **A supplicant must hold no state of its own.** wpa_supplicant runs with no persistent configuration and `update_config=0` set explicitly, and every network arrives over the control socket ([0015](docs/decisions/0015-the-supplicant-holds-no-state.md)). iwd cannot be driven this way — it writes its own network database during connections and has no stateless mode — which is what blocks it, rather than the D-Bus cost ([0014](docs/decisions/0014-wpa-supplicant-is-the-floor-not-the-fallback.md)).
- **netcfgd will never implement key management or EAP.** Permanently delegated, affirming design §1.5. Scan and BSS selection *could* become netcfgd's, and [0016](docs/decisions/0016-which-half-of-a-supplicant-could-ever-be-ours.md) records the shape and the cost — pinning a BSSID defeats 802.11r fast transition, so it buys explainability and spends roaming quality.
- **netcfgd does not gate addressing on carrier.** A link is brought up and addressed whether or not a cable is present. The `carrier` hook reports; nothing defers. Noted as a gap in 0011, not scheduled.
- **hostapd reads its configuration once, at startup.** There is no reload that keeps clients associated, so changing an `access_point` block — an SSID, a channel — means restarting hostapd, which deauthenticates everyone on the radio. The **station list is the exception**: it converges over the control socket with `DENY_ACL`/`ACCEPT_ACL` `ADD_MAC`/`DEL_MAC`, no restart and no `DEAUTHENTICATE` ([0041](docs/decisions/0041-a-station-list-converges-over-the-control-socket.md)). Three things in hostapd 2.10's source decided that shape, and each would have been a defect taken from the documentation: `DENY_ACL ADD_MAC` **disconnects the station itself** (`hostapd_disassoc_deny_mac`); `SET deny_mac_file` **appends rather than replaces**, so re-pointing hostapd at the regenerated file would leave every past entry denied forever; and `hostapd_check_acl` **consults the accept list first and the deny list second whatever `macaddr_acl` says**, so the list the policy does not name is not inert and is converged to empty too.
- **`macaddr_acl` is the one field that cannot converge in place.** It is settable over the socket, but nothing disassociates on the change and nothing reports it back, so netcfgd would be converging a value it could never confirm — and converging the *lists* without it would apply a `deny` → `allow` edit as an open network. So netcfgd records the policy it started hostapd with, as a `# netcfgd policy: deny` line in the generated station list that `hostapd_config_read_maclist` skips, and a changed policy restarts the access point with a warning saying what that costs. The record has to sit at column zero and fit hostapd's 128-byte `fgets` buffer; a longer line is split, parsed as an address, and takes the access point down at startup. Checked against a real hostapd in both directions.
- **Nothing notices that an access point's *other* configuration changed.** Router advertisement is the one backend where this is solved -- `ObservedBackend.advertised` records what radvd was last given and a changed delegation reloads it -- which is a worked example of the shape hostapd would need, not a reason to think hostapd has it. `ObservedBackend` carries whether a backend is running and, now, a running access point's two station lists — but an edited SSID, channel or band is still invisible to the planner. Older and wider than the ACL, and untouched by 0041.
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
- **iproute2 prints the same protocol tag in two bases.** A route shows `proto 110` and an address shows `proto 0x6e`. The obvious assertion fails on a perfectly correct address.
- **`accept_ra=1` means "accept unless this interface forwards".** A host in an environment that starts with forwarding on ignores every router advertisement, and `ip addr` shows nothing that explains it. `accept_ra=2` is the other way to say it.
- **A host fills in the bottom 64 bits of an advertised prefix itself**, so the address is `2001:db8:1234:0:...` and a grep for `2001:db8:1234::` matches nothing. `proto kernel_ra` is the kernel saying where an address came from, and is the thing worth asserting.
- **A MAC-based allow list is policy, not security.** An address is asserted by the station and changed with one command. It keeps honest devices off a network and stops nobody who does not want to be stopped; anything that must be secure belongs in `wifi { .. }` where the key material is.

---

## 10. Where this is now, and what to pick up next

Kept current deliberately: this is the section to read after a break, and the one to rewrite rather than append to.

### State

**Read this first after a break, and rewrite it rather than appending to it.**

M1–M6 are done. M7's NetworkManager shim has tiers 1 and 2 complete and tier 3 bounded rather than built — and **tier 3 bounds the shim, not netcfgd** ([0036](docs/decisions/0036-the-shim-is-not-the-roadmap.md)), which is the single easiest thing in this repository to misread. VPN, modems and complete wifi are wanted in netcfgd and will simply not be projected through NM's interfaces.

The M4 freeze's four inert features are all closed. Access points now go further than the freeze described: a station list ([0039](docs/decisions/0039-a-station-list-is-one-list.md)), the live client list that makes it usable ([0040](docs/decisions/0040-a-station-list-needs-a-station-list.md)), and the convergence that makes an edit to that list reach a running hostapd without deauthenticating everybody ([0041](docs/decisions/0041-a-station-list-converges-over-the-control-socket.md)). That last one is the first observation netcfgd takes by *asking another process* rather than reading the kernel or its own `/run`, which is a seam worth knowing about before the next backend wants one.

Walking away from a device is now decided rather than defaulted: `managed = false` on a device holding a **WireGuard private key** stops an apply with its own exit code until the operator says which they meant ([0042](docs/decisions/0042-only-a-key-nobody-can-revoke-stops-a-plan.md)). That closes 0037's open question, and narrows it — 0037 named three credentials and only one passes the test, which is *irrevocable from this host* **and** *the operator's choice can change the outcome*. A supplicant's passphrases fail the second half: the same secret is in the secrets directory whichever policy is picked.

**Cellular works end to end, and nothing in it is netcfgd's protocol.** A helper connects the bearer and writes what the network gave it to `/run/netcfgd/reported/<interface>`; netcfgd installs the addresses, the default route and the nameservers, and withdraws them when the report empties. `docs/interface-report.md` is the contract and is written for somebody who has never read this source, because [0045](docs/decisions/0045-the-contract-is-the-decision-and-the-helper-is-plural.md) makes the helper deliberately plural — `helpers/netcfgd-modem-mbim` is a reference, not a blessed one, and `umbim` on OpenWrt or ModemManager over D-Bus are equally valid writers. netcfgd never speaks MBIM, QMI or D-Bus itself ([0044](docs/decisions/0044-the-modem-helper-is-contained-the-way-an-adapter-is.md)).

**OpenVPN tunnels run, netcfgd never reads the `.ovpn`, and the routes are netcfgd's.** `openvpn --help` lists 253 top-level options against hostapd's couple of dozen, so the file stays the operator's and netcfgd owns the lifecycle instead — start, stop through the daemon's own management socket, credentials from the secret store, and the daemon's own words quoted when it will not start ([0046](docs/decisions/0046-the-ovpn-file-is-the-operators.md)). The tunnel's *address* stays with the daemon as a DHCP lease's already does; its *routes* are the contested half and are now taken ([0047](docs/decisions/0047-a-tunnels-address-stays-with-its-daemon.md), [0048](docs/decisions/0048-a-tunnels-routes-arrive-through-the-report.md)): `--route-noexec` plus a generated `--route-up` script that writes the report, and a metric from `preference` so a tunnel can be ranked against a wired link.

**The reporting contract is no longer a modem's**, in every place at once — path, document, model variant and config word. A tunnel reports through it, which is what 0047 said would make the old name start actively misleading somebody. A report is believed when the document asks for `reported` addressing *or* when netcfgd started the writer, and a tunnel is the second: netcfgd generated the script and launched the process that runs it.

**What openvpn will not tell you is written down rather than worked around.** `redirect-gateway` for IPv4 leaves no trace in a `--route-up` script's environment, and the IPv6 half does — measured both ways against a real openvpn 2.6.14 in a namespace. The local answer is `routes = "default"` in the document, and `tests/live/tunnel.sh` checks that recommendation rather than leaving it as advice.

**And when the ISP renumbers, the advertisement follows.** A prefix is the one value in the document that arrives after the document does, so it can arrive *again* as something else — and a daemon still announcing the block that was taken back tells every host on the LAN to use an address the upstream will not route. `ObservedBackend.advertised` records what a running radvd was last given, the planner compares it against what the delegation implies now, and `backend.reload` rewrites and signals. It is a **reload**: radvd re-reads on `SIGHUP` (checked in its own `radvd.c`, which the manual page does not mention), so nothing on the wire is disturbed — the opposite of an access point, where the same question means a restart and a deauthenticated LAN ([0026](docs/decisions/0026-an-access-point-is-a-file-hostapd-reads.md)).

**And it advertises what it was given, which is the last of M4's frozen-and-unwired features.** `advertise { prefixes = ["@pd:wan0"] }` on the LAN; netcfgd renders radvd's configuration and starts it, the same split [0026](docs/decisions/0026-an-access-point-is-a-file-hostapd-reads.md) made for hostapd and for the same reason — an RA is a packet a host acts on without asking. odhcpd is refused by name rather than handed radvd's file. The advertisement is not planned until a prefix reference resolves, because planning it early puts an action that must fail ahead of the DHCPv6 client whose lease it is waiting for, and the apply stops there.

**A router can ask its ISP for a prefix, and the whole of decision 0009 now runs end to end.** `config = "dhcp6 pd_length 56"` on the WAN and `@pd:wan0=::1/64` on the LAN, with `tests/live/delegation.sh` driving a real `odhcp6c` against a real `kea-dhcp6` over a veth pair: the ISP delegates, the hook reports, netcfgd derives the address ([0051](docs/decisions/0051-the-request-half-of-a-delegated-prefix.md)). It is the third root-only test and it needs an odhcp6c built from source on Debian, which its header explains — on OpenWrt, the device the feature is for, it is already installed.

**Prefix delegation is odhcp6c's, and the request half of it did not exist until 0051.** A real `kea-dhcp6` over a veth pair found three things at once, none of which any test here could have seen: dhcpcd was never told about netcfgd's hook, dhcpcd never solicited a prefix at all (that needs an `ia_pd` line in a config file netcfgd does not write), and dhcpcd's `$new_delegated_dhcp6_prefix` carries the addresses it *derived* rather than the prefix — which netcfgd forbids it from deriving. A document asking dhcpcd for a prefix is now refused by name ([0050](docs/decisions/0050-a-delegated-prefix-is-odhcp6cs-to-report.md)). The fourth thing found while writing that: **nothing can ask for a prefix anyway**, because `PdRequest` is in the frozen model and the DSL has no spelling that sets it. `-P 0` used to go to odhcp6c unconditionally, so every `config = "dhcp6"` solicited a delegation nobody had written down.

**A PPPoE session now hangs up, and did not until something dialled one.** `stop_backend` answered "not implemented in this build" for `Pppoe`, so deleting the block from a config failed the apply and left `pppd` holding the line — with the `persist` and `maxfail 0` netcfgd itself wrote into the options file. `tests/live/pppoe-session.sh` is what found it: a real `pppd` against a real `pppoe-server` over a veth pair, which is a real discovery and a real IPCP negotiation with no DSL line anywhere. It needs real root, so it sits in `hwsim.sh`'s bucket — and it has been run. pppd has no control socket, so netcfgd finds the pid file pppd wrote for the interface and checks `/proc/<pid>/cmdline` names the options file netcfgd generated before signalling anything, which is a stronger claim than "not by name" rather than an approximation of it.

**A DSL line's resolvers are taken too, and the option was left out for a reason that was wrong.** `usepeerdns` does not rewrite `/etc/resolv.conf` — `create_resolv` in pppd's `ipcp.c` writes `/etc/ppp/resolv.conf`, pppd's own file, which nothing reads unless somebody points it there. What the option is for is `DNS1` and `DNS2` in a script's environment, and on a DSL line those are the one thing nothing but pppd learns. netcfgd now asks for them and reports them through the same contract, with **two** generated scripts rather than one: pppd leaves `DNS1` and `DNS2` set for the `ip-down` call as well, so a single script branching on its environment would report an ISP's servers as the line went away.

**A tunnel's nameservers are taken and its opinion about routing is not** ([0049](docs/decisions/0049-a-server-may-name-resolvers-not-where-queries-go.md)). A server pushes `dhcp-option DNS` and `dhcp-option DOMAIN` in the same breath; the first is information netcfgd could not have had, the second is a decision about where every query on the machine goes, made by a remote party. So the report has a `dns=` key and will never have one for a routing domain, and what the server suggested is kept as a comment in the file rather than hidden. The gate is narrower than for a route, deliberately: a route down a tunnel goes down that tunnel, so netcfgd having started the tunnel is enough; a nameserver waits for `config = "reported"` or a `dns` block on the interface, and an empty `dns { }` is the minimal way to say it.

The schema version is pinned at 1.0 until the first release ([0038](docs/decisions/0038-versioning-starts-at-the-first-release.md)). That is not a licence to change it quietly — the four witnesses under `docs/schema/` still move on every change and still need a deliberate `make schema-bless`, which was always the mechanism doing the work. Two of them are new. `observed.json` and `plan.json` are the other things a `Status` response carries, and nothing had ever pinned either: an `Observed` field or an `Op` name could move and no gate anywhere noticed, while the socket witness said in a comment that both were "pinned by their own crates".

### Next, roughly in order

1. **Run the modem path against a real modem.** Everything is written and nothing has met hardware: `helpers/netcfgd-modem-mbim` drives `mbimcli` against a fake whose output is copied from libmbim's own `g_print` calls, and netcfgd consumes the report it writes. What no test can reach is a modem that does not behave — the 43 vendor plugins ModemManager carries are the measure of how common that is ([0043](docs/decisions/0043-mbim-is-ours-and-the-quirks-are-a-table.md)).
2. **The same question asked of an access point.** Router advertisement now notices that its own configuration went stale; hostapd does not, and project.md has said so since 0041. The shape is now worked out and running in one place -- record what the daemon was started with, compare against what the document implies, act on the difference -- and hostapd's answer differs only in that its act is a restart with a cost worth warning about.
3. **WireGuard as a first-class NM device**, if the shim is worth more attention than the core.

Longer-range direction is in [0036](docs/decisions/0036-the-shim-is-not-the-roadmap.md) and governed by constraint 9: VPN's second half (ipsec, where strongswan and libreswan disagree about nearly everything), complete wifi as configuration surface over `wpa_supplicant`/`hostapd`, teaming stays dropped in favour of bonding, Open vSwitch is out, and SNMP switch management is a fleet-tree concern rather than a single-host one.

**`ncfg explain` follows the indirection now.** A document that names a *source* rather than a value — a report, a delegated prefix — used to explain as "the configuration does not ask for this address" about an address netcfgd had installed itself and would withdraw itself. Both the address and the route paths now name the file the value came from, gated by the planner's own `takes_reports` rather than a second copy of the question.

### Things that are true and non-obvious

- **This session's method lesson is one lesson, and it is in §9.** Six corollaries now hang off "prove every new gate can fail", and every one was paid for by a gate that was green while the thing it guarded was broken. If something here is going to be re-learned, it is that. The newest instance is the worst-shaped one: a gate that did not exist, with a comment saying it did.
- **A witness built on an exhaustive match catches an addition by failing to compile, and the assertion beside it does something else.** Two of these witnesses claimed the assertion caught "an arm written with no sample added"; it does not, because neither the sample list nor the expected-name list would mention the new name and the two would agree. Tried it, then corrected all three comments. What the assertion catches is a sample that went away or a name that moved, and nothing in Rust can enumerate a variant without a value of it — so the gap is stated where it is rather than assumed away. Overstating a gate is the same disease as not having one: both leave somebody trusting a check that is not running.
- **A real daemon in a namespace is reachable more often than it looks.** OpenVPN's static-key point-to-point mode has no handshake, so a tunnel is up the moment the `tun` device opens — no server, no certificates, no second process. That is what made every claim about `--route-up`'s environment measurable rather than inferred, and `unshare -rn` plus `/dev/net/tun` is all it needs. The trick reached further than expected: a veth pair *is* an ethernet segment, so `pppoe-server` on one end and netcfgd's `pppd` on the other is a real PPPoE session, and the whole of DSL is testable without a DSL line. What that needs beyond the tunnel case is real root, which a privileged container supplies as well as `sudo` does. **Reach for this before writing another fake** — the session found an unimplemented hang-up on its first run, and no fake would have.
- **The TUI shows what was applied, not what was reported.** `ncfg status` marks a reported-and-not-applied address as such; the Devices pane does not, because it lists the observation's links and addresses. Deliberate as far as it goes -- the TUI is a subset by design (0025) -- but somebody debugging a modem in the TUI alone will not see the report at all.
- **`make live` is where defects are found**, not `make check`. Nearly every real bug in the last several milestones came from a real kernel or a real reference tool, and several came from a test that had been passing for the wrong reason.
- **`acl.sh` failed once, unreproduced, and the cause is a real property.** Two policy-change checks went red in one `make live` and have passed on every run since, including under deliberate load. They need netcfgd to have read a running access point's ACL, and that read has a one-second deadline *on purpose* -- a wedged hostapd must not stall the reconcile loop. A Python fake's first reply on a loaded machine can cost more than that, at which point netcfgd correctly converges nothing. The fix is a warm-up round trip before anything is measured, never a longer deadline: the deadline is the behaviour, and the same script measures it two checks later.
- **`switch.sh` failed once, unreproduced.** The socket appearing does not mean the first apply has finished — the daemon binds before it converges — so the veth peers are not guaranteed to exist when a script that waited on the socket uses them. The window is real, smaller than a `fork`+`exec`, and has never been caught open. The wait added there is not claimed as the diagnosis; what it does is report the failure with the daemon log instead of a message about permissions.
- **Size and RSS both ratchet, and RSS is noisy.** See §6. Raising either is a deliberate, reviewable edit with a line saying what it bought.
- **An observation that asks another process needs its own deadline, and the deadline has to cover the connect.** Reading a running hostapd's ACL put a control-socket round trip in the reconcile loop, which runs on every netlink event. A hostapd that is *wedged* — alive, socket bound, not answering — held a single `ncfg plan` for 10.2 seconds; a one-second deadline brings it to 1.0. The first attempt shortened nothing, because `Client::connect` opens with a `PING` and a timeout set on the returned client never covers it. Measured both times rather than reasoned about, and `tests/live/acl.sh` now keeps it measured.
- **Reading the daemon you are integrating with beats reading its documentation, and `apt-get source` is how.** Three separate design errors in 0041 came from believing the wpa_ctrl documentation and `strings` output; all three were settled in twenty minutes by reading `hostapd/ctrl_iface.c`. This is the third feature in a row where the source answered a question the documentation got wrong.
- **Breaking a gate to prove it fails needs the artefact rebuilt.** Restoring a file from a copy can leave it with an *older* mtime than the broken build, and cargo then keeps the broken artefact — so the "restored" run silently tests the break. It looked like a new test failing for no reason. `touch` after restoring, or the whole break-it-and-watch-it-go-red method reports on a binary nobody has.

---

## 11. Reference

Full rationale, principles, comparisons, security model, migration paths and the northbound-adapter discipline are in **`netcfgd-design.md`** (v0.6). Read §2 (principles), §4 (architecture and the compiler/reconciler seam), §9.2 (the one-way rule) and §10 (embedded tiers) before making structural decisions.
