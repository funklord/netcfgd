# netcfgd — implementation brief

**Status:** pre-implementation. Nothing is built yet. This document is the working brief; `netcfgd-design.md` is the reference design and holds all rationale. Where the two disagree, this document wins for *what to build*, the design doc wins for *why*.

**What it is, in one line:** a Linux network configuration daemon whose plain-text config is the single source of truth, whose runtime state is greppable files in `/run`, and whose behaviour is a visible reconcile loop (`plan` then `apply`, like Terraform for interfaces).

**Getting started:** [docs/first-run.md](docs/first-run.md) — taking a laptop from NetworkManager, wired first.

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
4. **`#![forbid(unsafe_code)]` everywhere except `netcfgd-netlink`**, which is the sole audited exception and carries its own fuzz targets and review bar.
5. **The desired-state document never contains secret material.** Only `SecretRef` indirections. This is invariant across local files, `/run` state, and any future wire transmission.
6. **The one-way rule.** No change to the model, config language or socket API may be justified *solely* by an adapter's needs (NM, RESTCONF/YANG, or anything else). If an adapter wants a concept, it must independently be something a local user would want in their own config file.
7. **`ncfg plan` survives to the smallest build.** Not being a black box is the product; a black box on an embedded device with no console is worse than one on a laptop.
8. **Size budgets are CI gates from commit 1.** Budgets adopted later are budgets already blown.

---

## 2. The desired-state document

This is the load-bearing artifact. Everything hangs off it: the compiler emits it, the reconciler consumes it, the NM and RESTCONF adapters project onto it.

**Encoding.** JSON for humans and `/run` introspection; CBOR for compact/embedded storage. Identical schema. The canonical form is whole-host; the per-interface files in `/run/netcfgd/desired/` are projections for convenience, not separate documents.

**Determinism.** The same config must produce a byte-identical document. All lists sort by their declared key; field order is fixed by the schema; integers canonical; no floats anywhere; no map types with unordered iteration. This is what makes plan diffs and caching trustworthy.

**Versioning.** `schema_version` is `{major, minor}`. A consumer **rejects** a document whose major differs from its own, and **rejects any document containing a field it does not recognise** — silent field-dropping is forbidden. Adding a field bumps minor. A remote producer must negotiate the consumer's version and emit at or below it.

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
    netcfgd-netlink/            # rtnetlink. ONLY crate permitted `unsafe`.
    netcfgd-observe/            # netlink + backend reports -> observed model
    netcfgd-plan/               # diff(desired, observed) -> Plan. Pure.
    netcfgd-apply/              # executes a Plan
    netcfgd-proto/              # control socket types
    netcfgd-host/               # reads /etc, writes /run, materialises hooks
    netcfgd-daemon/             # `netcfgd` binary
    netcfgd-cli/                # `ncfg` binary (incl. `ncfg tui`)
  backends/
    netcfgd-dhcp/  netcfgd-supplicant/  netcfgd-wg/  netcfgd-dns/  netcfgd-ppp/
  adapters/
    netcfgd-nm/                 # milestone M7
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
| Size budget | stripped static binary: embedded ≤ 1 MB ([0021](docs/decisions/0021-no-nano-tier.md) dropped the 400 KB nano tier) |
| RSS budget | steady-state < 4 MB |
| Filesystem footprint | `find /etc/netcfgd` on a fixture install with no optional features used must match a build compiled without those features |
| Unsafe policy | `forbid(unsafe_code)` holds everywhere except `netcfgd-netlink` |
| Supply chain | `cargo-deny`, `cargo-audit`, pinned lockfile, stated MSRV |
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
| **M4** | Link types, DNS scopes, router side | WireGuard, bridge/bond/VLAN/VXLAN polish. Scope-capable DNS backends (0007). DHCPv6-PD, `Delegated` resolution and RA handoff (0009). PPPoE via `netcfgd-ppp`. A read of the foreign formats against the model, in place of the importers that were dropped ([0019](docs/decisions/0019-no-importers-for-config-stores-that-rewrite-themselves.md)) — the gap-finding was the part worth keeping. **Model, document schema and socket API freeze here** -- enforced by two witnesses under `docs/schema/`, see [0020](docs/decisions/0020-the-freeze-is-two-witnesses.md). |
| **M5** | Embedded | Getting `netcfgd-embedded` under 1 MB, ~~procd integration~~ (done, `packaging/procd/`), read-only-root support. ~~Nano consumer without compiler~~ — dropped, [0021](docs/decisions/0021-no-nano-tier.md). `uci` import, deferred here from M4 ([0019](docs/decisions/0019-no-importers-for-config-stores-that-rewrite-themselves.md)) because OpenWrt is where it belongs and uci is not rewritten behind the operator. |
| **M6** | TUI | `ncfg tui` including the interactive plan-preview pane. |
| **M7** | NetworkManager shim | `netcfgd-nm`, tier 1 (`nmcli`, `nm-applet`, `plasma-nm` wifi flows). |
| **M8** | Desktop | GUI + tray applet; NM shim tier 2. |
| **M9** | **RESTCONF — last** | `netcfgd-restconf`: `ietf-interfaces`/`ietf-ip` mapping plus a netcfgd augment module, hooks read-only. Full NETCONF (SSH/XML) only if sites ask. |

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

### Known incompatibilities to carry forward

- **A netifrc `preup` that checks link state deadlocks under netcfgd's ordering.** Rule 6 runs `pre_up` before `link.up`, and the kernel returns `EINVAL` for `carrier` on a down interface, so `mii-tool`/`ethtool` checks cannot work there — and net.example's canonical `preup` aborts on "no link", which then prevents the bring-up that would have produced the carrier. The ordering stays. The warning was to have lived in `ncfg convert`, which [0019](docs/decisions/0019-no-importers-for-config-stores-that-rewrite-themselves.md) dropped, so the incompatibility is documented and nothing converts. [0011](docs/decisions/0011-preup-runs-before-the-link-is-up.md).
- **A supplicant must hold no state of its own.** wpa_supplicant runs with no persistent configuration and `update_config=0` set explicitly, and every network arrives over the control socket ([0015](docs/decisions/0015-the-supplicant-holds-no-state.md)). iwd cannot be driven this way — it writes its own network database during connections and has no stateless mode — which is what blocks it, rather than the D-Bus cost ([0014](docs/decisions/0014-wpa-supplicant-is-the-floor-not-the-fallback.md)).
- **netcfgd will never implement key management or EAP.** Permanently delegated, affirming design §1.5. Scan and BSS selection *could* become netcfgd's, and [0016](docs/decisions/0016-which-half-of-a-supplicant-could-ever-be-ours.md) records the shape and the cost — pinning a BSSID defeats 802.11r fast transition, so it buys explainability and spends roaming quality.
- **netcfgd does not gate addressing on carrier.** A link is brought up and addressed whether or not a cable is present. The `carrier` hook reports; nothing defers. Noted as a gap in 0011, not scheduled.

---

## 10. Reference

Full rationale, principles, comparisons, security model, migration paths and the northbound-adapter discipline are in **`netcfgd-design.md`** (v0.6). Read §2 (principles), §4 (architecture and the compiler/reconciler seam), §9.2 (the one-way rule) and §10 (embedded tiers) before making structural decisions.
