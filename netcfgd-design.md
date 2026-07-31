# netcfgd — a network configuration tool that doesn't fight you

**Design specification & architecture — v0.6 (draft for discussion)**

> **Names.** Project and daemon: `netcfgd`. CLI: `ncfg` (short, because it is typed constantly — the `nmcli` pattern). TUI: `ncfg tui`, a subcommand rather than a separate binary. Adapters: `netcfgd-nm`, `netcfgd-restconf`. Build tiers: `netcfgd-nano`, `netcfgd-embedded`, `netcfgd-full`. Hook environment prefix: `NCFG_`.
>
> **Changes in v0.6:** renamed from the `weft` placeholder throughout. `netcfg` and `netconfig` were unavailable (Debian source package and Solaris `netcfg(1M)`; openSUSE `netconfig(8)`), and `netconfd` is taken by the Yuma NETCONF server — `netcfgd` avoids all three and, unlike `netconfigd`, does not contain the string "netconf", which matters now that §9.6 ships a real NETCONF adapter.
>
> **Name availability, verified 2026-07-28:** `netcfgd` and `ncfg` are both free on crates.io and GitHub. Nearest neighbour is the unrelated personal repo `ksaegusa/netcfgdiff` — a prefix overlap only, no packaging or command-name conflict. Crate names on crates.io are first-come and unreclaimable, so both should be reserved with placeholder publishes before any public announcement.
>
> **Changes in v0.5:** §9 generalised to **northbound interfaces**, with the NM D-Bus shim joined by a **RESTCONF/NETCONF adapter** (§9.6) — including the NMDA convergence and a precise account of what YANG can and cannot express. §11 rewritten to **lead with RESTCONF**: conform to an existing standard rather than invent a protocol and a controller. Roadmap and comparison updated.
> **Changes in v0.4:** multi-host management demoted from a designed feature to a **reserved seam** (§11) — flagged as possible, not scheduled, and deliberately under-specified. New principle 12 and §4.6: **the filesystem reflects use, not capability** — an install that never joins a fleet must be byte-for-byte indistinguishable from one built without the feature. §11.4 states the separation invariant: a multi-host tree is legitimate and lives in its own tree, but a machine's own config never lives inside it, on any machine including a controller. Commit-confirm promoted out of fleet into core safety (§4.5). **Rust decided** (§12), with a security posture section. Protocol encoding/crypto delegated to an external protocol tool.
> **Earlier:** v0.3 embedded tiers and the compiler/reconciler seam; v0.2 NM D-Bus compat and netcfgd's own clients.

---

## 0. One-paragraph pitch

`netcfgd` is a network configuration tool whose **plain-text config is the single source of truth**, whose **runtime state is greppable files in `/run`**, and whose behaviour is a **visible reconciliation loop** (like `terraform plan/apply`, but for interfaces). It keeps the ergonomics people liked about NetworkManager — scan, remember, auto-connect, roam on wifi — while inheriting the **syntax and feature model of netifrc**. It has **no mandatory D-Bus, polkit, or systemd dependency**, delegates hard radio work to `iwd`/`wpa_supplicant`, and treats **hooks as a first-class API**. It runs from a **sub-megabyte build on a 16 MB-flash router** up to a desktop, and grows optional northbound adapters at the edge: NetworkManager's D-Bus interface so existing applets keep working, and **RESTCONF/NETCONF** so standard automation tooling can drive it. Written in Rust, because a daemon holding `CAP_NET_ADMIN` is security-critical. Above all it is a **single-host tool**: your config directory contains your config and nothing else, forever.

---

## 1. Goals and non-goals

### 1.1 The three pains we are explicitly killing

Every architectural decision below traces back to one of these.

**Pain 1 — Opaque config & state.** NetworkManager splits truth between keyfiles/ifcfg *and* live D-Bus/internal state; networkd splits between `.network` files *and* state you can only see through a tool. Manual `ip` changes get silently clobbered or silently ignored, and you can't answer "why is the interface like this?" by reading a file.

> **netcfgd's answer:** config is plain text and authoritative; observed state is plain text in `/run/netcfgd/`; the *difference* between them is a first-class, inspectable object (`ncfg plan`, `ncfg status --drift`). Nothing about the running system is knowable only through a daemon.

**Pain 2 — Bloat & dependencies.** NM pulls D-Bus, polkit, glib, ModemManager, its own DHCP stack, and increasingly assumes systemd. Absurd on a server, a container, or an embedded box.

> **netcfgd's answer:** a small core binary, statically linkable, no glib/D-Bus/polkit. Everything optional is a plugin or a compile-time feature. Core talks to the kernel directly over **rtnetlink**. Runs in **oneshot mode with no daemon at all**. §10 sets hard byte budgets enforced in CI.

**Pain 3 — Poor scriptability & hooks.** NM's dispatcher scripts are clumsy and under-documented; networkd barely has hooks; both fight your manual changes.

> **netcfgd's answer:** netifrc-style lifecycle phases are a supported contract with defined env vars and meaningful exit codes. Every CLI command has `--json`. And netcfgd **detects** manual drift and reports it instead of silently reverting it.

### 1.2 Scale down: the embedded target

Runs on an OpenWrt-class device: single-digit megabytes of free flash, 32–64 MB RAM, possibly a read-only squashfs root. It should be a credible `netifd` alternative, not a desktop tool that technically cross-compiles. §10.

### 1.3 Scale out: conform rather than build

Centralized multi-host management is **not a current goal**, and the plan is now to get most of it for free by speaking an existing standard: a RESTCONF adapter (§9.6) makes a host manageable by orchestration tooling that already exists. A bespoke controller with adoption and a dashboard (§11.3) remains a distant possibility that would need its own justification. §11 keeps the door open without walking through it.

The binding constraint that comes with it is negative rather than positive, and it is stated as principle 12: **no user who never touches this feature may ever see evidence that it exists.**

### 1.4 Also-goals

- Wifi that "just works": background scan, remembered networks, priority auto-connect, roaming, WPA2/WPA3/802.1X, per-SSID overrides, captive-portal hook.
- Zero-config DHCP on a fresh interface.
- One command to see everything: `ncfg status`.
- First-class clients of its own — CLI, TUI, eventually GUI/tray applet (§7).
- Optional NM D-Bus compatibility for existing GUI clients (§9).

### 1.5 Non-goals (on purpose)

- **Not** a routing daemon (no BGP/OSPF — hand off to bird/frr).
- **Not** a DNS server or caching resolver.
- **Not** a reimplementation of the 802.11 supplicant or a DHCP RFC stack.
- **Not** a GUI *in the core*. All UIs are clients over the socket API, including ours.
- **No** D-Bus as a hard requirement. It appears in exactly one optional plugin (§9).
- **Not** a firmware manager, image builder, or device lifecycle platform — ever, at any scale.
- **Not** a configuration management system. netcfgd is not Ansible, Puppet, or Salt, and must never acquire their filesystem shape. If §11 is ever built, it does not change this.
- **Not** a bug-for-bug NM clone; the compat layer is explicitly tiered and lossy (§9.5).
- **Not** a home for virtual networking features that are not directly useful for real-world networking, or are not very common use cases. Those are deferred indefinitely: an overgrown VM topology is not a use case, it is a failure, and a tool with a size budget and an embedded tier does not carry features whose users mostly built something they should not have. Open vSwitch is the case this rule was stated about; `ifb`, `veth`, `dummy`, `vrf` and `macvlan` are already here and earn their places ([0036](docs/decisions/0036-the-shim-is-not-the-roadmap.md)).

---

## 2. Design principles

1. **The file is the truth.** If it isn't in a config file, netcfgd won't do it.
2. **State is observable with `cat`.** `/run/netcfgd/` holds the world as netcfgd sees it, in flat text. Tools are conveniences, not gatekeepers.
3. **Declarative desired state, visible reconciliation.** Always able to show the diff before and after acting.
4. **Small core, optional everything.**
5. **Delegate the hard radio/lease work.** Don't reinvent supplicants or DHCP RFCs.
6. **Init-agnostic, daemon-optional.**
7. **Don't fight the operator.** Drift is detected and surfaced; reversion is opt-in.
8. **Least privilege, no polkit.**
9. **Every UI is a client, including ours.** Same public socket API for our TUI as for third parties. No private back doors.
10. **Adapters translate; they never define.** No foreign data model may leak inward past its adapter boundary.
11. **One model, many sizes.** A single desired-state model spans the 400 KB router build and the desktop. Size is a *build configuration*, not a fork.
12. **The filesystem reflects use, not capability.** Nothing appears on disk because a feature *could* exist — only because it *is being used*. A laptop that never joins a fleet, never installs the NM shim and never writes a hook has exactly one config file and one drop-in directory. Corollary, and equally binding: **a host's own config always lives at the same path in the same shape on every machine** — including a machine that manages hundreds of others. Multi-host trees are legitimate and belong in a *separate* tree of their own (§11.4); they never absorb the local config. §4.6 gives this a mechanical test.

---

## 3. Configuration language

### 3.1 The compatibility promise

netcfgd reads two syntaxes — a migration feature, not indecision.

- **`netifrc` compat mode** — reads existing `config_*`, `routes_*`, `dns_servers_*`, `preup()/postup()` conventions from a `conf.d/net`-style file, so a Gentoo box works on day one.
- **Native `ncfg` blocks** — same model as clean declarative blocks with typed keys, drop-ins and includes. Recommended for new setups.

Both compile to the same desired-state model. `ncfg convert net.conf` transpiles legacy → native.

### 3.2 Native syntax — worked examples

Config lives in `/etc/netcfgd/netcfgd.conf` plus `/etc/netcfgd/conf.d/*.conf` drop-ins (lexical order; later wins; explicit `include`/`override` allowed). Deliberately netifrc-flavoured: interfaces are named, keys read like `config_*`/`routes_*`, lifecycle phases are named blocks of shell.

**Static Ethernet:**

```ini
interface eth0 {
    config   = "192.168.1.10/24"          # netifrc's config_eth0
    routes   = "default via 192.168.1.1"  # netifrc's routes_eth0
    dns      = "192.168.1.1 1.1.1.1"
    mtu      = 1500

    post_up {
        logger "eth0 came up as $ADDR"    # $IFACE, $ADDR, $PHASE exported
    }
}
```

**DHCP:**

```ini
interface eth1 {
    config = "dhcp"          # or: dhcp, dhcp6, slaac, "dhcp dhcp6"
    dhcp {
        backend  = "auto"    # auto|dhcpcd|udhcpc|builtin
        hostname = "send"
        metric   = 100
    }
}
```

**Wifi — remembered networks, priority auto-connect, per-SSID override:**

```ini
device wlan0 {
    wifi {
        backend      = "auto"   # auto -> prefer iwd, else wpa_supplicant
        autoconnect  = true
        portal_check = true
    }
}

network "HomeFiber" {                    # an SSID profile, not tied to one device
    wifi   { psk = "@secret:HomeFiber"; priority = 30 }
    config = "dhcp"
}

network "Office" {
    wifi {
        eap      = "peap"
        identity = "dave"
        password = "@secret:Office"
        priority = 20
    }
    config = "dhcp"
    on portal { notify-send "Sign in to Office wifi" }
}

network "Phone Hotspot" {
    wifi     { psk = "@secret:Hotspot"; priority = 5 }
    config   = "dhcp"
    metered  = true                      # informs metric/backoff, exported to hooks
}
```

**VLAN, bridge, bond (core, via netlink — no external tools):**

```ini
interface br0     { bridge = "eth0 eth1"; config = "dhcp" }
interface eth0.42 { vlan { parent = "eth0"; id = 42 }; config = "10.42.0.2/24" }
```

**WireGuard (plugin):**

```ini
interface wg0 {
    wireguard {
        private_key = "@secret:wg0"
        listen_port = 51820
        peer "hub" {
            public_key  = "abc123..."
            endpoint    = "vpn.example.com:51820"
            allowed_ips = "10.0.0.0/24"
            keepalive   = 25
        }
    }
    config = "10.0.0.5/32"
}
```

Note what is absent from every example: any hostname, site name, group, role, environment, or inventory concept. There is no `host_vars`, no `group_vars`, no `sites/`. The config describes *this machine*, because that is what netcfgd configures.

### 3.3 Secrets

Never inline plaintext by default. `@secret:NAME` resolves through a pluggable provider: `file` (`/etc/netcfgd/secrets/NAME`, mode 0600 — the no-deps default), `kernel-keyring`, `pass`, `gnome-keyring`/`kwallet`, or an exec provider. `ncfg secret set HomeFiber` prompts and writes through the active provider. Config files stay safe to commit.

### 3.4 Why this beats the incumbents on config

Every value is in a file you can `grep`, `diff` and `git commit` — no binary blob, no UUID indirection, no D-Bus round-trip to learn your own settings. Drop-ins and includes give layering without a database. netifrc muscle memory transfers directly, and migration is `ncfg convert`, not a rewrite.

---

## 4. Architecture

### 4.1 Component map

```
   clients — all equal, all over the same public socket API
   +-----------+-----------+-------------+------------------+
   | ncfg      | ncfg tui  | GUI/applet  | netcfgd-nm       |
   | (CLI)     |           |             | netcfgd-restconf |
   +-----------+-----------+-------------+------------------+
                          |
                /run/netcfgd/netcfgd.sock
                          |
       +------------------v-----------------------------+
       |                 netcfgd (core)                 |
       |  +------------------+  +--------------------+  |
       |  | CONFIG COMPILER  |->| desired-state model|  |
       |  | (DSL, netifrc)   |  +---------+----------+  |
       |  | [omittable, §10] |            |             |
       |  +------------------+            |             |
       |  - rtnetlink watcher -> observed state         |
       |  - RECONCILER (desired vs observed -> actions) |
       |  - lifecycle/hook runner                       |
       |  - control socket                              |
       +----+------------+------------+-------------+---+
            |            |            |             |
      rtnetlink     backend IPC   hook exec   /run/netcfgd/*
      (kernel)      (plugins)     (scripts)   (state files)
            |            |
            |   +--------+---------+---------+---------+
            |   | wifi   | dhcp    | wg      | modem   |  (plugins)
            |   | iwd /  | dhcpcd/ | wg(8)   | Modem-  |
            |   | wpa_s  | udhcpc/ | netlink | Manager |
            |   |        | builtin |         | (opt)   |
            |   +--------+---------+---------+---------+
            v
        kernel link/addr/route/neigh tables
```

**Core (`netcfgd`)** parses config → desired state, subscribes to rtnetlink → observed state, runs the reconciler, executes hooks, serves the control socket, writes `/run/netcfgd/`. Links/addresses/routes/bridge/bond/vlan go **directly via netlink** — no shelling out to `ip`, no external dependency for wired setups.

**Backends (plugins)** are separate executables speaking a small JSON-over-pipe protocol (in the spirit of OpenWrt netifd's protocol handlers). Missing backend ⇒ feature unavailable, core still runs.

- **wifi**: prefers **iwd** (small, modern; 2.0 is current), falls back to **wpa_supplicant**. netcfgd owns *policy* (which SSID, priority, metered, portal); the backend owns *radio*.
- **dhcp**: wraps `dhcpcd`/`udhcpc`, with an optional minimal built-in DHCPv4 for the no-deps case.
- **wireguard / modem / dns handoff**: same protocol.

### 4.2 The reconciliation loop (the heart)

1. **Desired state** = compile(config). A pure function of the files. Deterministic.
2. **Observed state** = live snapshot from rtnetlink plus backend reports, cached to `/run/netcfgd/observed/`.
3. **Plan** = `diff(desired, observed)` → an ordered list of typed **actions** (`add_addr`, `del_route`, `assoc_ssid`, `start_dhcp`, `run_hook`…), each naming its reason and the differing field.
4. **Apply** = execute in dependency order (link before addr before route; carrier before dhcp), running hooks at phase boundaries, writing results back to `/run/netcfgd/`.

Reconciliation runs on demand (`ncfg apply`), on config change (inotify), and on netlink events. Because Plan is a first-class object: `ncfg plan` shows what would change *before* you commit; `ncfg status --drift` shows divergence from config, reported by default and reverted only where `on_drift = reconcile` is set; and applying an already-correct state is a no-op that runs no hooks.

### 4.3 The compiler/reconciler seam

Step 1 and steps 2–4 are two different programs wearing one binary:

- The **compiler** turns human-authored config — DSL parsing, includes, drop-in precedence, netifrc compat, validation — into a desired-state document. Pure, unprivileged, touches no hardware, and holds most of the *code complexity*.
- The **reconciler** takes a desired-state document and makes the kernel match it. Needs `CAP_NET_ADMIN` and netlink, holds most of the *risk*, but is comparatively simple and stable.

The interface between them is a serialized desired-state document, published at `/run/netcfgd/desired/<iface>.json` for introspection.

This seam earns its keep immediately, for the embedded target: a device can ship the reconciler **without the compiler** (§10.2), dropping the DSL parser, include resolution and netifrc compat — the largest and most string-heavy part of the codebase. That is the reason to build it now.

It also happens to be the natural attachment point for §11, should that ever happen, because a remote configuration source is just a compiler that runs elsewhere. That is a consequence, not a motivation. The seam is justified by the embedded tier alone and would be built identically if §11 did not exist.

### 4.4 Daemon-optional / oneshot mode

`ncfg up eth0` or `ncfg apply --oneshot` runs the exact same loader → plan → apply pipeline once, in the foreground, then exits. No daemon, no socket, no persistent process. You lose event-driven roaming and drift monitoring; you keep 100% of config semantics. This is how you run it in a container or from an initramfs.

### 4.5 Safe apply: commit-confirm

Changing network configuration on a machine you are connected *through* is uniquely dangerous, because a bad config severs the channel you'd use to fix it. Routers solved this decades ago (JunOS `commit confirmed`, Cisco `reload in`), and because Plan is already a first-class reversible object, netcfgd gets it nearly free:

```
ncfg apply --confirm-within 120
```

Apply the plan, start a timer, and **automatically revert to the last-good desired state unless explicitly confirmed** within the window. If you just broke your own SSH session, the box reverts and comes back on the old config two minutes later. No console cable, no truck roll.

This is a core local feature, valuable to anyone editing a remote server's routes, and it is specified here rather than in §11 because it has nothing to do with multi-host management. (It would also be the mechanism that makes remote pushes survivable, if §11 ever happens — but that is a later beneficiary, not the reason.)

### 4.6 What is on disk (principle 12, made concrete)

A default installation, in full:

```
/etc/netcfgd/
  netcfgd.conf              # global options
  conf.d/                # your config drop-ins
    10-eth0.conf
    20-wifi.conf
```

That is the entire filesystem footprint. There is no inventory directory, no hosts tree, no sites, no groups, no roles, no environments, no state database, no lock directory, no UUID-named files.

This holds on a controller too. A machine managing four hundred others has exactly this directory for its own network configuration, and keeps the tree describing those four hundred somewhere else entirely (§11.4). Being a controller is invisible in `/etc/netcfgd/`.

Directories that exist **only once used**:

| Path | Appears only when |
|---|---|
| `secrets/` | you store a secret with the `file` provider |
| `hooks/` | you write a drop-in hook (inline hooks need nothing) |
| `conf.d/nm/` | the NM shim is installed *and* a GUI has created a profile (§9.4) |

And the rule for §11 if it is ever built: an adopted device gains **one ordinary drop-in file** — `conf.d/50-fleet.conf`, with a header comment saying what wrote it and how to detach — plus one credential file. Not a directory tree. Not a new layout. Not a different config language. A file that looks exactly like the one you'd have written by hand, in the directory where your own files already live, because that is precisely what it is (§11.4).

**The mechanical test.** On a machine that has never used an optional feature, `find /etc/netcfgd` must produce output identical to the same machine running a build compiled with those features disabled entirely. If the two ever differ, the feature has leaked and the leak is a bug. This is a CI check against a fixture, not a code-review aspiration.

Runtime state, all in tmpfs, none of it authoritative:

```
/run/netcfgd/
  observed/<iface>.json  # what netcfgd currently sees
  desired/<iface>.json   # compiled desired state (introspection)
  lease/<iface>.json     # DHCP lease details
  plan.last.json         # most recent computed plan
  events.log             # append-only ring
  netcfgd.sock             # control socket
```

---

## 5. Lifecycle & hooks (the scriptability contract)

### 5.1 Phases

`pre_up → (backend assoc/lease) → up → post_up` … `pre_down → down → post_down`, plus event hooks: `carrier`, `lease`, `roam`, `portal`, `drift`.

### 5.2 The contract

Hooks are plain executables in any language, called with a stable environment, honouring exit codes:

```
NCFG_IFACE=wlan0
NCFG_PHASE=post_up
NCFG_SSID="HomeFiber"
NCFG_ADDR="192.168.1.23/24"
NCFG_GW="192.168.1.1"
NCFG_METERED=0
NCFG_LEASE=/run/netcfgd/lease/wlan0.json
NCFG_REASON="carrier_up"
```

A non-zero exit from a `pre_*` hook **aborts** the transition — you can veto a bring-up. `post_*` and event hook failures are logged, don't roll back, and surface in `ncfg status`. Hooks may be inline in a block or dropped in `/etc/netcfgd/hooks/<phase>/` (lexical order, netifrc-style). Everything a hook can learn is also in `/run/netcfgd/`, so hooks never need to call back into a daemon.

### 5.3 Why this beats NM dispatcher / networkd

Documented phases, defined env, meaningful exit codes, veto capability, and both inline and drop-in forms — versus NM's single coarse `dispatcher.d` bucket or networkd's near-absence of hooks. And because drift is an event, you can hook `on drift` to alert instead of being silently fought.

---

## 6. The control socket API (the real contract)

Everything above the daemon — CLI, TUI, GUI, NM shim, anything you write — speaks one protocol over `/run/netcfgd/netcfgd.sock`: newline-delimited JSON requests and responses plus a subscribe mode that streams events. Deliberately boring: no D-Bus, no IDL, no codegen, no bindings. You can drive it from `socat` and a shell script.

Verbs mirror the CLI (`status`, `plan`, `apply`, `up`, `down`, `reload`, `wifi.scan`, `wifi.connect`, `wifi.forget`, `secret.set`, `explain`), plus `subscribe`.

Two rules give this teeth. **It is versioned and stable:** a `hello` handshake negotiates protocol version; additive changes bump minor, breaking changes bump major and run in parallel through a deprecation window. **We are not allowed to cheat:** netcfgd's own TUI and GUI must be implementable over this socket alone. If our GUI needs something the socket can't express, the socket gets it, publicly and documented. That is what makes principle 9 real, and why the NM shim can be an ordinary unprivileged client rather than a privileged special case.

---

## 7. netcfgd's own clients: CLI, TUI, GUI

### 7.1 CLI (`ncfg`) — ships first, primary interface

Machine-readable by default (`--json` everywhere), human-friendly on a TTY.

```
ncfg status [iface]         # link, addr, routes, wifi, lease, drift
ncfg plan [iface]           # actions reconciliation WOULD take (no changes)
ncfg apply [iface]          # reconcile now (--oneshot, --dry-run, --confirm-within)
ncfg confirm                # confirm a pending commit-confirm window (§4.5)
ncfg up / down <iface>
ncfg reload

ncfg wifi scan [device]
ncfg wifi connect <ssid>
ncfg wifi list
ncfg wifi forget <ssid>

ncfg secret set/get/rm <name>
ncfg convert <netifrc-file>  # transpile legacy config -> native blocks
ncfg import nm|networkd|uci  # migrate from an incumbent (§16)
ncfg explain <iface>         # WHY it is in this state: desired vs observed, last plan, hooks
ncfg monitor                 # live event stream
```

`ncfg explain wlan0` is the debuggability showcase: compiled desired state, observed state, the last plan diff, hook exit codes, and current backend association — the whole causal chain in one screen.

### 7.2 TUI (`ncfg tui`) — the one that matters for servers

A full-screen client, because the machines that most need netcfgd are often reached over SSH where a GTK applet is useless and `nmtui` has long been the least-bad option. Panes: device list with live carrier/state; wifi scan with signal, security and remembered-markers, connect/forget inline; the live event stream; and the distinguishing one, a **plan preview pane** where you edit config, see the resulting action diff, and press a key to apply — with commit-confirm wired in, since this is exactly the context where you're one bad route away from losing the session. Must work in 80×24, over a slow link, without a mouse, degrading gracefully without unicode or colour.

### 7.3 GUI and tray applet — last, deliberately

A desktop GUI and tray applet (the `nm-applet` replacement: signal strength, click-to-connect, PSK prompt, portal notification), toolkit-agnostic in principle with GTK and Qt front ends over a shared core. These come **last** by design (§9.2): a GUI is the most opinionated consumer of a data model, and building it early would tempt us to bend the core toward whatever the widgets found convenient. The applet also solves desktop secrets honestly, registering as a secret provider against `gnome-keyring`/`kwallet` without the core ever growing a keyring dependency.

---

## 8. *(retired in v0.4 — northbound interfaces are consolidated in §9)*

---

## 9. Northbound interfaces (optional, additive, late)

netcfgd has two audiences that already have tools they like, and neither should have to abandon them. Desktop users have NetworkManager applets; network-automation shops have RESTCONF/NETCONF orchestrators. Both are served the same way: **an optional adapter process, outside the daemon, that translates a foreign interface into netcfgd's socket verbs.** Neither is in the core, neither is required, both are deletable without trace, and — the part that matters — **neither is permitted to shape the native model.**

The shared discipline is §9.2. The NM D-Bus shim is §9.1 and §9.3–9.5. The standards-based adapter is §9.6, and it is the one that also answers §11.

### 9.1 NetworkManager: why bother

There is a large installed base of perfectly good NM *clients* — `nm-applet`, `plasma-nm`, the GNOME Settings network panel, `nmcli`, and every "connect to wifi" widget in every minor desktop. They are not the problem; NM's daemon, config model and dependency tree are. Helpfully the ecosystem converges on one thing: **the D-Bus API**. GNOME-side clients use `libnm`, a client-side cache over that API; KDE's `plasma-nm` uses `NetworkManagerQt`, a Qt wrapper over the *same* API; `nmcli` is itself a libnm client. One D-Bus surface — not a library reimplementation — serves all of them, and `nmcli` doubles as a free scriptable conformance harness.

### 9.2 The sequencing discipline (applies to every northbound adapter)

The failure mode is specific: a foreign data model that is rich, opinionated and the adapter's most demanding consumer will seep inward until netcfgd is a reimplementation of it with different config files. For NM that means UUID-keyed profiles, activation semantics and the `a{sa{sv}}` settings blob; for RESTCONF it means YANG tree shapes and the IETF's lowest-common-denominator interface models. Same disease, same five structural defences:

**Ordering.** Built *after* the core model, config language and socket API are frozen. Too late to influence them. If a concept isn't already in netcfgd when the shim starts, the shim doesn't get to add it.

**Process isolation.** Separate executable, separate package (`netcfgd-nm`), depended on by nothing, deletable without trace.

**No privileged path.** An ordinary unprivileged client of the public socket with exactly the access `ncfg tui` has.

**The one-way rule.** No change to the core model, config language or socket API may be justified *solely* by an adapter's needs. Either it's independently good for netcfgd, argued on its own merits, or the adapter does without and reports the gap honestly. This goes in CONTRIBUTING, because it is the defence that erodes silently. It binds the NM shim, the RESTCONF adapter, and anything in §11 equally — **netcfgd's model is never redefined by what NM, YANG or the IETF's interface models would prefer.**

**Dependency containment.** D-Bus and glib for the NM shim; any YANG/XML/SSH machinery for the RESTCONF adapter. Both are dependencies of their own package only. The core's dependency manifest must not gain an entry — a mechanically checkable CI assertion.

### 9.3 What the shim actually is

A stateless translator. It claims the well-known bus name `org.freedesktop.NetworkManager`, synthesises NM's object tree from netcfgd state, and converts inbound calls into socket verbs.

| NM object path | Interface | Sourced from |
|---|---|---|
| `/org/freedesktop/NetworkManager` | `org.freedesktop.NetworkManager` | daemon state, device list |
| `…/Settings` | `…NetworkManager.Settings` | compiled profile set |
| `…/Settings/{n}` | `…Settings.Connection` | one netcfgd `network {}` / `interface {}` block |
| `…/Devices/{n}` | `…Device` + `.Device.Wireless` / `.Wired` | observed state per link |
| `…/AccessPoint/{n}` | `…AccessPoint` | wifi backend scan results |
| `…/ActiveConnection/{n}` | `…Connection.Active` | current activation |
| `…/IP4Config/{n}`, `…/DHCP4Config/{n}` (+v6) | respective | observed addrs/routes, lease JSON |
| `…/AgentManager` | `…AgentManager` | secret provider bridge |

It must also implement `org.freedesktop.DBus.Properties` with correct `PropertiesChanged` emissions and `org.freedesktop.DBus.ObjectManager` — NM implements ObjectManager, and libnm leans on bulk retrieval plus change signals to build its cache, so a shim that only answers direct property gets will pass `nmcli` and then hang in a real applet. *Exact ObjectManager root path to be confirmed against a running daemon during development.*

Easy to underestimate: NM's **enums are wire protocol** (`NMState`, `NMDeviceState`, `NMDeviceType`, `NMActiveConnectionState`, `NM80211ApFlags`/`WpaFlags`/`RsnFlags`) and must match numerically, because clients switch on the integers. Signal *ordering* matters too.

**UUID stability:** rather than storing UUIDs (state outside config files — forbidden), derive them as UUIDv5 over a fixed netcfgd namespace plus profile identity. Stable across restarts, reproducible from the same config elsewhere, invisible to netcfgd proper.

**Secrets:** clients register secret agents via `AgentManager` and expect to be asked for a PSK. The shim bridges this to §3.3 in both directions; an agent-supplied secret marked "save" is written through the active provider and the config gets an `@secret:` reference, never inline plaintext.

### 9.4 Where a GUI's edits go

**The GUI is just another editor of config files.** `AddConnection`/`Update` translate the settings dict into a native block written atomically under `/etc/netcfgd/conf.d/nm/`, marked machine-generated, followed by a `reload`. Your GUI-created wifi network is a plain text file you can diff and commit — something NM never gave you — and `ncfg plan`, drift detection and hooks apply identically with no second code path. Hand-written blocks outside that directory are exposed **read-only**: activatable, but `Update`/`Delete` returns a permission error the GUI already renders, so a stray click can't mangle your tuned `eth0`. Deleting the shim leaves those files behind, still valid.

Per principle 12, `conf.d/nm/` does not exist until a GUI actually creates something.

### 9.5 Honest tiering, and honest failure

- **Tier 1 (must work):** `nmcli` core verbs; `nm-applet` and `plasma-nm` for wifi scan, connect, PSK/EAP prompt, disconnect, signal display, wired up/down. The acceptance bar.
- **Tier 2 (best effort):** GNOME/KDE settings panels — profile editing, static IP, per-connection options.
- **Tier 3 (out of scope *for the shim*, reported as unsupported):** NM's VPN plugin architecture, ModemManager specifics, Wi-Fi P2P, team, OVS. Unmanaged features are exposed as `unmanaged`/`unavailable` — the honest NM idiom — rather than as broken managed objects.

**Tier 3 is a statement about the adapter, not about netcfgd** ([0036](docs/decisions/0036-the-shim-is-not-the-roadmap.md)). netcfgd is expected to grow VPN support, modem support and complete wifi — including forced-AP roaming of the pre-802.11k/v/r kind, which is still needed because standardised devices are not everywhere. NM's interfaces for those are not the shape netcfgd wants, and §9.2's one-way rule forbids letting an adapter's model reach inward, so the honest end state is a netcfgd that does considerably more than the shim projects. Reading this list as a roadmap is a mistake that has already been made once.

The `Version` property is a hazard since clients gate behaviour on it, so the shim reports a plausible recent NM version while exposing `org.netcfgd.Compat` (identity, real version, tier support map) for anything that wants the truth. **Mutual exclusion is free:** only one process can own a well-known bus name, so the shim and a real NM daemon cannot both run.

---

### 9.6 RESTCONF / NETCONF: the standards-based northbound

**What they are.** NETCONF (RFC 6241) is the IETF's standard protocol for programmatically configuring network devices — RPC over SSH, XML-encoded, with data models written in YANG (RFC 7950). Standard models cover precisely our domain: `ietf-interfaces` (RFC 8343), `ietf-ip` (RFC 8344), `ietf-routing`. RESTCONF (RFC 8040) is the same models and semantics over HTTP and JSON instead of SSH and XML. Between them they are what enterprise and carrier network automation actually runs on, and what Ansible's netcommon, ncclient, OpenDaylight and NSO all speak.

**Why it earns a place here.** An adapter that speaks RESTCONF makes a netcfgd host manageable by orchestration tooling that already exists, without netcfgd inventing anything. That is independently valuable for a single host in a netops shop — and it is also, per §11, the cheapest credible answer to multi-host management.

**The convergence.** NMDA (RFC 8342) extends NETCONF's datastore model in a way that maps onto §4.2 almost one-to-one:

| NMDA concept | netcfgd equivalent |
|---|---|
| `<candidate>` — staged changes, not yet active | the plan stage |
| `<intended>` — config after transformation; what the system should apply | desired state |
| `<operational>` — what is actually in use, including learned values | observed state |
| `:validate` capability | `ncfg plan` refusing broken config |
| `:confirmed-commit` — auto-revert after a timeout unless confirmed | `--confirm-within` (§4.5) |

We arrived at this decomposition independently, which is reassuring rather than embarrassing — it suggests the shape is forced by the problem. Two things are worth *borrowing* rather than merely mapping. NMDA's **origin metadata**, which tags each operational value with where it came from (statically configured, DHCP-learned, protocol-learned), is a genuine improvement on our lease-versus-static distinction and should be adopted natively in observed state. And `intended`/`operational` is arguably clearer vocabulary than `desired`/`observed`, though the latter reads better to a Terraform/Kubernetes audience; noted as a naming question, not a model change.

**Tiered mapping, and its limits.** The standard models are a lowest-common-denominator across hardware vendors and cannot express most of what makes netcfgd distinctive. So the mapping is explicitly tiered, exactly as the NM shim is:

- **Maps cleanly to standard models:** interfaces, addresses, routes, MTU, VLAN/bridge/bond, DHCP enable/disable, link status, counters. A generic tool gets real value with no netcfgd-specific knowledge.
- **Requires a netcfgd-specific YANG augment module:** wifi policy (SSID priority, metered, portal checking), backend selection, drift policy, secret references. Generic tools see opaque vendor extensions — which is the normal outcome; every vendor on earth augments these models.
- **Deliberately not writable over the adapter:** lifecycle hooks. A YANG model that accepts arbitrary shell from a remote client is remote code execution with extra steps. Hooks are *readable* through the adapter and writable only from local config. This is a security boundary, not an unfinished feature.

**Implementation order.** RESTCONF first: JSON over HTTP, no XML parser, no SSH stack, far less machinery. Full NETCONF is a later addition for sites that require it, and would lean on existing components (netopeer2/sysrepo, already packaged for OpenWrt) rather than reimplementing YANG. Either way: optional package, ordinary unprivileged socket client, never in the core, never in the nano tier.

#### 9.6.1 Is YANG just a key-value store?

No — and the answer matters, because it determines how much of netcfgd's model survives the trip.

YANG is a **typed, constrained, schema-validated tree**: nested containers, keyed lists, leaves and leaf-lists. On top of that structure it has a real type system (width-declared integers, `decimal64`, enumerations, unions, binary, regex-constrained strings, ranges, lengths), referential integrity via `leafref`, conditional presence via `when`, arbitrary assertions via `must` (XPath), cardinality via `mandatory`/`unique`/`min-elements`/`max-elements`, plus RPCs, actions and notification streams. It is genuinely modular — `grouping`, `augment`, `deviation`, `feature` — which is how vendors extend standard models without forking them.

So it is closer to "XML Schema plus database constraints plus RPC plus pub/sub" than to a key-value store. In some respects it is *more* expressive than netcfgd's config language (formal constraints, referential integrity, machine-checkable schemas); in others it is much less (no inline shell, no lifecycle phases, no secret indirection, no notion of a plan).

**None of which binds us.** The native model is defined first and stays authoritative; YANG is a *projection* of it, never its definition. Where standard models can express something, we map to them so generic tools work. Where they cannot, we augment. Where augmenting would be unsafe or meaningless, the adapter reports the gap honestly and refuses — the same Tier 3 behaviour the NM shim uses. If YANG cannot express a netcfgd concept, that is YANG's limitation to report, not netcfgd's cue to drop the concept. The one-way rule of §9.2 is what makes that stick.

---

## 10. Scaling down: the embedded target

### 10.1 What "embedded" concretely means here

**The 1 MB figure below is superseded.** Measured at M5 and found unreachable without giving up either the compiler or derived serialization; the install is 1.75 MB with every feature in, and that is the ratcheted budget. See [0024](docs/decisions/0024-one-binary-and-what-a-megabyte-would-actually-cost.md).

The reference target is an OpenWrt-class device: 16 MB flash (a built image leaves only single-digit megabytes free), 64 MB RAM, a slow MIPS or modest ARM core, frequently a **read-only squashfs root with a writable overlay**. 4 MB-flash devices are past end-of-life in OpenWrt and are explicitly not a target. The bar to clear is credibility against `netifd`, which is small, fast and already there.

### 10.2 Build tiers

Size is a **build configuration**, not a fork (principle 11). One codebase, compile-time features, three profiles:

| Profile | Contains | Binary budget | Use |
|---|---|---:|---|
| **netcfgd-nano** | reconciler, netlink, compiled desired-state consumer | **≤ 400 KB** | headless appliances, minimal images |
| **netcfgd-embedded** | + DSL compiler, netifrc compat, hooks, basic CLI | **≤ 1 MB** | routers, appliances |
| **netcfgd-full** | + TUI, all output formats, importers, full CLI | no hard cap | desktop, server |

These are **budgets to validate, not measurements** — nothing is built yet. They exist so "is it still small?" is a CI failure rather than an opinion.

The nano tier omits the compiler (§4.3), removing the DSL parser, include resolution, netifrc compat and most string handling — disproportionately the bulk of the *size*, since parsers are where formatting and error strings accumulate. Its honest cost: a nano device's stored config is the compiled document rather than readable text, so `cat` no longer explains it and you use `ncfg explain` over the socket instead. That is a real regression against principle 2, confined to a tier that is definitionally headless, and it is the reason §19.2 asks whether nano is worth shipping at all.

### 10.3 What compiles out, and what never does

Removable: DSL compiler and netifrc compat (nano only), hook runner, human-readable output formatting and help text, importers, TUI, and every optional backend (separate executables anyway — you just don't install them).

Never removable, at any tier: the reconciler, netlink handling, the desired-state model, drift detection, commit-confirm, and **`ncfg plan`**. Plan in particular must survive to the smallest build, because the value proposition is not being a black box — and a black box on an embedded device is worse than one on a laptop, since you have no console and no easy recovery.

### 10.4 RAM, flash wear, and read-only roots

**RAM:** target < 4 MB RSS steady-state for nano. The observed-state cache is bounded per-interface; the event log is a fixed-size ring in tmpfs.

**Flash wear:** nothing netcfgd writes routinely may touch flash. State lives in tmpfs. Only config changes — rare and operator-driven — hit persistent storage, written atomically (temp file + rename) so a power cut during a write cannot leave an unparseable config.

**Read-only rootfs:** config paths are build- and runtime-configurable. The idiomatic layout is a factory-default config baked into the read-only image, overlaid by writable runtime config; `ncfg reset` discards the overlay and returns to factory defaults.

---

## 11. Multi-host management: conform, don't invent

**Status: still not a scheduled goal.** What changed is the *approach*. The default answer is no longer "design a protocol and build a controller" — it is "speak a standard that already exists, and let other people's controllers drive us."

### 11.1 The RESTCONF answer (preferred)

A host that speaks RESTCONF with `ietf-interfaces`/`ietf-ip` plus a netcfgd augment module (§9.6) is already manageable at scale, today, by tooling that already exists: Ansible's netcommon, ncclient, OpenDaylight, NSO, or whatever a site has built. There is no controller to write, no adoption protocol to design, no telemetry format to invent, no wire schema to version, no dashboard to maintain.

The multi-host story becomes a single sentence — *we conform to RFC 8040* — and the work is one optional adapter that is **independently justified** by giving a single host a standard management interface. That last part is what makes this so much better than the alternative: the effort is not speculative fleet work, it is a feature that pays for itself on one machine and happens to scale to four hundred.

For the audience most likely to run hundreds of Linux hosts, this is strictly better than anything bespoke, at a small fraction of the cost.

### 11.2 What RESTCONF does not cover

It does not give you the Ubiquiti experience: L2 discovery and zero-touch adoption of a device that has never been configured, a graphical topology view, staged rollout coupled to firmware, or a dashboard an operations team watches all day. Those serve a different audience and are a layer *above* RESTCONF, not a substitute for it — a controller that drives standard RESTCONF southbound is an entirely ordinary design, and one that could manage other vendors' devices too, which a bespoke protocol never could.

Only if that experience is specifically wanted does §11.3 become relevant at all.

### 11.3 If a bespoke controller is ever built anyway

The seam is already there: a remote configuration source is **a compiler that runs somewhere else** (§4.3). It would resolve site intent, templates and per-device variables on a real machine, emit the same desired-state document the local compiler emits, and ship it down; the device reconciles it identically to a local file.

It would *not* be a firmware manager, image builder or device lifecycle platform (§1.5), and not a new authority layer inside the daemon — the receiving agent is an ordinary unprivileged socket client, exactly like the adapters in §9. Inventory, grouping, RBAC, audit and history live entirely on the controller; a controller can only express what a desired-state document can express, and any new concept must first justify itself as something a *local* user would want in their own config file. That test kills nearly all of it at the door.

Encoding, framing, authentication and encryption would be **out of scope for this document**, since you already have a protocol design tool for exactly that. netcfgd's responsibility would be limited to the document's schema and semantics — what fields mean, how versions skew, what a device must reject.

### 11.4 Two trees, never one (the binding constraint)

Multi-host configuration genuinely *does* want a directory tree — hosts, groups, sites, templates. That tree is legitimate and should be a good one. The constraint is not that it may not exist; it is that **it is a separate tree, and a machine's own configuration never lives inside it.**

So a machine that manages others has two entirely distinct bodies of configuration:

**`/etc/netcfgd/` — this machine's own network config.** Identical in shape everywhere: a laptop, a managed AP and the controller itself all have `netcfgd.conf` plus `conf.d/`. It never gains a host tree, a site directory, or a special self-entry. Whether the machine is a controller is invisible here (§4.6).

**A fleet tree — source material describing *other* hosts.** Exists only where you've installed the controller, and it is a path you point the controller at rather than a fixed location, since in practice it wants to be a git repository you own. Default `/etc/netcfgd-fleet/`, commonly `/srv/fleet/` or a checkout in `$HOME`:

```
/etc/netcfgd-fleet/
  fleet.conf                 # controller settings
  templates/
    ap-standard.conf
    switch-access.conf
  groups/
    aps.conf
    hq-wired.conf
  hosts/
    ap-lobby.conf
    ap-warehouse.conf
    sw-core.conf
```

Two rules keep that tree from degenerating into the thing you're trying to avoid.

**Directory position carries no meaning.** A host does not belong to a group because of where its file sits — it belongs because the file *says* `inherits = "aps, hq-wired"`. The tree is organisational convenience; reorganise it however you like and nothing changes semantically. Precedence is declared in the file you are already reading, not encoded in a path convention and a precedence table you have to memorise. This is the single biggest departure from `group_vars/`-style magic-by-path, and it is where most of the perceived messiness of existing config-management trees actually comes from.

**Same language, one dialect wider.** A host file in the fleet tree uses the identical blocks and keys as local config (§3.2), plus `inherits`, variables and templating, which are meaningless on a single host. One config language to learn. A fully resolved host file can be copied straight into a device's `conf.d/` and work unchanged — which is also the debugging story: `netcfgd-fleet render ap-lobby` prints exactly the file that device will receive.

**The controller manages itself like anything else.** If the controller is also a managed host it gets `hosts/controller.conf` like every other host, its agent receives a compiled document over a loopback path like every other device, and that document lands in its own `/etc/netcfgd/conf.d/50-fleet.conf` like every other device. The fleet tree is *input to a compiler*; `/etc/netcfgd/` is *this host's resolved truth*. Different kinds of object, never sharing a namespace, no localhost special case.

On the receiving side, an adopted device gains **one ordinary drop-in file and one credential file**:

```
/etc/netcfgd/conf.d/50-fleet.conf     # written by the agent; header says what wrote it
/etc/netcfgd/fleet.cred               # 0600 identity/credential
```

The drop-in is native netcfgd config text — the agent renders the received document back through a serializer, far cheaper than a parser — so it reads exactly like something you'd have written by hand and participates normally in drop-in precedence. Someone inspecting an adopted machine sees a readable config file in the directory their own files already live in. Detaching is deleting two files. Per principle 12 and the test in §4.6, a machine that never adopts is indistinguishable from one built without the feature.

(The nano tier is the exception, storing the compiled document rather than rendered text — consistent with §10.2, where that trade is already made for size.)

### 11.5 What already exists that it would reuse

Offline autonomy is structural rather than a feature: because the pushed config is a file, a device whose controller vanishes keeps running its last-good configuration indefinitely, across reboots. The controller would be for *management*, not *operation*. Commit-confirm (§4.5) already makes remote reconfiguration survivable. `ncfg plan` already means a controller could show the aggregate diff across a fleet before pushing anything. Ownership policy — whether local edits are permitted, refused, or merged with conflicts surfaced — is the one genuinely new concept, and it is a single enum.

### 11.6 Why the standards route also fixes the size conflict

v0.3 agonised over fitting a TLS stack into a 400 KB budget for a bespoke agent. That problem largely dissolves: RESTCONF is an *optional package on a machine that has room for it*, not a nano-tier requirement, and a nano device that needs remote management can be reached by whatever transport its deployment already has. The embedded tier and the management story stopped competing the moment management stopped being something netcfgd had to build.

---

## 12. Implementation: Rust

**Decided.** The daemon holds `CAP_NET_ADMIN`, parses kernel netlink messages, and would eventually parse input arriving from off-box — the historical shape of remote-exploit CVEs in network daemons. Memory safety is not a stylistic preference here.

C would reach a smaller binary (netifd-class, low hundreds of KB) but puts an unsafe parser on privileged and potentially network-adjacent paths. Rust gives safety with clean static linking; the cost is that binary size depends heavily on dependency discipline, which becomes a design constraint rather than an afterthought.

**Size posture.** `opt-level = "z"`, LTO, `codegen-units = 1`, `panic = "abort"`, static musl, symbols stripped. The dependency budget is severe: `serde_json` alone can consume a large fraction of the nano budget, so the nano tier uses a hand-rolled minimal codec while full builds may use the ergonomic path. Every added dependency is a size review as well as a supply-chain one, and both are CI-gated (§17).

**Security posture.**

- `#![forbid(unsafe_code)]` crate-wide, with unsafe permitted only inside a small, separately-audited netlink syscall wrapper that has its own review bar and its own fuzz targets.
- All parsers — netlink messages, config DSL, backend IPC, and any future wire format — are continuously fuzzed (`cargo-fuzz`) as part of CI, not as an occasional exercise.
- No dynamic allocation proportional to attacker-controlled length; bounded buffers with explicit limits at every parse boundary.
- Supply chain: `cargo-deny` and `cargo-audit` in CI, a pinned lockfile, a stated MSRV, vendored dependencies for reproducible builds, and a written policy that new dependencies require justification against both size and audit surface.
- Privilege separation is enforced in the design, not just the language: only the core holds `CAP_NET_ADMIN`; backends, adapters and hooks hold the minimum they need.

---

## 13. Security & privilege model

- **No polkit, no system D-Bus in the core.** Authorisation is unix-socket permissions: `/run/netcfgd/netcfgd.sock` owned `root:netcfgd`, mode `0660`. Group `netcfgd` may read status/plan; a separate `netcfgd-admin` group (or an `allow_apply` socket) gates state-changing verbs. That is the entire auth model.
- **Adapters inherit, never escalate.** The NM shim runs as a dedicated unprivileged user in the appropriate group. Installing it must not widen who can reconfigure the network — a merge-time review item, and the same standard would apply to any future agent.
- **Privilege separation.** Only the core needs `CAP_NET_ADMIN`. Backends run with the minimum they need. Hooks run as a configurable user, not blindly as root.
- **Secrets** never sit in world-readable config; `/run/netcfgd/` holds no secret material.
- **Config is the audit log.** Because all state changes come from files — hand-written or GUI-originated — `git log` on `/etc/netcfgd` *is* your change history.

---

## 14. Init-system integration (agnostic by construction)

`netcfgd` is a plain foreground-capable daemon (`netcfgd --foreground`) with a PID/notify option. No systemd primitives required.

**OpenRC:** `command=/usr/sbin/netcfgd`, `command_args="--foreground"`, `supervisor="supervise-daemon"`, `depend()` provides `net`. Existing `/etc/conf.d/net` feeds compat mode during migration.
**runit / s6 / dinit:** one-line run scripts.
**procd (OpenWrt):** first-class, since it is the embedded reference target.
**systemd (optional):** `Type=notify` with `sd_notify` — used if present, never required. netcfgd *replaces* networkd; it does not sit on top of it.
**No init at all:** `ncfg apply --oneshot` in a container entrypoint or initramfs.

`netcfgd-nm` is its own service, ordered after `netcfgd`, conflicting with `NetworkManager` however the local init expresses that.

---

## 15. How netcfgd compares

| Concern | NetworkManager | systemd-networkd | netifd (OpenWrt) | **netcfgd** |
|---|---|---|---|---|
| Source of truth | keyfiles **+** live state | `.network` **+** internal state | UCI files | **plain-text config only**; `/run` derived |
| Introspect without the tool | no (D-Bus) | no (`networkctl`) | partly | **yes** — `cat /run/netcfgd/observed/*` |
| "What will change?" preview | no | no | no | **`ncfg plan`**, at every build tier |
| Manual `ip` change | often clobbered | ignored/undefined | clobbered | **detected & reported**; revert only if opted-in |
| Safe remote reconfiguration | no | no | no | **commit-confirm auto-revert** |
| Core dependencies | D-Bus, polkit, glib | systemd (hard) | ubus/ubox | **none required**; netlink only |
| Runs without a daemon | no | no | no | **yes** (`--oneshot`) |
| Init system | assumes systemd | systemd only | procd | **any / none** |
| Hooks | coarse `dispatcher.d` | minimal | limited | **phased, typed env, exit codes, veto** |
| Embedded viability | no | no | **yes** | **yes** — ≤ 400 KB budget, CI-gated |
| Memory safety | C | C | C | **Rust**, `forbid(unsafe)` outside audited netlink |
| Existing GUI clients | native | none | none | **optional NM shim**; GUI edits land as readable files |
| Standards-based management | no | no | no | **optional RESTCONF/NETCONF adapter** (RFC 8040/6241) |
| Config dir footprint | scattered | `.network` files | UCI | **one file + one drop-in dir**, on every host including a controller |

---

## 16. Migration path

1. **Point at existing config.** `netcfgd --compat /etc/conf.d/net` — day-one netifrc parity.
2. **Transpile when ready.** `ncfg convert` → native blocks, review, drop compat mode.
3. **From NetworkManager:** `ncfg import nm` reads `/etc/NetworkManager/system-connections/` into blocks plus secret refs, optionally pinning `nm_uuid` so existing GUI clients keep their references across the switch.
4. **From networkd:** `ncfg import networkd` reads `.network`/`.netdev`.
5. **From UCI (OpenWrt):** `ncfg import uci` for the embedded path.
6. **Keep your desktop.** Install `netcfgd-nm` and your applet keeps working — drop it whenever netcfgd's own applet suits you, or keep it forever.

Every importer emits a report of anything it couldn't represent. Migration is never silently lossy.

---

## 17. Failure modes & testing

- **Backend crash:** core detects IPC EOF, marks the interface degraded, runs `down`/`carrier` hooks, retries with backoff. Wired links unaffected.
- **Shim crash:** nothing happens to the network; clients see the bus name drop and reconnect.
- **Config that breaks your own connectivity:** commit-confirm expires, device reverts to last-good, comes back on the old config (§4.5).
- **Config parse error:** `plan`/`reload` refuse to apply; last-good desired state stays in effect; error names file and line. No half-applied states.
- **Partial apply:** actions are ordered and idempotent; failure stops the plan, records progress in `plan.last.json`, leaves a re-runnable remainder. `ncfg apply` resumes cleanly.
- **Power loss during config write:** atomic temp-file-plus-rename means the old config survives intact.

**Testing.** The planner is fully unit-testable with no hardware, since desired state is a pure function of files and plan is `diff(desired, observed)` — feed fixture configs and fake observed snapshots, assert on the action list. Integration tests run in network namespaces with veth pairs; wifi against `mac80211_hwsim`. Shim conformance drives real `nmcli` and, under Xvfb, real applets.

**CI gates, all failing the build on regression:** binary size and RSS budgets per tier (§10.2); the §4.6 filesystem-footprint fixture; `cargo-deny`/`cargo-audit`; continuous fuzzing of every parser (§12).

---

## 18. Roadmap

*(Software release numbers below; not to be confused with this document's draft version.)*

| Version | Scope |
|---|---|
| **v0.1** | Core model, config language, reconciler; rtnetlink for wired static/DHCP; oneshot; CLI. |
| **v0.2** | Hooks contract; drift detection; `ncfg explain`; netifrc compat + `convert`; **commit-confirm**. |
| **v0.3** | Wifi via iwd (wpa_supplicant fallback); secrets providers; **TUI**. |
| **v0.4** | Plugins: WireGuard, bridge/bond/VLAN, DNS handoff; importers. **Desired-state model and socket API frozen here.** |
| **v0.5** | **Embedded tiers**: build profiles, size/RAM CI gates, procd, read-only-root support. |
| **v0.6** | **NM D-Bus compat shim**, tier 1, separate package. |
| **v0.7** | Shim tier 2; netcfgd's own **GUI + tray applet**. |
| **1.0** | Stabilise. |
| **v1.1 (last)** | **RESTCONF adapter**: `ietf-interfaces`/`ietf-ip` mapping + netcfgd augment module, hooks read-only. Deliberately the final piece — see below. |
| **later** | Full NETCONF (SSH/XML) if sites ask for it. |
| **someday, maybe** | A bespoke controller (§11.3) — only if the dashboard experience is specifically wanted. |

**The RESTCONF adapter is deliberately last**, after the desktop work and after 1.0. Since conforming to RESTCONF *is* the multi-host answer (§11.1), deferring it defers multi-host management to the very end — which is the intended consequence, not an oversight. netcfgd is a single-host tool first, and nothing before 1.0 should be shaped by fleet considerations. The seam that makes the adapter possible (§4.3) is built early for embedded reasons and costs nothing while unused.

The model freeze at v0.4 precedes every adapter, so none of them can shape it. Embedded tiers land before any adapter work so the size budget is a constraint that already exists rather than one we intend to impose later and won't.

---

## 19. Open questions for you

### 19.1 Decided
Language is Rust (§12). Multi-host leads with RESTCONF rather than a bespoke protocol (§11.1). Bespoke controller remains unscheduled and now needs a specific justification (the dashboard experience) rather than being the default plan.

### 19.2 Still open

0. **Adapter vocabulary.** Adopt NMDA's `intended`/`operational` terms in place of `desired`/`observed`? The standard's words are arguably more precise and would make the RESTCONF mapping self-documenting; `desired`/`observed` reads better to a Terraform/Kubernetes audience. Cosmetic, but it propagates into paths (`/run/.../operational/`) so it is cheaper to decide now.

1. **Native syntax flavour.** Blocks (`interface eth0 { config = ... }`) versus literal netifrc-style variables (`config_eth0="..."`) in the native format too. Which?
2. **Nano tier at all?** It is the one place principle 2 bends — stored config is compiled rather than readable (§10.2). Worth the build-matrix complexity and the philosophical exception for a differentiator against netifd, or should the floor be `netcfgd-embedded` at ~1 MB with the DSL always present and `cat` always working?
3. **Built-in DHCP.** Ship a tiny built-in DHCPv4 for the zero-deps story, or always delegate and keep the core smaller?
4. **Drift default.** `report` (never touch manual changes) vs `reconcile` (enforce config). I chose `report`; agree?
5. **iwd vs wpa_supplicant default.** Prefer iwd where present, or default to wpa_supplicant for ubiquity?
6. **Core-owned link types.** bridge/bond/vlan/vxlan in the netlink core, WireGuard as a plugin — right cut?
7. **NM shim writes.** Writable-but-quarantined (§9.4) or strictly read-only — simpler and safer, but the applet feels broken when someone clicks a new SSID?
8. **NM shim ceiling.** Pursue tier 2 (full GUI profile editing), or stay permanently at tier 1?

---

*Draft v0.4 — structure and semantics are the proposal; names, key spellings and exact flags are negotiable. Next step, if the direction holds: a concrete config grammar (EBNF), the reconciler action taxonomy, and the desired-state document schema. Then a walking skeleton — rtnetlink watcher, planner, oneshot apply for wired static/DHCP — in Rust, with the size and footprint CI gates in place from the first commit, since budgets adopted later are budgets already blown.*
