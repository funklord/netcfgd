# netcfgd

A Linux network configuration daemon whose plain-text config is the single
source of truth, whose runtime state is greppable files in `/run`, and whose
behaviour is a visible reconcile loop: `ncfg plan` shows what would change,
`ncfg apply` makes it so. Terraform for interfaces, roughly.

You describe the network you want in `/etc/netcfgd/`. netcfgd compares that
with the network you have and tells you the difference before it changes
anything. Applying an already-correct state produces zero actions, runs zero
hooks and touches nothing.

Three properties, in the order they matter:

- **Config files are the only authority.** Everything netcfgd does traces to a
  file under `/etc/netcfgd/`. Nothing edits your configuration behind you, so
  the file you wrote is the file that is running.
- **It is not a black box.** `ncfg plan` prints the actions it would take and
  why each one exists, down to which desired field differs from which observed
  field. `ncfg explain` answers where a given address or route came from.
- **The core has no mandatory dependencies** beyond libc and the kernel. No
  D-Bus, no glib, no polkit, no systemd. Adapters that need those carry them
  in their own packages.

**Maturity:** substantially built, not yet proven, no release, interfaces not
frozen. What has and has not met real hardware is tracked in
[project.md](project.md) section 10 — read it before deploying this anywhere
you care about.

---

# Features

## Addressing

Every source composes rather than competing: an interface may hold a static
address, a DHCP lease and a SLAAC address at once, and each contributes what it
knows.

| | |
|---|---|
| static | `config = "192.0.2.10/24"`, IPv4 and IPv6, with optional peer address and preferred/valid lifetimes |
| DHCPv4 | `config = "dhcp"` — via `dhcpcd` or busybox `udhcpc` |
| DHCPv6 | `config = "dhcp6"`, stateful or information-only |
| SLAAC | `config = "slaac"`, with privacy extensions and a stable interface token |
| prefix delegation | a prefix delegated to one interface, subnetted onto others |
| IPv4 link-local | `config = "link_local"`, coexisting with routable addresses rather than as a timeout fallback |
| hostname | left alone, taken from the DHCP lease, or pinned in the config |
| MTU, MAC | set per interface, including a MAC policy of permanent, per-network or per-connection |

netcfgd speaks netlink directly — there is no `ip` invocation anywhere.

## Wireless

| | |
|---|---|
| WPA2 / WPA3 | a passphrase negotiates both by default; `proto` narrows it |
| open, OWE | `open = true`, or opportunistic wireless encryption |
| enterprise (802.1X) | PEAP, TTLS, TLS and PWD, with identity, anonymous identity, CA and client certificates, and a phase-2 method |
| hidden networks | `hidden = true` |
| several saved networks | each its own `network` block; the supplicant picks which to join, `priority` biases it |
| access point | run one with `hostapd`: SSID, channel, band, regulatory domain, hidden, and a MAC allow/deny list |
| scanning | `ncfg wifi scan` lists what is in range, with signal and security |
| joining and leaving | `ncfg wifi connect ID` and `ncfg wifi disconnect`, keeping the configuration either way |
| radio on/off | over the control socket, which the GUI and the tray use; rfkill state is observed and streamed as events |
| privacy | `mac_policy` gives each network a fresh hardware address, or keeps the permanent one |
| power and regulatory domain | `powersave`, `scan_randomization` and `regdom` are understood and **not acted on yet** — `ncfg plan` says so where a config sets them |
| joining without an editor | `ncfg wifi add SSID` writes the block and stores the credential |

A network is a *place you sometimes are*, so it is a top-level block rather
than a property of a radio — which is what lets one machine carry many, and
lets a network be ranked against a cable (below).

## Wired, and 802.1X

Wired links are the default case and need no configuration beyond `config`.
Wired 802.1X runs on the same supplicant as wifi, and authentication is
ordered before addressing — a port that has not authenticated drops
everything, so a DHCP client started first would spend its whole backoff
talking to a switch that is not listening.

## Choosing an uplink

The point of the feature: a laptop should use the cable when it is plugged in
and the wifi when it is not, with no script and no command.

- **`preference` on an interface** ranks it. Higher preference wins while the
  link is usable, and its routes carry a lower metric.
- **`metric` on a wireless network** ranks *that network* against other links
  while the machine is on it — so "the office wifi beats this ethernet, the
  cafe wifi does not" is expressible, which a per-radio preference cannot say.
- **Link detection** decides *usable* by asking, not by trusting carrier. A
  cable plugged into a switch that has lost its own uplink has carrier and no
  path. A probe script per interface answers with its exit status, on an
  interval, with a timeout; a failing probe withholds that interface's routes
  exactly as an unplugged cable would.

Carrier is still used where it is the honest signal, and a probe is only
consulted where one is configured.

## Virtual interfaces and topology

Declared the same way as a physical interface, with a `kind`:

**bridge** (STP, forward delay, hello time, ageing, priority, VLAN filtering,
per-port PVID and tagged/untagged VLANs) · **bond** (mode, `miimon`) ·
**VLAN** (802.1Q and 802.1ad) · **VXLAN** · **veth** pairs · **macvlan**
(private, VEPA, bridge, passthru) · **VRF** · **dummy** · **IFB** ·
**tun/tap** (with owner and group)

## VPN, tunnels and DSL

| | |
|---|---|
| WireGuard | private key, listen port, fwmark, and peers with public key, preshared key, endpoint, allowed IPs and keepalive |
| OpenVPN | driven from an `.ovpn` file, with the credential kept out of it |
| IP tunnels | GRE, GRETAP, IP6GRE, IPIP, SIT, IP6TNL and GENEVE, with local, remote, TTL and key |
| PPPoE | for DSL: username, password, service name and access concentrator |

## Cellular modems

For LTE and 5G modules, with three helpers because one interface does not fit
every module:

- **MBIM** via `mbimcli`, where glib is already paid for.
- **MBIM via `umbim`**, for OpenWrt-class boxes where it is not — `mbimcli`
  pulls 6.77 MB of libraries beyond libc, which is several times the daemon.
- **AT commands**, for the large class of modules that offer neither MBIM nor
  QMI and appear only as a serial port.

A `modem` block carries the **APN** and an ordered list of **SIM sources**, so
a two-SIM device says which to try first. If a SIM's link fails its probe,
netcfgd falls back to the next and cycles the link so the change actually
takes effect, and the choice is sticky — a marginal primary does not flap.
The APN in effect is read back from the modem and reported, because a network
that substitutes its own default produces a link where ICMP works everywhere
and nothing else does.

A quirks table explains known modules rather than deciding for them, so a
module with no entry behaves identically and merely says less.

## Bluetooth

A `bluetooth` block per device, with a closed set of profiles: **PAN/NAP**
networking, and **A2DP** and **HFP** audio through `bluealsa` — ALSA only, no
PulseAudio. Adapters and devices are configured the same way networks are.

## Name resolution

DNS is a *scope*, not a global file to fight over. A network you joined
answers for its own domains rather than for everything, if you say so.

Modes: `write_resolv_conf` (needs nothing, the one to start with) ·
`resolvconf` · `openresolv` (the one that carries real scopes) · `resolved` ·
`dnsmasq` · `unbound` · `exec` (your own script) · `none`.

Per-interface or host-wide: servers, search domains, routing domains
(including exclusive `~domain` routing), and DNSSEC and transport settings
where the mode supports them.

## Routing policy and traffic control

Routes with next hop, metric, table, preferred source and `onlink`; **routing
rules** by source, destination, input and output interface, fwmark and mask,
suppressed prefix length and L3 master, resolving to a table or to blackhole,
unreachable or prohibit; **qdisc** and ingress bandwidth per interface; **NAT**
and **IP forwarding** per interface; router advertisement via `radvd`.

## Profiles

A profile is a directory of drop-ins layered over your configuration, so one
laptop can behave differently by location or preference.

```sh
ncfg profile list          # what this machine has
ncfg profile set office    # run one
ncfg profile save office   # write what is running back into a profile
ncfg profile unset         # back to no profile chosen
```

Switching is **manual only** — automatic switching invites a loop where a
profile changes the network and the changed network selects another profile.
The default is *no profile chosen*, which means the machine runs its own
configuration; that is not the same as the shipped `offline` profile, which
takes every link down deliberately.

Editing a setting by hand takes the machine off its profile and folds that
profile into your configuration in the same step, so nothing about the running
network moves — only the label. Nothing netcfgd writes for itself ever changes
the selection.

## Hooks

Shell run at `pre_up`, `up`, `post_up`, `pre_down`, `down`, `post_down`, and
on the `carrier`, `lease`, `roam`, `portal` and `drift` events. `pre_up` runs
*before* the link comes up, deliberately, and an already-correct interface runs
no hooks at all.

**A hook body ends at the first line containing only `}`.** netcfgd does not
parse the shell inside one, so it cannot tell your braces from its own -- which
means a shell function or brace group must not put its closing brace alone on a
line. Write

```
post_up {
greet() { echo hello; }
greet
}
```

rather than spreading `greet() {` and its `}` over three lines: the lone `}`
would end the hook there, and everything after it would be read as
configuration.

## Nothing changes until you say so

- **`ncfg plan`** prints every action, in order, with the desired and observed
  field that motivates each one. It changes nothing.
- **`ncfg apply --confirm-within 60`** arms a commit-confirm window: the change
  reverts on its own unless you `ncfg confirm`. This is what makes it safe to
  reconfigure a machine over the link you are connected on. `ncfg revert`
  undoes it immediately.
- **`global { confirm = 60 }`** says the same thing once, in the file, and
  covers the changes netcfgd applies by itself when it notices the
  configuration changed -- so editing the config over ssh gets the safety net
  without remembering the flag. Not at startup and not for a drift correction,
  for the reasons in [0157](doc/decision/0157-a-window-the-machine-arms-for-itself.md).
- **Drift policy** per interface or host-wide: `report` says the machine
  stopped matching the config and changes nothing, `reconcile` puts it back,
  `ignore` stops watching.
- **Ownership.** netcfgd removes only what netcfgd created, so an address you
  added by hand is not something it can delete.
- **Guards** refuse a disruptive action rather than performing it quietly —
  including one that would strand a credential nobody can revoke.
- **`device eth0 { managed = false }`** hands a device back entirely.

## Seeing what happened

`ncfg status` — what is observed now · `ncfg show` — the compiled desired
state · `ncfg explain` — why a given address, route or policy is as it is ·
`ncfg monitor` — a live event stream · a journal of applied actions, each with
its reason and its inverse.

Runtime state is greppable files under `/run/netcfgd/`, including a
per-interface report that DHCP clients, pppd scripts and VPN helpers write
into.

## Clients

| | |
|---|---|
| `ncfg` | the CLI: `plan`, `apply`, `explain`, `monitor`, `status`, `show`, `wifi`, `profile`, `secret`, `config`, `control`, `confirm`, `revert`, `reload`, `reset` |
| `ncfg tui` | a full-screen client over the public socket; 80x24, no colour required |
| Qt GUI | devices, wifi, DNS, profiles, secrets, modems, plan and events, with a tray icon that shows whether the machine is actually routed |
| NetworkManager shim | `nmcli`, `nm-applet` and `plasma-nm` talk to netcfgd through it |

Anything can be a client: the control socket's contract is written down in
[doc/socket-protocol.md](doc/socket-protocol.md), and a C frontend layer in
`client/` is there to build on.

## Permissions and secrets

Three tiers on the control socket — **observe**, **wifi** and **admin** —
grantable to a user, a group, anyone or root, and set separately for the local
socket and for remote connections.

**Secrets never enter the desired-state document.** It holds only a reference,
resolved from a file, the kernel keyring, `pass` or a program you name. That
holds for `/run` state and for anything sent over a wire, and the shim refuses
to hand a credential back out.

---

# Getting started

**[doc/first-run.md](doc/first-run.md)** takes a laptop from NetworkManager,
wired first, with every command checked. Start there.

## Install

```sh
make build          # release build
sudo make install   # the daemon and the CLI; honours DESTDIR

make gui            # the Qt client, if you want it
fmake               # the same client, from no build file
sudo make install-gui
```

[fmake](../fmake) is one Python file with nothing beyond the standard
library, so it builds the client on a machine that has not got this
project's toolchain set up. It covers the client and not the daemon: the
daemon and the CLI are a Cargo workspace of twenty-one crates, and fmake
drives `rustc` directly — one crate root, one artifact — so it resolves no
workspace, no inter-crate dependency and nothing from a registry. `make
build` is the way for that half.

Then pick your init: `make install-systemd`, `install-openrc` or
`install-procd`. Installing does **not** enable or start anything, and does
not decide that your other network daemons stop — that is a separate,
deliberate act, and `packaging/systemd/netcfgd-exclusive.conf` ships as
documentation rather than being installed.

## A minimal configuration

`/etc/netcfgd/netcfgd.conf`, plus `conf.d/` for drop-ins. Nothing else appears
on disk until a feature is used.

```ini
global {
	dns { mode = "write_resolv_conf" }
}

interface enp0s31f6 {
	preference = 100
	config     = "dhcp"
	dns        { }
}

network "YourNetworkName" {
	wifi { psk = "@secret:home" }
}
```

`preference` is how the cable wins while it is plugged in and wifi takes over
when it is not, with no command run. `dns { }` is not decoration: it is how
you say "use the nameservers this network hands out", because a network you
joined does not get to decide where your queries go unless you say so.

**[doc/netcfgd.conf.example](doc/netcfgd.conf.example)** documents every
feature with the syntax to use it, and is installed beside your config. Every
example in it is compiled by the test suite, so it describes a language
netcfgd currently speaks rather than one it used to.

## The first commands

```sh
ncfg plan                  # what would change, and why
ncfg apply --confirm-within 60   # do it, with a way back
ncfg confirm               # keep it
ncfg status                # what the machine looks like now
```

## What you need installed

**To build the daemon and the CLI** — Debian and derivatives:

```sh
sudo apt install build-essential cargo rustc libncurses-dev pkgconf python3
```

`rustc` must be **1.85 or newer**. Debian trixie's is exactly that; older
releases need rustup. `libncurses-dev` is for `ncfg tui` and is the only
library the daemon links beyond libc — `--no-default-features` drops both.
`python3` runs the style gate and several test scripts, not the daemon.

**To build the Qt client**, additionally `qt6-base-dev`. Note that the Qt
client links `libQt6DBus`, so the "no D-Bus" property above is the *core's*
and not the GUI's — that is Qt's own dependency rather than a choice made
here. The client is not in any package yet; `make install-gui` is opt-in.

**To cross-compile** (`make cross`), the linker for the target —
`gcc-aarch64-linux-gnu`, `gcc-arm-linux-gnueabihf` or `gcc-mips-linux-gnu` —
plus `rustup target add <triple>`, which a distro `rustc` cannot do.

## What you need at run time, and only if you use it

**None of these is required**, and nothing here is a package dependency.
netcfgd speaks netlink directly, so there is no `ip`, `iw` or `nft` in this
list — the programs below are ones it *manages*, each pulled in only by the
feature that needs it.

| feature | program | Debian package |
|---|---|---|
| DHCPv4, DHCPv6 | `dhcpcd` | `dhcpcd-base` |
| prefix delegation | `odhcp6c` | **not packaged in Debian** — see below |
| wifi, wired 802.1X | `wpa_supplicant` | `wpasupplicant` |
| access point | `hostapd` | `hostapd` |
| VPN tunnel | `openvpn` | `openvpn` |
| DSL / PPPoE | `pppd`, `pppoe` | `ppp`, `pppoe` |
| router advertisement | `radvd` | `radvd` |
| cellular, MBIM | `mbimcli` | `libmbim-utils` |
| cellular, MBIM on OpenWrt | `umbim` | **not packaged in Debian** — it is OpenWrt's, and is the point of that helper |
| cellular, AT modules | none — a serial port is enough | |
| Bluetooth audio | `bluealsa` | `bluez-alsa-utils` |
| DNS: `dnsmasq` mode | `dnsmasq` | `dnsmasq-base` |
| DNS: `unbound` mode | `unbound` | `unbound` |
| DNS: `resolvconf` mode | any `resolvconf` | `openresolv`, or `resolvconf` |
| DNS: `openresolv` mode | `resolvconf` | `openresolv` specifically |
| DNS: `resolved` mode | `resolvectl` | `systemd-resolved` |

**`odhcp6c` is the one gap and it is deliberate.** Debian does not package it,
and netcfgd needs it for prefix delegation specifically because `dhcpcd`
cannot report a delegated prefix to a script — so the two are not
interchangeable, and `ncfg plan` says so rather than taking a lease that goes
nowhere. On OpenWrt it is already there.

`resolvconf` and `openresolv` are two modes, not two spellings of one. The
first hands a flat per-interface blob to *any* implementation of the
`resolvconf` interface; the second uses openresolv's own `private_interfaces`
and subscriber mechanism, which is the one that carries DNS **scopes**.
`openresolv` is the mode to recommend where there is no systemd.
`write_resolv_conf` needs nothing at all, which is why it is where an ordinary
single-link host should start, and `exec` needs only the script you point at.

---

# Documentation

- **[doc/first-run.md](doc/first-run.md)** — a laptop from NetworkManager to
  netcfgd, wired first, every command checked.
- **[doc/netcfgd.conf.example](doc/netcfgd.conf.example)** — every feature
  with its syntax, and compiled by the test suite.
- **[doc/socket-protocol.md](doc/socket-protocol.md)** — the control socket:
  what a client sends, what the daemon answers, and what an implementation has
  to get right.
- **[doc/interface-report.md](doc/interface-report.md)** — the contract a DHCP
  client, pppd script or VPN helper writes into.
- **[project.md](project.md)** — the implementation brief and the
  authoritative record of intent, including current status, what is proven and
  what is not, and how to work in this repository. It wins over the code.
- **[netcfgd-design.md](netcfgd-design.md)** — the reference design, and where
  the rationale lives.
- **[doc/decision/](doc/decision/)** — 156 decision records, each a question
  that was settled and the measurement that settled it.
- **[code-style.md](code-style.md)** — tabs, `snake_case`, lowercase
  filenames, and the kernel commit format.

Where a document and the code disagree, that is a bug in one of them worth
raising rather than quietly resolving.

# Copyright

Copyright (C) 2026 Nabeel Sowan <nabeel@vibes.se>

**This is attribution and not a grant.** It says who wrote netcfgd, which is a
fact that vests automatically and gives nobody permission to do anything. What
you may do with it is the next section, and that is deliberately unsettled --
so this line must not be read as narrowing or widening it. `ncfg --version` and
`netcfgd --version` print the same line.

# Licence

Not yet settled, and deliberately not asserted here. There is no `LICENSE`
file, and no SPDX headers in netcfgd's own sources.
