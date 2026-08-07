# netcfgd

A Linux network configuration daemon whose plain-text config is the single
source of truth, whose runtime state is greppable files in `/run`, and whose
behaviour is a visible reconcile loop: `ncfg plan` shows what would change,
`ncfg apply` makes it so. Terraform for interfaces, roughly.

**Status: a proof of concept, substantially built and not yet proven.** Wired and wireless addressing,
DHCPv4/v6 and prefix delegation, WireGuard, PPPoE, OpenVPN, bridges, bonds,
VLANs and VXLANs, DNS scopes, access points, a control socket, a TUI, and a
NetworkManager shim are all implemented and exercised against real kernels and
real daemons. Interfaces are not frozen and there has been no release — and
nothing here has driven a real radio, run on the OpenWrt-class device it was
designed for, or been anybody's daily network configuration. `project.md`
section 10 keeps that list under *What would prove it*.

## Why it exists

Three properties, in the order they matter:

- **Config files are the only authority.** Everything netcfgd does traces to a
  file under `/etc/netcfgd/`. Nothing edits your configuration behind you, so
  the file you wrote is the file that is running.
- **It is not a black box.** `ncfg plan` prints the actions it would take and
  why each one exists, down to which desired field differs from which observed
  field. `ncfg explain` answers where a given address or route came from.
- **The core has no mandatory dependencies** beyond libc and the kernel. No
  D-Bus, no glib, no polkit, no systemd. Adapters that need those carry them in
  their own packages, enforced mechanically by `make nm-containment`.

Applying an already-correct state produces zero actions, runs zero hooks and
touches nothing.

## Getting started

**[docs/first-run.md](docs/first-run.md)** takes a laptop from NetworkManager,
wired first, with every command checked.

```sh
make build          # release build
make check          # the gates: fmt, clippy, tests, size, style
make test           # unit and fixture tests
make live           # scripted checks against real daemons
sudo make install   # honours DESTDIR
```

### What you need installed

**To build the daemon and the CLI** — Debian and derivatives:

```sh
sudo apt install build-essential cargo rustc libncurses-dev pkgconf python3
```

`rustc` must be **1.85 or newer** (`rust-version` in `Cargo.toml`). Debian
trixie's is 1.85, so it is exactly enough; older releases need rustup.
`libncurses-dev` is for `ncfg tui` and is the only library the daemon links
beyond libc — `--no-default-features` drops the TUI and with it that
dependency. `python3` runs the style gate and several test scripts, not the
daemon.

**To build the Qt client** as well:

```sh
sudo apt install qt6-base-dev
```

That one package is enough: it pulls `qmake6` and `qt6-base-dev-tools` (which
has `moc`) as dependencies, and it is what CI installs. At runtime the client
needs `libqt6widgets6`, `libqt6gui6` and `libqt6core6t64`, which `dpkg-shlibdeps`
works out for itself.

Worth knowing before you install it: **the Qt client links `libQt6DBus`**, so
the "no D-Bus" property above is the *core's* and not the GUI's. That is Qt's
own dependency rather than a choice made here, and it is one more reason the
client is a separate package from the daemon.

**To cross-compile** (`make cross`), the linker for the target — the table in
the `Makefile` maps triples to these:

```sh
sudo apt install gcc-aarch64-linux-gnu     # aarch64-unknown-linux-gnu
sudo apt install gcc-arm-linux-gnueabihf   # armv7-unknown-linux-gnueabihf
sudo apt install gcc-mips-linux-gnu        # mips-unknown-linux-gnu
```

The Rust half also needs a standard library for the target, which is
`rustup target add <triple>` and cannot be done with a distro `rustc`.

### What you need at run time, and only if you use it

**None of these is required**, and nothing here is a package dependency. netcfgd
speaks netlink directly, so there is no `ip`, `iw` or `nft` in this list — the
programs below are ones it *manages*, each pulled in only by the feature that
needs it.

| feature | program | Debian package |
|---|---|---|
| DHCPv4, DHCPv6 | `dhcpcd` | `dhcpcd-base` |
| prefix delegation | `odhcp6c` | **not packaged in Debian** — see below |
| wifi, wired 802.1X | `wpa_supplicant` | `wpasupplicant` |
| access point | `hostapd` | `hostapd` |
| VPN tunnel | `openvpn` | `openvpn` |
| DSL / PPPoE | `pppd`, `pppoe` | `ppp`, `pppoe` |
| router advertisement | `radvd` | `radvd` |
| DNS: `dnsmasq` mode | `dnsmasq` | `dnsmasq-base` |
| DNS: `unbound` mode | `unbound` | `unbound` |
| DNS: `resolvconf` mode | any `resolvconf` | `openresolv`, or `resolvconf` |
| DNS: `openresolv` mode | `resolvconf` | `openresolv` specifically |
| DNS: `resolved` mode | `resolvectl` | `systemd-resolved` |

**`odhcp6c` is the one gap and it is deliberate.** Debian does not package it,
and netcfgd needs it for prefix delegation specifically because `dhcpcd` cannot
report a delegated prefix to a script — so the two are not interchangeable and
`ncfg plan` says so rather than taking a lease that goes nowhere. On OpenWrt it
is already there.

`resolvconf` and `openresolv` are two modes and not one spelling of the same
thing. The first hands a flat per-interface blob to *any* implementation of the
`resolvconf` interface; the second uses openresolv's own `private_interfaces`
and subscriber mechanism, which is the one that carries DNS **scopes** — so a
network you joined answers only for its own domains instead of for everything.
`openresolv` is the mode to recommend where there is no systemd, and it shares
an upstream with the `dhcpcd` netcfgd already delegates leases to.

The `write_resolv_conf` mode needs nothing at all, which is why it is the one
an ordinary single-link host should start with. `exec` needs only the script
you point it at.

A minimal configuration is `/etc/netcfgd/netcfgd.conf` plus `conf.d/`. Nothing
else appears on disk until a feature is actually used.

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
when it is not, with no command run. `dns { }` is not decoration: it is how you
say "use the nameservers this network hands out", because a network you joined
does not get to decide where your queries go unless you say so.

Handing a device back to something else is `device eth0 { managed = false }`,
which stops netcfgd operating on it and changes nothing else.

## The pieces

| | |
|---|---|
| `netcfgd` | the daemon: watches config, reconciles, answers the control socket |
| `ncfg` | the CLI — `plan`, `apply`, `explain`, `monitor`, `wifi`, `reload`, `reset` |
| `ncfg tui` | five panes over the public socket; 80x24, no colour required |
| `crates/` | the Rust workspace: model, compiler, planner, netlink, apply, daemon |
| `adapters/netcfgd-nm` | a NetworkManager shim, so `nmcli` and desktop applets work |
| `gui/` | a Qt Widgets client, desktop and Android, over `client/` |
| `client/` | the C frontend layer any client can use: connections, models |
| `packaging/` | systemd, OpenRC and procd glue, plus Alpine packaging |
| `debian/` | Debian packaging, built with debhelper from `VERSION` |

Secrets are never stored in the desired-state document — only `SecretRef`
indirections into a file, keyring, `pass` or an exec provider. That holds for
local files, `/run` state and anything ever sent over a wire.

`#![forbid(unsafe_code)]` everywhere except `netcfgd-sys`, which is the single
audited exception and carries its own fuzz targets.

## Documentation

- **[project.md](project.md)** — the implementation brief, and the
  authoritative record of intent. It wins over the code.
- **[netcfgd-design.md](netcfgd-design.md)** — the reference design, and where
  the rationale lives.
- **[docs/decisions/](docs/decisions/)** — 116 decision records, each one a
  question that was settled and the measurement that settled it.
- **[docs/socket-protocol.md](docs/socket-protocol.md)** — the control
  socket: what a client sends, what the daemon answers, and what an
  implementation has to get right.
- **[docs/interface-report.md](docs/interface-report.md)** — the contract a
  DHCP client, pppd script or VPN helper writes into.
- **[code-style.md](code-style.md)** — tabs, `snake_case`, lowercase filenames,
  and the kernel commit format.

Where a document and the code disagree, that is a bug in one of them worth
raising rather than quietly resolving.

## Licence

Not yet settled, and deliberately not asserted here. There is no `LICENSE`
file, and no SPDX headers in netcfgd's own sources.
