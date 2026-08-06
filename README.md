# netcfgd

A Linux network configuration daemon whose plain-text config is the single
source of truth, whose runtime state is greppable files in `/run`, and whose
behaviour is a visible reconcile loop: `ncfg plan` shows what would change,
`ncfg apply` makes it so. Terraform for interfaces, roughly.

**Status: pre-1.0, and substantially built.** Wired and wireless addressing,
DHCPv4/v6 and prefix delegation, WireGuard, PPPoE, OpenVPN, bridges, bonds,
VLANs and VXLANs, DNS scopes, access points, a control socket, a TUI, and a
NetworkManager shim are all implemented and exercised against real kernels and
real daemons. Interfaces are not frozen and there has been no release.

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
| `ncfg tui` | four panes over the public socket; 80x24, no colour required |
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
- **[docs/decisions/](docs/decisions/)** — 114 decision records, each one a
  question that was settled and the measurement that settled it.
- **[docs/interface-report.md](docs/interface-report.md)** — the contract a
  DHCP client, pppd script or VPN helper writes into.
- **[code-style.md](code-style.md)** — tabs, `snake_case`, lowercase filenames,
  and the kernel commit format.

Where a document and the code disagree, that is a bug in one of them worth
raising rather than quietly resolving.

## Licence

Not yet settled, and deliberately not asserted here. There is no `LICENSE`
file, and no SPDX headers in netcfgd's own sources.
