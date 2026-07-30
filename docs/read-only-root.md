# Running netcfgd on a read-only root

On an OpenWrt-class device `/` is a squashfs and `/etc` is the writable half of
an overlay. The configuration an image ships and the configuration an operator
edits cannot live in the same place, because one of them is not writable.

netcfgd reads two directories: a **factory** layer that is part of the image,
then a **writable** layer on top. `ncfg reset` discards the second.

## The two directories

| | Default | What it is |
|---|---|---|
| Factory | `/usr/share/netcfgd` | Shipped in the image. Never written by netcfgd. |
| Writable | `/etc/netcfgd` | The operator's. Everything `ncfg reset` removes. |

Both are overridable, per run with `--factory-dir` and `--config-dir` or by
`$NCFG_FACTORY_DIR` and `$NCFG_CONFIG_DIR`. Neither has to exist: an ordinary
install has no factory layer, and a freshly flashed device has nothing in the
writable one.

Each directory is read the same way -- `netcfgd.conf` first, then
`conf.d/*.conf` in filename order.

## The factory layer gets no special rule

The factory directory behaves exactly as if its files sorted before the
writable ones. In particular there is **no implicit override**: a writable
block that redefines a factory block is the same error as one drop-in
redefining another.

```
netcfgd.conf:1:1: `interface eth0` is already defined
  help: first defined at /usr/share/netcfgd/netcfgd.conf:1; write
        `override interface eth0` to replace it
```

Replacing a factory block means saying so:

```ini
override interface eth0 {
	config = "10.0.0.5/24"
}
```

`override` replaces the block **wholesale**, so anything the factory set and
you did not re-state is gone -- including the `kind`. That is the same rule
`override` has everywhere else, and it is why the message names the file: the
two definitions are in different directories, so a line number on its own sends
you to the wrong one.

Adding a block the factory does not define needs no keyword.

## Resetting

```
ncfg reset
```

prints what it would remove and stops. Nothing happens without `--yes`:

```
ncfg reset --yes
```

It removes the files the loader reads from the writable directory --
`netcfgd.conf` and `conf.d/*.conf`, and nothing else. Secrets under
`secrets/`, disabled drop-ins ending in something other than `.conf`, and
anything an `include` points at are all left alone. An include may name a path
outside the config directory entirely, and deleting a file because something
mentioned it is not a thing a reset should do.

A running daemon notices by itself, the same way it notices any other config
edit. There is no reload to run.

**Two things it refuses or warns about.** Resetting when the config directory
and the factory directory are the same path is refused outright -- it would
delete the defaults it is meant to fall back to, and it is reachable through a
wrong `--config-dir` in a unit file rather than through a typo. And a reset
with no factory layer says so:

```
note: /usr/share/netcfgd holds no factory config, so this leaves netcfgd
with no configuration at all. The next apply would remove every address,
route and link netcfgd installed.
```

That is a legitimate thing to want. It is not a legitimate thing to discover.

## Flash wear

Nothing netcfgd writes routinely touches persistent storage. Observed state,
the last-good document, provenance and the control socket all live under
`/run`, which is tmpfs. The only writes to flash are config edits, which are
operator-driven, and they go through a temp file and a rename so a power cut
during one cannot leave an unparseable config.

The exception is DNS. `dns { mode = "write_resolv_conf" }` writes
`/etc/resolv.conf`, which on a read-only root fails. Either point it elsewhere
with `$NCFG_RESOLV_CONF`, or use a mode that hands the policy to something that
owns a writable location -- `resolvconf`, `openresolv`, `resolved`, `dnsmasq`
or `unbound`.

## Building an image

Put the defaults in the image at `/usr/share/netcfgd/netcfgd.conf` and leave
`/etc/netcfgd` empty. A device that has never been configured then comes up on
the factory configuration, an operator's changes land in the overlay, and
`ncfg reset --yes` returns it to the shipped state without reflashing.
