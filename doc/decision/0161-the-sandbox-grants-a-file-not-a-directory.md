# 0161: the sandbox grants a file, not a directory

Status: accepted
Date: 2026-09-06
Milestone: reported from a machine where `write_resolv_conf` could not write

## Context

`netcfgd-dns`'s `replace` is the standard atomic file swap: stage a dotfile
beside the target, `rename` it over. Every resolver file netcfgd owns goes
through it.

`packaging/systemd/netcfgd.service` sets `ProtectSystem=full`, which mounts
`/etc` read-only, and names what must stay writable:

```
ReadWritePaths=/etc/netcfgd
ReadWritePaths=-/etc/resolv.conf
ReadWritePaths=-/etc/dnsmasq.d
ReadWritePaths=-/etc/unbound/unbound.conf.d
```

Three of those are directories and are writable through and through. **The
`resolv.conf` line grants one file**, and staging a temporary beside it is
creating a new entry in `/etc`, which stays refused. So `write_resolv_conf`
failed on every systemd machine, with a permission error naming a dotfile the
operator has never seen, for a file they had explicitly made writable.

Reproduced with the mounts the unit actually produces, inside a user and mount
namespace:

```text
mount --bind        $work/sys $work/sys
mount -o remount,bind,ro $work/sys          # ProtectSystem=full
mount --bind        $work/writable $work/sys/resolv.conf   # ReadWritePaths

staging a temp beside it:  Read-only file system
writing the file itself:   ok
```

**A `chmod` does not reproduce it and this is the trap that was walked into.**
An unprivileged process refused write on a directory gets `EACCES`, which looks
like the same fault; root has `CAP_DAC_OVERRIDE` and walks straight through a
mode. It does not walk through a read-only mount. A first end-to-end check ran
under `unshare -rn` against a `chmod`'d directory, passed, and passed just as
happily with the fix reverted -- a vacuous pass caught only by running the
control.

## Decision

**Stage and rename where the directory allows it; write the file in place
where it does not.**

The fallback engages on `PermissionDenied` and `ReadOnlyFilesystem` only.
A full disk also fails to stage, and falling back there would truncate the
resolver's configuration and then fail to refill it -- an empty `resolv.conf`
is worse than an unchanged one.

**It gives up atomicity, and that is the trade.** A reader can catch an
in-place write half-done where a rename could not be caught at all. The
alternative is not writing, which is what happened before.

**It will not follow a symlink.** `/etc/resolv.conf` is a symlink into another
resolver's runtime state on a great many machines. The rename path *replaces*
such a link, which is what `write_resolv_conf` mode asks for -- the operator
has said netcfgd owns the file. `fs::write` would instead follow it and edit
systemd-resolved's or openresolv's own state, silently, and only on the path
where the sandbox makes the fallback engage. Measured with the guard removed:
the write succeeds and the resolver's file changes. It refuses and names the
situation.

**Existing files only.** The fallback opens what is there rather than creating.
A file that is absent needs a writable directory anyway, and pretending
otherwise would swap one confusing error for another.

## Alternatives rejected

- **`ReadWritePaths=/etc`.** Buys the atomicity back and gives away what
  `ProtectSystem=full` is for. The unit deliberately names four paths.
- **Staging under `/run/netcfgd` and renaming across.** `rename(2)` cannot
  cross filesystems, and `/run` is a tmpfs while `/etc` is on the root
  filesystem: `EXDEV`, every time.
- **Always writing in place.** Would lose the atomic replace for the three
  directory-granted paths, which do not need the fallback and are read by
  daemons that glob them.

## It is a property of the pattern, not of DNS

Reported alongside the original as applying to files the GUI writes too, and
the tree agrees in shape if not yet in fact. `netcfgd-host`'s
`write_atomically` stages and renames exactly as `replace` does, and it is
what every `config put`, `secret set`, `profile save` and `control set` goes
through -- so it is what the GUI's write verbs reach through the socket.

**Measured against the packaged unit: those all work today.** `/etc/netcfgd`
is granted as a whole directory, so staging inside it succeeds, and each verb
was driven under the real mounts to confirm it rather than reasoned about.
`/etc/resolv.conf` is the only path the unit grants as a file, which is why
DNS is where this surfaced.

**It is still fixed in both**, because the exposure is one `ReadWritePaths`
line away and the shape should not have to be rediscovered. Driven under the
tightest grant a hardened unit could write -- `/etc/netcfgd` read-only with
`netcfgd.conf` alone bound read-write -- `ncfg control set --observe any`
fails with `EROFS` without the fallback and writes with it.

**Two copies of one rule, and they cannot be merged where they are.**
`netcfgd-host` depends on `netcfgd-apply`, which depends on `netcfgd-dns`, so
sharing the helper would invert the graph. Each names the other. A home both
could reach is a structural change and is not made here.

While confirming that, a third copy turned out to have gone: `write_atomically`'s
comment said it was one of two, the other being `netcfgd-nm`'s. `0d99c70` --
"ask netcfgd to write, rather than writing /etc/netcfgd" -- removed that one
when 0127 made netcfgd the only writer of its own configuration, and the
comment had gone on describing it. Corrected to name `netcfgd-dns` instead.

## Consequences

- `tests/live/sandbox_writes.sh` makes the mounts and asserts the writes land,
  through both helpers. Its DNS checks go red with `replace`'s fallback removed
  and its config check with `write_atomically`'s, independently.
- The unit gains a comment saying a named path grants a file rather than a
  directory, because that is the fact the next reader needs and it is not
  obvious from the setting's name.
- The unit test in `netcfgd-dns` covers the `EACCES` half, which an
  unprivileged caller really does hit, and says in as many words that it
  reproduces the shape rather than the mechanism.
