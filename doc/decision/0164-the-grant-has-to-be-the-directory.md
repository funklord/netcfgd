# 0164: the grant has to be the directory

Status: accepted
Date: 2026-09-06
Milestone: M8; reported from a second systemd machine where
`write_resolv_conf` still did not write

Supersedes the rejected alternative in
[0161](0161-the-sandbox-grants-a-file-not-a-directory.md), which declined
exactly this change on the day it was written.

## The report

"The writing of resolv.conf does not work on another systemd computer. If that
is configured you should take steps to ensure it is written."

0161 had landed hours earlier for the same symptom, so the first question was
whether that fix was absent or insufficient. It is insufficient, and the reason
is that it was reproduced against the uncommon shape.

## What 0161 left

It gave `replace` two paths:

1. **Stage a temporary beside the target and rename it.** Needs write on the
   directory. `ProtectSystem=full` mounts `/etc` read-only and the unit named
   `ReadWritePaths=-/etc/resolv.conf`, which grants the **file**, so this is
   refused.
2. **Write the existing file in place.** This one **refuses when the target is
   a symlink**, deliberately: writing through the link edits whatever owns the
   target, which is systemd-resolved's or openresolv's own runtime state.

Both are right on their own. **On a machine running systemd-resolved they do
not intersect**, because `/etc/resolv.conf` is a symlink into
`/run/systemd/resolve` there -- which is the default, not an unusual
configuration. Path 1 is refused by the sandbox and path 2 refuses by design,
so the mode could not work at all.

0161's prose names the symlink refusal and argues it from "the rename path
*replaces* such a link, which is what `write_resolv_conf` mode asks for". True,
and the rename path is precisely the one that never runs under the sandbox it
had just finished describing. **The two halves of that record are each correct
and were not put together.**

## Reproduced

With the mounts the unit actually produces, in a user and mount namespace, and
`/etc/resolv.conf` a symlink to a stub file the way systemd-resolved leaves it:

```text
FAIL dns.apply  dns: write_resolv_conf (was <absent>)
     .../resolv.conf is a symlink, and netcfgd cannot stage a replacement
     beside it (Read-only file system (os error 30)). ...
ncfg: stopped at action 0 (dns.apply); 0 done, 0 not attempted
```

resolv.conf untouched, and the whole apply stopped at the first action.

The same reproduction with `/etc` granted read-write instead: the link is
replaced by netcfgd's own file, the servers land, and the stub the link used to
point at is not written.

## Decision

**The unit grants `/etc`, not four paths inside it.**

```
ReadWritePaths=/etc
```

Replacing a symlink means unlinking it and creating a file, and both need the
**directory**. There is no narrower systemd grant that permits creating one
named entry: `rename(2)` requires write permission on the destination
directory, and staging under `/run` cannot be renamed into `/etc` because
`rename` does not cross filesystems -- the `EXDEV` that 0161 already rejected.

So the choice was to grant the directory or to leave the mode broken on the
machines most people run. **Put to the copyright holder with both costed, and
the grant was chosen.**

`/etc/netcfgd`, `-/etc/resolv.conf`, `-/etc/dnsmasq.d` and
`-/etc/unbound/unbound.conf.d` are subsumed and removed rather than kept: four
redundant entries would read as a narrower grant than the one in force.

## What it costs, stated rather than implied

netcfgd may write any file under `/etc`. `ProtectSystem=full` still holds
`/usr`, `/boot` and `/efi` read-only, and every other hardening line is
unchanged. This is a real reduction in what the sandbox contains, accepted
because a resolver that cannot write the file it was told to own is not a
working program.

**0161's in-place fallback stays**, and is not dead code: a hardened drop-in or
a read-only root still produces a directory netcfgd may not add to, and the
fallback is what writes a regular file there. Its symlink refusal stays too,
and is now the *only* thing standing between a narrow grant and netcfgd writing
into another resolver's state.

## Consequences

- `tests/live/sandbox_writes.sh` grew the case it never had. It modelled the
  sandbox faithfully and only ever with a **regular file**, so it was
  structurally blind to the reported machine. It now drives the symlink under
  the wide grant (replaced, servers land, the old target untouched) and under
  the narrow grant (refused, and nothing written through the link), and asserts
  the unit still grants the directory -- because every other check in the file
  makes its own mounts and would go on passing if the unit narrowed.
- Each new check was made to fail: narrowing the unit fails the two
  declaration checks, and removing the symlink guard fails the refusal, the
  readability and the not-written-through checks together.
- **The operator-facing message was mangled and is fixed.** It was a multi-line
  string literal with no continuations, so the tabs indenting the source were
  inside the string and an operator read the remedy with three tabs in the
  middle of it. A check asserts the line carries no tab, and it fails on its
  own when the old spelling is restored.

## Alternatives rejected

- **An opt-in drop-in adding the grant.** Keeps the tight default and leaves
  the reporting machine broken until somebody copies a file. Offered and not
  chosen.
- **`ProtectSystem=true`.** Same practical exposure, expressed as a lower
  hardening level rather than a named path, so a reader cannot see why it was
  lowered.
- **Following the symlink.** Edits another daemon's state, and that daemon
  rewrites the file anyway.
- **Replacing the link from a maintainer script**, which runs unsandboxed.
  Installing a package is not an instruction to seize the resolver, which is
  the rule `debian/prerm` already states in the other direction.
