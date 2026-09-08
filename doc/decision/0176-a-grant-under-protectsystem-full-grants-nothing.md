# 0176: a grant naming what ProtectSystem= protects grants nothing

Status: accepted
Date: 2026-09-08
Milestone: M8; found with root on the machine 10.66 was written for

Supersedes the `ProtectSystem=full` half of
[0164](0164-the-grant-has-to-be-the-directory.md), and the alternative that
record rejected. 0164's decision that **the grant has to be the directory**
stands and is not in question here; what is overturned is the belief that
`ProtectSystem=full` plus `ReadWritePaths=/etc` delivers one.

## The report

*"We have been having trouble connecting to wifi consistently with netcfgd."*

The daemon had been saying why, on every start, for weeks:

    netcfgd: cannot write /etc/netcfgd (Read-only file system (os error 30)),
      so no client can store configuration: `ncfg wifi add`, `ncfg config put`,
      `ncfg secret set`, `ncfg profile save` and the gui's write buttons will
      all be refused
    netcfgd:   netcfgd is the only writer of that directory (0127). Under
      systemd this is `ProtectSystem=`, and the unit has to name the path in
      `ReadWritePaths=` -- `systemctl cat netcfgd` shows what yours says

That message is correct, it names the right knob, and following it leads
nowhere: `systemctl cat netcfgd` showed `ReadWritePaths=/etc` already there.
**A diagnostic that points at a setting which is already set reads as
already-actioned**, which is why this survived 10.60 writing the message,
10.66 writing a runbook whose first step greps for that very line, and two
decision records about the grant.

## The measurement

`systemd-run` on systemd 257, one invocation per row, each writing a probe
file and reporting the mount options it found:

    ProtectSystem=full    ReadWritePaths=/etc           -> /etc ro,  EROFS
    ProtectSystem=full    ReadWritePaths=/etc/netcfgd   -> /etc ro,  subpath rw
    ProtectSystem=yes     ReadWritePaths=/etc           -> /etc rw
    ProtectSystem=strict  ReadWritePaths=/etc           -> /etc rw
    ProtectSystem=no      ReadWritePaths=/etc           -> /etc rw

`ProtectSystem=` applies its read-only remount **after** the `ReadWritePaths=`
bind mounts, so an entry naming the very path being remounted is covered
straight back over. An entry *strictly below* one survives, because the parent's
remount does not reach into a mount nested underneath it.

The rule fits all five rows: **an entry equal to a protected path is inert; an
entry strictly below one is granted.** Under `strict` the only protected path
is `/`, so every entry is strictly below it and every entry works -- which is
why `strict` is not the exception it looks like.

## What it cost, and the shape is worth more than the instance

**0164 reverted 0131 while fixing nothing.** 0131 allow-listed four narrow
paths under `full` and they worked, being subpaths. 0164 consolidated them into
the single `ReadWritePaths=/etc` on the reasoning that "four redundant entries
would read as a narrower grant than the one in force" -- and consolidating a
set of working subpath grants into their common parent turned all four inert at
once.

So from 0164 onwards netcfgd could write **nothing** under `/etc`: not
`/etc/netcfgd`, so every client write 0127 built was refused again, exactly as
before 0131; and not the `/etc` directory, so `write_resolv_conf` could not
stage, exactly as before 0164. Two fixes undone by the change that was meant to
complete the second.

**Widening a grant is not monotonic**, which is the generalisation. Every
instinct says a wider allow-list can only permit more. Under a sandbox whose
protection is expressed as a mount, replacing several narrow grants with the
broad one that contains them can permit strictly less -- and it does so
silently, because both the unit and the sources still name the path.

## Why nothing caught it

Three checks looked at this and all three were satisfied.

- **`tool/sandbox_gate.py`** compared every `/etc` literal in the sources
  against the unit's allow-list, in both directions. Both lists named `/etc`,
  so both directions agreed. It was checking that two lists match, and they
  did match. What neither direction asked was whether the line *does anything*.
- **`tests/live/sandbox_writes.sh`** builds its own bind mounts to model the
  sandbox -- `mount --bind`, then `remount,bind,ro`, then a writable bind over
  the granted path. That models what the author believed `ReadWritePaths=`
  produces. Real systemd does not produce it for a path `ProtectSystem=`
  protects, so the test exercised an arrangement the unit never creates. Its
  functional checks pass under mounts of their own making, and its declaration
  check asserts the `ReadWritePaths=` line is *present*. Neither can fail on
  this.
- **The unit's own comment** quoted `systemd.exec(5)` correctly -- "If set to
  `full`, the /etc/ directory is mounted read-only, too" -- diagnosed the
  earlier `full`-versus-`strict` confusion accurately, and then kept `full` and
  tried to reopen `/etc` below it.

`sandbox_writes.sh` needs root and mount namespaces; the thing that would have
caught this needs neither. **It is a property of one file**, and it is now
checked as one.

## Decision

**`ProtectSystem=yes`, and `ReadWritePaths=/etc` stays.**

`yes` holds `/usr`, `/boot` and `/efi` read-only and leaves `/etc` alone, which
is the access 0164 decided netcfgd needs. The `ReadWritePaths=` line grants
nothing new under `yes` and is kept deliberately: it is what says which
directory the hardening was lowered for, and it is what a reader checks the
level against.

**`tool/sandbox_gate.py` gained the check that would have caught this.** It
carries `PROTECT_SYSTEM_READ_ONLY`, a table of what each level remounts, and
fails any `ReadWritePaths=` entry equal to a protected path. Static: no root,
no systemd, no namespace. Sabotaged by restoring `ProtectSystem=full` -- the
gate fails, naming the line and why -- and the sabotage was confirmed to have
landed before the result was believed.

## Alternatives rejected

- **`ProtectSystem=strict` plus a named grant.** Measured and wrong, and this
  is the row that decides it: `strict` takes `/run` and `/var/lib` too, leaving
  the supplicant no `/run/wpa_supplicant` for its control socket and dhcpcd no
  `/var/lib/dhcpcd`. netcfgd's children inherit this mount namespace, so a
  grant the unit does not make is one they do not get -- and the failure would
  arrive as a radio that will not associate rather than as an EROFS anybody
  could read.
- **Keeping `full` and reverting to 0131's four subpaths.** Measured to restore
  `/etc/netcfgd`, so the client writes work again -- but the `/etc` directory
  stays read-only, so `write_resolv_conf` cannot stage and 0164's actual
  problem returns. It fixes the half that was broken most recently and
  reinstates the half 0164 was written for.
- **A drop-in adding the grant.** Leaves every existing install broken until
  somebody copies a file, which is what 0164 rejected for the same reason.

## What it costs, stated rather than implied

Identical to what 0164 already accepted and stated: netcfgd may write any file
under `/etc`. `ProtectSystem=yes` holds `/usr`, `/boot` and `/efi` read-only,
and every other hardening line is unchanged.

0164 rejected this spelling as "same practical exposure, expressed as a lower
hardening level rather than a named path, so a reader cannot see why it was
lowered". **The exposure is the same and the access is not**, which is the half
that rejection assumed and nobody had measured. The readability objection was
real and is answered by keeping the `ReadWritePaths=` line and the comment
above it, rather than by a spelling that grants nothing.
