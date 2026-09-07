# 0173: a build that lost a feature says so, and so does a sandbox that refuses one

Status: accepted
Date: 2026-09-07
Milestone: M8; the packaged-install half of
[0171](0171-a-refused-write-says-what-refused-it.md), and the other end of
[0169](0169-a-manager-is-not-the-tools-it-drives.md)'s lesson that this tree
cannot see a machine it does not build on

## Two reports from one install

    netcfgd-tui is the same as netcfgd-gui, and there is no --tui argument

    could not write /etc/netcfgd/conf.d/wifi-EMP-XYLEM.conf: ... (Read-only
    file system (os error 30)) ... the unit has to name the path in
    `ReadWritePaths=`

The second is 0171's message working: it named the directory, the reason and
the setting, where the week before it would have said "No such file or
directory". The complaint is not the message, it is that the machine was in
that state at all and said nothing until a button was pressed.

The first is a feature that went missing without a word.

## What was wrong, and it is the same shape twice

**A build can lose the terminal frontend silently.** Everything about the TUI
is behind `NETCFGD_QTTY`, which `gui.pro` defines only when the vendored
`qtty` submodule is checked out *and* built. A clone without
`--recurse-submodules` produces a working GUI, no `--tui` option, and -- because
`install-gui` makes the symlink unconditionally -- a `netcfgd-tui` command
that opens a window. Every part of that is defensible on its own and the
combination tells the operator nothing.

**A daemon can be unable to write its own configuration and not mention it.**
0127 makes netcfgd the only writer of `/etc/netcfgd`, so a read-only mount
there refuses `wifi_add`, `config_put`, `secret_put`, `profile_save` and
`wifi_forget` -- all of them, one at a time, in front of whoever pressed the
button. The condition is true from the moment the daemon starts.

## Decided

**The binary refuses `-tui` when it has no TUI**, rather than opening a
window. The check is the same argv scan `want_tui` does, deliberately kept in
step: the two must agree about what "asked for the TUI" means, or the refusal
fires on a different set of invocations than the frontend would have. It runs
before `QApplication`, because somebody typing `netcfgd-tui` usually has no
display. It names the remedy -- `git submodule update --init` -- and says
which command is the window.

**`gui.pro` says so at build time too**, in the case that had no `else` at
all: a `QTTY_ROOT` that does not exist announced nothing. The other end of the
same fact, where whoever built it can still act on it.

**netcfgd probes its config directory at startup** and says, once, when it
cannot write: which directory, the kernel's reason, that no client can store
configuration, and that `systemctl cat netcfgd` shows what the unit grants.

**Asked by writing, not by reading a mode.** netcfgd is root, and root walks
through a mode; it does not walk through a read-only mount, which is what
`ProtectSystem=` imposes. `access(2)` and a `stat` would both answer *yes* on
exactly the machine this exists for.

**Only `EACCES` and `EROFS`.** A full disk or a colliding name is not this
check's subject, and a sentence about sandboxes in front of somebody whose
disk is full would be the wrong specific cause, which is worse than a vague
one.

## What this does not do

It does not diagnose *why* a unit lacks the grant. The shipped
`netcfgd.service` has carried `ReadWritePaths=/etc` since `aef7d4a`
(2026-08-21), so a machine without it is running an older unit, a drop-in that
overrides it, or a daemon that has not been restarted since the package
changed -- and this tree cannot tell which from here. Naming the mechanism and
the command that shows it is the honest stopping point; guessing at the cause
would be a diagnosis with an authority it has not earned.

## Measured

    the refusal      built with `QTTY_ROOT=/nonexistent`, `netcfgd-tui` exits 2
                     with the message, and `--tui` is refused the same way;
                     the ordinary build still lists `--tui` in `--help`
    the warning      a daemon under a read-only bind mount prints both lines;
                     the same daemon on the same directory with no mount
                     prints neither, and its startup line proves it ran

Not run by `make live`: the refusal needs a second full Qt build, which would
add about a third to that target's time for one message. The method is two
commands and is written above.
