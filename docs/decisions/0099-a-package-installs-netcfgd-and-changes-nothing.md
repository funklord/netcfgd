# 0099: a package installs netcfgd and changes nothing

Status: accepted
Date: 2026-08-04
Milestone: something an evaluator can install

## Context

netcfgd could be built and it could be `make install`ed. It could not be
*handed to somebody*, which is what an evaluation needs: an installable package
that puts the right files in the right places and does nothing else.

Two formats, because netcfgd's documented init systems live on two
distributions and the project already treats that split as a decision rather
than a detail. `packaging/openrc/netcfgd` says "for Gentoo and Alpine";
`install-systemd`, `install-openrc` and `install-procd` exist as separate
targets precisely so that a machine gets the one it runs.

## Decision

**Installing configures nothing and starts nothing.** The systemd unit is
installed and left disabled; the OpenRC script is installed and not added to a
runlevel. No configuration file is shipped, so `/etc/netcfgd` arrives empty and
`ncfg plan` on a fresh install says *"no configuration found"*.

This is the packaging expression of what the whole daemon is for. A network
daemon that took over on `apt install` could take a machine off the network
before its operator had written a line — and netcfgd's shape is that it says
what it will do before doing it. The `postinst` prints the three commands that
follow instead.

**Each package ships one init file: its own.** The deb carries the systemd
unit, the apk carries the OpenRC script, and neither carries the other. That is
`make install`'s rule, unchanged — a systemd unit on a machine without systemd
is litter.

**Dependencies are derived, never written down.** The binary links `ncursesw`
behind a default-on TUI feature, which is exactly the kind of fact a hand-typed
`Depends:` gets wrong the first time it changes. `dpkg-shlibdeps` reads the ELF
and produces versioned dependencies; `abuild` does the same for Alpine. project.md
already carried "a container also needs `libncursesw6`, which is not obvious
from anything" as a thing learned by hand — the package now states it.

**Removal takes back only what the package put there.** `/etc/netcfgd` holds
the operator's configuration and, under `secrets/`, key material 0042 calls
irrecoverable. The package ships no file in there, so dpkg removes none, and
`postrm` does not either: the directory goes only if it is empty. Removing a
package is not an instruction to destroy the machine's configuration.

**Removal does not take the network down.** `prerm` stops the daemon; it does
not undo what the daemon configured. An interface does not go down because the
thing that brought it up was uninstalled.

**Two spellings of one version.** Debian takes `~`, which sorts before the
release it heads for, and accepts a commit hash: `0.0.0~git226.8b88f74`.
Alpine's grammar takes neither — a version is digits and dots with a `_git`
suffix — so it gets `0.0.0_git226`. Both increase with the commit count, which
is what an evaluator needs: a package built from a later commit must upgrade
one built from an earlier.

**The apk is built by `abuild`, in Alpine.** Not approximated here. `abuild` is
not packaged for Debian, so `make apk-container` runs the distribution's own
tool in a container — the same answer this project already uses for the
root-only live scripts. `make apk` remains the target for a real Alpine machine.
The source is `git archive HEAD`, so a package cannot be built from a dirty
tree.

## The gates

`make packaging` already checked that a path named by an init script is a path
that gets installed. It now also checks that every maintainer script **parses**
and is **executable** — a `postinst` without the executable bit is one dpkg
silently does not run — and that every `@TOKEN@` in a template is one some
recipe substitutes. An unsubstituted `@VERSION@` ships a package versioned
literally `@VERSION@`, which dpkg accepts and which sorts below every real
version.

Four breaks, all red: a script that does not parse, a script with its
executable bit cleared, a new placeholder nothing fills in, and the
substitution list going stale while a template still uses the token.

**And both packages were installed and exercised**, each in a clean container of
its own distribution — because a package that builds is not a package that
works, and every gate above would pass on one that installed to the wrong
prefix. Same script both times: install, both binaries run, `ncfg plan` on an
empty config says so rather than failing, the daemon starts and answers its
socket, a real config produces a real three-action plan, the init file is
present and not started, and removal leaves the binaries gone and the operator's
configuration untouched.

The first Debian run **failed usefully**: `dpkg -i` refused to configure the
package because `libncursesw6` was absent. That is the derived `Depends` doing
its job on the exact trap project.md records for bare containers. It also
exposed a defect in the test rather than the package — `dpkg -i ... | tail`
hides the exit status, so the fallback never ran.

## What is not done

**Nothing here has been evaluated on Alpine beyond installing.** The apk builds
with Alpine's toolchain and the package installs, runs and plans in a container.
No live test has been run on musl, and the suite's namespace tests have never
executed there. The package is real; the platform coverage is not, and this
records that rather than implying otherwise.

No signing key. `abuild` needs one, so the container generates a throwaway that
dies with it, and the apk installs with `--allow-untrusted`. A package for other
people to install needs a real key, which is a decision about who signs rather
than about packaging.

No repository, no `.changes`, no `dpkg-buildpackage` source package. What exists
builds a binary package from a working tree; uploading to a distribution is a
different piece of work with different rules.
