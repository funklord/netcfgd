# 0126: The GUI is a build profile, because the C client is shared

Status: accepted
Date: 2026-08-20
Milestone: M8's desktop half

## Context

The Qt client built and installed (`make gui && make install-gui`) and was in
no package, so the audience it exists for -- somebody who does not understand
networking and wants a tray applet -- could not install it. `project.md` had
this under *Waiting on a decision* with the obstacle stated: putting the GUI in
the `netcfgd` source package would add `qt6-base-dev` to its `Build-Depends`,
and the daemon is meant to build on machines with no toolkit at all. Several
of its targets are routers.

The note there, and the answer given when this was raised, was that **splitting
the source package is the usual answer**. It is, and it turns out to be the
wrong one here.

## What ruled it out

A second source package has to be rooted somewhere, and the only candidate is
`gui/`, which is otherwise self-contained: its own Makefile, its own `.pro`,
its own `project.md`. It is not self-contained in the way that matters.
`gui/Makefile` names `CLIENT_DIR = ../client` and links
`../client/libncfg_client.a`.

`client/` is not the GUI's. It is the shared C frontend layer -- connections,
request matching, models -- and the daemon's own gates build it:
`make conformance` builds `client/tests/client_test` and compares the C
client's extraction against the Rust one, and `make cross` builds `client/`
for the cross target as one of its two halves.

So a source package rooted at `gui/` could not see `client/`, and would have to
carry a copy. **Two copies of one thing is the failure this tree keeps
finding** -- three spellings of an access point's name, two lists of installed
paths, five documents describing a `run_as` default that never existed. Buying
packaging separation with a duplicated C library is a bad trade, and the
conformance gate that compares two client implementations would then be
comparing one of them against a fork of itself.

## Decision

**One source package, and the GUI behind the build profile
`pkg.netcfgd.gui`.**

- `Build-Depends` carries `qt6-base-dev <pkg.netcfgd.gui>`, so the dependency
  applies only when the profile is active.
- The `netcfgd-gui` binary stanza carries `Build-Profiles:
  <pkg.netcfgd.gui>`, so the package is produced only then.
- `debian/rules` builds and installs the GUI under `ifneq (,$(GUI_PROFILE))`.
- `make deb` produces the daemon and the shim and needs no Qt. `make deb-gui`
  is the same recipe with the profile set, and refuses early if `qmake6` is
  absent rather than failing somewhere inside dpkg-buildpackage.

`pkg.<source>.<name>` is the namespace dpkg reserves for a source package's own
profiles, which is why the name is that and not a bare `gui`.

## The property, and how it was checked

The whole point is that a machine with no Qt can still build the daemon, and
that cannot be demonstrated by building on a machine that has Qt: the build
would succeed either way. So it was checked by making the restricted
dependency unsatisfiable -- adding a package that does not exist, under the
same profile -- and asking `dpkg-checkbuilddeps` twice. Without the profile it
is satisfied; with `-P pkg.netcfgd.gui` it reports the missing package. The
restriction is therefore doing the work, rather than being ignored while Qt
happened to be installed.

## Consequences

**One version and one changelog**, which is the other half of the gain. The
tree already keeps `VERSION`, `debian/changelog` and `Cargo.toml` in step
through `make version-check`; a second source package would have added a
second changelog to that list, and the netcfgd-gui package would have been
free to drift from the daemon it talks to. It now carries `netcfgd (=
${binary:Version})`, so the two are the same build by construction.

**The GUI package is produced only when somebody asks.** A Debian archive
build, or anybody running plain `dpkg-buildpackage`, gets the daemon and the
shim. That is correct for this project and would be wrong for one that wanted
its GUI in the archive -- if netcfgd is ever uploaded, this is the decision to
revisit, and splitting the source package properly would then mean moving
`client/` somewhere both could see it rather than duplicating it.

**No maintainer script, and none needed.** The package ships a binary and a
desktop entry, no unit, so it enables and starts nothing by construction.
`make deb`'s artifact check counts it as seen rather than inspected, which is
what keeps its "checked nothing" guard honest.

## Rejected

**A separate source package**, as above: it would duplicate `client/`.

**A negative profile** (`qt6-base-dev <!nogui>`, GUI built by default). It has
the defaults backwards for this project: a plain build would need Qt, and
every router build would have to remember to pass `nogui`. The thing that
should require no special knowledge is the daemon.

**Building the GUI with `dpkg-deb` from a staged install**, bypassing
debhelper. Rejected on the same grounds `build-and-commit.md` records: no
source package, no shlibdeps, and the Qt dependencies would be hand-written.
They are derived here -- `libqt6core6t64`, `libqt6gui6`, `libqt6widgets6` with
versions -- and nobody has to maintain that list.
