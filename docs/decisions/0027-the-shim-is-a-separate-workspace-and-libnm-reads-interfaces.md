# 0027: The shim is a separate workspace, and libnm reads interfaces

Status: accepted
Date: 2026-07-31
Milestone: M7

## Context

M7 is the NetworkManager shim: serve NM's D-Bus API from netcfgd's state so
that `nmcli`, `nm-applet`, `plasma-nm` and every desktop network panel keep
working (design section 9.1). This is the first adapter, so it also settles how
adapters are built at all -- and it is the first netcfgd code with a dependency
tree rather than a dependency list.

Design section 9.2 sets the discipline and section 9.3 sketches the object
tree, leaving one question explicitly open: where NM's `ObjectManager` lives.

## Decision, part one: an adapter is its own cargo workspace

**`adapters/netcfgd-nm` is excluded from the root workspace and has its own
`Cargo.lock` and its own `deny.toml`.**

Section 9.2 requires the adapter's dependencies to be its package's only, and
the core's manifest never to gain an entry, "a mechanically checkable CI
assertion". A single workspace makes that assertion impossible to state: one
lockfile, one `cargo-deny` graph, and the honest answer to "may netcfgd depend
on this?" becomes "it depends which binary you mean".

The core's `deny.toml` lists **every crate netcfgd may depend on,
transitively**, and that list is twelve entries long. The shim needs about
ninety. Merging them would not weaken the rule so much as delete it.

So: two workspaces, and `make nm-containment` as the assertion. It does not
grep for `zbus` -- naming the thing to keep out only keeps that thing out, and
the next adapter brings something else. It checks the core's lockfile against
`deny.toml`'s allow list, so *any* new core dependency fails it, whoever
introduced it. It then checks that the adapter's own lockfile is not trivially
small, because "the core does not have the adapter's dependencies" is
uninteresting if the adapter has none either. Both halves were verified by
breaking them.

The measurement that matters: the core binary is byte-identical before and
after this commit.

### Why zbus, rather than writing D-Bus

The rule this project uses is to own its protocol encoders and link the solved
infrastructure. netlink is netcfgd's protocol; D-Bus is not. What netcfgd owns
here is the *NetworkManager interface* -- the object tree, the enum values, the
mapping from observed links to devices -- which is the part nobody else has
written. The marshalling, the SASL handshake and the bus routing underneath it
are somebody else's solved problem with a decade of other people's bug reports
in them.

zbus over the libdbus bindings because it is pure Rust: no C build dependency,
and `#![forbid(unsafe_code)]` holds in the adapter without an exception.

One consequence worth writing down: the adapter's workspace uses cargo's
resolver 3 where the core uses 2, because it is MSRV-aware. Without it the
first `cargo build` selected zbus 5.18, which requires rustc 1.87 against a
stated MSRV of 1.85 -- a routine dependency update silently raising the
compiler netcfgd needs is exactly the kind of drift a project with a size
budget and an embedded tier cannot afford to discover from a bug report.

## Decision, part two: what a device object is

**Every device carries exactly one per-kind interface, and `DeviceType` is
derived from that choice rather than chosen alongside it.**

This is the finding that justifies the whole live test. libnm does **not** read
the `DeviceType` property to decide what a device is. It builds its device
cache from the *interfaces present on the object*: `.Device.Wired` makes an
ethernet, `.Device.Wireless` makes a wifi device, `.Device.Loopback` makes a
loopback. A device object carrying only `org.freedesktop.NetworkManager.Device`
is not a device of unknown type -- it is a device libnm does not put in its
cache at all.

The first working version served six devices, correctly typed, with correct
properties, and `nmcli device status` listed one of them. The five that
vanished were the ones with no per-kind interface; the one that appeared was
the loopback, shown as an *ethernet*, because it had `.Device.Wired` and libnm
believed the interface over the number.

So there are four flavours -- loopback, wireless, wired, generic -- and
`type_of` is a function of the flavour, which makes the two incapable of
disagreeing. Everything netcfgd creates that is not a NIC (bridge, bond, vlan,
wireguard, tunnel, dummy, ifb) is `Generic` with a `TypeDescription` carrying
netcfgd's own link kind. `nmcli` then prints `probe0  dummy` in its TYPE
column, which is both honest and more informative than NM manages for the same
device.

That is deliberately not `.Device.Bridge` for a bridge. Claiming an interface
means implementing its properties, and a bridge object with none of them is a
worse lie than a generic device that says what it is. Those interfaces stay
free to be implemented properly later.

`.Device.Loopback` has no properties at all. That is not an omission here; the
real daemon's has none either. Its whole job is to exist so a client knows
which class to build.

## What was learned by pointing a real client at it

Design section 9.1 said `nmcli` would double as a free conformance harness. It
was worth more than that: **every defect in this commit was found by a client
and none by reading the specification.**

**The ObjectManager root is `/org/freedesktop`.** Section 9.3 left this as an
open question to be confirmed against a running daemon. It is confirmed: not
under NM's own object, one level above it. libnm calls `GetManagedObjects`
there to build its entire cache in one round trip.

**Requesting a bus name queues by default.** Section 9.3 says mutual exclusion
is free because only one process can own a well-known name. True of the bus,
and it was not true of this program: zbus's connection builder asks for the
name *without* `DoNotQueue`, so a second shim started while the first held the
name reported success, served nothing, and would have silently become the
machine's NetworkManager the moment the first exited. The live test found it by
hanging rather than failing -- which is why the two shim invocations in that
script now run under `timeout`, so a regression into waiting is a failed check
instead of a stuck suite.

With `DoNotQueue`, the bus's refusal arrives as an `Err` rather than as
`RequestNameReply::Exists`. Both are handled; only the error path is reachable
today, which was established the same way everything else here was -- by
breaking each one and seeing which test noticed.

**A link-local address is not connectivity.** An interface with no addressing
in the config showed as `connected`, because the kernel had given it an
`fe80::` address microseconds after it came up. Every dummy, every fresh bridge
and every just-plugged cable has one. `169.254.0.0/16` is the same idea in
IPv4, and it specifically means DHCP *failed*.

## The version is a deliberate lie

Section 9.3 calls `Version` a hazard and it is: clients gate behaviour on it,
so an honest "0.0.0" makes libnm decide half its API is unavailable. The shim
claims 1.44.0 and serves `org.netcfgd.Compat` alongside, carrying the
implementation name, the version being impersonated, and a map of which parts
of section 9.5's tiers this build actually serves.

Nothing has to ask, and `nmcli` prints a version-mismatch warning against any
number that is not its own, which no fixed choice avoids. The tier map is the
part that matters: it is how a client finds out that wifi scanning is not here
yet without discovering it through an empty list.

## What this commit does not do

Tier 1 (section 9.5) is `nmcli` core verbs plus applet wifi flows. This is the
device half of it: the object tree, the daemon state, and every device with its
properties. Access points, connections, activation and the secret agent bridge
are not here, and `org.netcfgd.Compat`'s `Supported` map says so by name rather
than leaving a client to infer it from silence.
