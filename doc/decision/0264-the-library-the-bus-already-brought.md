# 0264: the library the bus already brought

Status: accepted
Date: 2026-09-18
Milestone: M9; the C port

## The question this answers, and the one it does not

`adapter/netcfgd-nm` is 8,699 lines of Rust over `zbus` 5. 0263 is the contract
the C port is written against and it names eleven modules; the adapter is not
one of them. So the question was asked directly: when the shim's turn comes,
does it link a D-Bus library, write the wire protocol by hand, or stay Rust?

**The answer is: link `libdbus-1`, and not yet.** The "not yet" is not a
hedge, it is where the dependency order puts it -- see *When*, below. What is
decided here is the answer for when it arrives, taken now because it is cheap
now and because the question is otherwise re-asked by whoever picks the module
up.

Nothing in this record is authority to write the module. 0263's *What is not
being decided here* still holds: the packaging ships the Rust.

## What the adapter actually uses, counted rather than remembered

Counted by walking every `#[zbus::interface]` block and attributing each `fn`
to the attribute above it, because "roughly forty properties" was the kind of
figure this record would have been read back with.

| interface | methods | properties | signals |
|---|---|---|---|
| `org.freedesktop.NetworkManager` | 6 | 24 | 0 |
| `...NetworkManager.Settings` | 6 | 3 | 0 |
| `...Settings.Connection` | 9 | 4 | 0 |
| `...Connection.Active` | 0 | 17 | 0 |
| `...AgentManager` | 3 | 0 | 0 |
| `...Device` | 0 | 31 | 0 |
| `...Device.Wireless` | 3 | 8 | 2 |
| `...Device.Wired` | 0 | 5 | 0 |
| `...Device.Vlan` | 0 | 4 | 0 |
| `...Device.Bridge` / `.Bond` / `.WireGuard` | 0 | 3 each | 0 |
| `...Device.Generic` | 0 | 2 | 0 |
| `...Device.Loopback` | 0 | 0 | 0 |
| `...AccessPoint` | 0 | 11 | 0 |
| `...IP4Config` | 0 | 13 | 0 |
| `...IP6Config` | 0 | 11 | 0 |
| `org.netcfgd.Compat` | 0 | 3 | 0 |
| **18 interfaces** | **27** | **145** | **2** |

That counts what is *exported*, which is the right question for a port and is
not quite the same as what was meant: one of `Settings.Connection`'s nine is a
private helper that reached the bus by accident, and is the first defect below.

**The shape of that table is the finding.** 145 properties against 27 methods:
this is a projection, not an RPC service. Four of the twenty-seven methods are
unconditional refusals with a sentence in them, and two more refuse whenever
the block was not one the shim wrote.

**Three more interfaces are served that are not in the table, and they are the
load-bearing ones.** `org.freedesktop.DBus.Properties`,
`.Introspectable` and `.ObjectManager` are implemented by `zbus` and named in
`packaging/dbus/netcfgd-nm.conf`, and the code says in three places why each is
not optional: libnm calls `GetAll` and treats a missing property as missing
from the daemon rather than from the shim (`manager.rs`); it calls
`GetManagedObjects` at `/org/freedesktop` -- not under NM's own object, a fact
`main.rs` records as confirmed against a running NetworkManager 1.52 -- to
build its entire cache in one round trip; and `tests/live/nm.sh` parses the
`Introspect` XML of four object kinds and fails on malformed output.

`GetManagedObjects` is the one that constrains an implementation rather than
merely appearing in it. It serialises every property of every interface of
every object into one `a{oa{sa{sv}}}`, so every getter has to be reachable
generically. That forbids a dispatch built from `strcmp` chains per object and
requires a property table -- which is a design consequence, not a coding style.

**Signals are emitted two ways, deliberately.** Registering an object *is*
`InterfacesAdded`, and `main.rs` says there is no second code path on purpose.
On top of that the shim emits `AccessPointAdded`/`Removed` explicitly, and
eight `*_changed` calls for properties that are computed rather than stored --
`AccessPoints`, `ActiveAccessPoint`, `LastScan`, `Connections`,
`ActiveConnections`, `PrimaryConnection`, and each device's
`ActiveConnection`. `zbus` cannot know those moved. Neither could anything
else; this is the adapter's own bookkeeping and it ports unchanged.

**The type set is nearly the whole of D-Bus.** Observed in the served
signatures: `y b q i u x t s o v`, and `ao au as ay aay aau a{sv} aa{sv}
a{sa{sv}} a{sb} a(ayuay)`, and the struct `(uu)`. Absent: file descriptors,
doubles, and signatures as values. An implementation that supports what is
already used supports essentially everything except fd passing.

## The direction each thing goes

Inbound is the table. **Outbound is four calls and they are what make the shim
a client of the bus as well as a server on it:**

* `org.freedesktop.DBus.RequestName` with `DoNotQueue`. Not a formality:
  `main.rs` records that requesting through the connection builder *queues*, so
  a second shim reported success, served nothing, and would have silently
  become the machine's NetworkManager when the first exited.
* `NameHasOwner`, to drop an agent whose process has gone, asked at the moment
  it matters rather than tracked through `NameOwnerChanged`.
* `GetConnectionUnixUser`, which is the whole security of the write path --
  `settings.rs` is explicit that a sender name is whatever the client put
  there and the bus's answer is not.
* `GetSecrets` on `org.freedesktop.NetworkManager.SecretAgent`, at the agent's
  own bus name and a fixed path.

## What the secrets agent needs that a plain method server does not

**Re-entrancy.** The other three outbound calls happen at connection time or
inside a write that has nothing waiting on it. `GetSecrets` does not: it is
made from inside `ActivateConnection`, before that method returns, so the shim
is holding an inbound call open while it waits for a reply to an outbound one
on the same connection. A method server that is a strict receive-dispatch-reply
loop cannot do that at all.

**And the hazard it creates is in the protocol, not in the library.** 0106 and
0107 are that scar: `nmcli connection up` registers a secret agent of its own
and then activates, so the caller is blocked on the very reply it would have to
answer. It unwound at GDBus's twenty-five-second default, intermittently,
depending on which agent came first out of the list. The fix -- never ask the
caller -- is a property of the conversation and survives any transport. A port
inherits the fix if it ports the code; it does not inherit it from a library.

**One thing the port does *not* inherit is the job queue, and that is worth
saying out loud so it is not preserved by reflex.** `state::Job` exists because
a `zbus` method handler runs on the executor's thread and cannot touch the
object server or emit a signal -- `Job::Reload`'s comment records a `Delete`
that timed out after ten seconds waiting for a main loop that was waiting for
it. That is `zbus`'s blocking API, not D-Bus. An implementation owning its own
main loop can register and unregister inline. **Which makes the adapter port a
concurrency redesign rather than a transliteration**, and redesigning
concurrency while porting is how a tree acquires a different program with the
same tests. The queue is cheap and correct; keeping it is the safe default and
removing it is a separate change with its own evidence.

## Is sd-bus already there? No, and it is the wrong library anyway

**Nothing in this tree links systemd.** `grep` over the Makefiles, the C
sources and headers, `debian/control`, `debian/rules` and `APKBUILD.in` for
`libsystemd`, `sd-bus`, `sd_bus` and `systemd-dev` returns nothing. The only
systemd in the repository is unit files, which are text.

Measured on this machine, 2026-09-18:

    libsystemd.so.0      1,131,784 bytes
    libdbus-1.so.3         350,360 bytes

**libdbus-1 is not a new dependency on any machine that can run the shim.**
`dbus-bin` -- which `dbus-daemon` depends on -- depends on `libdbus-1-3`
exactly. The shim needs a system message bus to exist at all, so the library is
already installed by construction, everywhere the program can do anything.
Linking it adds zero packages.

**The non-systemd targets do not have the question.** `netcfgd-nm` is not in
`packaging/alpine/APKBUILD.in` at all -- that package is `subpackages=""` and
installs the daemon and the OpenRC script -- and `packaging/procd/netcfgd`
names nothing about it. The adapter ships to Debian, with a sysvinit script and
a systemd unit beside it. So "libsystemd on a procd router" is a hypothetical
about a target the adapter has never shipped to; and if it ever does, Alpine
and OpenWrt both package a D-Bus library and neither packages libsystemd.
sd-bus would buy a smaller API for a larger object on fewer platforms.

## The size

**Today:** the installed binary in `dist/netcfgd-nm_0.1_amd64.deb` is
**5,771,640 bytes**, statically carrying `zbus` and 88 other external crates.
For scale, the whole daemon is 2,972,192 -- the shim is nearly twice the
program it is a shim for.

**It is outside the ratchet.** `size-budget.txt` names one binary, `netcfgd`,
and `make size` looks for it under `target/release/`; the adapter builds in its
own workspace under `adapter/netcfgd-nm/target/release/` and could not be found
even if it were named. So the 5.77 MB has never been gated.

**What C would cost, estimated with a density measured from this tree rather
than guessed:**

    c/src + c/include     76,999 lines -> 561,645 bytes text+data   7.29 B/line
    client/ (2 .c, 1 .h)   7,940 lines ->  57,182 bytes text+data   7.20 B/line

Two independent samples agreeing to within 1.3%. The shim is 4,463 lines of
production Rust (8,699 total, less 1,669 doc comments, 420 comments, 565 blank
and 1,582 lines of `#[cfg(test)]` modules). At 1.5 to 2 times for C, that is
6,700 to 8,900 lines, so **roughly 50-65 KB of text and data**, and a binary in
the low hundreds of kilobytes once the ELF and its strings are counted.

The point does not need three digits: it is the difference between 5.77 MB and
something under half a megabyte, against a shared library of 350 KB that the
machine already has. That is about 5.6 MB of installed size, which is more than
the core binary the whole project is measured on.

## Option (b), costed and refused

The tree does hand-write wire formats, and the precedent was taken seriously
before it was declined. The calibration:

    c/src/sys/wire.c        913 lines   the netlink codec
    c/include/ncfg/wire.h   359 lines
    c/tests/wire_test.c   1,028 lines   the adversarial cases

2,300 lines for a format whose type system is: an attribute is a type, a
length and a value; nests; fixed-width integers; 4-byte alignment. D-Bus is
strictly larger at every point. The smallest honest subset that serves the
table above:

| part | est. lines of C |
|---|---|
| marshalling both ways: signature grammar, per-type alignment, variants | 1,200-1,800 |
| header (`a(yv)`, nine fields), serials, framing, partial reads, both orders | 400-600 |
| SASL `EXTERNAL` over the unix socket, `NEGOTIATE_UNIX_FD`, `BEGIN` | ~120 |
| connection loop, dispatch, a reply awaited inside an open inbound call | 400-600 |
| `Properties`: `Get`, `Set`, `GetAll`, `PropertiesChanged` | ~250 |
| `Introspectable`: XML for 18 interfaces and 174 members | ~300 |
| `ObjectManager`: `GetManagedObjects`, `InterfacesAdded`/`Removed` | ~300 |
| object tree and registration | ~250 |
| **transport, total** | **3,200-4,700** |

Plus its adversarial tests, which 0263 requires in the same wave and which the
netlink codec sets the ratio for: another 3,500-5,000 lines. **Call it 7,000 to
10,000 lines to carry 4,463 lines of shim** -- a transport larger than the
program it exists for, and a second implementation of somebody else's format
with no users of its own to find its bugs.

**The argument that carried `wire.c` does not carry this, and that is the whole
refusal.** Netlink has no library alternative worth the name: the kernel is the
only source, netcfgd's own audited crate is where that boundary lives, and the
choice was to write it or not have it. D-Bus has a reference implementation
that is 350 KB, is on every machine where the shim can start, and is already a
hard dependency of the bus daemon the shim cannot work without. Writing it by
hand would buy nothing measurable and cost a fuzz target set nobody has time
for -- the tree's one hand-written binary wire format has one,
`fuzz/fuzz_targets/netlink_wire.rs`, and a D-Bus demarshaller would owe at
least as much.

**And constraint 3 already permits this in as many words.** "Core has no
mandatory dependencies beyond libc and the kernel... Adapters carry their own
dependencies in their own packages." The adapter carries 89 external crates
today -- 102 lockfile entries, thirteen of them netcfgd's own.
Going from 89 static crates at 5,771,640 bytes to one shared library at
350,360 that is already installed is a *reduction* in the dependency surface,
not a concession on the claim. The claim is about the daemon, it is checked by
`make linkage` against the daemon's own `NEEDED` entries, and nothing here
touches it.

## When, which is why (c) needs no decision

**0263's order has no slot for the adapter, and cannot.** The order runs base,
json, model, compile, sys, proto, host, plan, apply, daemon, cli. The shim is
an ordinary socket client: `client.rs` speaks `netcfgd-proto`'s `Request` and
`Response`, and `state.rs`, `settings.rs`, `device.rs` and `emit.rs` between
them read `Observed`, `ObservedLink`, `ObservedWireGuard`, `Document`,
`WifiNetwork`, `Interface`, `Route`, `DnsPolicy`, `Security`, `Ssid`,
`Principal`, `ScanEntry` and `connectivity::Rung`. That is most of the model
and all of the protocol. **The adapter is last, after `proto`, or it is a
second copy of the model** -- which is the thing 0263 refuses in its own words
about `ncfg_json.c` being compiled in rather than copied.

So the Rust shim goes on shipping, which is 0263's position already and needs
no record of its own. (c) is the state of the world, not a choice; the choice
is what replaces it, and it is (a).

## What has to change with it, named now so it is not discovered later

* **`make nm-containment` fails on a C adapter, for the right reason in the
  wrong words.** It requires `adapter/netcfgd-nm/Cargo.lock` to exist and to
  carry at least twenty dependencies, "because it is supposed to be containing
  a D-Bus stack". A C adapter has no lockfile and no stack to contain. The gate
  must be re-pointed *before* the Rust adapter is removed and not after, and it
  has an obvious successor: `make linkage` already reads a binary's `NEEDED`
  entries against `LINKAGE_ALLOWED` and refuses what constraint 3 does not
  allow. A second allowed list naming `libdbus-1.so` exactly, checked on the
  adapter's own binary, is a check on the artifact rather than on a manifest.
* **`size-budget.txt` gains its first second line.** The adapter has never been
  in the ratchet; a C one should be, since it would finally be a number worth
  ratcheting.
* **`debian/control` loses nothing and gains one name.** `netcfgd-nm` already
  depends on `dbus-system-bus-common`; `${shlibs:Depends}` picks up
  `libdbus-1-3` by itself.
* **The oracle needs no change at all, and it is the strongest one this module
  could have.** `tests/live/nm.sh` is 1,269 lines reaching the shim through 37
  `nmcli` and 45 `busctl` invocations, against a private bus in a private
  network namespace, with the
  shim on `--session`. It judges the shim by what libnm believes, which is a
  foreign witness rather than one of ours -- better evidence than the schema
  witnesses, which both implementations would derive from the same source. A C
  shim is right when that script passes unchanged but for a path.

## Three things found while reading, which are defects rather than design

**`Writable` is an exported D-Bus method that should be a private helper.**
`settings.rs:861`, `fn writable(&self, id: &str) -> zbus::fdo::Result<()>`,
sits inside the `#[zbus::interface]` block for
`org.freedesktop.NetworkManager.Settings.Connection` rather than in the plain
`impl` beside it -- which is the idiom the same file uses correctly for
`Settings::republish` and `Settings::authorize`. So `zbus` exports it, and the
bus policy grants sends on that interface to `context="default"`. Any local
process can call `Writable("anything")` and learn from the reply whether
`/etc/netcfgd/conf.d/nm-<sanitised>.conf` exists. It is the one method on that
interface with no authorization at all: `Update` and `Delete` both call
`caller_uid` and `may_write` and this does neither, because it was never meant
to be reachable. NetworkManager has no such method, so it is also a difference
a client introspecting the shim can see. **Not fixed here** -- this record
changes no code -- and it is a two-line move.

**`save`'s documentation contradicts its body.** Same file: the doc comment
says "# Errors / Always. Nothing here is ever unsaved, so there is nothing to
save", and the function returns `()` and succeeds by doing nothing, which its
own inline comment explains correctly. The `# Errors` section is left over from
the refusal it used to be.

**`tool/dbus_policy_gate.py` cannot see one of the interfaces it exists to
check, and two errors hide it.** Its docstring is "Every D-Bus interface the
shim serves must be named in its bus policy", and its extraction regex is
anchored to `org\.freedesktop\.NetworkManager`. So `org.netcfgd.Compat` -- an
interface the shim genuinely serves, at the manager path, deliberately, to tell
the truth `Version` cannot -- is invisible to it and is absent from the policy.
Meanwhile `org.freedesktop.NetworkManager.SecretAgent` is counted as served
when the shim only *calls* it. The gate prints "18 interfaces, all granted";
the served set is 18 too, but it is not the same 18. Nothing is broken today:
`Compat` has only properties, and properties are read through
`org.freedesktop.DBus.Properties`, which the policy does grant. It would break
the day `Compat` gains a method. The gate's own comments are about a check that
passes vacuously, which makes this worth reporting rather than passing over.

*Corrected before this record was filed.* The extraction now reads
`#[zbus::interface(name = "...")]`, which is the attribute that decides the
matter, and interfaces the shim calls rather than answers for are a named list
whose entries are checked for still appearing in the source. On its first
corrected run it asked for the `org.netcfgd.Compat` grant, which the policy now
carries. The count it reports is unchanged at 18 and is now the right 18 --
which is the part worth remembering: the total was never the thing that was
wrong.

## Not decided here

Whether the adapter is ported at all -- 0263 settles that no C is installed
until the comparison it describes has been made, and that comparison is a later
record. Whether the shim ever ships to Alpine or OpenWrt. And whether the job
queue survives the port, which is a question for whoever writes the main loop
and wants evidence rather than a preference.
