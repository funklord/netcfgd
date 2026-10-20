# 0276: the Rust NetworkManager shim is retired

Status: accepted
Date: 2026-10-21
Milestone: M9; the C port

## What this decides

`adapter/netcfgd-nm` has one implementation and it is the C one.

`make nm` builds `adapter/netcfgd-nm/c/netcfgd-nm`; `make install-nm` installs
that binary; the Debian package builds it with no Rust toolchain at all. The
Rust sources, its cargo workspace, its lockfile, its `deny.toml` and the
differential oracle that compared the two programs are deleted -- 10,034 lines
in one commit.

Decided by the copyright holder on 2026-10-21, in these words: "retire the Rust
shim, <- the less code we have, the less bug surface to maintain."

## What this supersedes

0266 shipped the C daemon and said, under *What is not retired, and cannot be*:
"`adapter/netcfgd-nm` is Rust and stays Rust ... 0264 decided its C replacement
is `libdbus-1` and 'not yet'." That is no longer the arrangement. 0266 still
governs the daemon and the client, including why the Rust core is kept; this
record changes the adapter only.

0264 set the condition under which it would change, and the condition was met
the day before this: `tests/live/nm.sh` is 0264's acceptance test, and the C
shim passed it 124 of 124 with the whole guest tier at 214 of 214 and seven
scripts of seven (project.md 10.503). 0264's own text and 0243's and 0229's and
0107's all describe the Rust in the present tense and are left exactly as they
are -- a record is not edited once accepted, and this is the one that overtakes
them.

## What the bar actually bought, and what it cost to keep

The two programs were kept side by side for four weeks because the C was proved
*by comparison*: `tool/nm-compare.sh` ran both shims against one fixture over a
private bus and diffed what `nmcli` saw. Every defect it found was invisible
from the properties -- a device whose `DeviceType` said wireguard while its
introspection document said ethernet, a `Strength` formula the unit test agreed
with because one hand wrote both, a `GROUP_CCMP` colliding with `KEY_MGMT_PSK`
so a WPA3 network rendered as "WPA2 WPA3".

That oracle dies with its subject. It is the real cost of this decision and it
is named here rather than in a note somebody has to find: **there is no longer a
second implementation to measure a C regression against.** What remains is
evidence of a different kind, and all of it was already running:

    tests/live/nm.sh             124 checks, driven by nmcli through libnm --
                                 a client's belief rather than a property read
    adapter/.../tests/bus_test   the dispatcher's tables, both stores' path
                                 contracts, the write authorization, the signal
                                 detectors, reached by `make nm-c-test`
    make vm-skipped              the guest tier, 214 checks over seven scripts

The distinction worth keeping is that the oracle answered "where do these two
differ", which is a question about an implementation, while these answer "can a
client do this", which is a question about the product. The second is the one
that mattered at the end: the last twelve defects this port fixed were found by
libnm refusing something, not by a diff.

## What the retirement removes, measured

    the Rust shim          8,736 lines of Rust, 16 files
    its dependency graph     102 crates in its own Cargo.lock
    the oracle               174 lines of shell
    cargo and rustc           out of debian/control's Build-Depends

**The C is bigger as source and that is not the saving.** 12,909 lines across
`src/` and `include/`, plus 1,615 of tests -- about 1.5 times the Rust for the
same bus surface, which is what C costs and what 0266 measured for the daemon
too. The saving is that there is one program to fix instead of two, and that a
D-Bus stack of 102 crates is replaced by one system library the distribution
already maintains. The shipped binary is 224 KB and links `libdbus-1` and
`libc`.

## What this changes in the build, and the two gates it touched

**`make adapters` is gone**, with the `ADAPTERS` variable and the per-adapter
`cargo deny`/`cargo audit` loop. It existed to hold each adapter's own cargo
workspace to the core's bar, and there is no such workspace now. `make
nm-c-test` is the adapter suite.

**`nm-containment` keeps its first half and has a new second one.** The first
half -- the core's `Cargo.lock` against `deny.toml`'s allow list, which is
constraint 3 written down -- is unchanged. The second half existed because the
first proves nothing if no adapter has any dependencies to contain, and it used
to assert the adapter's lockfile held at least twenty crates. There is no
lockfile to count. It now asserts that the shim still takes D-Bus from the
system (`pkg-config --libs dbus-1` in its Makefile) and that no adapter has
acquired a `Cargo.lock` again, which is the only route by which the leak it
guards could come back. Both arms were seen to fail before this was committed.

**`tool/dbus_policy_gate.py` reads the C tables.** It parsed
`#[zbus::interface(name = "...")]` out of the Rust, and a served interface in
the C is a value of type `nmc_interface_t` -- the type the dispatcher routes
with and the introspection renderer walks, so the parse is anchored on the type
rather than on a string that looks like an interface name. That is what makes
0264's miss impossible rather than merely fixed: `org.netcfgd.Compat` is an
`nmc_interface_t` and cannot be overlooked, and `SecretAgent` is a `#define` the
shim builds a call from and cannot be counted as served.

It was left static rather than made to ask the program. Running
`netcfgd-nm --interfaces` would be the more decisive instrument and `nmc/bus.h`
argued for it, but it would add code to the shim for a gate's benefit and would
make the gate skip on a machine with no libdbus -- which is the machine where a
missing grant is only ever found by an operator with no network. The comment in
`bus.h` claiming the gate reads the program was corrected in the same change.

**The two extractions were measured against each other before the switch**: the
same 18 interfaces from both, plus `org.freedesktop.DBus.ObjectManager`, which
the C declares in its own tables because libdbus generates nothing and zbus did.
That is the strongest evidence available that repointing the gate lost nothing,
and it was only available on the one day both sources existed.

## What is not retired

The Rust core, for 0266's reasons, which are unchanged: it is the instrument
`make agree` compares the C daemon against. The Qt client is C++ and the TDE
adapter is C++ over cmake; neither was affected.

`NCFG_NM_SHIM` stays in `tests/live/nm.sh`. It pointed the acceptance test at
the other binary while there were two; what it is for now is pointing it at a
build somewhere else -- an installed `/usr/bin/netcfgd-nm`, or a tree a bisect
left in another directory.
