# 0043: MBIM is ours, and the quirks are a table

Status: superseded by [0044](0044-the-modem-helper-is-contained-the-way-an-adapter-is.md)
Date: 2026-07-31
Milestone: settles the fork 0036 named

> **Superseded.** The gate this record names in "The gate before any code" was
> checked and it fails: `wwan_hwsim` creates an AT port and nothing else, so an
> MBIM backend cannot be tested. 0044 follows the branch this record itself
> named for that case. What survives is the measurement, the reason
> ModemManager's only door is the bus, and the quirks-as-a-table shape.

## Context

Decision 0036 named the fork and deferred it: "ModemManager as a backend, which
is D-Bus and therefore an optional package by constraint 3, or QMI/MBIM
directly, which is large but keeps the dependency posture."

Both halves of that sentence turn out to be wrong in an informative way. QMI and
MBIM are not one thing and are not both large; and the reason to decline
ModemManager is not the one the sentence gives.

## What was measured

| | installed | needs |
|---|---|---|
| `modemmanager` | 4716 KB | polkit, libsystemd0, glib, gudev, **libqmi-glib5**, libmbim-glib4, libqrtr-glib0 |
| `libqmi-glib5` | 4667 KB | glib, libmbim-glib4, libqrtr-glib0 |
| `libmbim-glib4` | **920 KB** | **libc and glib, and nothing else** |
| `libmbim-utils` | 263 KB | libmbim-glib4 |

QMI costs five times what MBIM costs, and it is Qualcomm's rather than anyone's
-- MBIM is published by the USB-IF and is what Windows drives a modem with, so
every modem that ships for a laptop supports it. **QMI is dominated**: it is the
larger dependency, the proprietary protocol and the narrower hardware base at
once. It is not considered further here.

## The reason to decline ModemManager is D-Bus, and not systemd

This matters enough to state precisely, because declining it for the wrong
reason would be a record that misleads the next person to read it.

Debian's `ModemManager` binary really does link `libsystemd.so.0` and
`libpolkit-gobject-1.so.0` -- one `sd_journal` symbol and three
`polkit_authority` symbols. But both are build-time choices upstream offers to
turn off, and a distribution that cared could ship it without either. "It needs
systemd" is not true.

**D-Bus is not a build flag.** ModemManager has no unix socket, no control file
and no local interface of any kind: the system bus is the only door. That is the
difference from every other daemon netcfgd drives -- `wpa_supplicant` and
`hostapd` take a unix datagram socket carrying line-oriented text, `pppd` takes
an options file, `dhcpcd` takes a command line and a hook.

So integrating ModemManager means D-Bus in the **southbound** path. Today D-Bus
exists in this repository only northbound, in an adapter that is its own cargo
workspace with its own lockfile, and `make nm-containment` fails the build if
its dependencies reach the core (0027). Taking ModemManager as a backend would
put a D-Bus client on the other side of that wall, in the daemon itself.

Decision 0014 already declined iwd on exactly this reasoning, and the sentence
it used applies here without changing a word: a Rust D-Bus client "is either a
large crate tree or several thousand lines of hand-rolled marshalling, and
either would be, by a wide margin, the biggest thing in this repository".

## Decision

**netcfgd speaks MBIM itself, over `/dev/cdc-wdmX`, with no dependency.**

That is the same call this project has made every time the question came up,
and for the reason that keeps holding: a wire protocol nobody else speaks the
way netcfgd needs is a protocol encoder netcfgd owns, in the same category as
rtnetlink, nftables, the qdisc messages and WireGuard's generic-netlink family.
All of those together are **11,904 bytes of symbols** in the shipped binary.
MBIM's framing -- fragmentation, UUID-identified services, a command id per
message -- is bounded work of that shape.

The data path costs nothing extra. `cdc_mbim` presents an ordinary network
interface, and the bearer's reply carries the address, gateway and nameservers.
That lands on the model netcfgd already has: it is an address *source*, like
DHCP, where something outside the kernel is asked and answers. Decision 0006's
`addressing` list is where it goes.

## Split the way ModemManager splits, and take the split as data

ModemManager's value was never the protocol. It is `libmm-plugin-generic.so`
plus **43 vendor plugins, 10 shared helpers and 18 FCC-unlock entries** --
1.76 MB of accumulated knowledge about modems that do not do what the
specification says. Declining the dependency does not make that knowledge
untrue, and the shape it is stored in is worth copying.

Three things transfer:

**A plugin claims a device declaratively.** The keys are
`allowed-vendor-ids`, `allowed-subsystems`, `allowed-mbim`, `allowed-qmi`,
`allowed-qcdm`, `allowed-at` and `allowed-vendor-strings`. That is a *match
table*, not a program. netcfgd can carry the same thing as data -- a quirk
keyed on `vid:pid` -- and keep the code path single. A quirk expressed as a
table entry is one somebody can read, diff and contribute without touching
Rust; a quirk expressed as a branch is one that grows a second branch.

**Quirks cluster by chipset, not by brand.** The ten `libmm-shared-*` helpers
are the evidence: `xmm` is Intel's modem family, sold under Fibocom, Foxconn and
several other names, and they share a helper because they share the silicon.
A table keyed only on brand would carry the same entry a dozen times and drift.

**Firmware unlock is a hook, and netcfgd already has the phase.** MM ships
FCC-unlock scripts in an `available.d` directory that an administrator symlinks
to enable -- opt-in, per device, and deliberately not automatic, because
unlocking somebody's modem without being asked is not a networking daemon's
business. netcfgd's equivalent exists already: decision 0011 named "unlocking a
modem" as the example of what `pre_up` is for, and argued the ordering on the
strength of it. So this is not a feature to design. It is a hook, documented.

## What netcfgd will not claim

**Modems that need a vendor plugin are modems netcfgd does not handle**, and
the documentation will say which rather than failing in the field.

This is 0016's shape -- "which half of a supplicant could ever be ours" -- and
the honest version of the same trade. netcfgd gets the modems that follow the
specification, which is most of what ships in a laptop today, and states the
limit. An operator with a modem on MM's list has a working answer: install
ModemManager and let it own the device, with the interface `managed = false`.
That is what the flag is for.

Promising general modem support on the strength of a conformant-path
implementation would be the one outcome worse than not having it, because it
fails at the point where somebody is relying on a link that is their only link.

## The gate before any code, which is not size

A modem backend would be **the first thing in this repository with no live
test.** Every other integration is checked against a real kernel or a real
reference tool, and the record of that method is that it finds things reading
the encoder does not.

There is a candidate: **`CONFIG_WWAN_HWSIM`** exists in the kernel, and is the
modem equivalent of `mac80211_hwsim` -- which is what makes the wifi half of
this project testable at all. It is **not enabled in Debian's 6.12 kernel**
(`CONFIG_WWAN=m`, `# CONFIG_WWAN_HWSIM is not set`), which is the same shape of
finding as `ieee80211r` being absent from Debian's hostapd: a per-distribution
packaging question standing in front of a feature.

So the next step is not to write an MBIM encoder. It is to establish what
`wwan_hwsim` presents to userspace and whether a control port can be driven
through it on a kernel built with it on. If it can, the backend is testable
before it is written and this is ordinary work. If it cannot, the honest
sequence is `mbimcli` against a borrowed modem, recorded the way the hostapd
station parser was -- and that has to be known before the schema commits to
anything.

## Schema

Nothing yet. This record decides an approach and explicitly does not add a
field, because the `modem` block's shape depends on what the testing question
above answers. Constraint 6 is satisfied trivially: no adapter asked for this.
