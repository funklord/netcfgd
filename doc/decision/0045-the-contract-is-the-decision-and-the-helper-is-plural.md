# 0045: The contract is the decision, and the helper is plural

Status: accepted
Date: 2026-07-31
Amends: [0044](0044-the-modem-helper-is-contained-the-way-an-adapter-is.md)

## Context

Decision 0044 put modem support in a helper that reports to netcfgd through
`/run`, and named ModemManager as the helper. The containment is right and
stands. Naming one helper was the mistake.

**Some people hate D-Bus**, and this project exists partly because of them.
Design section 1 opens on it: "NM pulls D-Bus, polkit, glib, ModemManager, its
own DHCP stack, and increasingly assumes systemd. Absurd on a server, a
container, or an embedded box." Making D-Bus the road to a modem would put a
netcfgd user in front of the exact thing they came here to avoid, and 0044 said
as much about the 16 MB router without noticing it had written off its own
target hardware.

The valuable part of 0044 is the **contract**, not the helper. That is what
this amends.

## The contract is defined by what a connection is

A helper reports: the interface, the addresses, the gateway, the nameservers.
That is what any modem stack can produce, and it is what netcfgd needs to treat
a bearer as an address source the way it treats a lease.

**It is not defined by what ModemManager reports.** No MM property names, no MM
object paths, no field that exists because one implementation has it. A
contract shaped around one helper is a contract with one helper.

## Three helpers, all verified to be possible

**`umbim`, for the box 0044 wrote off.** OpenWrt's MBIM client, and its whole
dependency line is `DEPENDS:=+libubox +kmod-usb-net +kmod-usb-net-cdc-mbim
+wwan`. No glib, no libmbim, no D-Bus, no bus daemon -- libubox is OpenWrt's
own small utility library. It runs on exactly the hardware 0044 said had no
answer, and OpenWrt's own network scripts already drive it this way, which
makes it a proven pattern on the target rather than a proposal.

**`mbimcli`, for a distribution that has it.** 263 KB over `libmbim-glib4`'s
920 KB. Checked what it links: `libmbim-glib`, `glib`, `gio`, `gobject`,
`libc` -- **no `libdbus`, no `libsystemd`**. It talks to `/dev/cdc-wdmX` and
nothing else. The two commands a helper needs are there:
`--connect="access-string=APN,..."` and `--query-ip-configuration`.

**A ModemManager helper, for a machine already running one.** This is where the
43 vendor plugins and 18 FCC-unlock entries live, and somebody whose modem needs
one should have that road open. It is now one option rather than the option.

## What this costs, honestly

`mbimcli` has **no machine-readable output** in 1.32 -- no `--output-json`, no
key-value mode, only human-readable text and `--verbose`. A helper parsing it is
parsing prose, which is the brittleness this project usually refuses.

That is a real cost and it is worth naming rather than glossing. Two things make
it acceptable: it lives entirely inside a helper package, which is what the
containment is *for*; and a helper that minds can link `libmbim` directly
instead, at 920 KB and still no bus. The choice is the helper author's, and
netcfgd sees a file either way.

## And this retires the MBIM encoder for a better reason

Decision 0043 wanted netcfgd to implement MBIM; 0044 declined it because it
could not be tested. The stronger reason is the one that was there all along:
**MBIM is solved at the tool level, twice over, by implementations with users
who find their bugs.** That is the line this project already draws -- own the
protocol encoders nobody else speaks the way netcfgd needs, link or drive the
solved infrastructure. `wpa_supplicant` and `hostapd` are on that side. So is
this.

netcfgd owning an MBIM encoder was never the shape. It was 0036's framing
carried too far.

## Consequence

The first thing to build is the reporting contract and netcfgd's side of it,
which is a file reader and a fixture that writes one -- unchanged from 0044.
What changes is that the contract must be written down as a contract, in
`doc/`, so that a second helper can be written by somebody who has never read
netcfgd's source. That is the difference between an interface and an
implementation detail that happens to be in `/run`.
