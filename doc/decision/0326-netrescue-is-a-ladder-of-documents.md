# 0326: netrescue is a ladder of documents the daemon applies

Status: accepted
Date: 2026-11-20

## Context

The holder, 2026-11-20, building a USB rescue stick for the HP G6 servers:
"netrescue sounds like something we should have in netcfgd instead and
include that when it's finished." The proposal came by the inbox
(20261120T0015Z, from the system-notes tree). A box booting on a network it
may not know, with nobody at the console, must end up reachable by ssh, by
escalating when it cannot reach a gateway after about 30 seconds:

1. DHCP on every Ethernet port, plus a fixed fallback address (the stick
   uses 10.0.0.250/16 on the first port up, whatever DHCP did);
2. force the link -- fixed speed and duplex, 1000/full then 100/full -- for
   ports or cables that will not autonegotiate;
3. reload NIC drivers and log firmware errors;
4. learn an unknown network by listening for ARP and DHCP, and take an
   address nothing answers for;
5. stay reachable on a direct cable: IPv6 link-local on every port, and an
   mDNS name;
6. USB Ethernet and phone tethering as they appear; PPP over the serial
   console as the last resort;
7. report what was tried and what worked, on the consoles and in a log.

It never touches disks beyond its own log. A local language model trying
"unconventional things" was rejected in the proposal: on pre-AVX Xeons at a
token a second, each step takes minutes, and restricted to network commands
it is a search over a fixed list, which a deterministic ladder does in
seconds and exhaustively.

## Decision

**netrescue is a fourth name of the multi-call program, and each rung is a
document.** It finds the machine's Ethernet ports itself, writes a netcfgd
document for the rung it is on into a configuration directory of its own,
and runs a netcfgd daemon on that directory; when no gateway has answered
by the rung's deadline it writes the next rung's document, and the daemon's
watcher applies it. Rungs are cumulative: a later document keeps what the
earlier ones put on the machine, so climbing never takes away a way in.

What decided it is that rungs 1, 2 and 5 are things netcfgd already does --
DHCP through dhcpcd or udhcpc, a fixed address beside it, `ethtool`'s
forced speed and duplex, the kernel's link-local address left alone -- and
a document is how netcfgd is asked for them. A ladder that called `ip` and
`ethtool` itself would be a second implementation of the executor, with
none of its ownership, drift handling or tests, and constraint 3 (no
mandatory dependency beyond libc and the kernel) would not hold for it.

The imperative rungs -- rebinding a driver, listening for the subnet -- are
netrescue's own code, and each ends by writing a document: a rebind changes
nothing netcfgd holds, and what listening learns becomes an address in the
next document.

**Constraint 1 holds in its own terms.** Everything the daemon does traces
to a file in the configuration directory it was given; netrescue is the
author of that file, as a person is of `/etc/netcfgd`. The directory is
netrescue's (`/run/netrescue` by default), so a machine that also has an
`/etc/netcfgd` keeps it untouched -- and should not run both, which is two
managers on one set of ports.

**Which ports**: an entry under `/sys/class/net` whose `type` is 1
(Ethernet framing), which has a `device` (hardware, USB included, so a
tethered phone counts and a bridge or a veth does not), and which is not a
radio (`wireless`, `phy80211`, or a `DEVTYPE` of `wlan` or `wwan`). The
list is taken again every cycle, which is how a USB adapter plugged in
later is picked up (rung 6's first half) without a rung of its own.

**Reachable** means an IPv4 default route's gateway answers an ICMP echo.
That is the question the proposal's 30 seconds asks; a box that is
reachable only on its fallback address or by link-local keeps climbing,
since every rung keeps those.

## Options rejected

- **A shell script under `helper/`.** Cheapest to write, but it depends on
  `ip`, `ethtool`, `arping` and a packet capture for rung 4, and repeats
  what the executor does. The modem helpers are shell because they speak to
  a device's own tools; this one speaks to the kernel, which netcfgd
  already does.
- **Device matching in the configuration language** (`match` with a name
  glob, which the model carries and nothing reads -- project.md, the
  unreachable fields). It would let one static document say "every
  Ethernet port", but not climb, and the language change is a larger
  decision than this program needs. netrescue enumerates and names the
  ports itself.
- **netrescue in the daemon**, as a policy the document states. The
  daemon's job is to make the machine match a document; deciding which
  document to want is a different job, and keeping it outside keeps the
  daemon's contract unchanged.

## Consequences

- netrescue needs a DHCP client netcfgd drives (dhcpcd, or busybox's
  udhcpc); the rescue stick's isc-dhcp-client is not one of them.
- Built in steps: the address rung, the forcing rungs and the report first
  (project.md 10.876, with 10.877 making the forcing real); then listening
  (10.878), which runs second, before forcing, because it disturbs nothing
  and serves the ports forcing does not -- the ones with a carrier and no
  lease; then the driver rebind as the last rung (10.879), a responder for
  NAME.local that runs from the start rather than as a rung (10.880), and
  PPP on a serial console.
  The stick takes it when project.md says it is ready.
- Stopping netrescue stops its netcfgd and leaves what it configured,
  DHCP clients included, as a stopped netcfgd does: a rescue that took the
  network away on exit would cut off the person who stopped it.
