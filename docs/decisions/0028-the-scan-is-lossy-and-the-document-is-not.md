# 0028: The scan is lossy, and the document is not

Status: accepted
Date: 2026-07-31
Milestone: M7

## Context

The NM shim's wireless half turns netcfgd's scan results into
`org.freedesktop.NetworkManager.AccessPoint` objects. Three of NM's properties
need information netcfgd reports in a different shape, and one of them needs
information netcfgd does not report at all.

- `Strength` is a percentage; netcfgd reports dBm.
- `Ssid` is a byte array; netcfgd reports hex.
- `Flags`, `WpaFlags` and `RsnFlags` are bitfields describing exactly what an
  access point will negotiate; **netcfgd's socket reports a boolean.**

The first two are arithmetic. The third is a gap, and it is the interesting
one, because the information exists inside netcfgd and is thrown away at the
socket: `netcfgd-supplicant` parses `[WPA2-PSK-CCMP][ESS]` and keeps the string
on its `ScanResult`, and the daemon collapses it to `secured: bool` when it
builds a `ScanEntry`.

## Decision

**The socket is not changed. The shim asks the document instead, and guesses
where the document is silent.**

Constraint 6 -- the one-way rule -- says no change to the model, config language
or socket API may be justified *solely* by an adapter's needs. "nm-applet wants
to know whether to prompt for a passphrase or a certificate" is exactly that
justification, so the change does not get made here, in the commit that wants
it, as part of the work that discovered the gap.

What the shim does instead turns out to be better than the thing it was denied:

**For a network the configuration describes, ask the configuration.** The
document says whether a `network` block is `psk` with which generation, `eap`,
or `owe`. That is not an approximation of the scan flags -- it is strictly more
authoritative, because it is what netcfgd will actually negotiate with. It also
covers the case that matters, since a network in the document is the one an
applet is about to be asked to join.

**For everything else, WPA2-PSK with CCMP.** The overwhelmingly common shape of
a secured network, and the one an applet handles by prompting for a passphrase.
A wrong guess costs a prompt for the wrong credential type. Refusing to answer
costs the network not appearing in the list at all, which is worse.

### The change the socket probably should have anyway

`ncfg wifi scan` today prints `secured` or nothing. An operator choosing
between `proto = "wpa2"` and `proto = "wpa3"` for a `network` block cannot see
which the access point offers, and the TUI's wireless pane has the same gap.
That is an argument for enriching `ScanEntry` **on its own merits, for local
users**, and it would pass the one-way rule cleanly.

It is deliberately not made here. It is a socket API change after the M4 freeze
and would move `docs/schema/socket.json`, which is a reviewable act that
deserves its own commit and its own argument -- not a paragraph inside an
adapter's. Recorded so the next person does not have to rediscover that the
information exists two layers down.

## A radio is what the configuration says it is

The shim asks the document a second question: which devices are radios. The
answer is `device <name> { wifi { } }` on a managed device, which is netcfgd's
*own* definition -- it is what makes the planner start a supplicant -- and
deferring to it means the shim and the daemon cannot disagree about which
interfaces are wireless. `/sys/class/net/<name>/wireless` is kept as a fallback,
for a radio the configuration has not mentioned yet.

That has a consequence worth stating plainly: being a radio outranks the link
kind. A `device` block with a `wifi` section on a dummy makes a wireless device
in the shim, because it makes one in the planner too. That is also what makes
the whole wireless half testable on a machine with no wireless hardware.

## `RequestScan` returns before the scan does

NM's semantics, and this took a redesign to get right. The method posts a job
and returns; the results arrive as `AccessPointAdded` and a changed `LastScan`.
Blocking the caller until the radio finished would be a different method than
the one clients think they are calling -- and, in this implementation, would
block zbus's own thread for the duration of a scan.

That is also why the shim has a job queue at all. Registering an object and
emitting a signal are the two things a D-Bus method handler cannot do from
zbus's blocking API, so everything that mutates the object tree happens in one
place: the main loop, fed by the monitor thread and by `RequestScan`.

Nothing scans on a timer. A scan makes the radio do something, and NM clients
already call `RequestScan` when a menu opens, which is exactly when a scan is
wanted. One scan happens at startup so a client that connects and immediately
reads `AccessPoints` sees something rather than an empty list it would draw as
"no networks found".

## A fake radio, and what it is allowed to be fake about

`tests/live/nm.sh` grew a fake `wpa_supplicant`: a unix datagram socket
answering `PING`, `SCAN`, `SCAN_RESULTS` and `STATUS` with canned rows.

The justification is narrow and worth stating, because faking a dependency is
usually how a test stops proving anything. `wifi.sh` drives a **real**
`wpa_supplicant` and is what proves netcfgd parses that protocol correctly. But
a real supplicant with no radio finds no networks, so everything downstream of
"the scan returned" -- which for this shim is *all* of it -- was untestable.
The fake supplies inputs with known outputs: -40 dBm must become 100, -100 must
become 0, and -53 must become 79.

So the wire format is real and the radio is fake. If netcfgd's parser ever
changes its mind about `SCAN_RESULTS`, `wifi.sh` is what notices.

## What the numbers were checked against

`RsnFlags` 1416. That is what a running `NetworkManager` 1.52 reported for a
WPA2/WPA3 transition access point on the network this was written on, and it
decomposes exactly to `PAIR_CCMP | GROUP_CCMP | KEY_MGMT_PSK | KEY_MGMT_SAE` --
so one observation confirms four constants, and a unit test asserts the whole
number rather than the pieces.

`Strength` could not be checked directly: NM does not expose the dBm it
converted, and `/proc/net/wireless` reports the current link level rather than
the last beacon, so the two disagree for good reasons. What is available is
consistency -- the daemon reported 79 for a nearby router, and 79 is what this
returns for -53 dBm.

## Two tests that passed for the wrong reason

Both found by breaking what they guard, and both worth recording because they
are the same mistake in different clothes.

**A range written the way the sentence reads.** `for dbm in -40..=-100` is
empty, so the monotonicity test asserted nothing and passed. Clippy noticed
before a human did.

**A check whose two branches agreed.** "A configured network reports the
security the config gives it" used a WPA2 network -- and WPA2-PSK is also what
the shim guesses for an unconfigured secured network. Removing the document
lookup entirely left the test passing. The fixture is WPA3 now, so the two
paths produce different answers and the check can fail.
