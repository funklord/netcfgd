# 0044: The modem helper is contained the way an adapter is

Status: accepted
Date: 2026-07-31
Supersedes: [0043](0043-mbim-is-ours-and-the-quirks-are-a-table.md)

## Context

Decision 0043 chose to implement MBIM in netcfgd, and named the thing that had
to be true first:

> the next step is not to write an MBIM encoder. It is to establish what
> `wwan_hwsim` presents to userspace and whether a control port can be driven
> through it [...] If it cannot, the honest sequence is `mbimcli` against a
> borrowed modem [...] and that has to be known before the schema commits to
> anything.

It cannot. This record answers that question and follows it where it leads.

## `wwan_hwsim` presents an AT port and nothing else

Read out of the running kernel's own source (6.12.96) rather than from the
feature name:

- **One port is ever created**, at `drivers/net/wwan/wwan_hwsim.c:208`:
  `wwan_create_port(&dev->dev, WWAN_PORT_AT, ...)`. There is no second call
  site.
- **The core knows the others and the simulator creates none of them.**
  `wwan_port_types[]` in `wwan_core.c` carries `AT`, `MBIM`, `QMI`, `QCDM`,
  `FIREHOSE`, `XMMRPC` and `FASTBOOT`, each with a device suffix. Ports appear
  as `wwan<id><suffix><n>` -- so `/dev/wwan0mbim0` is a name the kernel knows
  how to make and `wwan_hwsim` never asks it to.
- **The AT emulator does not parse commands.** It is a four-state machine that
  looks for `A`, then `T`, then consumes to `\r`, echoes the line back and
  appends `"\r\nOK\r\n"`. Every command succeeds, including ones no modem has.
- It is **not enabled in Debian's kernel** either (`CONFIG_WWAN=m`,
  `# CONFIG_WWAN_HWSIM is not set`), so even the AT port is not loadable
  without building a module.

So the simulator exercises the WWAN core's port plumbing. It cannot exercise a
modem protocol, because it does not implement one.

**An MBIM backend would therefore ship untested**, in a repository whose entire
method is that netlink bugs are found by writing to a kernel and reading back,
never by reading the encoder more carefully. That is not a reason to write it
carefully. It is a reason not to write it.

## D-Bus is not free either, and that was worth checking

The question was asked directly -- does D-Bus depend on anything else? Measured:

| | installed | needs |
|---|---|---|
| `libdbus-1-3` | 445 KB | libc6, **libsystemd0** |
| `dbus-daemon` | 352 KB | libapparmor1, libaudit1, libcap-ng0, **libexpat1**, libselinux1, libsystemd0 |
| `dbus-broker` | 465 KB | the above, plus **`systemd-sysv`** -- systemd as init, as a hard dependency |

So: no. The client library pulls libsystemd; a **bus daemon has to be running**,
which is a new mandatory runtime service; and that daemon drags an XML parser,
SELinux, AppArmor and audit. The two available brokers differ in whether they
merely link systemd or require it as PID 1.

In Rust the shape is different but not smaller. `netcfgd-nm` uses `zbus`, and
its lockfile holds **99 crates against the core's 12**.

And for the modem case specifically, the D-Bus client is the *smallest* line on
the bill. ModemManager is 4716 KB and pulls `libqmi-glib5` (4667 KB), glib,
gudev and polkit regardless of how netcfgd reaches it.

## What has actually changed since 0014

0014 declined iwd because a D-Bus client "would be, by a wide margin, the
biggest thing in this repository". That was true when it was written and is not
true now: `netcfgd-nm` speaks D-Bus, in production, driven by a real `nmcli` in
`tests/live/nm.sh`.

What that decision established is not "no D-Bus". It is **where D-Bus is
allowed to live**: its own cargo workspace, its own lockfile, its own
`cargo-deny` graph, and `make nm-containment` failing the build if any of it
reaches the core (0027). The wall is real, it is enforced mechanically, and it
has held for a whole milestone.

The mistake in 0043 was treating "southbound" as the thing that mattered. It is
not. What matters is whether the core's dependency graph changes, and a separate
binary in a separate workspace does not change it whichever direction the arrow
points.

## Decision

**Modem support is a helper: its own workspace, its own package, its own
binary, talking D-Bus to ModemManager -- and reporting to netcfgd through
`/run`, not through a library.**

netcfgd's core gains nothing: no D-Bus, no glib, no crate, no link. Its side of
the contract is reading a file.

That contract already exists and is already the way netcfgd learns something a
client discovered. A `DHCPv6` client's hook writes
`/run/netcfgd/prefixes/<interface>` -- one value per line, `#` comments
ignored, a missing file meaning nothing was reported -- and the observer reads
it into `Observed::delegations` (0004, and design section 9.2's one-way rule).
A modem helper writes what the bearer answered in the same shape, and the
address arrives through the `addressing` list the way a lease does.

The name is deliberate: **helper**, not backend. netcfgd starts and supervises
backends and speaks their protocol. It does neither here, and calling it a
backend would suggest an integration that does not exist.

## What this buys, and what it costs

**Buys**: the 43 vendor plugins, 10 shared helpers and 18 FCC-unlock entries
that 0043 could only admire from outside -- plus SIM and PIN handling, signal
reporting, and the firmware unlock that made 0043 reach for a `pre_up` hook.
None of it is netcfgd's to write, test or carry.

It is also **testable**, which is the argument that decided it. netcfgd's half
is a file under `/run`; a fixture writes one. The helper's half is a D-Bus
conversation with a real ModemManager, which is exactly what `tests/live/nm.sh`
already does in the other direction -- a private bus via
`DBUS_SYSTEM_BUS_ADDRESS`, no root, no touching the system's own daemon.

**Costs**: modem support now requires ModemManager and a running bus. On the
16 MB router this project targets, that is not available, and **that is stated
rather than hidden**. Such a box has no modem support from netcfgd today.

0043's MBIM path is not wrong and is not withdrawn as an idea -- it is the right
answer for exactly that box. It is simply not being written now, because the
version of it that could ship today would be one nobody could test.

## What stays taken from ModemManager

0043's other half survives intact, because it was never about the dependency:
if a quirk table is ever needed, it is a table -- keyed on `vid:pid`, quirks
clustering by chipset rather than brand, firmware unlock as an opt-in hook that
0011 already has a phase for. That is now knowledge held for when it is needed
rather than a design to build.

## Schema

Still nothing. The `modem` block waits on the helper existing, and its shape
should follow what ModemManager actually reports rather than what this record
guesses. Constraint 6 is satisfied: no adapter asked for this.
