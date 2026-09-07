# 0169: a manager is not the tools it drives

Status: accepted
Date: 2026-09-07
Milestone: M8; a defect in
[0168](0168-installing-netcfgd-selects-netcfgd.md), reported from a machine
it broke

## The report

"Now I cannot get wifi on netcfgd, nor NM, as NM doesn't even scan."

## What happened

0168's `netcfgd_select.sh` kept one list of daemons and stood down every
entry that was not the selected one. `wpa_supplicant` was in that list, so
**every selection masked `wpa_supplicant.service`** -- including
`netcfgd_select.sh networkmanager`, which is supposed to hand the machine
back to NetworkManager.

NetworkManager does not talk to radios itself. It drives wpa_supplicant over
D-Bus. Mask that unit and NM starts, enumerates devices, and finds no
networks: exactly the symptom reported.

**netcfgd was unaffected, which is why nothing here noticed.** It spawns the
`wpa_supplicant` *binary* directly with its own
`-P /run/netcfgd/supplicant/<iface>.pid` (0140) and never wants the service.
So on a machine where netcfgd is running and configured for wifi, the mask
costs nothing; on any other, the radio has no daemon that can use it. That is
[0145](0145-a-stopped-daemon-leaves-its-claim-behind.md)'s outcome -- "the
guard against two daemons fighting produced a machine with no daemon on it at
all" -- reached by a new route, in code written after that record.

## The error, stated so it is not repeated

**A network manager competes for interfaces. A tool is what a manager
drives.** They were in one list, and the loop that stands down "everything
that is not the target" is only correct for the first kind.

    managers   netcfgd networkmanager networkd connman ifupdown wicd
    radios     supplicant iwd
    tools      dhcpcd modemmanager resolved

Two more consequences of the same conflation, fixed here and neither
reported:

- **`systemd-resolved` was masked by every selection.** It is a resolver, not
  an interface manager, and masking it breaks `dns_mode = "resolved"` -- the
  arrangement 0007 recommends. netcfgd contends with resolved only under
  `write_resolv_conf`, which is `netcfgd-exclusive.conf`'s business and
  0165's, not the switcher's.
- **`ModemManager` was masked by every selection**, which takes NM's mobile
  broadband away.

## Decision

**Only managers are masked. A radio or a tool is stopped when the selected
manager does not want it, and never masked.**

`needs_of` says what each manager needs: NetworkManager needs the supplicant
and ModemManager, networkd and connman need the supplicant, ifupdown needs
the supplicant and dhcpcd, **netcfgd needs none of them** -- it runs the
binaries itself, so a service instance is a rival rather than a dependency.
Anything a manager needs is unmasked, enabled and started; anything it does
not is stopped and disabled.

**Masking is what makes a machine unrecoverable without root and knowledge**,
so it is reserved for the thing that genuinely cannot coexist. Stopping is
reversible by anything that wants the service.

`none` now unmasks the radios and tools as well as the managers, whether or
not the current code would ever mask them -- because a machine broken by the
version this record fixes still has `wpa_supplicant.service` masked, and
`none` is its recovery.

## Consequences

- `tests/live/select.sh` drives the switcher's systemd paths **on a machine
  with no systemd**: a mount namespace, a tmpfs over `/run` so
  `/run/systemd/system` can exist, and a `systemctl` on `PATH` that records
  its arguments. What is under test is which units the script acts on, which
  is a property of the script. Putting the supplicant back among the managers
  turns three of its eight checks red.
- `tool/select_gate.py` refuses a radio or tool named in `managers`
  statically, refuses a `needs_of` entry that is not a known service, and
  checks `none` walks all three lists. Each was made to fail.
- **The switcher shipped having only ever run under `--dry-run`**, on a
  development machine with no systemd, and this record exists because that was
  not enough. The harness above is what should have been written first: it
  needs no systemd and would have caught this before it left the tree.
