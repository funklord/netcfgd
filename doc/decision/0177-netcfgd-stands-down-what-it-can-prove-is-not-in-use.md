# 0177: netcfgd stands down what it can prove is not somebody's working daemon

Status: accepted
Date: 2026-09-08
Milestone: M8; instructed after a switch to netcfgd cost the association on the
copyright holder's machine

Closes the question [0134](0134-an-unannounced-stop-holds.md) and 10.13 left
open, and narrows the "never masked" rule
[0169](0169-a-manager-is-not-the-tools-it-drives.md) introduced. Neither is
reversed: what changes in both is the **scope**, and in both cases the old
statement was broader than the incident that produced it.

## The instruction

> just kill every dhcpcd, wpa_supplicant and what ever else that isn't part of
> your configuration and control.

Given after watching a `netcfgd_select.sh netcfgd` leave the machine with no
working radio, and it is [0168](0168-installing-netcfgd-selects-netcfgd.md)'s
original instruction -- *"any other processes that interfere with it are to be
killed, disabled and if they still persist, renamed"* -- reaching two cases that
had been carved out of it for reasons that do not survive contact with them.

## Why the carve-outs looked right

Both were written from a real incident and both generalised one step too far.

**"An unannounced stop holds" (0134), and 0141's refusal to restart a wedged
backend.** The reasoning is sound and stays: a daemon that is running and silent
may only be busy, killing a healthy one is worse than saying so, and a person
decides. The incident behind the adoption guard is real too -- netcfgd once
adopted an unreachable supplicant, displaced NetworkManager's working one, then
declined to restart what it had adopted, and the radio was held by a corpse with
NM locked out. "Three defensible changes composing into a trap", as the comment
says.

**"A tool is never masked" (0169).** Also from a real machine: the switcher
masked `wpa_supplicant.service` on *every* selection, so
`netcfgd_select.sh networkmanager` produced a NetworkManager that could not
scan.

## What each was actually about, measured

**The busy-daemon objection is about processes netcfgd cannot identify.** It
does not apply to a process carrying netcfgd's own marker -- an absolute path
netcfgd composed, which the process carries in its own `argv` for as long as it
lives (0140). `netcfgd_select.sh`'s `is_netcfgds` is that exact test and has
been shipping for weeks. So "is this mine" is **answered from `/proc`, not
guessed**, and a guard that declines to distinguish is not being careful, it is
declining to read something it has.

What that cost, measured on the reporting machine: netcfgd started beside an
orphan of its own, systemd logging `Found left-over process 1159032
(wpa_supplicant) in control group while starting unit`; the orphan was not
adoptable (unreachable), not a contender (not another manager's), and never
stopped; netcfgd started a second supplicant; the two deauthenticated each other
until the association went. netcfgd's own refusal text names that outcome
exactly -- *"two on one radio drop the association, which takes the address and
the default route with it."* **The guard produced the outcome it existed to
prevent.**

**The masking objection is about which selection masks.** 0169's fault was
masking the supplicant when *NetworkManager* was selected. Masking it when
*netcfgd* is selected is a different act with a different consequence, and it is
required rather than merely permitted: `wpa_supplicant.service` is D-Bus
activatable, so `disable` governs boot and nothing else, and
`netcfgd-exclusive.conf` conflicts with it. **`Conflicts=` is symmetric** --
verified with two throwaway units, where starting the unit that declares nothing
stopped the one that declared the conflict. So a desktop applet asking for
`fi.w1.wpa_supplicant1` does not merely start a rival, it **stops netcfgd**.
Measured: netcfgd started at 14:09:33 and was gone at 14:09:46. The stop is
clean, so `Restart=on-failure` does not bring it back.

## Decision

**A process netcfgd can prove is its own, and can prove it can no longer talk
to, is stopped.** In `adopt_running_backend`: an absolute-path marker, no pid
file naming a live process, `backend_is_reachable` false, `pid_by_marker` finds
one, and `shares_network_namespace` says it is in this world (0167) -- terminate
it, say so, then start fresh.

**Scoped to what netcfgd has lost the handle to.** A backend whose pid file
still names a live process is returned as adopted by the first branch and never
reaches this, wedged or not. That one *is* under netcfgd's control and stays
0141's decision, with `ncfg apply --restart-wedged <iface>` as the override. The
distinction is not "reachable versus not", it is **"does netcfgd still have a
record of it"** -- which is what "part of your configuration and control" means.

**A service is masked when it both contends for a device and comes back on its
own.** `revived_over_dbus='supplicant modemmanager'` in `netcfgd_select.sh`;
`stand_aside` masks those and nothing else. Reached only for a service the
selected manager does not need, so `needs_of networkmanager` naming both is what
keeps 0169's machine working -- NM's selection unmasks, enables and starts them.

`systemd-resolved` is excluded although it is D-Bus activatable too: it contends
for no device, netcfgd does not conflict with it, and masking it would break
`dns_mode = "resolved"`, the arrangement 0007 recommends.

## The rule, stated so it does not over-generalise again

**Do not kill what you cannot identify; do kill what you can.** Both carve-outs
came from incidents where netcfgd acted on a process it had no way to
distinguish, and both were written as bans on the *act* rather than on the
*uncertainty*. The marker removes the uncertainty for netcfgd's own backends and
`needs_of` removes it for services, so in exactly those cases the ban had
nothing left to protect.

And **a stop is not a stand-down against anything activatable.** Where a unit
can be started by a bus name, a socket or a dependency, `disable` addresses only
the boot path. That is a property of the unit, not of netcfgd, and it is now
recorded in the list rather than in somebody's memory.

## Consequences

- `tests/live/select.sh` asserts both directions of the mask and that `none`
  recovers, and `select_gate.py` refuses any `revived_over_dbus` entry that
  `unmask_all` does not walk -- so nothing can be masked that `none` cannot put
  back, which is 0145's outcome guarded statically.
- Each new check was made to fail: emptying `revived_over_dbus` turns two red,
  adding an unrecoverable entry turns the gate red, removing the decoy turns the
  kill-path check red, and every sabotage was confirmed to have landed before
  the result was believed.
- **`tests/live/select.sh` used `unshare -rm` and therefore shared the host's
  network namespace**, so it ran the switcher's kill path against the real
  machine and terminated the supplicant of anyone who ran it as root. It uses
  `unshare -rmn` now, with a decoy inside the namespace so the path still has
  coverage. Found by reading the file rather than by running it.

## Alternatives rejected

- **Refusing the radio when an unreachable orphan is found**, which 10.13 offered
  as the other half of the choice. Honest, and it leaves the machine with no
  network for a reason the operator cannot act on: the orphan is netcfgd's, so
  there is nobody else to hand the radio to.
- **Dropping `Conflicts=wpa_supplicant.service` from the drop-in** instead of
  masking. Removes the eviction and restores the fault that line was added for:
  the system supplicant holds the radio, netcfgd's guard sees a supplicant it
  did not start, and declines for ever.
- **Masking on every selection**, which is 0169's fault exactly.
- **Killing by program name rather than by marker.** Reaches supplicants netcfgd
  did not start, which is the thing every guard here exists to prevent.
