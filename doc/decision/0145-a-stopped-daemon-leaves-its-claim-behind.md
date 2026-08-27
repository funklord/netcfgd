# 0145: a stopped daemon leaves its claim behind

Status: accepted
Date: 2026-08-27
Milestone: M8; the fault the operator has been reporting since M7

Qualifies [0144](0144-an-ifindex-means-nothing-outside-its-namespace.md), which
fixed where contention state is read from and not whether it is still true, and
[0125](0125-displacing-networkmanager-is-a-runtime-switch-and-nothing-else.md),
whose drop-in is one half of the failure.

## The report

"I installed the latest deb packages. When I start netcfgd ping stops working,
and the gui is not really helpful." Said in several forms over several days,
and every attempt to reproduce it cost the operator the only network link they
had.

## What actually happens

Three true things compose into it, and none of them is wrong on its own.

**`netcfgd-exclusive.conf` was active on that machine**, copied into
`/etc/systemd/system/netcfgd.service.d/` on 2026-08-26. It is opt-in and ships
as documentation precisely so that this is a deliberate act, and it had been
deliberately done. It conflicts with `NetworkManager.service`,
`systemd-networkd.service`, `connman.service`, `wpa_supplicant.service` and
`ModemManager.service`.

**`NetworkManager` does not clean up after itself.** Its unit has no
`RuntimeDirectory=` and no `ExecStop=`; the only relevant line is
`KillMode=process`. So `/run/NetworkManager/devices/<ifindex>` outlives the
daemon with `managed=true` still in it. `systemd-networkd` is worse in the same
way: it has a `RuntimeDirectory=systemd/netif` and then sets
`RuntimeDirectoryPreserve=yes`.

**netcfgd's contention check read those files as a live claim.** It was right
that a file is the only per-interface evidence available, and wrong that its
presence means anybody is still there.

Composed, starting `netcfgd.service`:

1. systemd stops NetworkManager, and `wpa_supplicant.service` with it.
2. NM's device files remain, still saying `managed=true`.
3. netcfgd reads them, concludes NM holds the radio, and declines it.
4. Nothing is managing the network -- including netcfgd, by its own choice.

The guard that exists to stop two daemons fighting over one interface produced
a machine with no daemon on it at all.

## The other half: `Conflicts=` does not order anything

The drop-in declared five `Conflicts=` and no `After=`, and `systemd.unit(5)`
is explicit about what that leaves out:

    Note that this setting does not imply an ordering dependency, similarly
    to the Wants= and Requires= dependencies described above. This means
    that to ensure that the conflicting unit is stopped before the other
    unit is started, an After= or Before= dependency must be declared.

Unordered, netcfgd reaches its contention check while NetworkManager is still
shutting down. NM is then genuinely alive and genuinely still claims the radio,
so netcfgd correctly declines it -- on behalf of a daemon one second from gone.
Liveness alone does not fix that, because at the moment it is asked the answer
is honestly "yes".

**This is why the failure was intermittent**, which cost more time than the
failure itself: the operator reported both "keeps disconnecting now" and "Now
it didn't go down" about what they took to be the same thing, and a fault that
comes and goes gets attributed to whatever else changed. Whether it bit
depended on how fast NM exited.

The drop-in now carries an `After=` for each unit it conflicts with. `After=`
on a unit being stopped orders against the completion of the stop job, which
is the ordering wanted.

## The rule

**A file says which interfaces. A live process says the claim is current.
Neither is sufficient alone -- and neither helps if the question is asked
before the other daemon has finished leaving.**

The module's own header said detection is "by the files these daemons leave in
`/run`, not by D-Bus and not by scanning process names", and gave the reason: a
process name tells you something is running without telling you which
interfaces it has opinions about. That reason is correct and it argues against
using process names *instead of* the files. It does not argue against using
both, and reading it as though it did is what left the stale-file case
unexamined.

Liveness is read from `/proc/<pid>/comm` rather than `/proc/<pid>/exe`, because
`comm` is world-readable and `exe` is not. netcfgd runs as root, but a check
that silently degrades when it does not is a check that lies. `comm` is
truncated to 15 characters by the kernel, so `systemd-networkd` is matched
under its truncation as well as its full name.

Unreadable `/proc` falls back to believing the files, the same direction 0144
chose and for the same reason: being wrong that way costs a refusal the
operator can override, and being wrong the other way starts a second supplicant
on a radio somebody else is holding.

## What was rejected

**Having netcfgd delete another daemon's runtime files.** Reaping state that
belongs to a program that may be restarted at any moment, to make a guard
easier to write.

**Asking systemd whether the unit is active.** It would work on the machine
that reported this and nowhere else. netcfgd ships OpenRC and procd init
scripts, and `contention.rs` is not the place to acquire an init dependency.

**D-Bus.** Declined by [0014](0014-wpa-supplicant-is-the-floor-not-the-fallback.md),
and nothing here changes that.

## How it stayed hidden

The tests drove a fake `/run`, deliberately, so that they would not only pass
on a machine running NetworkManager -- the file says so in its own header. A
liveness check read from the real `/proc` would have destroyed that property
silently: the machine this was written on runs NetworkManager, so every
assertion would have passed without testing anything, and inverted on a machine
that does not. `NCFG_PROC` exists so liveness is a property of the fixture, and
the test carries the alive case as a control beside the stopped one.

## What it does not fix

The operator's radio still has to be taken from a running NetworkManager, and
that hand-over is unchanged: the refusal is correct while NM is up. What is
fixed is the machine being left with nothing after NM is stopped -- and the
refusal now names the whole-machine remedy as well as the per-device one,
because an operator who has installed the exclusive drop-in has already said
which of the two they want.
