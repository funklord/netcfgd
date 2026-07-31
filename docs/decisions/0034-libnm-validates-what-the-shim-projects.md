# 0034: libnm validates what the shim projects

Status: accepted
Date: 2026-07-31
Milestone: M7

## Context

The last of tier 2: the options a settings panel offers beside the address --
metered, autoconnect priority, per-profile DNS -- in both directions. Each is a
field-by-field mapping with no new mechanism, which is why they came last.

They produced the most interesting failure in the whole shim.

## A projection can make a profile unusable

Emitting a profile's nameservers looked like the safest change in the set: a
`network` block with a `dns` block gains `ipv4.dns-data` and `ipv4.dns-search`,
and a panel shows them.

It made the profile impossible to activate. `nmcli connection up` reported:

```
device 'radio0' not compatible with connection 'HomeFiber': The connection was
not valid: ipv4.dns: this property is not allowed for 'method=disabled'.
```

**libnm validates the whole settings dictionary before it will activate
anything.** A `network` block with nameservers and no addressing in that family
produced `method=disabled` beside `dns-data`, which is an invalid combination --
and the failure was not "your DNS was ignored", it was the entire profile
becoming unusable, with an error naming the DNS rather than the addressing that
caused it.

So DNS is emitted only where the method permits it. Losing one field is much
cheaper than losing the profile, and NM has no way to express "no addressing,
but these nameservers" anyway.

The general lesson is worth stating on its own, because it applies to every
field that will ever be added here: **the settings dictionary is validated as a
whole, so a field that is individually correct can still be wrong in company.**
Projecting more of the native model is not monotonically safer.

## Where each option lives

netcfgd's DSL puts the keys a station uses to *choose between* networks inside
the `wifi` block, and the keys about the network itself beside it. So
`autoconnect-priority` becomes `wifi { priority = 42 }` and `metered` becomes a
network-level `metered = true`. A generated file has to match where an operator
would have typed them, or the next person to edit it by hand is fighting the
layout.

**`metered` is a tri-state in NM and a boolean in netcfgd.** `false` is reported
as `NM_METERED_NO` rather than `UNKNOWN`: an operator who wrote `metered =
false` said something, and reporting unknown would have a desktop guess at it
instead. In the other direction only an explicit `YES` writes anything, because
`NO` and `UNKNOWN` are both the absence of the key.

**A negative priority is refused by name.** netcfgd's `priority` is written as
an unsigned number, so `-5` cannot be expressed. Clamping to zero would turn a
network the operator deliberately deprioritised into an ordinary one, which is a
silent change of meaning; refusing says what to do instead.

**An MTU has nowhere to go.** An interface has one and an SSID does not, so
`802-11-wireless.mtu` is named in the generated file's dropped list rather than
quietly ignored. That is the one-way rule working: the model does not grow a
field because a client sent one.

## Both spellings of nameservers

NM has `dns` (packed integers) and `dns-data` (text). nmcli 1.52 sends and reads
`dns-data`; older clients use `dns`. Both are emitted, and both are read --
serving only the one this machine's client happens to use is how a shim works
until somebody runs a different desktop.

The live test asserts them against each other. The fixture's nameserver is
9.9.9.9, which is `0x09090909` and therefore the same number whichever way round
it is read -- chosen deliberately, because it means the live check cannot
accidentally become a byte-order test that passes for the wrong reason. The
asymmetric case is in the unit tests, against a number a real daemon produced.

## A fixture change that broke a test three sections earlier

Adding `autoconnect = false` to the fixture's network to exercise that field
made the activation checks fail, several sections above: a network netcfgd will
not join by itself is one `nmcli connection up` cannot bring up either. The
field is now asserted at its default instead.

Worth recording because it is the cost of one long fixture: the checks are not
independent, and a change made for one section can be paid for in another. The
alternative -- a fresh daemon and bus per section -- would multiply a
ninety-second test by ten, so the fixture stays shared and this note stands in
for the discipline of reading the whole file before changing it.

## Tier 2 is done

Devices, scanning, profiles, activation, the write path, the secret bridge, the
address configuration objects, static addressing both ways, and the
per-connection options. `org.netcfgd.Compat`'s `Supported` map reports each.

What is left of section 9.5 is tier 3, which is the list of things that are
supposed to be refused: VPN plugins, ModemManager, Wi-Fi P2P, team and OVS.
They are already absent; making them *honestly* absent -- reported as
unmanaged rather than as broken managed objects -- is a smaller piece of work
than any of the tiers, and it is the last of the shim.
