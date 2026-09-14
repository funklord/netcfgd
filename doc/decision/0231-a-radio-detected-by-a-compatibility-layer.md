# 0231: a radio detected by a compatibility layer

Status: accepted
Date: 2026-09-14
Milestone: M9; the wifi driver and interface audit

## The question every wifi decision hangs off

`is_wireless` decides whether netcfgd treats an interface as a radio, and five
places ask it:

```text
start_supplicant   -Dnl80211,wext for a radio, -Dwired otherwise
radios_of          which interfaces get a supplicant planned at all
ObservedLink       what the observation says the link is
ncfg wifi          whether the command will talk about this interface
wireless_links     which radios `ncfg wifi add` offers
```

It asked one question: does `/sys/class/net/<name>/wireless` exist.

## That attribute is a kernel option

`wireless` is the Wireless Extensions attribute. On a cfg80211 radio -- which is
every radio a current driver presents -- it exists because the kernel was built
with `CONFIG_CFG80211_WEXT`, a separate config symbol from `CONFIG_CFG80211`.
Read from the reporting machine:

```text
$ grep -E 'CONFIG_CFG80211_WEXT|CONFIG_WIRELESS_EXT' /boot/config-$(uname -r)
CONFIG_WIRELESS_EXT=y
CONFIG_WEXT_CORE=y
CONFIG_CFG80211_WEXT=y

/sys/class/net/wlp0s20f3/wireless   present
/sys/class/net/wlp0s20f3/phy80211   present
```

Both attributes are here *because* that option is on. It is on by default in the
large distributions and routinely off in small ones -- which is the kind of
kernel netcfgd is being aimed at on a board.

On such a kernel a working radio answers "not a radio", and everything
downstream follows without complaint: the supplicant is started with `-Dwired`,
the planner leaves the interface out, the observation says it is not wireless,
and `ncfg wifi` declines to discuss it. **No message names a cause, because from
netcfgd's side there is no radio to have a problem with.**

`phy80211` is the attribute to ask for. cfg80211 creates it for every device it
registers and there is no option in front of it.

## What is measured and what is inferred

Measured: the option exists, it is a distinct symbol, it is on here, and both
attributes are present here.

Inferred: that turning it off removes `/sys/class/net/<name>/wireless`. That
follows from what the option is for -- it is the layer that installs the wext
handlers a cfg80211 device would otherwise not have -- but it was not tested,
because testing it means building a kernel.

**The fix does not depend on the inference.** Asking for `phy80211` *or*
`wireless` is strictly more permissive than asking for `wireless` alone: every
interface that was a radio before still is. If the inference is wrong, nothing
changes; if it is right, a class of machine starts working. That asymmetry is
why this was worth doing without the kernel build.

## The second test is not dead weight

`wireless` is still asked, after `phy80211`. A driver old enough to register no
cfg80211 device at all has that attribute and nothing else, and that is exactly
the case `start_supplicant`'s `-Dnl80211,wext` exists for. The fallback in the
driver list and the second half of this predicate are the same case, and they
should agree about whether it exists. Now they do.

## The fixture that could only agree

The existing test built a fake sysfs containing `wlan9/wireless` and asserted
that `wlan9` was a radio. That is the attribute the predicate asked for, so the
test could not have failed for the reason the predicate was wrong -- the kernel
configuration it implicitly assumed was the only one it could describe.

The sixth fixture in this campaign built from the implementation rather than
from the thing modelled. The new test describes three machines instead: a radio
with only `phy80211`, one with both, and one with only `wireless`.

## Sabotage

| reverted | test | result |
| --- | --- | --- |
| ask only `wireless` | `a_radio_is_one_whether_or_not_...` | FAILED |
| ask only `phy80211` | `a_radio_is_one_whether_or_not_...` | FAILED |
| " | `a_fixture_root_is_asked_instead_of_the_machine` | FAILED |

The second sabotage is the one that matters: dropping the old-driver case is the
tempting simplification, and it takes the wext-only radio with it.

## What the audit found sound

`start_supplicant` detects the wireless case rather than assuming it, and its
comment says why -- guessing wrong "produces a supplicant that starts and never
associates". The name is rejected rather than joined if it contains a separator
or `..`, because these names come from a configuration file. 0125's guard about
not taking a radio from another manager is there, with the D-Bus case that
defeated its first version written up beside it.

And `STATUS` on the running machine confirmed 0226 from the other side:

```text
key_mgmt=SAE  pmf=1  sae_h2e=0
```

`sae_h2e=0` is hunting-and-pecking -- the supplicant on this radio has not been
repopulated since `sae_pwe` was added, which is the populate-time class 0228
recorded. The setting is in the binary and not yet on the radio.

## A prediction about the build, and a proxy again

Installing this, the NetworkManager shim was predicted to come out
byte-identical: `adapter/netcfgd-nm/Cargo.toml` declares `netcfgd-proto` and
`netcfgd-model` and nothing else, and neither changed. It changed.

`cargo tree` says why. `netcfgd-proto` declares `netcfgd-apply`, which pulls in
the planner, every backend, and `netcfgd-sys` -- the crate this decision
changes. The shim links it at depth four:

```text
netcfgd-nm
  netcfgd-proto
    netcfgd-apply
      netcfgd-supplicant
        netcfgd-sys
```

**The manifest's direct dependencies were read as a proxy for what the binary
links**, which is the substitution this campaign keeps finding in the code,
made here in the reasoning about it instead. `cargo tree` answers the real
question and is one command.

Worth keeping for its own sake as well: the shim is a separate workspace for
the reason design section 9.2 gives -- keeping its D-Bus stack out of the core's
dependency graph -- and that separation runs one way only. The core does not
gain the shim's dependencies; the shim links very nearly all of the core.

The same confusion has a second half that is not a defect. A local
`cargo build --release` of the shim and the packaged binary never match, because
debhelper strips the packaged one and splits the symbols into
`netcfgd-nm-dbgsym`: 7,171,696 bytes against 5,669,240. Built twice from
unchanged sources the shim is byte-identical, so the build is reproducible and
only the comparison was wrong.

