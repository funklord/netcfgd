# 0144: an ifindex means nothing outside its namespace

Status: accepted
Date: 2026-08-27
Milestone: M8; the first association netcfgd has ever been observed to make

Qualifies the contention detection added for
[0125](0125-displacing-networkmanager-is-a-runtime-switch-and-nothing-else.md),
which is right about what to look for and wrong about what a kernel index
identifies. That detection carries its reasoning in `contention.rs` rather than
in a record of its own, which is part of how this went unexamined.

## The failure

`tests/live/hwsim.sh` stands two simulated radios up in a private network
namespace and has netcfgd associate with one from the other. It had never been
run. When it was, it failed at the first action:

    FAIL backend.start wlan1  wifi: Supplicant (was <absent>)
         NetworkManager is already managing `wlan1`, so netcfgd will not
         start a second supplicant on it

`NetworkManager` was not managing `wlan1`. It could not see `wlan1`: the radio
existed only inside a network namespace NM has no presence in, and had existed
for under a second.

## Why it said so

`network_manager_claims` reads `/run/NetworkManager/devices/<ifindex>` and
treats `managed=true` as the claim. `contenders` chose the index over the name on the
grounds that an interface can be renamed and an index cannot, and says so in
its own doc comment. That is true -- and incomplete. **An index is issued by a network namespace and means nothing
outside it.** `/run` is a mount rather than a namespace, so a netcfgd in a
private namespace that can still see the host's `/run` reads the host's files
and matches them against its own indices.

Both numberings start at 1, so this is not an unlucky collision. Measured on
the machine that found it: inside the namespace the station was index 3, and
on the host index 3 was the operator's own `wlp0s20f3`, `managed=true`. netcfgd
read the operator's NetworkManager state and attributed it to a virtual radio.

**The guard that exists to stop two daemons fighting over one radio was the
only thing preventing the association it was protecting.**

## What was rejected

**Cross-checking the interface name or MAC in NM's file.** There is nothing to
check against: the device file records neither. It carries `managed`, a
connection uuid, an effective route metric and a `dhcp4` block. A permanent MAC
appears only as `perm-hw-addr-fake` on some devices, and the real one only
where a client identifier happens to embed it.

**Asking NetworkManager over D-Bus.** The dependency
[0014](0014-wpa-supplicant-is-the-floor-not-the-fallback.md) declined, and the
reason has not changed.

**Having the test set `NCFG_RUN_ROOT`.** It would have made the test pass and
left the daemon wrong. The test was right: a netcfgd in a namespace should not
be reading another namespace's daemon state, and no fixture should be needed to
stop it.

## The rule

**State keyed by ifindex is only about our interfaces if it was written from
our network namespace.** Pid 1 is the machine's init, host daemons write `/run`
from its namespace, so `/proc/self/ns/net` and `/proc/1/ns/net` settle it.

An explicit `NCFG_RUN_ROOT` is exempt: a tree somebody pointed at this netcfgd
on purpose does not raise the question.

**Unreadable is treated as ours, deliberately.** Only a privileged process can
read another's namespace link. Being wrong in that direction costs a refusal
the operator can override; being wrong in the other lets netcfgd start a second
supplicant on a radio somebody else is holding, which is what the module
exists to prevent.

## What this does not explain

**It is not the fault the operator reports on real hardware.** There netcfgd
runs in the host namespace, the check passes, and NetworkManager genuinely does
hold the radio -- so the refusal was correct and remains correct. This defect
sat in front of that one, blocking the only test that could have examined it.

## What it cost, and the shape it shares

The suite had 935 passing checks and not one had watched a station associate.
Eleven wifi tests drive `fake_supplicant.py`; `wifi.sh` and `dot1x.sh` drive a
real `wpa_supplicant` with no radio, so everything up to joining a network was
verified and the joining was not. `hwsim.sh` is the only test that closes it,
it needs real root, and it is not part of `make live`.

The same day, `tests/live/dhcpcd_orphan.sh` was found scanning the host's
`/proc` from inside a namespace and killing every dhcpcd it found. **Both are
one mistake: matching on an identifier that is not unique across a namespace
boundary.** One reached out to kill, the other reached out to read. Neither
`/proc` nor `/run` is namespaced by the thing that namespaces indices and pids,
and a number that starts at 1 in both places will collide rather than fail.
