# 0148: Bluetooth is two backends and an adapter

Status: accepted
Date: 2026-08-30
Milestone: M9; Bluetooth networking and audio

The holder asked for Bluetooth networking and Bluetooth audio -- multiple in
and out, ALSA only, no PulseAudio -- and later audio device handover over
fuzznet's streaming. This settles the shape before any of it is built.

## The scope question, answered rather than ignored

**Audio is not networking, and it is in netcfgd anyway** -- but only the part
netcfgd is already in the business of doing. netcfgd manages devices and links
and delegates the work to backends it starts and supervises: `wpa_supplicant`,
`dhcpcd`, `hostapd`. Bluetooth audio adds one more of those and no new kind of
thing.

**netcfgd never touches a sample.** What it owns is which adapter is powered,
which backends run, and what the resulting links are configured as. What
carries audio is `bluealsa`, and what pairs a device is `bluetoothd`.

That framing is what keeps this from being an exception. A Bluetooth adapter is
a radio netcfgd already sees through rfkill (0062); a PAN connection produces a
`bnep0` interface that goes through the existing addressing and route model
with no special case at all.

## ALSA only, and why nothing is written here

`bluez-alsa` (Debian `bluez-alsa-utils`, 4.3.1) registers as a BlueZ media
endpoint and exposes ALSA PCMs, with SBC, AAC, LDAC, LC3 and Opus. Multiple in
and out is its native behaviour: each connected device is its own PCM.

So netcfgd implements no A2DP, no codec and no audio path. Writing one would be
a second implementation of a solved problem, in a network daemon, against a
4608 KB resident budget.

## Where D-Bus may live, which decided the architecture

BlueZ is D-Bus and nothing else. [0014](0014-wpa-supplicant-is-the-floor-not-the-fallback.md)
declined iwd partly for that, and says exactly how far the objection reaches:
"Constraint 3 keeps D-Bus out of the **core**, and wifi is a backend so it
could in principle carry the dependency in its own package".

**A backend crate cannot carry it here, and the tree already says why.** The NM
shim is a separate workspace deliberately, because "a cargo workspace shares
one lockfile and one `cargo-deny` graph, so a member here would put zbus and
its eighty-odd transitive crates in front of the gate that exists to keep the
core at libc, serde and nothing else". `make nm-containment` proves the core
links none of it. A `backend/netcfgd-bluetooth` speaking D-Bus would defeat
that gate rather than pass it.

So the work splits three ways, and the split is forced rather than chosen:

- **The core needs no D-Bus at all.** Adapters are observed from
  `/sys/class/bluetooth` and rfkill. `bluetoothd` and `bluealsa` are supervised
  the way every other backend is: started, given a pid file, adopted, stopped.
  `bnep*` interfaces arrive in netlink like any link and are configured like
  any link.
- **`bluetoothd` is a backend, not a peer.** It holds the adapter through the
  kernel's management socket, so netcfgd driving `mgmt` directly while it runs
  would be two daemons on one radio -- the failure `contention.rs` exists for,
  one layer down, and the one that cost the operator their link twice while
  the wireless work was going on. netcfgd supervises it and does not race it.
- **Pairing and profile selection are an adapter**, in its own workspace beside
  `netcfgd-nm`, because they need D-Bus and because they are interactive: a
  passkey is a person, and an agent is a desktop concern.

## What is deliberately not decided here

The configuration vocabulary. A `bluetooth` block naming an address, a profile
and a role is the obvious shape and obvious is not enough: it is the operator's
language and it outlives the implementation, so it gets its own record once
there is a working path to describe.

Handover over fuzznet's streaming is last and depends on all of it. It is also
the one part that is not netcfgd's protocol to design -- a gap found there is
reported to fuzznet rather than worked around here.

## How it will be known to work

**The lesson of the wireless work applies directly and is why this section
exists.** Every wifi fault found in the days before this record came from
something that had never run: a test that needed root and was not in `make
live`, eleven tests driving a fake supplicant, a GUI probe that only ran when
the GUI was built. netcfgd associated with a network for the first time only
after `hwsim.sh` was finally run.

So the rig comes before the feature. `hci_vhci` is the `mac80211_hwsim`
equivalent and needs no hardware. Debian's `bluez` ships no `btvirt`, so two
virtual controllers cannot be linked to pair with each other out of the box;
`btvirt` is built from bluez source for the tests, which is the difference
between this landing verified and landing in the state wireless was in.
