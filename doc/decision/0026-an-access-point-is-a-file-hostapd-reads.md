# 0026: An access point is a file hostapd reads

Status: accepted
Date: 2026-07-31
Milestone: M4 (schema), delivered after M6

## Context

The M4 freeze put four features in the document that nothing implemented.
Policy routing rules, `ipv6_token` and the ethtool offloads are built; the
`access_point` block is the last one, and `ncfg plan` has been saying so on
every plan since.

The other three were netlink. This one is not: there is no kernel interface
that runs an access point. Something has to build beacons, answer probes and
run the four-way handshake, and netcfgd will never do any of that -- design
section 1.5 permanently delegates key management, and decision 0016 restated it
when it looked at which half of a supplicant could ever be netcfgd's.

So the question is which program, and what the interface to it is.

## Decision

**hostapd, configured by a file netcfgd generates into `/run` and regenerates
on every apply.**

`wpa_supplicant` was the alternative and it is a real one. It has an AP mode,
it is already a dependency (decision 0014 makes it the floor), it is driven
entirely over the control socket netcfgd already speaks -- which would let
decision 0015 stand unchanged, with no configuration file anywhere and no
passphrase on disk. `tests/live/hwsim.sh` already stands up its access point
that way, precisely because it needed no package the station side did not.

It still loses, for one reason that outweighs all of that: **hostapd is what a
wireless router runs**. Every OpenWrt device, every consumer access point,
every enterprise deployment with a RADIUS server behind it. `wpa_supplicant`'s
AP mode is a laptop tethering feature -- no RADIUS, no multiple BSS, no serious
control over the parts of 802.11 that make an access point good rather than
present. netcfgd's embedded tier exists for exactly the class of device that
runs hostapd, and picking the other one would mean the schema's `access_point`
block could never grow the fields those devices need.

## What that costs, stated plainly

**A passphrase goes on disk in the clear.** hostapd has no way to be handed a
credential at runtime; `wpa_passphrase` is a line in its configuration file.
So netcfgd resolves the `SecretRef` at apply time and writes the value into
`/run/netcfgd/hostapd/<device>.conf` at mode 0600, opened with that mode rather
than chmodded afterwards -- a mode set after the write is a mode that was wrong
once, and the window is exactly when the secret is on disk.

This does not weaken constraint 5, which is about the *desired-state document*:
that still carries only a `SecretRef`, in local files, in `/run/netcfgd/desired`
and on any future wire. What is new is a backend artifact holding a resolved
value, and it is not new at all -- `write_ppp_options` has been writing a PPPoE
password into `/run/netcfgd/ppp` at 0600 since M4, for the same reason. The
live test asserts that the value appears in that one file and nowhere else
under `/run`, and in neither the plan nor the apply output.

**The file is derived, never read back.** Constraint 1 says the configuration
under `/etc` is the only authority. hostapd's file is a rendering of the
document, regenerated on every apply, and nothing in netcfgd ever parses it --
so it cannot become a second place a network is defined. It says so in its own
first three lines, because somebody will find it and edit it.

**One radio is one BSS, and one thing at a time.** A radio running an access
point does not also join networks: that needs a second virtual interface on the
phy, which netcfgd does not create. A radio with two `access_point` blocks runs
the first by name. Both are warned about rather than refused, and the planner
and the executor agree on which one runs -- if they disagreed, the plan would
name one access point and hostapd would serve another.

**The station side had to be taught to get out of the way.** Adding an
`access_point` block to a radio that was joining networks has to *stop* its
supplicant. Without that, the access-point pass starts hostapd, the station
pass wants a supplicant, and every reconcile undoes the last one -- forever.
This is the second time that failure mode has been found in this planner and it
was found the same way: by writing the test that observes the supplicant
running, and then removing the guard to check that the test noticed.

## What is not rendered, and why

The document has no fields for HT/VHT/HE, so none are emitted. An access point
netcfgd starts today runs at 802.11g rates. That is a poor access point, and
it is deliberate: `ieee80211n=1` and a matching `ht_capab` depend on what the
radio supports, and this whole feature was written on a machine with no radio.
Adding it is a schema change plus a measurement, and the measurement needs
hardware. Naming it here so the next person does not have to rediscover that
the gap was noticed.

`Security::Eap` is refused by name. An access point using EAP authenticates
against a RADIUS server, and an `eap` block describes a client's credentials --
the wrong end of the exchange, and there is no field for a server. The model's
own comment predicted this ("validation belongs with the implementation"); this
is the implementation, and this is the validation.

The 6 GHz band is refused for the same shape of reason: it needs an operating
class and HE parameters that the document cannot express.

## How it was checked without a radio

hostapd parses its configuration before it touches a driver, and it says which
line it disliked. That makes it usable as a reference tool on a machine with no
wireless hardware at all, which is what
`backend/netcfgd-hostapd/tests/reference.rs` does: every security variant,
every band, an SSID that is not text, all rendered and all fed to a real
hostapd, asserting it found nothing to complain about. The test next to it
feeds hostapd a deliberately wrong `wpa_key_mgmt` and requires the check to
notice -- a gate nobody has seen fail is not evidence.

That found nothing wrong with the encoder, which was not the expected outcome
and is worth recording: the spellings were checked against hostapd 2.10 while
they were being written rather than afterwards, so `ssid2` taking bare hex,
WPA3 being `wpa=2` with `key_mgmt=SAE`, and transition mode needing
`sae_require_mfp=1` were all confirmed before any Rust existed.

What it did find was in the error path. hostapd announces a failure and then
narrates its shutdown, so the last three lines of a failed start are
`AP-DISABLED`, `CTRL-EVENT-TERMINATING` and `Interface ap0 wasn't started` --
all true, none of them the reason, and the reason ("this driver is not a
wireless driver") four lines earlier. Reporting the tail of the log sent the
operator to inspect the interface. It now picks out the lines that look like a
diagnosis instead, and the live test asserts on hostapd's own words rather than
on the fact that something failed.

## Alternatives that lost

**`wpa_supplicant` AP mode.** Above. It would have been less code, no new
package and no secret on disk, and it would have capped this feature at what a
laptop hotspot needs.

**Both, with a backend selector.** `WifiDevicePolicy` has a `backend` field for
stations; an access point would need its own. Adding one is a post-freeze schema
change, and it would be justified by an implementation convenience rather than
by something an operator wants -- which is close enough to constraint 6's shape
to refuse on principle, and to refuse on cost besides.

**netcfgd implements an access point.** Never. Design section 1.5.
