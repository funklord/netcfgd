# 0014: wpa_supplicant is the floor, not the fallback

Status: accepted
Date: 2026-07-29
Milestone: M3

## Context

Design section 19.2 question 5, still open: "iwd vs wpa_supplicant default.
Prefer iwd where present, or default to wpa_supplicant for ubiquity?"

The milestone table answers it one way -- M3 reads "iwd backend
(wpa_supplicant fallback)" -- and the brief was written before two things were
true.

**iwd speaks D-Bus and nothing else.** Its entire control surface is the
system bus. Constraint 3 keeps D-Bus out of the core, and wifi is a backend so
it could in principle carry the dependency in its own package -- but the
dependency is not small. A Rust D-Bus client is either a large crate tree or
several thousand lines of hand-rolled marshalling, and either would be, by a
wide margin, the biggest thing in this repository. It would also be the first
dependency that makes `cargo deny`'s allow list stop fitting on a screen.

**wpa_supplicant has a control socket that needs nothing.** A unix datagram
socket carrying line-oriented text: `PING` answers `PONG`, `SCAN_RESULTS`
answers tab-separated rows, `SET_NETWORK 0 psk "..."` answers `OK` or `FAIL`.
Parsing it is a hundred lines of safe code with no dependency at all, which is
the same shape as everything else netcfgd talks to.

And decision 0008 already settled a related case: wired 802.1X uses
wpa_supplicant, because iwd has no wired driver. So wpa_supplicant is going to
be present and integrated whatever happens with wifi.

## Decision

**Build wpa_supplicant first, and treat it as the floor rather than the
fallback.** One supplicant integration then covers wifi and wired 802.1X, with
no new dependency of any kind.

**iwd stays wanted, and its cost is now explicit.** It roams better, it is
smaller on disk, and it is the default on some distributions -- those are real
and this record is not an argument against it. What it needs is a D-Bus
client, and taking that on is a decision to make deliberately, with the size
gate in the room, rather than something to arrive at by implementing the
milestone table in order.

`WifiDevicePolicy.backend` already has `Auto`, `Iwd` and `WpaSupplicant`, so
the model needs no change. `Auto` resolves to wpa_supplicant in this build,
and asking for `Iwd` is refused by name -- the same treatment every other
unimplemented feature gets, because a reader has to be able to tell a gap from
a bug.

### What this changes about the milestone

M3's entry should read "supplicant backend (wpa_supplicant), iwd deferred"
rather than the other way round. That is a real reversal of the brief and is
recorded here rather than quietly implemented, because somebody reading the
milestone table should not have to diff the source to find out the order
changed.

## Consequences

**No new dependency for wifi.** The supplicant client is safe code over a
unix socket, so `netcfgd-supplicant` needs nothing that is not already in the
tree, and the size gate sees only the code actually written.

**One integration serves two features.** Wired 802.1X and wifi both drive the
same daemon through the same socket, which means the awkward parts -- knowing
whether it is running, restarting it, reading its state -- get solved once.

**iwd users get an honest error rather than silence.** A config asking for
`backend = "iwd"` is refused with a message naming the milestone, not
downgraded to wpa_supplicant behind the operator's back. Silently substituting
a different supplicant would produce different roaming behaviour than the
config asked for, and that is exactly the kind of thing nobody would think to
check.

**The parsing is testable without a radio.** Everything about the control
protocol -- scan results, network lists, status -- is text in and structs out,
so it is exercised against captured-shape fixtures. What is *not* testable
that way is association itself, and that needs `mac80211_hwsim`. This machine
has neither wpa_supplicant nor the module, so the integration is written
against the documented protocol and marked as needing a hwsim run before M3
can be called done. Saying so is better than implying the tests cover it.

## Alternatives considered

**iwd first, as the milestone table says.** Rejected on the dependency, which
the table did not weigh because the D-Bus question had not been faced yet.
Doing it in this order also means the wired 802.1X work in decision 0008 would
have waited on a supplicant integration nobody had built.

**Both at once.** Rejected: two backends before either has run against real
hardware is two things to debug when association fails, and no way to tell
which one is wrong.

**iwd through `iwctl`, shelling out instead of speaking D-Bus.** Tempting, and
rejected. Parsing the output of an interactive tool is a contract nobody
promised to keep, and the failure mode is a working system that breaks on an
upgrade with no warning. If iwd is worth doing it is worth doing through its
actual interface.
