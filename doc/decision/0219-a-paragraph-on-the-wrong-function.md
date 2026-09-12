# 0219: a paragraph on the wrong function

Status: accepted
Date: 2026-09-12
Milestone: M9; the wifi power and rfkill audit

## The audit's honest result

The power and rfkill path is in good order and this round changed almost none
of it. That is worth writing down, because a round that finds little is a
result rather than a gap in the looking -- and most of what is here was
established by earlier rounds that measured it.

What holds:

- **`/dev/rfkill` is opened read-only**, and the module says why that is a
  property of the code rather than of the intent: the same device accepts
  writes that block or unblock every radio on the machine, and 0062 decided a
  switch an operator flipped is reported rather than overruled.
- **One read is one record.** The kernel dequeues a single event per read, so a
  generous buffer gets one whole record and never two -- and the eight bytes
  every version has are read while anything past them is ignored, which is the
  kernel's own rule for userspace and is what keeps a reader built today
  working on a kernel that grows `rfkill_event_ext`.
- **A switch is matched to an interface by the phy's name**, sorted, with
  `continue` rather than `?` on an unreadable entry -- each of which is a
  measured fault in its own right: a laptop has a platform button beside the
  phy's own switch, `read_dir` order is luck, and one unreadable `name` sorting
  early abandoned the whole search and took the "switched off" warning with it.
- **A blocked radio is warned about by name**, with the remedy differing by
  switch, and nothing is refused or unblocked.

## What it did find

`warn_blocked_radios` was documented with somebody else's prose. Two doc
comments had run together with no item between them, so everything intended for
`warn_unapplied` -- the dispatcher for the whole family of "what this build does
not do" warnings -- attached to the radio warning four hundred lines above it,
and `warn_unapplied` itself had no documentation at all.

The stranded paragraph had also gone stale where it stood. It said the list was
down to

> the half of the `ethtool` block that needs a physical NIC, and the parts of an
> access point that hostapd can do and the schema cannot say

and by then the dispatcher also covered a wifi device's `regdom`, `powersave`
and `scan_randomization`, a bluetooth block, a `phase2` that pins nothing
([0218](0218-the-inner-method-the-example-did-not-pin.md)), a MAC
contradiction, a bridged station, a hook that never fires, and a device with no
interface.

So it is back on `warn_unapplied`, and it no longer enumerates: **the list is
the body of the function**, and each arm says for itself what it is about. An
enumeration in prose beside a list in code is a second copy that goes stale, and
this one had.

## What it found and did not fix

**Activating a radio that is switched off reports plain success.**
`ncfg wifi activate wlan0` writes the drop-in, applies the radio's own plan, and
answers `Response::Ok` -- which is defined as "succeeded and had nothing to
return" and has no room for a caveat. The radio is off, the operator is told
nothing, and `activate` is the command somebody runs *because* the wifi is not
working.

The information is one command away -- `ncfg plan` warns, `ncfg wifi status`
shows the switch -- so this is a sentence arriving late rather than a fact
being lost, which is why it is recorded rather than forced.

Fixing it properly means a response that can carry a caveat alongside success,
which is a protocol change: a new variant, the schema witness, the C client and
the gui. The alternatives are worse in a way worth naming: logging it puts it in
the journal rather than in front of the person who just typed the command, and
having the command-line client ask a second question after activating would fix
one client and leave the gui as it is, which is the split
[0217](0217-a-stale-scan-that-only-one-client-mentions.md) is about.

It is the same shape as that one -- the daemon knows something and the answer
has nowhere to put it -- and the same shape as `private_key_passwd` in 0218: a
piece of work rather than an audit's finding.
