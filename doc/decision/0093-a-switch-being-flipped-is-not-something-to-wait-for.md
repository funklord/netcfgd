# 0093: a switch being flipped is not something to wait for

Status: accepted
Date: 2026-08-04
Milestone: the last open item on the laptop list

## Context

[0062](0062-a-blocked-radio-is-reported-and-not-unblocked.md) made netcfgd
*report* a blocked radio, read out of `/sys` during an observation, because a
radio that is switched off looks exactly like a network that will not associate.
Section 10 carried what it could not do:

> Nothing reads `/dev/rfkill`'s event stream, so a flipped switch is noticed on
> the next observation rather than as it happens.

An observation runs on a netlink event or on the loop's five-second backstop.
**Blocking** a radio usually takes the interface down, so netlink reports it and
the delay is invisible. **Unblocking** one produces nothing at all until
something else happens — so a machine could sit with a working radio and a plan
still saying it was off, for as long as nothing else moved.

## Decision

A watcher thread reads `/dev/rfkill` and reports `KernelChanged`.

**`KernelChanged` and not a command of its own.** What changed is something an
observation already reads, so the answer is the one netlink gets: look again. A
second command would be a second path through the loop doing the same thing.

**Read-only, structurally.** The same device accepts writes that block or
unblock every radio on the machine. 0062 decided that a switch an operator
flipped is a decision netcfgd reports rather than overrules, and nothing here
opens the device for writing — which makes that a property of the code rather
than of the intent.

A machine with no radio has no `/dev/rfkill`. The thread ends and says nothing:
"this laptop has no wifi" is not a warning.

## What measuring changed

The first version was wrong, and reading the header would not have caught it.

`struct rfkill_event` is eight packed bytes, and newer kernels have
`rfkill_event_ext`, which appends a ninth. The kernel's rule for userspace is to
read what you know and ignore the rest — so the obvious reading is "a byte
stream of records", and the obvious implementation buffers what arrives and cuts
it every eight bytes.

That is wrong, and on a kernel writing the longer record it would have kept the
ninth byte and shifted **every following event by one**: a fault that appears
only on kernels newer than the one it was written against.

Opening the real device and reading it says what actually happens:

```
read 8 bytes: 00 00 00 00 01 00 00 00
read 8 bytes: 01 00 00 00 02 00 00 00
read 8 bytes: 02 00 00 00 02 00 00 00
read 8 bytes: 03 00 00 00 01 00 00 00
```

**One read is one record.** The kernel dequeues a single event and copies
`min(what you asked for, the struct it has)`, so a generous buffer gets one whole
record and never two. There is nothing to reassemble, and the surplus of a
longer record is discarded with the read that carried it.

Four records on opening, before anything was flipped: the kernel queues one
`ADD` per existing switch. So the watcher costs a handful of reobservations at
startup, and in exchange netcfgd does not have to ask `/sys` whether anything
changed while it was not running.

## The gates

**Unit**, on the record format: the kernel's layout byte for byte, a multi-byte
index (where a byte-order mistake shows), and a longer record being one event
rather than two. The bytes in one of them are the ones captured above — a real
kernel's, not a fixture agreeing with what this module believes.

**Live**, against a **fifo** and deliberately not the real device. Writing to
`/dev/rfkill` blocks every radio on the machine, and rfkill is not namespaced,
so `unshare -rn` would be no protection — a test that flipped a switch would
take the wifi off the desk it was running on. What is real is the record format
and the daemon's reaction: a record on the device makes it write a fresh
observation within a second, which is well inside the five-second backstop, so
the event is doing the work and not the tick. Making the watcher swallow the
event turns that red.

`tests/live/rfkill.sh` still reads the real device for the other half, and the
daemon was run once against the real `/dev/rfkill` to confirm it opens, replays,
and goes quiet.

## What this does not do

It does not act on a blocked radio, which is 0062's decision and unchanged: the
plan says the radio is off and what would clear it, and netcfgd does not clear
it. This makes that sentence prompt, not different.
