# 0194: a scan is not a round trip

Status: accepted
Date: 2026-09-10
Milestone: M8; the wifi scanning and signal audit

## The measurement that started it

```
$ time ncfg wifi scan wlp0s20f3
 -58 dBm   5500 MHz  enterprise  EMP-XYLEM  [EMP-XYLEM]

real	0m0.007s
```

**Seven milliseconds.** A scan is the radio leaving the channel it is on and
visiting every other one it is allowed to use, in both bands and in 6 GHz where
the hardware has it, dwelling on each long enough to hear a beacon. It takes
seconds. Whatever that command did, it did not scan.

Three consecutive calls, five seconds apart:

```
first:  15
second: 20
third:  20
```

The first returned a list five networks out of date, and the scan it asked for
is what made the second one right.

## Why

```rust
// A scan already in progress answers FAIL, which is not a failure worth
// reporting: the results are about to be fresh either way. Anything else
// wrong will surface on the read below.
let _ = client.command("SCAN");
let body = client.ask("SCAN_RESULTS")?;
```

**`SCAN` queues a scan and returns at once. `SCAN_RESULTS` reads the cache the
last completed scan filled.** Sending one and immediately reading the other
returns the previous scan's results, always, and the scan just asked for lands
in whatever reads the cache next.

The comment said the results were "about to be fresh either way". That is the
fault stated as a reassurance: *about to be* is not *are*, and the client is
gone by the time it becomes true.

Worst on the case that matters most -- a supplicant that has just started has
an empty cache, so the first scan after netcfgd brings a radio up returns
nothing at all. "I pressed scan and nothing appeared" is not a mystery; it is
this.

## What replaces it

Attach, scan, **wait to be told it finished**, then read.
`CTRL-EVENT-SCAN-RESULTS` is the supplicant saying so, and
`CTRL-EVENT-SCAN-FAILED` is the other outcome, worth returning early for since
nothing further is coming.

The order is the whole of it: `ATTACH` before `SCAN`, because events reach only
connections that asked, and asking afterwards races the scan finishing on a
radio with little to look at.

A `SCAN` that answers `FAIL` is a scan already running, and is **not** a reason
to skip the wait -- a scan is in flight and its completion event is the one
being waited for.

## Ten seconds, and saying so when they run out

`SCAN_PATIENCE` is ten seconds, `REPLY_TIMEOUT`'s reasoning applied to the
thing it was written about. Being wrong in the impatient direction returns the
previous results **and says so**; being wrong the other way makes a person wait
on a radio that is not going to answer.

`ScanReport` gains `stale: Option<String>`, absent on the ordinary answer.
Stale results are worth more than no results, so they are still returned --
labelled, with the driver's own `ret=` passed through rather than translated,
because that set is the kernel's and any translation here would be a partial
one. -16 is `EBUSY`, -100 is `ENETDOWN`; both appear in this machine's journal.

## The part that would have been a regression

**Waiting is only correct if the waiting happens somewhere the rest of netcfgd
is not.** Requests are answered on the reconcile loop, so a scan that now takes
seconds would hold that loop for seconds -- and 0111 is the record of exactly
that cost: a wedged `PING` on an unrelated interface blocked the loop for 12.2
seconds, and the fix was to stop waiting rather than to wait better.

So authorise on the loop, where the policy and the peer are, and do the waiting
off it. The answer travels on a `SyncSender` and does not care which thread
sends it, and the server already runs a thread per connection -- this is the
model the daemon has, not a new one.

The now-unreachable `answer()` arm returns a message rather than calling
`wifi::scan`. A scan routed back through there would *work*, and would quietly
restore the stall the split was made to avoid. A message is a regression
somebody sees.

## Also found: the event 0192 missed

0192 read the events that say an association is failing and not the one that
says the radio could not look at all. Twenty-four `CTRL-EVENT-SCAN-FAILED` in
three days here. It is now a note, and it is the reason the scan path does
**not** log its own failure: the same event reaches the journal through the
watcher, and logging both put two nearly identical lines there for one event,
from two subsystems. The reason travels to whoever asked, in `stale`.

## Verification

Nine checks in `tests/live/wifi_trouble.sh`. `fake_supplicant.py` gains the
half it never had -- a real supplicant answers `SCAN` with OK **and then sends
an event**; the fake only ever answered, which is why netcfgd's new wait had to
be checked against it before anything else, since a fake that never announces a
result makes every scan wait out its patience and report stale.

`FAIL_NEXT_SCAN <ret>` and `SILENT_NEXT_SCAN` are modes rather than events a
test sends directly, and that is not incidental: the connection netcfgd scans
on attaches for that scan and goes, so an event sent out of band arrives at
nobody and the test would pass on a fake talking to itself.

Sabotage, all three landing: not waiting takes the two failure checks red;
never attaching takes three red and leaves the fourth passing for the wrong
reason, which is why "passes the driver's return code through" is asserted
separately from "says the results are stale"; putting the scan back on the
reconcile loop takes the stall check red and nothing else.

The controls are asserted from both sides -- an ordinary scan says nothing
about staleness *and* returns the network the fake radio can see, so the
first check cannot pass on an empty answer.
