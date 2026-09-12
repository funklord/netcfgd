# 0217: a stale scan that only one client mentions

Status: accepted
Date: 2026-09-12
Milestone: M9; the wifi scanning and signal audit

## The daemon says it and the C client dropped it

[0194](0194-a-scan-is-not-a-round-trip.md) made the scan honest:
netcfgd attaches to the supplicant's event stream *before* asking for a scan,
waits for the completion event, and where that did not arrive -- the radio was
busy, the interface went down, the scan outlasted its patience -- reports the
previous scan's results **with the reason attached** rather than handing them
back as though they were fresh.

`ncfg wifi scan` prints it, above the list, under a comment that says exactly
why it is above:

> "nothing is in range" and "netcfgd could not scan" are different answers and
> the second one printed as the first is the whole complaint this fixes.

`ncfg_scan_t` had no field for it. So the C client could not carry it, the Qt
client could not show it, and the gui showed the same list with nothing said --
including, when the scan failed outright, an empty table summarised as
"wlan0 found nothing". That is the second answer printed as the first, in the
client most likely to be the one an operator is looking at.

## Where it had to be read

`convert_scan` returns early when there are no access points, which is correct
-- a radio that found nothing is a real answer. Reading the reason after that
return would have dropped it in **exactly the case it exists for**: a scan that
failed comes back with an empty list and a reason.

So it is read before, and the test that pins this stages an answer with no rows
and a reason. Moving the read below the early return takes it red.

## What the gui says now

The reason leads the sentence rather than being appended, for the command
line's reason: a caveat read after the rows is one the operator has already
acted on.

```text
wlan0: these are the previous scan's results -- the supplicant could not scan
       (ret=-16)
```

and with rows behind it, the count follows in parentheses instead of replacing
it.

## What the audit found sound

The scan and signal path is otherwise in good order, and most of this round was
checking rather than changing:

- **`SCAN_RESULTS` parsing.** `signal` is an `i32` parsed from the third
  tab-separated field, so a negative dBm survives; a row that will not parse is
  skipped rather than failing the whole scan.
- **The ordering.** `sort_by(|l, r| r.signal.cmp(&l.signal))` is descending on
  dBm, which puts -45 before -90 -- strongest first -- and `sort_by` is stable,
  so equal levels keep the supplicant's order rather than swapping between
  scans, which is what the comment claims.
- **No dBm-to-percentage conversion anywhere.** Both clients print dBm as dBm.
  The most common signal-strength defect is a made-up quality percentage, and
  there is none to get wrong.
- **`channel_of`** in the gui converts 2.4 and 5 GHz correctly, special-cases
  channel 14, and prints the frequency for anything else -- including 6 GHz,
  whose numbering is a third rule, rather than guessing at it.
- **A hidden access point survives.** `Ssid::new` rejects only lengths over 32,
  so the empty SSID a hidden network scans as is kept rather than dropped.

## And an unrelated finding this round turned up

`make check` went red once, in `netcfgd-sys`, on
`the_real_uid_is_read_before_the_effective_one`. It is not caused by anything
here, and it is not environmental: the cause is in the test suite and it
explains two earlier red runs in this same session that could not be
reproduced.

`privilege::shed()` reaching `Shed::Fully` takes **the whole process** to uid
65534, and a test calls it. Its own documentation says so -- "it is also why
every test that runs after this one in a root run is running as 65534" -- and
frames it as a known consequence. The test harness runs tests in parallel
threads of one process, so "after" is not an ordering, it is a race: any other
test in that binary that reads its own uid, or chmods a file it created as
root, races the thread that sheds.

That is both flakes this session. The `chmod: Operation not permitted` that
could not be reproduced was a test making a file executable while another
thread had already taken the process to 65534.

Not fixed here, because it belongs to a different subsystem and a different
piece of work: containing it means running the shedding test in a child process
rather than a thread, which is a change to how that crate tests rather than a
line. Recorded so the next red run is read as this rather than as the machine.
