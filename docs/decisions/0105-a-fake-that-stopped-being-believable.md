# 0105: a fake that stopped being believable

Status: accepted
Date: 2026-08-04
Milestone: the nm.sh regression, bisected properly

## Context

The previous session reported `nm.sh` as failing seven checks, blamed
`b1cd6eb`, and described a "gradual erosion" across many commits. **Both claims
were wrong, and they were wrong for the same reason: single runs of a test that
is not deterministic.**

The first was a bisect that tested two endpoints forty commits apart and named
the later one. The second was a table built from one measurement per commit.

Sampling five runs per commit says what is actually there:

| commit | five runs |
| --- | --- |
| `8ddf020` | 0 0 0 0 0 |
| `d2db524` | 0 0 0 0 1 |
| `1a6f5dc` | **7 7 7 7 7** |
| `master` | 7 7 7 7 7 |

One commit, consistently, and its parent consistently clean apart from a rare
single failure that is a separate and older thing. There is no erosion. The
earlier "4 failures at `d2db524`" and "6 at `1a6f5dc`" were both flakes read as
signal.

## The regression

`1a6f5dc` is [0080](0080-a-socket-outlives-the-process-that-bound-it.md), *stop
trusting its socket*, and it is correct. It changed the **start** path to ask a
question a control socket cannot answer:

```rust
if netcfgd_sys::process::pid_of(&pidfile, &pidfile.to_string_lossy()).is_some() {
```

A supplicant is running when `$run/supplicant/<iface>.pid` names a live process
**whose own command line contains that path** — which is what netcfgd's own
start writes, via `-P`. A socket proves nothing, because a socket outlives the
process that bound it.

`fake_supplicant.py` offered a socket and nothing else. So netcfgd correctly
decided no supplicant was running and started a **real** `wpa_supplicant`, which
bound the same socket path and answered scans from a radio that does not exist.
Every wireless check downstream read blank:

```
--- ncfg wifi scan radio0 ---   no access points in range of radio0
--- fake.log ---                ready / PING / ATTACH
--- daemon.log ---              Successfully initialized wpa_supplicant
```

At the parent commit the same log reads `REMOVE_NETWORK all`, `ADD_NETWORK`,
`SET_NETWORK 0 ssid …` — netcfgd configuring the fake, which is what the test is
for.

## Decision

**The fake writes the pid file, and is told its path.**

Both halves are needed and neither works alone: writing the file makes the pid
real, and passing the path as an argument is what puts it in the process's
command line so the marker matches. It is an optional fourth argument, so the
four other scripts using the fake are unaffected.

**Nothing in netcfgd changes.** 0080 is right, and the failure was a fake that
had quietly stopped resembling the thing it stands in for. A test double is a
claim about the real component; when the real one gains a property the double
must gain it too, and nothing enforces that.

## The gates

`nm.sh` over six runs after the change: five clean, one failing a single
unrelated check. Before: seven failures, five times out of five. The other four
users of the fake — `roam.sh`, `wedged.sh`, `hooks.sh`, `rfkill.sh` — are
unchanged by it.

## What is left, measured rather than guessed

**A pre-existing flake, roughly one run in six**: *"a cancelled prompt is
reported as such"*, in the secret-agent bridge and not the wireless path. It is
visible at `d2db524`, before 0080, so it is older than the regression above and
unrelated to it. The wait for the fake agent's `registered` line breaks silently
after ten seconds and proceeds either way, which is a plausible mechanism and
not a demonstrated one — recorded as an observation rather than fixed on a
guess.

**`rfkill.sh` fails one check, consistently**: *"the observation names the phy's
own switch"* expecting `"switch":"phy0"`. Reproduced identically with this
change reverted, so it is neither caused nor fixed here. Newly noticed because
`make live` stops at the first failing script and never used to get this far.

## The lesson

**A flaky test cannot be bisected one run at a time, and will happily produce a
narrative.** Two single-run passes over the history produced a confident,
detailed, wrong story — a specific culprit commit and a gradual decline — and
the story survived being written down because each number in it was real. The
fix is not care; it is sampling. Five runs per point cost four times as much and
gave a different answer.
