# 0212: two writers on one report

Status: accepted
Date: 2026-09-11
Milestone: M9; the wifi DNS and resolver audit

Asked to audit the wifi DNS path, the first thing it turned up was a defect
committed earlier the same day, in
[0210](0210-the-card-is-the-only-thing-that-says-which-sim.md).

## The single report file has one writer, and it is not the helper

`doc/interface-report.md` is explicit and has been from the start:

> **Write this file. It is yours.** One file, one interface, one writer --
> because the thing writing it is the thing that brought the interface up.

0210 had `netcfgd-modem-at` write `/run/netcfgd/reported/<interface>` to report
the ICCID. On an ECM module the thing that brought the interface up is the
**DHCP client**: the module runs a DHCP server, the host takes an ordinary
lease, and `netcfgd-modem-at`'s own header says so twice. The file was never
the helper's to take.

Both writers build a temporary file and `rename(2)` it over the same path, so
they did not merge -- whichever went last won outright. Measured, both
directions:

```text
helper attaches, then a lease renews  -> the card is gone
lease is taken, then the helper attaches -> grep -c '^dns=' goes 2 -> 0
```

The second is the one that matters here: **a cellular link with an address, a
default route and no resolver at all**, produced by a helper whose only job in
that moment was to say which SIM card it had read.

The fix is what the contract already provides for: "A helper may write there
too, if it genuinely has more than one source for one interface." A modem on
ECM does -- the client for the addressing, the helper for the card -- so the
helper writes `reported.d/<interface>/modem-at` and `read_reports` merges the
two. The test now asserts the lease's nameservers survive an attach, and
putting the single file back takes it red.

## A rule in prose is not a rule

This one had been written down, in the file the author had read that morning
in order to know the report format at all. It still broke within hours.

So `tool/report_writer_gate.py` refuses a shipped shell writer of
`reported/<interface>` that is not named in `tool/report-single-writers.txt`
with the reason it is the writer that brought the interface up. The list has
three entries and each one can give that reason in a clause. **Writing the
reason is the check**: for the AT helper there is no such sentence, because its
own header says the DHCP client does it.

It is the shape `tool/write-best-effort.txt` already uses -- a list somebody
has to edit deliberately, so that adding one is a decision rather than an
accident.

## Two things the gate found by being wrong

**Its first detector matched the literal `reported/`.** Shell assembles paths
from variables, and the mutation that puts the defect back --
`directory="$run_dir/reported"` with a `$directory/$interface` three lines
later -- never spells a slash after the segment. That sabotage passed on the
first run. The pattern is anchored on the slash *before* the segment now, and
excludes the fragment tree by its suffix.

**Then it flagged the systemd unit**, which names the directory in
`ReadWritePaths=` rather than writing it. A false positive, and it was pointing
at a real fault: the grant still said `/run/netcfgd/reported` while the helper
had just moved to `reported.d`. Under `ProtectSystem=strict` that would have
denied the write -- and the helper is deliberately silent when it cannot
report, so the card would simply never have appeared, on the board, with
nothing anywhere saying why. The grant moved with the write; the gate now only
reads files with a shell shebang.

A gate that is wrong in a way that finds something is still wrong. Both were
fixed, and both are worth recording: the first is why the sabotage pass is not
optional, and the second is why a false positive gets read before it gets
suppressed.

## What the audit did not find, which is worth saying

The suspicion that started the DNS half of this round was that `dns { }` -- the
one-line remedy netcfgd prints when a lease's nameservers go unclaimed -- did
not actually claim them. It does. `ncfg plan` with the block emits `dns.apply`
for the interface's scope; without it, "nothing to do" and the warning naming
the remedy.

The appearance came from the test harness rather than from netcfgd: `ncfg plan`
and `ncfg show` **compile locally** rather than asking the daemon, so a run with
`NCFG_RUN_DIR` pointed at a fixture and `NCFG_CONFIG_DIR` left alone plans
`/etc/netcfgd` against the fixture's reports. The message was exactly right
about the document it had been given.

Recorded because the wrong conclusion was one step away and the measurement
that settled it is cheap: set both variables, and check the control from the
other side.
