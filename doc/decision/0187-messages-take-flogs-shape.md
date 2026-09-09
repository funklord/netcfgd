# 0187: messages take flog's shape

Status: accepted
Date: 2026-09-09
Milestone: M8; the eighth audit, asked for with the shape named

## The question

> now check the error message quality too, and make it flog shaped like
> fuzzypickles/fuzznet

## What was there

**Fifty messages, every one an `eprintln!("netcfgd: ...")`.** The prose was
good -- this tree has spent a long time on what a message says, and the audits
of the last two days sharpened a dozen more. What none of them had was any
*structure*:

* **no severity.** `adopted the dhcp client already running` and `could not
  stop the orphaned backend` were the same kind of line.
* **no subsystem.** Whether a message was about DHCP, the supplicant, the
  confirm window or netlink was carried only by the words.
* **no filter.** Nothing could be turned down or up. Measured the same day:
  an adoption line printed every five seconds for twenty minutes while a
  restart loop ran -- ordinary, correct, and indistinguishable at a glance
  from the failure causing it.

## The shape, and what of it is copied

`flog` is the C logging library `fuzzypickles` and `fuzznet` share as a
submodule. Read at `fuzzypickles/flog`, and the parts taken are:

* **The severity vocabulary, name for name**: critical, error, warning, note,
  info, verbose info, debug.
* **The rendering**: `[subsystem] Error: text`, `!` for a note, and **no
  label at all for info** -- flog's own judgement that the ordinary line
  should read as a sentence rather than as a log record.
* **The accept mask**: flog holds a bitmask of the types an output takes;
  netcfgd holds the same idea as a threshold, because its severities are
  ordered and a mask that can express "warnings but not errors" answers a
  question nobody asks.
* **The subsystem argument**, which is the thing netcfgd most obviously
  lacked. `journalctl -u netcfgd | grep '\[dhcp\]'` is now a question that
  can be asked.

**Not copied: message ids and source location.** flog carries both for
embedded targets, where a numeric id saves the string table and `__FILE__`
places a crash. netcfgd runs under a journal that timestamps and attributes
every line; its messages are sentences an operator reads rather than codes a
receiver decodes; and `file:line` in an operator-facing message is noise.

This is the same split the sibling tree already draws: fuzzypickles keeps
`diag` -- "a severity/subsystem/detail accumulator" that includes nothing but
its own header -- and bridges it to flog with a `severity_to_flog()` in the
daemon, because `core/` never links against flog. netcfgd's `log` module is
that vocabulary; where flog would be linked, netcfgd writes a line.

## What is not in it

**The CLI's output is not the log.** `ncfg` prints `ok`/`FAIL` per action,
`warning:` for a planner warning, and its refusals name a file, a line and a
column. That is a user interface, and giving it `[subsystem] Error:` would
make every one of those lines worse. flog is daemon-only in fuzzypickles too,
and for the same reason.

## The level

`NCFG_LOG=critical|error|warning|note|info|verbose|debug`, read once at
startup, **before anything else can speak** -- a level that arrives after the
configuration has been read cannot filter the startup somebody is debugging.
The default is `info`, which is exactly what netcfgd printed before it had
levels at all: a change of shape must not also be a change of what an
ordinary machine says.

A level that is not a level is refused out loud, names the one still in
force, and lists the words that would have worked. That is this tree's own
rule about settings, applied to the setting that controls the messages.

## What is checked

`tests/live/log_shape.sh` drives a real daemon three times: at the default,
turned down, and told a level that does not exist. It asserts the subsystem,
the absence of a label on an ordinary line, `!` on a note, silence below the
level -- with the control that the same run speaks again at a level that
takes it, because silence is also what a daemon that failed to start
produces.

Unit tests beside the module pin the ordering (a threshold only works if a
more severe message compares as smaller), the default, the round trip of
every level through both its name and the atomic, and the labels themselves,
which are the one place that could drift from flog.

## The gate that caught its own author

`tool/write_gate.py`, written this morning for 0180, refused this change:
`emit` discards the result of `write_all`. It is right to discard it -- **a
message about a message that could not be written has nowhere to go**, and a
daemon that fails an apply because the journal is full is worse than one that
goes quiet -- so `tool/write-best-effort.txt` gets its first entry, with that
reason. The file's header had said "nothing in the tree is that today". Today
there is.
