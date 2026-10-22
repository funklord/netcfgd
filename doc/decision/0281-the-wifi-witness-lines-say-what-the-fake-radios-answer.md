# 0281: the wifi witness lines say what the fake radios answer

Status: accepted
Date: 2026-10-22
Milestone: M9; the C port

Supersedes the open question in
[0280](0280-the-socket-witness-has-a-builder-and-six-lines-it-cannot-produce.md),
which this closes. Everything else 0280 decided stands.

## What this decides

The six wifi lines of `doc/schema/socket.json` are re-authored to what the
repository's fake supplicant and fake hostapd answer, and
`c/tests/socket_witness_test.c` produces all 67 lines. `make schema-bless`
writes the file; `make check` holds every line of it byte for byte.

Decided by the copyright holder on 2026-10-22, asked as 0280's open question
with both costs stated: re-author the lines, or re-author the fakes.

## Why the builder had to own the order

0280's builder matched its own bytes against whatever line of the file was
still unclaimed, which looked like a comparison and could not have been a
generator: the only file it could ever write was the one it had just read, so
a line whose bytes had changed was a line it refused rather than replaced.
That is `evidence.md`'s gate that compares an artifact to itself, and it is
why a bless arm that was never going to fire went unnoticed as a problem.

So the sequence of 67 lines is written in the test now. The requests are
still decoded from the file and re-encoded -- their values are samples and no
program derives them -- but they are emitted by position, which the builder
asserts: the first 41 lines are requests and no request may sit below them.

## What the six lines became, and what moved with them

They are produced by calling `ncfg_wifi_scan`, `ncfg_wifi_radios`,
`ncfg_wifi_status` and `ncfg_wifi_ap_stations` against the fakes -- the same
functions the daemon answers with, which have no encoder to call with a value
because they write members as they parse a control socket's replies.

**Three shapes the file had are gone, and each is still checked somewhere the
values are the test's own**:

- an `access_points` list that is empty while `stale` is set. The daemon does
  not do that -- a scan that failed answers with what it last saw -- so the
  old line described behaviour no code here produces. `json_write_test` pins
  the empty-and-stale spelling directly.
- `"owe":true` and a `mobility_domain` member. The fake's four networks are
  WPA2-PSK, open, WPS and WPA2-EAP, so neither appears. `supplicant_test`
  covers the mobility domain's parse and `cli_test`, `plan_gaps_test` and
  `tui_test` carry OWE fixtures.
- a `wifi_status` in state `SCANNING` with no association. The fake radio is
  associated, so the switched-off line now carries `blocked` beside a full
  status, which is the harder case anyway: the member that matters is present
  next to everything that might hide it.

**And three it did not have**: a scan with four access points rather than one,
sorted strongest first with `configured` on exactly the one a `network` block
names; a station hostapd reports no statistics for, beside two it does; and
`not_trying` with both flags named rather than one.

## What it cost outside the witness

Two tests read the file and were selecting lines by a prefix that two lines
now share.

- `cli_test` found the stale scan by `"access_points":[]` and the blocked
  status by `"state":"SCANNING"`. Its finder takes a `mark` as well as a head
  now, so each pair is told apart by the member that differs -- which is at
  the end of the line, where a prefix cannot reach.
- `tui_test` asserted the first rendered row named `home` and that some line
  showed `-40`, two literals from the old sample. It asks the decoded scan for
  the strongest access point's name and signal now, which is what the test
  actually means and what `evidence.md` asks for: assert the relationship, not
  either value.

Both of those are better tests than they were, and neither change was the
point of the work -- which is the usual shape of re-authoring a fixture that
several things read.

## The rig is shared, not copied

The fakes are started by `c/tests/fakewifi.h`, extracted from
`daemon_wifi_test.c`: a forked `timeout 60 python3`, a socket waited for
rather than slept on, and a kill that reaches the process group. Two binaries
need it now and the second copy is where the kill gets forgotten. Header-only
and `static`, which is `testdir.h`'s shape -- one translation unit per binary
uses it, so there is nothing to link.

A caller owes `stop_fakes()` on every exit path. Nothing registers an
`atexit`, because a test that has already called it would then kill twice and
wait on a pid it does not own.

## What was seen to fail

- The five changed lines, before the bless: the builder reported each
  difference with both spellings and failed, which is the frozen surface
  moving and is what freezing means.
- The fakes absent: `./socket_witness_test <path> /nonexistent` exits 1 having
  written nothing, and the witness's hash is unchanged. A builder that carried
  on would have written six lines of `[]` over six real answers and reported
  success -- the vacuous pass, aimed at the one file nothing else can check.
- One producer removed: `66 produced, 67 in the file`, failed. A builder that
  wrote what it had would be a silent truncation of the frozen surface.
- Re-blessing twice: the same five-line diff against `HEAD`, not a growing
  one.
