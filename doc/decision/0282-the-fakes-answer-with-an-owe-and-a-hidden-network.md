# 0282: the fakes answer with an OWE and a hidden network

Status: accepted
Date: 2026-10-22
Milestone: M9; the C port

Completes
[0281](0281-the-wifi-witness-lines-say-what-the-fake-radios-answer.md), which
re-authored the witness's wifi lines to what the fakes answer and recorded
three shapes lost in the move. Two of them are back.

## What this decides

`tests/live/fake_supplicant.py` answers `SCAN_RESULTS` with six networks
rather than four. The two new ones are an OWE access point and one hiding its
name, which are exactly the two shapes 0281 took out of
`doc/schema/socket.json`, and the witness carries both again -- produced this
time rather than written by hand.

Decided by the copyright holder on 2026-10-22, after 0281 reported what the
re-authoring had cost: "add the owe and hidden ssid networks to the fakes
too".

## Why these two, and not the third

0281 lost three shapes. Two were losses worth undoing and one was not:

- **OWE.** `ncfg_supplicant_scan_is_owe` reads the flags field and nothing
  else, because there is an access point called `OWNIT_24GHz_8A41A0` in range
  of the machine that classifier was written on and a check over the whole row
  would call it OWE. `[RSN-OWE-CCMP][ESS]` drives that reading end to end, and
  reports no `WPA` -- so `Guest` is the one network in the fixture that is
  encrypted without being `secured`, which is the pair a client has to render
  as "open, and private".
- **A hidden name.** A row for one really does arrive with nothing after the
  fourth tab, and `scan_row` was written for that case with a comment saying
  so. No fake had ever sent one, so the branch was reached by a hand-written
  fixture and never by a supplicant.
- **An empty `access_points` beside `stale`, which stays gone.** The daemon
  does not write it: a scan that failed answers with what it last saw. That
  line described behaviour no code here produces, which is why 0281 called its
  loss a correction rather than a cost. `json_write_test` pins the spelling
  where the values are a test's own.

## Entries are appended, never inserted

`network_id` is the index into that list and tests assert `id=0` and `id=1`, so
an entry in the middle renumbers networks nobody touched. The file already said
so for the enterprise network; both new rows go on the end, and their signals
(-47 and -66) place them in the middle of the sorted answer without moving
anybody's id.

## What it cost, and what that bought

`daemon_wifi_test` asserted the scan by **position**: four rows, each named
signal in order, and `access_points[1]` for HomeFiber. Six checks failed over
positions rather than over anything netcfgd does -- a row's place is decided by
its signal, which is the fake's data.

They ask by address now, through a `scan_at(scan, bssid)` helper, and the
ordering check is sortedness over every row rather than a copy of the fake's
table. That is what those checks always meant: a sort that quietly stopped
sorting is the fault, and naming four signals made the assertion a second copy
of the fixture. The same shape as `tui_test`'s fix in 0281, found the same way
-- by a fixture moving under a test that had hard-coded its contents.

**And the hidden row's check was wrong in the instructive direction.** It
asserted the name was *absent*; the daemon writes it as *empty*. The two are
different answers and `ncfg_proto_str_t` exists to carry the difference: a
client reading a missing `ssid` as absent could not tell a hidden network from
a row of some kind it does not know. The check says empty-and-present now.

`tests/live/nm.sh` carried the other two literals -- `4` access points and the
sorted name list. It asks for five named rows and the five names now, both
filtered to named rows, so what the shim exports for a nameless access point is
not asserted where it cannot be checked. **That file could not be run here:
this machine has no `nmcli`**, so those two expectations are derived from the
shim's own code -- `accesspoint.c` keys a slot by bssid and skips only a row
whose bssid is empty -- rather than observed.

## What was seen to fail

- The six position-keyed checks in `daemon_wifi_test`, before they were
  rewritten: the two new rows broke every one of them and nothing about the
  daemon had changed.
- The hidden row's first check, which asserted absence and failed against a
  daemon that writes empty.
- The witness, before the bless: two lines differed, each reported with both
  spellings, and `"owe":true` and `"ssid":"","name":""` appear twice in the
  file afterwards -- once in the fresh scan and once in the stale one.
