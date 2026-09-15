# 0242: a scan that never said what it found

Status: accepted
Date: 2026-09-15
Milestone: M9; the wifi scan and probe request audit

## Re-checking 0227's ground

The scan path holds up on re-reading, and the things 0121 and 0227 recorded as
sound still are: `SCAN` queues and `SCAN_RESULTS` reads a cache, so
`wait_for_scan` waits for `CTRL-EVENT-SCAN-RESULTS` rather than reading the
previous scan's list; a blocked radio is not asked to scan and answers with its
cached results and the reason; the mobility domain costs a `BSS` round trip only
where the flags already say fast transition.

The probe-request settings are sound too, and one of them is worth naming
because it is the pattern the rest of this decision is about failing to follow.
`preassoc_mac_addr` is sent **in both directions** -- `1` when the document asks
for scan randomisation and `0` when it does not -- for 0015's reason, that a
silent default is not a control. The digest that decides whether a running
supplicant still matches carries a line for it only when it is on, which is
0220's asymmetry, and the observation asks the same question the executor asked.
Three places, consistent.

## What the scan could not say, and nothing checked

`ncfg wifi scan` classifies every access point it finds as open, secured,
enterprise or OWE, and every client shows that word: the command-line list, the
TUI's grouping, the GUI's add dialog, and the NetworkManager shim's PRIVACY
flag. 0227 is entirely about getting that vocabulary right.

The classification reads `wpa_supplicant`'s flag string -- `is_secured` looks
for `WPA`, `WEP` or `SAE`; `is_enterprise` for `EAP`; `is_owe` for `OWE` -- and
**nothing had ever checked it against an access point that was really
beaconing.** `hwsim.sh` asked only whether the SSID appeared in the list.

That gap is not like the others this campaign has found, because the usual way
out is closed. The `CONNECTED` event's shape could be pinned against
`wpa_supplicant`'s own format string, read out of the binary; these words are
assembled at run time from the RSN element and are not literals anybody can read
out of anything. A real beacon is the only source.

There is one in this tree. `hwsim.sh` stands up an access point with
`key_mgmt=SAE WPA-PSK` and `proto=RSN`, and now asserts that netcfgd calls what
it finds `secured`. It does. **The claim was right and had never been checked**,
which is the outcome to expect from most of these and is worth recording as
such: the value is that the next change to the flag parsing has something real
to fail against.

## Two coverage claims that were false, from the gate's own author

0240 added a gate requiring every setting netcfgd sends a supplicant to be
driven against a real one, with a `// covers:` line for settings a test drives
through `add_network` rather than naming. **Two of the first four lines were
wrong**, written by the pass that built the gate, and both failures were the
same one: the helper every test in that suite uses builds a network with

```quote from=backend/netcfgd-supplicant/tests/live.rs
hidden: false,
```

and `metric: None`. So `scan_ssid` and `priority` are precisely the two settings
that helper never sends, and both were claimed as covered.

`scan_ssid` is this round's subject. It is the probe-request setting: without it
a hidden network is never probed for, so it never appears, with no error
anywhere to say why. It was being declared as tested and was not.

Both are named in `GET_NETWORK` strings now, so the gate reads them out of a
literal and the promise is a check. The gate's documentation says what this
episode proved: **every `covers:` line is somewhere it is trusting a sentence**,
and a setting that can be named should be named.

## Two sabotages, and the second is the campaign's own shape again

The `scan_ssid` half went in with a sabotage that failed as it should. The
`priority` half passed:

| sabotage | outcome |
|---|---|
| `scan_ssid` never sent for a hidden network | caught |
| `join_rank` returns the metric unchanged, sign flipped | **passed** |

The assertion compared what the supplicant stored against
`join_rank(Some(100))` -- the function under test. Both sides of the comparison
moved together, so a rank with the sign inverted still matched. **A test built
from the code rather than from the thing modelled**: the sixth instance of that
shape in this campaign, produced by the pass that has been cataloguing it, two
rounds after writing that a fixture must not be derived from the document it is
compared against.

The literal `3996` is what it asserts now, and the sabotage fails.

## What the supplicant says for a field nobody set

Measured, because the control for the checks above depended on it and the first
version guessed wrong. On wpa_supplicant 2.10, `GET_NETWORK` for a field that
was never set answers:

```text
scan_ssid  ->  0        priority   ->  0
mac_addr   ->  -1       bgscan     ->  FAIL
```

So an integer field reads back the default the supplicant would use and a string
field refuses. The control had asserted a refusal for all of them.

**`mac_addr` is the one worth carrying forward**: unset is `-1`, and netcfgd
sends `0` for a permanent address. Those are different values, so 0015's
"send it in both directions" is doing real work there rather than restating a
default -- which is what 0230's table would lead a reader to assume.

## Not fixed

Nothing. No behaviour changed this round: the scan classification was correct
and undertested, and the two coverage claims were tests that did not exist
rather than code that was wrong.
