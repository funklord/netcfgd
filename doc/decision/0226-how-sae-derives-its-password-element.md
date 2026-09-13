# 0226: how SAE derives its password element

Status: accepted
Date: 2026-09-13
Milestone: M9; the wifi WPA3 and SAE audit

## What was already right

Most of this area has been gone over before and holds up.

The station sends `sae_password` for WPA3 and `psk` for anything that can still
negotiate WPA2, because those are different fields and 0205 found netcfgd
putting every passphrase in the second one. `ieee80211w` is 2 for SAE, 1 for
transition mode and 1 for WPA2 -- 2 excludes WPA2 access points and 0 excludes
SAE, so transition mode has exactly one workable value. The access point writes
`wpa=2` for all three generations, because that selects RSN and there is no
`wpa=3`. Transition mode writes `wpa_passphrase` *and* `sae_password` from one
value, with `sae_require_mfp=1` so a client that negotiates SAE cannot be
downgraded.

Two things checked and found sound that would have been defects elsewhere in
this campaign. A passphrase is always quoted by `passphrase_argument`, so a
64-character hex value goes to the supplicant as a passphrase rather than as a
pre-computed PMK -- which SAE could not have used. And `key_mgmt_of` returns
hostapd's spelling rather than the station's, so the planner compares `SAE`
against the `SAE` in the file rather than against the station's `SAE FT-SAE`;
the mismatch would have been a restart loop of the kind 0222 found twice.

## The mechanism nobody chooses

SAE derives its password element one of two ways: the original
hunting-and-pecking loop, or hash-to-element. `sae_pwe` selects it, and both
daemons document the same values and the same default:

```text
# 0 = hunting-and-pecking loop only (default without password identifier)
# 1 = hash-to-element only (default with password identifier)
# 2 = both hunting-and-pecking loop and hash-to-element enabled
# Note: The default value is likely to change from 0 to 2 once the new
# hash-to-element mechanism has received more interoperability testing.
```

**netcfgd set it nowhere.** Measured against wpa_supplicant 2.10 on the
reporting machine, on the `none` driver so no radio was involved:

```text
GET sae_pwe     -> 0        the default
SET sae_pwe 2   -> OK       reads back 2
SET sae_pwe 99  -> FAIL     the control: the parser does validate
SET not_a_real_global 2 -> FAIL   and an unknown global is refused outright
```

So a netcfgd station could not complete SAE with an access point configured for
hash-to-element only, and nothing said why: the handshake does not finish and
there is no event naming a cause. `2` keeps hunting-and-pecking for everything
that already worked and adds the other, which is the value both daemons' own
documentation expects to become the default.

**An aside worth recording.** `SET sae_pwe 99` returns `FAIL` and the value
reads back as `3` -- the supplicant assigns before validating, and 99 masked to
two bits is 3. A `FAIL` from this control socket does not mean nothing changed.
netcfgd only ever sends constants here, so it costs nothing today; it would
matter to anyone passing an operator's value through.

## Sent for every radio, and not fatal

For every radio rather than only where the document names a WPA3 network: it is
one command, it affects nothing but an SAE handshake, and a network added later
by `ncfg wifi add` would otherwise land in a supplicant that was set up before
it existed.

**Not fatal, unlike `preassoc_mac_addr` beside it.** `sae_pwe` arrived in
wpa_supplicant 2.10, and a `FAIL` means the supplicant predates it -- a
supplicant that cannot do hash-to-element at all, so there is nothing to fall
back to and nothing worth refusing to populate over. Failing here would lose
every network on the radio to make a point about one that could not work either
way. It logs a note naming the consequence and carries on.

## The access point does not get it, deliberately

The same line is not added to hostapd's configuration, and the asymmetry is in
how the two daemons are configured rather than in what they support.

A station takes the setting over a control socket, where a daemon too old to
know it answers `FAIL` and keeps running. hostapd reads a file, and an unknown
key there stops it from starting at all -- so writing `sae_pwe=2` would make
every netcfgd access point require hostapd 2.10, with nothing able to check the
version at the moment the file is written. The tree already writes
`sae_require_mfp`, which puts the floor at about 2.9; this would move it again
for a gain that is much smaller in practice, since hash-to-element-only clients
are rare where hash-to-element-only access points are not.

So a netcfgd access point cannot serve a client that does hash-to-element only.
Recorded rather than traded for. Asking `hostapd -v` at render time is the fix
that would let both sides move, and it is not in this build.

## Sabotage

The station's setting is covered by `tests/live/enterprise.sh`, which drives a
real daemon against a fake supplicant and reads what was sent -- the same place
`preassoc_mac_addr` is covered, for the same reason: this is an executor
sending a command, not a value a unit test can render.

```text
ok   hash-to-element is offered          (with the fix)
FAIL hash-to-element is offered          (with the command changed to another name)
```

**That suite is not part of `make check`**, so the assertion runs when somebody
runs it. That is the existing arrangement for the setting beside it rather than
something this decision chose, and it is the weaker half of this round's
evidence.

## An unrelated flake, found while verifying and left open

`make check` failed once during this round, in `netcfgd-daemon --lib`, and then
passed three times. Rather than call it the known uid race, it was chased:
`require_lease_false_runs_the_probe_with_no_lease_at_all` fails about **1 run in
8**, on `assert!(marker.exists())` -- the probe's script did not create its file.

Ruled out, each by reading the code rather than by re-running:

- **not an async spawn race.** `run_due` waits for the child, polling `try_wait`
  against a deadline, so it returns after the probe has exited.
- **not the timeout.** That document sets `timeout = 5`, and the probe is
  `/bin/sh` running one `touch`.
- **not a `TestDir` collision.** Paths carry the pid and a serial, so two tests
  cannot share one.
- **not the uid race of 0217.** Nothing in this crate sheds privilege.

The leading hypothesis is a `spawn` failure under load -- the test asserts only
on the marker, so a probe that never started and one that started and failed are
the same outcome to it. Confirming that means making the test report the
`Outcome` it already has in hand, which is a change to a test outside this
round's subject.

**Recorded rather than fixed**, and deliberately not attributed to the flake
already on the books. A gate that fails one run in eight is one people learn to
re-run, which is how a real failure gets waved through.

