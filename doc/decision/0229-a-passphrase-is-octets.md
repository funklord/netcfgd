# 0229: a passphrase is octets

Status: accepted
Date: 2026-09-13
Milestone: M9; the wifi PSK and passphrase audit

## What was already right

A passphrase is always quoted on its way to the supplicant, so a 64-character
hex value arrives as a passphrase rather than as a pre-computed key -- which is
0227's finding restated: SAE could not have used a raw key, and the quoting is
what makes the transition arm work at all. The escaping covers the quote and the
backslash, and `passphrase_is_sendable` refuses a newline outright because the
control protocol has no escape for one and everything after it would be read as
another command. hostapd's side refuses the same, plus `\0`, because a
configuration file is read a line at a time. The value never reaches a log, a
plan or `/run`; what travels is a digest.

The length was the one that was wrong, and it was wrong in four places.

## Characters are not octets

Every check in the tree counted `chars().count()`:

```text
backend/netcfgd-supplicant/src/network.rs     the station
backend/netcfgd-hostapd/src/render.rs         the access point
crates/netcfgd-cli/src/wifi.rs                before writing a file
adapter/netcfgd-nm/src/emit.rs                the NetworkManager shim
```

Both daemons count octets. Measured against wpa_supplicant 2.10 over its control
socket, on the `none` driver so no radio was involved:

```text
63 x "a"        63 chars  63 bytes   SET_NETWORK psk -> OK
64 x "a"        64 chars  64 bytes   SET_NETWORK psk -> FAIL
32 x "e-acute"  32 chars  64 bytes   SET_NETWORK psk -> FAIL
31 x "e-acute"  31 chars  62 bytes   SET_NETWORK psk -> OK
 4 x "e-acute"   4 chars   8 bytes   SET_NETWORK psk -> OK
```

And against hostapd 2.10, reading a configuration file:

```text
wpa_passphrase of 32 accented characters:
  Line 8: invalid WPA passphrase length 64 (expected 8..63)
wpa_passphrase of 4 accented characters:
  parsed without complaint
```

So netcfgd was wrong in **both** directions, and only for a passphrase that
leaves ASCII:

- **it accepted what the daemon refuses.** 32 accented characters is 64 octets.
  netcfgd counted 32, wrote the configuration, and the supplicant answered
  `FAIL` at association or hostapd refused to start -- an error at apply time,
  naming a line in a file under `/run` that netcfgd wrote, rather than the
  operator's own block.
- **it refused what the daemon takes.** Four accented characters is eight
  octets, which both daemons accept. netcfgd counted four and called it too
  short. This is the direction that is easy to miss, because it never produces
  a broken machine -- only a configuration somebody could not write.

`chars().count()` is never greater than `len()`, so the minimum could only ever
be wrong by refusing and the maximum only by accepting. Both happened.

## One rule, four callers

The four copies had drifted in nothing but they were four copies, which is the
shape 0222 found for the band rule and fixed the same way: the rule is stated
once, in `netcfgd-model`, as `PASSPHRASE_OCTETS` and `passphrase_fits`, and the
station, the access point, the CLI and the shim all ask it.

The messages were wrong too and now say `octets` with the reason: *"a character
outside ASCII counts as more than one, which is how the supplicant counts it"*.
A message that states a rule in the wrong unit is worse than no message, because
somebody counts on their fingers and gets the answer netcfgd already got wrong.

`netcfgd.conf.example` said "8 to 63 characters" and now says octets, with both
measured cases.

## A measurement I got wrong on the way

The first sabotage run reported that only two of the four callers noticed the
rule being disabled, which would have meant the two renderers -- the ones that
actually hand a passphrase to a daemon -- were uncovered.

That reading was an artefact: `cargo test --workspace` stops after the first
failing target, so the list was everything up to `netcfgd-cli` and nothing
after. Run per crate, every caller notices:

```text
netcfgd-model        2 tests
netcfgd-supplicant   3
netcfgd-hostapd      3
netcfgd-cli          2
netcfgd-nm           1
```

The same lesson as the audits before it, arriving from a new direction: a test
run that stopped early is not a test run that found nothing, and reading its
output as a complete list is how a covered thing gets called uncovered -- or,
pointed the other way, an uncovered thing gets called covered.

## Sabotage

| reverted | test | result |
| --- | --- | --- |
| count characters in the shared rule | `a_passphrase_is_measured_in_octets_...` | FAILED |
| the rule always answers yes | 11 tests across five crates | FAILED |

The model's helpers had no tests at all before this; `key_mgmt_of` and
`phase2_pins_nothing` still have none, which is worth knowing and is not this
round's subject.
