# 0215: the length rule on the other side of the radio

Status: accepted
Date: 2026-09-12
Milestone: M9; the wifi WPA3 transition mode audit

[0205](0205-the-length-rule-belongs-to-a-field-not-to-wpa.md) established that
WPA's 8-to-63 character limit belongs to the **field** a passphrase is written
into and not to WPA: `psk` has it, `sae_password` does not, so a WPA3 network
can take a longer one. It fixed the station.

`netcfgd-hostapd` still enforced 8..=63 for all three protocols, under this:

> hostapd enforces this itself, at parse time, with a clear message. It is
> checked here anyway so the operator hears it from netcfgd naming their
> `access_point` block, rather than from a daemon naming a line number in a
> file under /run that netcfgd wrote.

True of the field hostapd checks, and not of the one a WPA3 access point is
configured with. Asked of hostapd 2.10, 70 characters each:

```text
wpa_passphrase=<70>   Line 6: invalid WPA passphrase length 70 (expected 8..63)
sae_password=<70>     parsed; the run failed later, on the interface
```

The second line is the finding and the first is the control that makes it mean
something: hostapd does reject an over-length passphrase, in the field that has
a limit. So netcfgd was refusing a WPA3 access point hostapd would have run,
and telling the operator it was WPA's rule.

## Transition mode keeps the limit, and that is the whole subtlety

The rule is not simply wrong; it is wrong for one arm of three.

- `wpa2` writes `wpa_passphrase`. Limit applies.
- `wpa3` writes `sae_password` and nothing else. No limit anywhere.
- `wpa2wpa3` writes **both**, because a WPA2 client needs the first and an SAE
  client the second. So the limit applies, and it must: a value `psk` would
  refuse is one hostapd will not parse, and netcfgd should say so first,
  naming the block.

The test pins all three and fails on either mutation -- restoring the blanket
rule refuses a WPA3 access point, and removing the rule altogether lets
transition mode through with a passphrase hostapd rejects.

## The message said it too

Both the variant's documentation and the sentence an operator reads said "WPA's
8..=63 character range". 0205 had corrected the station's *message* and left
its variant doc; the access point had neither. Both now name the field, and the
hostapd message quoted above is what they were describing all along.

## What the audit found sound

The transition-mode rendering itself, on both sides, and it is the part most
worth getting wrong:

- **The access point** emits `wpa_key_mgmt=WPA-PSK SAE`, `rsn_pairwise=CCMP`,
  `ieee80211w=1` and **`sae_require_mfp=1`**. The last is what stops transition
  mode being a downgrade to WPA2 for everybody: protection is optional overall,
  because a WPA2 client cannot do it, and required for whoever negotiates SAE.
- **The station** offers `WPA-PSK SAE FT-PSK FT-SAE` with `ieee80211w=1`, which
  is the only value that works against both -- 2 excludes a WPA2 access point
  and 0 excludes SAE.
- `wpa=2` for all three, because it selects RSN, and there is no `wpa=3`.

**6 GHz cannot reach any of this**, which closes the question it would
otherwise raise: transition mode is not permitted on 6 GHz, and SAE there
requires hash-to-element. netcfgd's access point refuses the band outright --
"the 6 GHz band needs an operating class and HE parameters, which the document
cannot say" -- so there is no configuration in which it emits a 6 GHz
transition-mode access point.

## Documented where an operator looks

`netcfgd.conf.example` showed `proto = "wpa3"` in one block and never named the
three values, the default, or what changes with them. It now says that the
default is transition mode, that management frame protection follows from the
choice rather than being a setting, and that `wpa3` alone lifts the passphrase
length limit -- because that is a property of the field, which is the sentence
this record and 0205 are both about.
