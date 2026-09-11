# 0205: the length rule belongs to a field, not to WPA

Status: accepted
Date: 2026-09-11
Milestone: M8; the wifi WPA3 and security audit

## What was already right, and it is the part that usually goes wrong

**Management frame protection is handled correctly, which is the classic WPA3
trap.** `ieee80211w=2` for SAE, because WPA3 personal is not WPA3 without it,
and that requirement is also what makes `FT-SAE` safe to name in the same arm.
`ieee80211w=1` for transitional, with the reasoning written down: 2 excludes
WPA2 access points and 0 excludes SAE, so 1 is the only value that works
against both. OWE gets `ieee80211w=2` as well, and the comment says it is
required rather than optional there.

The passphrase is refused before it is sent rather than after, because a bare
`FAIL` is what the supplicant answers otherwise. A quote, a backslash and a
control character cannot pass through. `ncfg wifi add` makes the same checks
where the operator can still fix them, and says so: "at association time the
failure is a bare `FAIL`, half an hour after the file was written". The length
is reported and the value never is.

The EAP half is 0189's, from the start of this run: an empty `ca_cert` is a
filename, not "verify nothing", and removing it is what let this machine's
enterprise network authenticate at all.

## The fault

Every passphrase went into `psk`, including for SAE, and the 8..=63 check was
applied to all three generations. **That range is what `wpa_supplicant`
accepts in the `psk` field. It is not a rule of WPA, and SAE does not have
it** -- a WPA3 password can be any length, and `sae_password` is the field for
it.

So a WPA3 network with a longer password could not be joined, and netcfgd said:

```text
a WPA passphrase is 8 to 63 characters; this one is 70
```

which states a protocol rule that the protocol does not have. The limit was
netcfgd's own choice of field, described as the standard's.

`PskProto::Wpa3` now sends `sae_password` and takes a password of any length.
`Wpa2` and `Wpa2Wpa3` keep `psk` and keep the limit, because **the WPA2 half
reads that field and cannot read the other one** -- and in transitional mode
the access point chooses, so one value has to work for both. The message says
which is which now, rather than naming WPA for a rule belonging to a field.

## What is deliberately unchanged

The transitional arm is the default, so this alters nothing for a network
written without `proto`. That was checked against the reporting machine before
the change: its `OpenPC.se` block sets no `proto` and negotiates `key_mgmt=SAE`
with `mgmt_group_cipher=BIP` through the transitional arm, which is exactly
what that arm is for.

The digest of what was handed to the supplicant changes for a `proto = "wpa3"`
network, so one re-send follows an upgrade. That is what the digest is for.

## Verification

The field and the limit, in both directions: WPA3 alone sends `sae_password`
and not `psk`, and takes 70 characters; `Wpa2` and `Wpa2Wpa3` send `psk`, must
*not* send `sae_password`, and still refuse the same 70 characters.

Sabotage: putting WPA3 back on `psk` takes the new test red; dropping the limit
for everyone takes it red *and* the length test that predates this decision,
which is the better signal -- the rule still holds where the field still does.
