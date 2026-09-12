# 0218: the inner method the example did not pin

Status: accepted
Date: 2026-09-12
Milestone: M9; the wifi EAP and enterprise audit

## `phase2` is `key=value`, and the example said otherwise

`netcfgd.conf.example` told operators to write:

```
phase2 = "mschapv2"
```

`wpa_supplicant` accepts that and does nothing with it. Asked directly, on the
`none` driver so no radio is needed:

```text
SET_NETWORK 0 phase2 "auth=MSCHAPV2"  -> OK
SET_NETWORK 0 phase2 "MSCHAPV2"       -> OK
SET_NETWORK 0 phase2 "nonsense"       -> OK
GET_NETWORK 0 phase2                  -> "MSCHAPV2"
```

It stores the string verbatim and selects an inner method by scanning for
`auth=` and `autheap=` tokens. A value carrying neither constrains nothing, so
**the server proposes the inner method and the supplicant accepts it** --
including one that sends the password in clear inside the tunnel, which is what
pinning `auth=MSCHAPV2` exists to prevent.

The tunnel is only as trustworthy as `ca_cert` and `domain_suffix_match` make
it ([0206](0206-a-pinned-issuer-is-not-a-checked-server.md)), and this is the
layer underneath that one.

So an operator following netcfgd's own documentation believed they had pinned
the inner method and had pinned nothing. The example is corrected and says why.

## Warned, not refused, and that was a reversal

The first implementation refused a malformed `phase2` at compile time, beside
the regulatory domain and the `https` portal URL. That was wrong, and the
argument that changes it is the asymmetry of the costs.

A value that pins nothing is **inert, not invalid**: the network it configures
works today, and the protection it appears to add was never there. Refusing it
takes the whole document out -- netcfgd runs with no configuration when one
will not compile -- so an upgrade would take the wifi off every machine
carrying one, to fix something already absent. And the machines carrying one
are exactly those whose operators followed the example.

That is [0189](0189-an-empty-ca_cert-is-a-file-that-is-not-there.md)'s rule: a feature
that stops a network working teaches an operator to use something else rather
than to configure it properly. The refusals netcfgd does make at compile time
are for values that would not work *anyway* -- a regulatory domain the kernel
ignores, an `https` URL a portal cannot be detected through -- where refusing
costs nothing that accepting would have bought.

So it is a plan warning, in the shape `scan_randomization` already uses for
"understood and not acted on": said on every plan, naming the value and what to
write instead.

## What the check judges, and what it does not

The **shape**, not the key names: a token counts if it is `key=value` with both
halves present. Judging by a closed list of `auth` and `autheap` would make
netcfgd the reason a working configuration started complaining the day
`wpa_supplicant` grew a key this build has never heard of -- and the test pins
that from both sides, with `somethingnew=1` required to stay quiet.

`phase2_pins_nothing` lives in `netcfgd-model` beside `EapConfig`, for last
round's reason: the planner is what says it and must not depend on the compiler
to ask.

## What the audit found sound

The EAP path has been through two rounds already and most of it held:

- **No `ca_cert=""`** (0189), and no `domain_suffix_match` line where the
  document states none -- an empty one would be 0189's fault in another field.
- **`private_key` is sent as a path**, never as the key's contents, which a
  line-oriented control protocol could not carry anyway.
- **A wired port uses `key_mgmt = IEEE8021X`**, not `WPA-EAP`, which is the
  difference between bare EAPOL and a WPA handshake that is not there.
- **Identities and certificate paths are quoted** through the same escaping as
  a passphrase, because a RADIUS realm is attacker-influenced often enough that
  treating it as trusted text would be a distinction without a reason.
- The compile stage **warns by name** about a network that pins no `ca_cert`,
  on every apply.

## What is still missing, and is a feature rather than a defect

**`private_key_passwd` does not exist anywhere in the tree.** An EAP-TLS client
key that is encrypted at rest -- which is how key material is usually
distributed -- cannot be used: `wpa_supplicant` is handed the path, OpenSSL
asks for a passphrase nobody supplies, and the failure reads as a TLS error
rather than as a missing field.

Named here rather than fixed, because it is a new field with a secret in it
across the model, the compiler, the renderer and the schema, and this round is
an audit. It is the one gap in EAP that a working configuration can meet.
