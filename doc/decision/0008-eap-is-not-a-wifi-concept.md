# 0008: EAP is hoisted out of WifiNetwork so wired 802.1X can exist

Status: accepted
Date: 2026-07-28
Milestone: model in M1, implementation in M3

## Context

§2.1 nests `Security` inside `WifiNetwork`, and `Eap` inside `Security`. That
makes 802.1X a property of an SSID profile.

It is not. IEEE 802.1X is port-based network access control and it predates
its use on wifi; the wired case is ordinary on corporate and campus networks,
and NetworkManager supports it on ethernet through the same `802-1x` setting
it uses for wifi. As the model stands, a wired 802.1X port is inexpressible —
there is no path from `Interface` to `Eap` at all.

The timing is what makes this urgent rather than merely wrong. Moving a type
out of one parent and into a shared position is a structural change to the
document, so it is a major version bump after the M4 freeze (§2) and a
five-minute edit before it.

## Decision

Extract the EAP configuration into its own top-level type. Wifi security keeps
its enum; the interface gains a direct field.

```
EapConfig {
  method             : enum { Peap, Ttls, Tls, Pwd }
  identity           : string
  anonymous_identity : string?
  password           : SecretRef?
  ca_cert            : string?
  client_cert        : string?
  private_key        : SecretRef?
  phase2             : string?
}

Security =                        // wifi only, unchanged in meaning
  | Open
  | Psk { passphrase: SecretRef, proto: ... }
  | Eap(EapConfig)
  | Owe

Interface {
  ...
  dot1x : EapConfig?              // wired 802.1X
}
```

**The shared thing is EAP, not "security".** Hoisting `Security` whole would
put `Psk` and `Owe` — both meaningless on a wire — within reach of an
`Interface`, and then a validation rule has to exist forever to forbid what
the types allow. Hoisting `EapConfig` gives one definition, no nonsense
variants anywhere, and no cross-field validation.

**The field is `dot1x`, not `eap`.** The feature is called 802.1X and that is
what an operator will search the documentation for; an identifier cannot start
with a digit, and `dot1x` is the conventional spelling of that constraint
(NetworkManager writes `802-1x`, wpa_supplicant writes `IEEE8021X`). It is an
abbreviation that is already vocabulary, which is what `code-style.md` §1
requires of one.

## Consequences

**Wired 802.1X means wpa_supplicant, always.** `iwd` does not do wired, so
`WifiDevicePolicy.backend` has no bearing on it and the wired path uses
`wpa_supplicant -Dwired` regardless of what a device policy says for radios.
Implementation therefore depends on M3's supplicant work and cannot land
before it, even though the model lands in M1.

**`backend/netcfgd-wifi/` becomes a misleading name**, since one crate will
drive the supplicant for both radios and wired ports. Rename it
`netcfgd-supplicant` now. §0 of the brief is reserving crate names on
crates.io this week, so the cheap moment to fix this is before the placeholder
is published, not after.

**MACsec fits the same slot later.** It is another link-layer security
mechanism that belongs on an `Interface` and not on an SSID, and having
already established that `Interface` carries link security means adding it is
additive rather than another hoist.

`Interface` gaining a field is a minor version bump; the hoist of `EapConfig`
out of `Security` is the major one, and it is the whole reason this is being
done in M1 rather than when someone asks for it.

## Alternatives considered

**Hoist `Security` entire and validate per context.** Rejected above: it makes
the type system permit `Psk` on an ethernet port and then relies on a rule to
say no. A type that cannot express the wrong thing beats a check that rejects
it.

**Duplicate the EAP fields into a separate wired type.** Rejected. Eight
fields, two definitions, two parsers, two sets of fixtures, and they drift the
first time one gains an option.

**Leave it and treat wired 802.1X as out of scope.** Rejected: it is a
supported NetworkManager feature that campus and corporate deployments
genuinely require, and "we cannot express it" is a poor answer when the
remedy costs one type extraction before a freeze that has not happened yet.
