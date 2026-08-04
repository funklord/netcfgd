# 0087: an enterprise network is a form, and a flag list can hold it

Status: accepted
Date: 2026-08-04
Milestone: the last item on the laptop list that was about a person rather than a kernel

## Context

Section 10's laptop list had one entry left that nothing had touched:

> **An enterprise network cannot be added from the command line.** `eap` wants an
> identity, a method and certificates, which is a form and not a flag list.

That is eduroam and most corporate wifi -- on a laptop, the single most likely
network after the one at home. The config language has expressed it since M1;
what was missing was every way of getting there without an editor, which is what
[0069](0069-adding-a-network-is-writing-a-file.md) removed for personal networks
and did not for these.

"A form and not a flag list" is the right diagnosis and the wrong conclusion.

## Decision

**`ncfg wifi add SSID --eap METHOD ...`**, with `--identity`,
`--anonymous-identity`, `--ca-cert`, `--client-cert` and `--phase2`.

The form part is not the flags. It is that **which fields are needed depends on
the method**, and that is expressible as refusals:

- any method needs `--identity`;
- `tls` needs `--client-cert`, and the other three refuse one -- TLS presents a
  certificate, the rest present a password;
- `--eap` refuses `--open` and `--wpa2`/`--wpa3`, which describe a different
  kind of security;
- an enterprise flag with no `--eap` is refused rather than ignored, because
  ignoring it writes a personal network for somebody who believed they had
  written a corporate one.

Every refusal names the flag to add. The reader is at a command line, not in the
model.

**The prompt follows the method.** `read_credential` asks for a WPA passphrase,
an EAP password or a private key, and says which. A PEAP password typed into a
prompt that said "passphrase" is a network that never joins, and the 8-to-63
length rule is WPA's -- applying it to an EAP password would refuse valid
credentials. Never an argument, for 0075's reason.

**Written values are escaped and read back.** An identity is `you@example.ac.uk`
and a certificate is a path; a quote in either would end the string early and
produce a directory that does not compile, taking every other interface with it.
`verify` now compares the compiled identity, anonymous identity, certificates
and phase-2 method against what was asked for, because `secured != open` is true
for a `psk` network too -- so without it an `--eap` run that compiled to a
passphrase network would have passed.

## What it found

**netcfgd could not configure an EAP network that pins no CA certificate.**

The compiler pushed a diagnostic for a missing `ca_cert`, under this comment:

```rust
// Not an error, because plenty of real deployments pin nothing and
// refusing would make netcfgd unusable on them.
```

`Diagnostic` is the only severity this compiler has. Every one is fatal. So the
network did not compile, the comment above it was exactly wrong, and
[0017](0017-a-wifi-block-refuses-three-things-that-would-work.md) had already
rejected the behaviour the code had:

> **Refuse EAP without `ca_cert`.** Tempting, and rejected because it would make
> netcfgd unable to configure networks that other tools configure fine. Refusing
> to support a real deployment on security grounds it did not ask for is how a
> tool gets replaced by the one that works.

The model agrees with the decision, too: 0008 has `ca_cert : string?`.

It is a **plan warning** now, in `netcfgd-plan`, which is the only place in
netcfgd that can say something loudly without also stopping it -- and which
`ncfg plan`, the TUI and the GUI all already show. The sentence is unchanged in
substance: a network that pins nothing will trust any server that answers, which
is how the credential is taken.

This is not a weakening. An operator whose network pins nothing could not use
netcfgd for it at all, so they used `wpa_supplicant` directly -- where nothing
warns them about anything. A warning they see beats a refusal they route around.

## The gates

Unit tests for what reaches the file (`password` for three methods,
`private_key` for TLS, never a `psk` beside an `eap`), for escaping, and for
every refusal. On the planner side, both halves of the ca_cert decision: the
warning is emitted, **and** the radio is still configured.

A pty test, because the prompt is what tells an operator which credential to
type and a pipe cannot show it: `--eap peap` asks for an EAP password, `--eap
tls` asks for a private key, neither says "passphrase", echo is off for both,
and the secret lands under the key its method uses.

Four breaks. Removing the escaping, removing `check_enterprise`'s call from
`add`, and stopping `verify` after the open-vs-secured check all go red. The
fourth is the one worth recording:

**A break that does not compile is not a break.** The `verify` break was written
so that `method` fell out of scope, so `cargo test` failed to build -- and the
harness, which grepped for `FAILED`, reported the gate as holding. Section 9
already warns that a break which fails to *apply* reads like a gate that works;
this is the same disease one step later, and the harness now treats a build
failure as "not a break" rather than as a pass.

Finding it also exposed a real gap: the first version of the refusal test called
`check_enterprise` directly, so deleting its call from `add` changed nothing any
check could see. A refusal nobody reaches is not a refusal, and there is a test
through the command now.
