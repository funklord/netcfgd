# 0189: an empty `ca_cert` is a file that is not there

Status: accepted
Date: 2026-09-10
Milestone: M8; the wifi fault this project was opened for, found on the tenth
audit and reported by the holder as "it was not able to switch"

## What happened

The laptop moved to the corporate network and netcfgd could not join it. The
supplicant's own log says why, and says it forty-five times:

    CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25
    OpenSSL: tls_connection_ca_cert - Failed to load root certificates
             error:80000002:system library::No such file or directory
    OpenSSL: tls_load_ca_der - Failed load CA in DER format ... No such file
    TLS: Failed to set TLS connection parameters
    EAP-PEAP: Failed to initialize SSL.
    EAP: Failed to initialize EAP method: vendor 0 method 25 (PEAP)
    CTRL-EVENT-SSID-TEMP-DISABLED ssid="EMP-XYLEM" auth_failures=45
                                  reason=CONN_FAILED

netcfgd was stopped, NetworkManager was started, and it joined the same
network on the same laptop a minute later:

    Config: added 'phase1' value 'peapver=1'
    Config: added 'phase2' value 'auth=MSCHAPV2'
    Config: added 'identity' value 'nabeel.sowan@xylem.com'
    EAP-MSCHAPV2: Authentication succeeded
    CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully

## The line

```rust
} else {
    // No CA certificate means the supplicant will accept any server that
    // speaks the protocol, which is the whole attack. ...
    out.push(Setting::plain("ca_cert", "\"\""));
}
```

**Every value in that block is a path**, because wpa_supplicant opens all of
them as files -- the code says so two lines above, about the branch that
*does* have a certificate. So `ca_cert=""` asks it to open a file whose name
is the empty string. OpenSSL refuses, the TLS context is never built, and PEAP
fails before it proposes an inner method. The network could never have
authenticated.

An omitted `ca_cert` is how "verify nothing" is spelled. NetworkManager writes
no such line for the same network, which is why the same laptop, radio,
credential and access point worked under it.

## What the old comment got right and what it got wrong

Right: a network with no pinned CA does accept any server that answers, and
that is how the credential is taken. That argument is untouched -- the compile
stage still warns about it by name on every apply, and the message names the
flag that fixes it.

Wrong: it made a *security* argument for emitting a *broken* setting. A
feature that cannot connect does not teach an operator to pin a certificate;
it teaches them to use something else. The warning is the right instrument and
it was already there.

## What is checked

Two tests beside the renderer -- a network that pins nothing sends no
`ca_cert` at all (and still sends `key_mgmt`, `eap` and `identity`, so it
cannot pass by rendering nothing), and one that pins a certificate still names
the file. Sabotage confirms: putting the empty setting back turns the first
red.

## Why nothing caught this

`tests/live/enterprise.sh` and the EAP unit tests all supply a `ca_cert`,
because a test that pins a certificate is the one somebody writes when the
feature is about certificates. **The default case -- the corporate network
that pins nothing, which is most of them -- was the untested one.** That is
this tree's oldest lesson in a new place: the fixture modelled the careful
configuration and the machine ran the ordinary one.

## The audit this arrived during: upgrade and downgrade

Asked in the same breath, and the finding is next door. `read_owned` treats an
unreadable ownership record as empty, which is right -- refusing to start over
a disposable file in `/run` would turn it into an outage -- and **said nothing
at all**. That record is what tells netcfgd which addresses and routes are its
own to remove, so forgetting it silently means an address netcfgd configured
reads as somebody else's from then on. A downgrade is exactly how a machine
gets one: an older netcfgd meeting state a newer one wrote.

It now carries on and says so, naming the file and what is lost. Measured
either way: unknown fields from a future version parse and are ignored (serde's
default, and the right one); a file that is not JSON at all is discarded, the
daemon starts, the machine stays configured, and the next apply writes a good
record.

**Version skew is not otherwise guarded**, and that is recorded rather than
fixed: `Hello` carries a protocol and a schema version, both ends send them,
and nothing compares them. What saves it today is that `ncfg` and `netcfgd`
ship in one package, so the skew window is the seconds between unpack and
restart.
