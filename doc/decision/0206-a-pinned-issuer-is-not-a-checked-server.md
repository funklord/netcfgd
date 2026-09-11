# 0206: a pinned issuer is not a checked server

Status: accepted
Date: 2026-09-11
Milestone: M8; the wifi EAP and enterprise audit

## The gap

netcfgd could say `ca_cert` and could not say anything else about the server.

**`ca_cert` answers "who signed this certificate". It does not answer "who is
this certificate for".** Pinning an issuer accepts every certificate that
issuer ever signed, which is exactly the intent when the issuer is the
organisation's own CA, and close to worthless when it is a public one -- and a
commercial certificate on a RADIUS server is ordinary.

Where the issuer is public, anybody who can buy a certificate from the same CA
can raise an access point with the right SSID, be believed, and take whatever
the inner method sends: an MSCHAPv2 exchange to crack offline, or the password
itself. The client has verified that the server's certificate was signed by
somebody the client trusts, and nothing about *which* server it is.

`domain_suffix_match` is the other half -- a suffix match against the
certificate's names, matching downward, so `radius.example.com` accepts that
host and `example.com` accepts anything under it. netcfgd now carries it from
the document through the compiler to the supplicant.

Absent sends no line rather than an empty one. **That distinction is 0189's**:
`ca_cert=""` was read as a filename, OpenSSL refused it, and PEAP never reached
an inner method -- which is the fault this entire run of audits opened with. An
empty `domain_suffix_match` would be the same mistake in a different field.

## The warning was too easily satisfied

It fell silent as soon as `ca_cert` appeared, which reads as "that is dealt
with". It now distinguishes three states: neither pinned, the issuer only, and
both. The middle one is new and is the common case -- somebody who did the
obvious thing and stopped.

The existing test was called "one that pins a CA says nothing", and would have
gone on passing while its name became untrue. It now asserts all three states,
because the silent one is what the old shape got wrong.

## The example taught the insecure pattern

All three enterprise blocks pinned:

```text
ca_cert = "/etc/ssl/certs/ca-certificates.crt"
```

That is the system bundle: **trust every public CA on earth**. Against somebody
willing to buy a certificate it is barely better than pinning nothing, and it
was the reference an operator copies -- shipped, and pointed at by the postinst
as the thing to read on a machine with no network.

Fixed in all three, with the reasoning kept beside them, and a note that a
suffix matches downward so guessing wide defeats the point of setting it.

Fifth fault found in `netcfgd.conf.example` during this run, after a missing
`probe` block, a `mac_policy` value that does not exist, an access point
described as the whole of what you write, and a `band` the compiler rejects.
It is the only one with a security consequence, and -- like three of the other
four -- it was not a compile failure, so no gate could have found it.

## What is not done here

`ncfg wifi add` takes `--ca-cert` and has no companion flag for this, so a
network added that way still needs the key written by hand afterwards. Named
rather than quietly left: the add path has its own argument handling and its
own refusals, and widening it is a change to make deliberately rather than as
a tail of this one.

## Verification

The renderer, both ways: the name reaches the supplicant quoted when the
document asks, and there is no line at all when it does not -- with `ca_cert`
still pinned either way, so the check cannot pass by removing both.

The planner, three ways, as above.

Sabotage: making the warning fall silent on `ca_cert` again takes the planner
test red; never sending the setting takes the renderer test red.

The witness carries the field present in one sample and absent in the other,
because a `skip_serializing_if` field that is only ever absent is a field
nothing pins. Additive; `SCHEMA_VERSION` is unchanged, as it has been for every
additive field in this tree.
