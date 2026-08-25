# 0102: a test fixture with a deprecation deadline

Status: accepted
Date: 2026-08-04
Milestone: the dated item 0101 left open

## Context

[0101](0101-a-fake-on-path-does-not-fake-what-netcfgd-finds-in-sbin.md) recorded
three Alpine failures that were not netcfgd's, and singled one out as having a
clock attached:

> `tunnel.sh` against openvpn 2.7.5. The test's own `.ovpn` uses a static key
> with no TLS, and 2.7 refuses to start on it [...] it does mean this script
> cannot run against a current openvpn, and 2.8 will make that permanent.

`tunnel.sh` is the only test that drives a **real** openvpn — everything else
about the tunnel path uses `fake_openvpn.py`. What it proves is that the
`--route-up` script netcfgd generates actually runs under the real daemon, and
that netcfgd installs what the daemon reports. On Alpine, which already ships
2.7, it failed 18 of 22 checks.

The fixture used `secret` — a pre-shared static key — for one reason: it brings
a tunnel up with **no peer at all**, which is the cheapest way to reach the
moment netcfgd cares about.

## Decision

**The fixture uses TLS, and the test starts a real far end.**

`allow-deprecated-insecure-static-crypto` was measured and rejected. It cannot
be written once for both: openvpn 2.6 refuses it as an unrecognised option and
2.7 requires it, so it would need version detection — and 2.8 removes the mode
regardless. That buys time and nothing else.

**Peer-to-peer TLS, not client/server.** `tls-client` with an explicit
`ifconfig` keeps the addressing and every `route` and `dhcp-option` line exactly
where they were, so what this script asserts about *netcfgd* is unchanged. A
client/server fixture would have moved the routes into `push` directives on the
far end, which is a different test wearing the same name.

**Two self-signed certificates and `peer-fingerprint`** — openvpn's own
documented setup without a PKI. No CA, no `dh`, and nothing that expires in a
way that fails a year from now, since they are minted per run.

**The far end is deliberately on a different subnet.** This is the part worth
recording, because it is not obvious and it was got wrong first.

## What building it found

The first attempt gave the peer the matching half of the point-to-point pair —
`ifconfig 10.8.0.2 10.8.0.1` against the client's `10.8.0.1 10.8.0.2`, which is
what a real deployment looks like. Twelve checks passed and six failed, all of
them about routes, with:

```
FAIL route.add vpn0  routes: 10.9.0.0/24 via 10.8.0.2 metric 700
     could not add route 10.9.0.0/24 on vpn0: Invalid argument (os error 22)
```

Both ends of this tunnel live in **one network namespace**. So the client's peer
address is simultaneously a *local* address — it is on the far end's `tunpeer` —
and the kernel refuses a route whose gateway is one of its own, with `EINVAL`.
Nothing netcfgd does is wrong; the topology is an artefact of the test.

The far end now uses `10.7.0.2/10.7.0.1`. Nothing is ever sent through the
tunnel — this script checks what openvpn *reports* and what netcfgd then
*installs* — so the two ends may disagree about addressing, and the TLS
handshake over loopback does not care. Verified on both versions.

**The control mattered more than the diagnosis.** Those six failures looked like
netcfgd defects until the original fixture was run on the same Debian image and
passed 22 checks. A sweep has to start from green, and this one started from a
change already applied.

## The gates

The result matrix is the argument, because a fix for one version that quietly
regresses the other is the obvious way to get this wrong:

| | as written (TLS) | static key restored |
| --- | --- | --- |
| Debian, openvpn 2.6.14 | 22 pass | 22 pass |
| Alpine, openvpn 2.7.5 | **22 pass** | 18 fail |

The top row says the change is a **no-op on 2.6** — same 22 checks as the
baseline, so nothing was traded away. The right column is the break: putting the
static key back reproduces the original failure on 2.7 and only there.

`openssl` joins `openvpn` in the preflight, and its absence is a skip with the
package named for both distributions.

## What this does not change

netcfgd. The daemon hands the operator's file over unread
([0046](0046-netcfgd-does-not-generate-openvpns-configuration.md)), so the
`.ovpn` is the test's own and always was. What changed is what the test asks a
real openvpn to do — which is the point: a fixture that a current release
refuses to start on is a test on its way to covering nothing, and it gets there
without anybody editing it.
