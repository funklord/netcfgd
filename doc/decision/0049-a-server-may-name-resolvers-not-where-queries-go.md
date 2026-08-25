# 0049: A server may name resolvers, not where queries go

Status: accepted, and **split in two by
[0067](0067-a-suffix-is-not-a-routing-domain.md)**: the refusal below covers two
different things, and a *search suffix* -- what to append to a bare name -- is now a
report key under the same gate as a server. A *routing domain* is still refused and
still has no key, which is what this record is about.
Date: 2026-08-02
Milestone: finishes what [0048](0048-a-tunnels-routes-arrive-through-the-report.md) left

## Context

0048 took a tunnel's routes and deliberately left its nameservers, saying the
reporting side was three lines and the *behaviour* was the hard part. This is
that part.

A VPN server pushes two different kinds of thing in the same breath:

```
dhcp-option DNS 10.0.0.53          # here is a resolver
dhcp-option DOMAIN corp.example    # and these names should use it
```

They look alike and are not. The first is information netcfgd could not have
had. The second is a *decision about where every query on this machine goes*,
made by a remote party, taking effect the moment a tunnel connects.

Decision 0007 already refuses to make that decision by accident: it is why a
flat DNS mode asked for routing domains is a compile error rather than a
flattening, and its opening paragraphs describe exactly this failure -- "bring
up a VPN and one of two things happens: the VPN's servers win and every query
on the machine goes to the corporate resolver, or they are appended and
internal names resolve or do not depending on server order and timeouts.
Neither is configured by anyone; both are emergent."

## Decision

**A report may name servers. It may not name routing domains.** There is no key
for one in `doc/interface-report.md` and there will not be, because constraint
1 says the config files are the only authority and a routing domain is
authority over where queries go.

**A reported server is delivered only where the document asked for it**, which
is narrower than the rule for a reported route:

| | route | nameserver |
|---|---|---|
| addressing says `reported` | delivered | delivered |
| netcfgd started the writer | delivered | **not** delivered |
| interface has a `dns` block | -- | delivered |

The asymmetry is the point. A route down a tunnel goes down *that tunnel*, and
netcfgd started the tunnel, so installing it changes nothing the operator did
not ask for. A nameserver changes where names resolve for the whole machine, so
netcfgd waits to be told. A modem is the first row: its addressing *is* the
report, it is the uplink, and its servers are the ones to use -- that case has
worked since the modem work and is unchanged.

What an operator writes to take a tunnel's resolvers:

```
global { dns { dns_mode = "dnsmasq" } }

interface vpn0 {
	openvpn { config = "/etc/netcfgd/work.ovpn" }
	dns { domains = ["corp.example"] }      # these names, this way
}
```

The `domains` line is the split the server tried to push, written where an
operator can read it, diff it and delete it. The servers that answer for it
still come from the report, because those genuinely are the server's to give.

**What the server suggested is not hidden.** The generated script writes it into
the report as a comment:

```
# the server also said: dhcp-option DOMAIN corp.example
```

netcfgd's reader drops comments and a person reading the file does not. Silently
discarding it would leave an operator wondering why the VPN "does not work",
which is a different failure from the one this record prevents and no better.

## What this cost, in a defect it found

Writing that config as the documentation would recommend it produced:

```
netcfgd.conf:1:1: dns scope vpn0 uses routing domains, which mode none
                  cannot express
```

`check_dns_capability` asked the *scope's own* mode, and a scope states one only
to override -- so the check named a mode nobody wrote and no delivery would use,
and the only way past it was to repeat `dns_mode` in every interface block. That
is a second place for the host's resolver to be stated and disagree.

This is the compile-time twin of the defect `dns::inheriting` fixed at delivery
(project.md's "a scope with no mode of its own was dropped at delivery,
silently"), and it was found the same way: by writing the config the
documentation recommends and watching it be refused. The check now asks the mode
that will actually deliver the scope, and names *that* when it refuses.

## Alternatives considered

**Honour a pushed `DOMAIN` as a routing domain.** This is what a corporate VPN
expects and what NetworkManager does. Rejected: it hands a remote party the
answer to "where do my queries go", and `dhcp-option DOMAIN .` -- a legal push --
takes all of them. A VPN that wants everything is asking for something an
operator can write in one line, and should have to.

**Deliver a tunnel's servers flatly when the document says nothing.** This is the
behaviour 0007 opens by rejecting, arrived at from the other direction. It is
also the *quiet* version: nothing in the config would say it happened.

**Refuse to start a tunnel that pushes DNS options the document has not
claimed.** Too loud, and wrong-headed: the tunnel works fine, and refusing it
would make netcfgd's opinion about DNS into a reason a VPN will not connect.

**A `domain=` key in the report that only netcfgd's own generated scripts may
write.** Rejected as a distinction the contract cannot enforce: the file is a
file, anything can write it, and a rule that depends on who wrote a line is not
a rule.

## Consequences

- A tunnel's servers are read, shown by `ncfg status` as reported and not
  applied, and delivered nowhere until a `dns` block appears. An operator moving
  a working NetworkManager VPN to netcfgd has one line to add, and the
  documentation has to say so.
- Split DNS down a tunnel needs a scope-capable mode, which 0007 already made an
  opt-in dependency. A host on `write_resolv_conf` can still take the tunnel's
  servers flatly, because **the gate is the block and not what is in it**: an
  empty `dns { }` on the interface means "this link's resolvers count" and
  nothing else. That is the minimal spelling, and it is deliberately a spelling
  rather than a default.
- `pppd`'s `usepeerdns` is the same question and now has the same answer
  waiting for it: report the servers, leave the routing to the document.
