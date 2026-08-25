# 0007: DNS is per-link scopes, and a mode that cannot express them is an error

Status: accepted
Date: 2026-07-28
Milestone: model in M1, flat backends in M2, scope-capable backends in M4

## Context

`DnsPolicy` as written in §2.1 is `{mode, servers, search, options}`, where a
per-interface policy merges over the globals and the result is written through
`WriteResolvConf`, `Resolvconf` or `Exec`. That is a single global list of
servers assembled from every link.

It is also, exactly, NetworkManager's behaviour before `systemd-resolved`
existed, and it fails in the way that behaviour is famous for failing. Bring up
a VPN and one of two things happens: the VPN's servers win and every query on
the machine goes to the corporate resolver, or they are appended and internal
names resolve or do not depending on server order and timeouts. Neither is
configured by anyone; both are emergent.

The information needed to do better is already present and is being thrown
away. A DHCP lease on `eth0` yields servers *for `eth0`*. A VPN yields servers
*for the domains behind it*. DNS configuration is per-link at its source, and
the current model destroys that structure at compile time — the earliest and
least recoverable moment.

What `systemd-resolved` and NetworkManager-with-dnsmasq provide instead is
per-link scopes with **routing domains**: resolved's `~corp.example`,
dnsmasq's `--server=/corp.example/10.0.0.1`. Both spellings mean the same
thing — queries under this suffix go to this link's servers and nowhere else —
and both support `~.` for "this link is the catch-all".

The constraint that shapes the whole decision: **`resolv.conf` cannot express
this.** Its `search` line is suffix completion, not query routing. There is no
per-domain server concept in the file format at all.

## Decision

**The document always carries per-link scopes.** Merging into a flat list is a
rendering step performed by a delivery mode, never a compile step. The
compiler's output preserves the structure it was given.

**Each mode declares what it can express, and the compiler checks it.** A
config using routing domains under `WriteResolvConf` is a **compile error**
naming the file, the line and the mode — not a warning, and not a flattening.
This is §2's prohibition on silent field-dropping applied one level up, and it
matters more here than elsewhere because a silent flattening is a security
failure rather than a convenience one: it sends internal queries to a public
resolver, or every query to a corporate one that logs them. Quietly getting
that wrong is the exact class of behaviour this project exists to eliminate.

The types become:

```
DnsPolicy {
  mode      : enum { None, WriteResolvConf, Resolvconf, Openresolv,
                     Resolved, Dnsmasq, Unbound, Exec(string) }
  servers   : [DnsServer]
  search    : [string]           // suffix completion; every mode supports it
  domains   : [RoutingDomain]    // query routing; scope-capable modes only
  options   : [string]
  dnssec    : enum { No, Allow, Yes }?
  transport : enum { Plain, Tls, Https }?
}

DnsServer    { addr: IpAddr, port: u16?, sni: string? }
RoutingDomain{ suffix: string, exclusive: bool = false }   // "." = catch-all
```

`search` and `domains` stay **separate fields**. resolved overloads both into
one list distinguished by a `~` prefix, which is a spelling accident of its
config file and a persistent source of confusion. They are different
operations, only one of them is universally supported, and the capability
check has to tell them apart anyway.

`servers` becomes `[DnsServer]` now, before the M4 freeze, even though DoT
lands much later. A bare `IpAddr` cannot carry a port or an SNI name, and
widening it afterwards is a major version bump.

### The capability table, and why openresolv is the reference path

| Mode | Flat | Scopes | Needs |
|---|---|---|---|
| `WriteResolvConf` | yes | **no** | nothing; the file format cannot route |
| `Resolvconf` | yes | **no** | any resolvconf implementation |
| `Openresolv` | yes | **yes** | openresolv plus a configured subscriber |
| `Resolved` | yes | yes | systemd |
| `Dnsmasq` | yes | yes | dnsmasq |
| `Unbound` | yes | yes | unbound |
| `Exec` | yes | yes | the script's problem |

**`Openresolv` is a separate mode from `Resolvconf` on purpose.** They are two
different contracts against tools that share a command name. `Resolvconf`
means "hand a flat per-interface `resolv.conf` blob to whatever
implementation is installed", which every implementation supports.
`Openresolv` means "use `private_interfaces` and the subscriber mechanism to
deliver scopes", which requires that specific implementation *and* a
configured subscriber. Collapsing them would make the capability of a mode
depend on which package happens to be installed, and the compile-time check
in this record depends on the table being static. Naming the capability in
the mode keeps it static; netcfgd verifies the named tool is actually present
at apply time and fails loudly when it is not.

**openresolv is the path to recommend for this project's audience**, and it
should be what the documentation leads with. It ships subscribers for
dnsmasq, unbound, named and pdnsd; its `private_interfaces` option — "these
interfaces name servers will only be queried for the domains listed in their
resolv.conf, useful for VPN domains" — is exactly the exclusive routing domain
of this model, arrived at independently. It is also by Roy Marples, who wrote
the dhcpcd that decision 0004 already delegates DHCP to, carries no systemd
anywhere, and is the tool the Gentoo, Alpine and BSD worlds already use —
which is the same audience the netifrc compatibility in 0001 is aimed at.

**There is no `Auto` for DNS mode, deliberately.** `Dhcp4.backend` has one and
should: a lease is a lease, and which client fetched it changes nothing an
operator can observe. The DNS mode determines *where queries go* and whether
split DNS functions at all, so a heuristic preference order would be both a
silent security decision and an unavoidable statement about which resolver
this project favours. The operator names the resolver. That is one more line
of config in exchange for never guessing about this.

**A field earns its place in `DnsPolicy` only if at least two delivery modes
can express it.** This is the southbound counterpart of §1 constraint 6: the
one-way rule stops a northbound adapter shaping the model, and this stops a
backend doing it. `dnssec` and `transport` qualify — resolved, unbound and
dnsmasq all do DNSSEC, resolved and unbound both do DoT. `MulticastDNS` and
`LLMNR` do not; they are resolved-only knobs, they are service discovery
rather than address configuration, and admitting them would make `DnsPolicy`
into resolved's config file one field at a time. `Exec` mode is where a site
that wants them puts them.

**`Exec` receives the whole scoped structure as JSON on stdin**, not a
flattened list. It is the escape hatch, and an escape hatch that has already
discarded the interesting part is not one.

## Consequences

**Split DNS carries a runtime dependency on a capable resolver**, and that is
opt-in by construction. A config with no routing domains never needs one, uses
`WriteResolvConf`, and leaves the filesystem exactly as principle 12 requires.
The embedded target is better off than it looks: OpenWrt ships dnsmasq in the
default image, so the reference device has a scope-capable backend already
installed.

**No mode is a dependency of netcfgd.** A delivery mode is selected by config
on a host that already has the tool, exactly as `Dhcp4.backend` selects
between dhcpcd and udhcpc, and §1 constraint 3 governs what the binary links
rather than what it may hand work to — the reading decision 0004 already
established. This matters most for `Resolved`, which does pull in systemd,
because it is a systemd component and is packaged as depending on it: a host
that does not run systemd never names that mode, and principle 12 means
nothing on such a host shows any evidence the mode exists. It is one of four
scope-capable modes, it is not the default, there is no `Auto` that could
drift towards it, and the documentation leads with `Openresolv`. Supporting
it costs one backend and one row in the capability table; refusing to support
it would remove systemd from nobody's machine and would only make netcfgd
worse on the desktops that M7 and M8 target.

**`ncfg explain` can account for configuration, not for resolution.** Once
scopes exist the question a user actually asks is "why did this name resolve
*there*", and answering it fully means explaining what resolved or dnsmasq did
with the config, which netcfgd does not know. The honest scope is: print the
desired scope table, the mode that rendered it, and what that mode emitted.
Stop there. Do not grow a DNS debugger — that is a different tool and it
belongs to whoever ships the resolver.

**This is the second place principle 2 bends, and it should be recorded as
such alongside the nano tier (0003).** The project's claim is that "why is the
system like this?" is answerable by reading a file. Hand DNS to resolved and
the effective behaviour lives in that daemon's state, not in `/run/netcfgd/`.
The mitigation is partial and worth doing anyway: write the **rendered** scope
table to `/run/netcfgd/dns/` — what netcfgd asked for, per link, per domain,
and through which backend. That makes netcfgd's half of the answer greppable
even though the resolver's half is not, and it means a disagreement between
the two is diffable rather than a matter of opinion. State the limit in the
documentation rather than letting a user discover it while debugging a VPN.

**Four delivery backends instead of three**, each needing its own capability
declaration and its own fixture tests. The capability table is data, not code,
so the compiler check is one function over a small table.

The M4 milestone's "DNS handoff" becomes specifically the scope-capable
backends; the flat ones land with the daemon in M2 so that ordinary
single-link hosts work long before any of this matters.

## Alternatives considered

**Keep the flat model; document the limitation.** Rejected. It is the
incumbent behaviour, it is the specific behaviour design §1.1 lists as Pain 1
in another guise — state that is emergent rather than configured — and a VPN
is not an exotic setup.

**Implement a small forwarding stub inside netcfgd so split DNS needs no
dependency.** Genuinely tempting: a non-caching forwarder that routes by
suffix is a few hundred lines, and it would make the feature dependency-free.
Rejected, and named here because it is the attractive wrong answer. It is a
network-facing parser answering untrusted queries, which is precisely what
design §1.5 excludes and precisely the surface that the security posture and
the size budget are built to avoid. Configuring a resolver and being one are
different jobs.

**Flatten with a warning when the mode cannot route.** Rejected on the
security argument above. A warning in a log that nobody reads, attached to a
change in where queries go, is worse than a refusal — the refusal is loud at
the moment of the mistake and design §17 already keeps the last-good desired
state in effect when a config fails to compile.

**Model resolved's config surface directly and translate for other backends.**
Rejected under the two-backend rule. It would make one implementation the
model's shape, which is the same error the one-way rule forbids in the other
direction.

**Treat `Resolvconf` as scope-capable and probe the implementation at apply
time.** Rejected: the compile-time capability check is the whole mechanism
this record turns on, and a capability that is only known at apply time cannot
be checked when the config is compiled. The `Openresolv` mode names the
capability instead, which keeps the table static.

## Sources

- [`resolvconf.conf(5)`, openresolv](https://manpages.debian.org/trixie/openresolv/resolvconf.conf.5.en.html)
  — `private_interfaces`, and the `dnsmasq_conf` / `unbound_conf` subscriber
  outputs that carry domain-specific servers.
- [openresolv, ArchWiki](https://wiki.archlinux.org/title/Openresolv)
  — subscribers for dnsmasq, named, pdnsd and unbound.
