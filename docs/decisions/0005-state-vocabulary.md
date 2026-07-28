# 0005: desired and observed, not intended and operational

Status: accepted
Date: 2026-07-28
Milestone: M1

## Context

`project.md` §8 question 5. RFC 8342 (NMDA) names the configuration remaining
after all transformations `<intended>`, and the running state — configuration
in effect plus derived read-only state — `<operational>`.

The mapping onto netcfgd is not approximate, which is what makes this a real
question. The compiled document *is* intended in the NMDA sense: includes and
drop-ins are already expanded, `override` is already resolved, nothing further
happens to it before it is applied. The observed model *is* operational.
Adopting the names would make the M9 RESTCONF mapping (design §9.6)
self-documenting rather than requiring a translation table.

## Decision

Keep `desired` and `observed` everywhere — type names, `/run` paths, socket
API fields, CLI subcommands, documentation. `netcfgd-restconf` translates at
its own boundary.

**§1 constraint 6, the one-way rule, decides this.** No change to the model,
config language or socket API may be justified *solely* by an adapter's needs.
"The RESTCONF mapping would read better" is exactly and only an adapter's
need. For the NMDA names to win, they would have to be independently better
for somebody editing a file on a single host — and they are not.
`desired`/`observed` is the Terraform and Kubernetes vocabulary that this
project's own pitch invokes ("like `terraform plan/apply`, but for
interfaces"), and a sysadmin who runs `ls /run/netcfgd/desired/` needs no
glossary. `ls /run/netcfgd/intended/` invites the question "intended by
whom?", and `operational` is jargon for a directory of files describing what
is currently true.

This record exists precisely because the case for switching is good. A rule
that only ever fires when the other side is obviously wrong is not doing any
work; the one-way rule earns its keep here, where the adapter is correct about
its own convenience and loses anyway.

Settled now rather than at M9 because it propagates into `/run` paths, socket
API field names and every human-readable string, and is free to decide while
none of those exist. At M9 the schema has been frozen since M4.

## Consequences

`netcfgd-restconf` carries a two-line equivalence table and the documentation
for it, permanently. That is the right home for it — the adapter already
translates an entire model into YANG, so two names cost nothing next to that,
and stating the equivalence up front is ordinary practice for an adapter
between two vocabularies.

A reader arriving from a NETCONF background meets unfamiliar words. A reader
arriving from Terraform, Kubernetes, Ansible or Puppet does not, and the
second group is far larger and is who the single-host tool is for.

## Alternatives considered

**Adopt the NMDA names.** Rejected under §1 constraint 6, as above.

**Support both, as aliases.** Rejected: two words for one concept are two
concepts as far as any reader is concerned, and `code-style.md` §1 forbids
exactly this ("one word per concept, everywhere"). It would also double every
`/run` path or introduce a symlink farm that lies about what is there.

**Defer to M9 and decide with the adapter.** Rejected: that is the most
expensive possible moment. The schema froze at M4, the paths are in every
user's scripts, and the decision would then genuinely be driven by adapter
convenience — which is the thing the one-way rule exists to prevent.
