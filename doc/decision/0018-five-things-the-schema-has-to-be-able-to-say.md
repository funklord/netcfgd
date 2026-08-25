# 0018: five things the schema has to be able to say

Status: accepted
Date: 2026-07-30
Milestone: M4 (schema), implementation later where noted

## Context

M4 freezes the model, the document schema and the socket API. Project.md
section 8 row 4 already established what that means in practice: the
`BackendKind::Builtin` variant is in the schema, unimplemented but recognised,
"because adding it after the M4 freeze is a major version bump". M1 did the
same for DNS scopes, `EapConfig` and `Delegated`.

Five things had been noticed during M1-M3 and written down nowhere but a
running list:

- per-network MAC randomization
- access point mode
- policy routing rules (`ip rule`)
- ethtool settings
- IPv6 tokens

Each is a thing real machines need and netcfgd could not express. That has a
worse consequence than "missing feature", and it is the same one in every
case: the operator puts the command in a `post_up` hook, and netcfgd then
reports no drift while part of the network configuration comes from somewhere
it cannot see. Constraint 1 says the config files are the only authority, and
a gap in the schema is a hole in that claim, not merely an inconvenience.

## Decision

**All five land in the schema now. Three of them do nothing yet, and say so.**

| Feature | Schema | Implemented | Why not |
|---|---|---|---|
| MAC randomization | `WifiDevicePolicy.mac_policy` | **yes** | -- |
| Policy routing rules | `Document.rules` | no | needs `RTM_*RULE` in the netlink crate, planner ops and an observer |
| IPv6 token | `Interface.ipv6_token` | no | `IFLA_AF_SPEC` nesting; small, just not done |
| ethtool | `Interface.link_settings` | no | needs an ioctl outside the audited crate, or generic netlink (0016) |
| Access point | `Document.access_points` | no | needs hostapd or supplicant AP mode driven as a backend |

`SCHEMA_VERSION` goes to 1.1. Fields were added and nothing changed meaning,
which is a minor bump by the rule the constant's own documentation states.

### Recognised, not applied, and never silent

The three unimplemented ones **compile**. Rejecting them at compile time would
mean a config that will work in a later release is a config that has to be
rewritten to upgrade, which is the opposite of what a schema freeze is for.

What must not happen is silence. `ncfg plan` warns once per feature, naming the
interface where there is one, so a plan never reports "one action" about a
document that asked for four things. That is tested, and so is the inverse: a
document using none of them warns about none of them, because a warning that
always fires is one people learn to scroll past.

### The choices inside the five that are not obvious

**A rule is named, and its priority is mandatory.** `rule vpn { priority =
100; ... }`, not `rule 100 { ... }`. The kernel identifies a rule by number,
but a number is a poor thing to put in a diagnostic -- "rule 100 conflicts with
rule 200" tells an operator nothing they cannot already see. The priority stays
required despite the kernel being willing to assign one, because an unnumbered
rule lands wherever the kernel puts it, two applies can produce different
orders, and at that point the document has stopped describing the system.

Rules are host-wide rather than per-interface. They are consulted by priority
across the whole machine and two interfaces' rules interleave by number, so
attaching them to interfaces would make the effective order something you
reconstruct by reading every block.

**MAC policy has three values and defaults to `permanent`.** Not because
permanent is the better default in the abstract -- it is the trackable one --
but because changing the address breaks MAC-based admission control, DHCP
reservations and captive portal sessions, and a networking tool that silently
stops your laptop working on the office wifi after an upgrade has made the
wrong trade. The value is sent to the supplicant for *every* policy including
`permanent`, since leaving it unset inherits whatever global the distribution
configured -- and a privacy property that depends on somebody else's default
is not a property.

Scan randomization is a separate flag, because it is a separate exposure: a
device that randomises on association but not on scan is trackable by a passive
listener in a cafe it never joined.

**An access point is bound to a device; a `network` deliberately is not.** A
station profile describes a network that might be in range of any radio. An
access point is a thing one specific radio is doing, and pretending otherwise
would leave the binding to be guessed at apply time.

**An IPv6 token is host bits only.** `::5`, not `2001:db8::5`. The kernel
accepts a full address and silently uses the bottom 64 bits, so a config that
looks like it pins an address would quietly pin half of one. That is refused
with a message showing the right shape.

**`Toggle` is three-valued, not `Option<bool>`.** "netcfgd does not manage
this" and "netcfgd requires this off" are different instructions producing
different plans. `Option<bool>` says the same thing and reads worse at every
use.

## Consequences

**Both binaries grew for features that do nothing.** netcfgd by 61 KB and ncfg
by 29 KB, mostly serde's generated code. That is the cost of the freeze,
recorded in size-budget.txt rather than absorbed quietly, and it is a good
trade against a major version bump.

**Three entries now exist that a future contributor will find and want to
implement**, with the blocker written down in each case rather than
rediscovered. Two of them share the blocker that decision 0016 identified for
`nl80211`: generic netlink family resolution is unpaid work in the one crate
allowed `unsafe`, and doing it once unlocks ethtool as well.

*Paid, 2026-07-30.* That resolution now exists, and `ethtool` resolves as id
22. What remains for ethtool is its own message types and the reconciliation --
the shared cost is gone, and it turned out to need no new `unsafe`.

**The hook workaround is still there and now has a deadline.** Somebody with
`ip rule` in a `post_up` today keeps it working. When rules are implemented,
that hook becomes drift against a document that finally describes it -- which
is the right outcome and will surprise whoever wrote the hook. The migration
note belongs with the implementation.

## Alternatives considered

**Implement all five before the freeze.** Rejected on time, not principle.
Policy routing alone is a netlink message family, planner ops, observer support
and reconciliation; doing five features badly to hit a freeze date is how a
schema acquires fields that do not survive contact with their implementation.

**Leave them out and take the major bump later.** Rejected. A major bump means
every consumer of the document format refuses to read it, and the whole reason
the freeze is scheduled before the adapters exist (project.md section 8: "the
model freezes before any adapter exists, so no adapter can shape it") is that
the format has to be stable for anything to build on.

**Reject unimplemented features at compile time.** Rejected above: it turns an
upgrade into a rewrite, and it would mean the schema and the language disagree
about what a valid document is.

**A `Vec<String>` of raw `ip rule` arguments.** Tempting, and the fastest route
to expressing everything. Rejected: it is a hook with extra steps. Nothing
could diff it, `explain` could say nothing about it, and the first thing anyone
would ask -- "which rule is sending this traffic there?" -- would be
unanswerable. A typed field set that covers less is worth more than an opaque
one that covers everything.
