# 0001: the native config syntax is blocks, not netifrc-style variables

Status: accepted
Date: 2026-07-28
Milestone: M1

## Context

`project.md` §8 question 1. The design doc already answers this — §3.1 makes
native `ncfg` blocks the recommended dialect and netifrc a compat mode — but
the brief reopened it, and for a good reason: netifrc muscle memory is a
stated selling point (design §3.4), and that muscle memory is *literally*
`config_eth0="192.168.1.10/24"`. Keeping the promise appears to argue for
keeping the syntax.

## Decision

The native dialect is blocks, per the §3 grammar. netifrc syntax is read only
by the compat front end, behind its own feature flag, and `ncfg convert`
transpiles one way.

Four reasons, in descending order of how hard they are to work around.

**1. netifrc's variables are shell, and that is not a detail.** `config_eth0=`
is a shell assignment in a file that gets *sourced*; `preup()` is a shell
function. Adopting the syntax without sourcing produces a language that looks
identical to netifrc and behaves differently — the worst available outcome,
because the familiarity it trades on is exactly what will mislead. Adopting it
*with* sourcing makes the configuration language shell, which forfeits the
determinism gate (§6), static analysis, and the compiler's ability to run
anywhere without a shell.

**2. The model is nested and flat names cannot address it.** A `WgPeer` inside
a `WireGuard` inside an `Interface` would need something like
`wireguard_wg0_peer_1_allowed_ips=`. netifrc gets away with flat names because
it does not model wifi profiles or WireGuard peers at all. Any scheme invented
to flatten them is a second grammar with worse diagnostics and no precedent to
borrow from.

**3. Drop-in precedence needs block identity.** §3's rule — redefining an
existing block without `override` is a compile error — is what keeps layering
predictable, and it is the rule that stops this becoming another config system
where last-wins silently. Over flat variables the unit of redefinition is a
single key, so "add a route to eth0" and "replace eth0 entirely" stop being
distinguishable.

**4. Diagnostics hang off spans.** `ncfg explain` must say which file and line
produced a field. A block is a stable thing to anchor a span to and a natural
unit to report.

## Consequences

Two front ends to write and fuzz. §6 requires a fuzz target per parser
regardless, so the marginal cost is the netifrc grammar itself.

netifrc compat is permanently a second-class path. A bug report against it is
answered with `ncfg convert` and a native block, and it should not grow
features the native dialect lacks.

The compatibility promise that survives is **vocabulary, not syntax**: keys
inside blocks read like `config`, `routes`, `dns` (design §3.2 already writes
them that way), so what transfers is knowing what to call things. That is the
honest version of the promise and the docs should make it, rather than
implying a Gentoo config drops in unchanged.

## Alternatives considered

**Flat variables in the native dialect too.** Rejected on all four points
above; point 1 alone is decisive.

**Both dialects first-class and native.** Rejected: two grammars to keep in
step forever, every documentation example written twice, and a standing
argument about which one a new feature lands in first.

**Native blocks, but sourced by a shell for interpolation.** Rejected for the
same reason as point 1, plus it would put a shell in the dependency set that
§1 constraint 3 exists to keep empty.
