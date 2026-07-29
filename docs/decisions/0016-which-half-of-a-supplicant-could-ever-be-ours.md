# 0016: which half of a supplicant could ever be ours

Status: accepted
Date: 2026-07-29
Milestone: not scheduled; the boundary applies from M3

## Context

Design section 1.5 excludes "a reimplementation of the 802.11 supplicant", and
decisions 0014 and 0015 arrange to drive wpa_supplicant as a mechanism rather
than adopt it as a manager. Working through that raised the obvious next
question: if the supplicants are the wrong shape, does netcfgd eventually want
its own?

"Roll our own supplicant" sounds like one decision. It is at least six, and
they have wildly different answers, so the useful thing is to say which is
which before anybody has to decide under pressure.

| Part | Difficulty | Whose? |
|---|---|---|
| Scanning -- `NL80211_CMD_TRIGGER_SCAN`, parsing results | Low | **Could be ours** |
| BSS and network selection policy | Low, and it is *policy* | **Should be ours** |
| Association / SME state machine | Medium | Could be ours |
| Key management: 4-way handshake, SAE, OWE, PMKSA | High, and cryptographic | **Never ours** |
| EAP methods: TLS, PEAP, TTLS | High, needs a TLS stack | **Never ours** |
| Roaming: 802.11r/k/v, RSSI hysteresis | High, and real-time | Not ours; explaining it is |

The two rows marked never are not a matter of effort. WPA2's handshake gave
the world KRACK and SAE gave it Dragonblood, both in implementations written
by people who specialise in this. A network configuration tool whose pitch is
that it is *predictable* has nothing to gain and a great deal to lose by
having opinions about Dragonfly. EAP is worse still: it means shipping a TLS
stack, which would be larger than the rest of netcfgd combined and would put
the project in the business of certificate validation.

## Decision

**netcfgd will never implement key management or EAP.** Not "not yet" --
those stay delegated permanently, and section 1.5's non-goal is affirmed
rather than softened.

**The parts worth owning are scan and selection, and there is a defined path
to owning them** if the explainability gap ever justifies the cost:

1. netcfgd drives `nl80211` scans itself, keeping the results in the observed
   model. Scan output becomes greppable in `/run` like everything else.
2. netcfgd picks the BSS, by declared policy: priority, band preference,
   signal floor, `bssid_pin`. Deterministic, explainable, and written down in
   the config rather than buried in a heuristic.
3. wpa_supplicant is handed a network pinned to that BSSID and does only the
   handshake.
4. Roaming becomes netcfgd re-running step 2 on its own cadence rather than a
   decision taken inside a daemon it cannot see into.

That would close three gaps the supplicant analysis identified: BSS selection
becomes deterministic, `ncfg plan` can say which access point it intends to
join, and `ncfg explain` can answer "why this one?" with a signal figure and a
policy line rather than a shrug.

**It is not scheduled, and the trigger is evidence rather than appetite.**
Build it when somebody has an actual case where not being able to explain a
roam cost them something. Until then the honest position is that wpa_supplicant
chooses well enough and netcfgd says so.

### The cost, stated now so it is not discovered later

Pinning a BSSID **defeats 802.11r fast transition**. A supplicant that owns
selection can roam within a mobility domain in tens of milliseconds; one told
to associate with one specific AP cannot, because the decision has already
been made elsewhere. On an enterprise network with voice traffic that is not a
trade worth making, and it means the nl80211 path would have to be optional
rather than the only way -- which doubles the code paths through the most
timing-sensitive part of the system.

That is the real argument against, and it is stronger than the implementation
cost. Owning selection buys explainability and spends roaming quality, and
which of those matters depends on whose laptop it is.

## Consequences

**The boundary is now a line rather than a feeling.** A future contributor
proposing "netcfgd should handle the handshake itself" has a record saying no
and why, and one proposing "netcfgd should choose the access point" has a
record saying yes, here is the shape, here is what it costs.

**`nl80211` would be more work in the audited crate.** It is a generic netlink
family, so it needs family resolution through the controller as well as the
message types -- more surface in the one crate permitted `unsafe`, and more
for the fuzz targets to cover. Worth knowing before starting rather than
halfway through.

**Nothing about M3 changes.** The supplicant integration being built now is
the same either way: whether netcfgd picks the BSS or wpa_supplicant does, the
association still goes through the control socket. The nl80211 path adds a
step before it rather than replacing it, which is what makes this deferrable
without leaving a stub anywhere.

## Alternatives considered

**Write a full supplicant, crypto included.** Rejected permanently, above. The
one place in this project where being unoriginal is a feature.

**Take the nl80211 path now, as part of M3.** Rejected: it would mean shipping
wifi that cannot fast-transition, on the strength of an explainability
argument nobody has yet complained about. The gap is real and it is not
urgent, and building the thing that costs roaming quality before anybody has
asked is how a project acquires features it cannot remove.

**Say nothing and revisit if it comes up.** Rejected because it came up, and
because the decomposition above is the useful part -- it is what turns "should
we roll our own?" from a mood into two separate questions with different
answers.
