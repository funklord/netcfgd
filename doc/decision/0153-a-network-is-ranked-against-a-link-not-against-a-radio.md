# 0153: a network is ranked against a link, not against a radio

Status: accepted
Date: 2026-09-02
Milestone: M9; link selection

An operator wants to say "the office wifi beats this ethernet, the cafe wifi
does not". Until now netcfgd could not express it. `interface.preference`
ranks *interfaces* -- wlan0 against eth0 -- and a radio carries one preference
whichever network it joined, so the two wifi networks above necessarily got
the same answer. The thing being ranked was the wrong thing.

## The decision

**A `network` may carry a `metric`, and while the machine is associated with
that network it replaces its interface's `preference` for that interface's
routes.** Absent, the preference stands, which is what every configuration
written before this does.

`metric` is a route metric on the kernel's scale: lower wins, and it is
directly comparable with every other link's `preference`, which is the same
scale already. That comparability is the whole point -- ranking a network
against a cable is only meaningful if both numbers mean the same thing.

## Why not extend `priority`

`network.priority` already exists and already ranks networks, so reusing it
looks obvious for about a minute. It is the wrong number twice over:

- **Opposite direction.** `priority` is higher-wins; a route metric is
  lower-wins. One of the two would have to be inverted somewhere, and an
  inversion between the document and the kernel is a defect waiting for
  somebody to reason about it in the wrong direction.
- **Different question.** `priority` is wpa_supplicant's own vocabulary,
  passed through to it verbatim, and it chooses **which network in range to
  join**. `metric` ranks the network **already joined** against other links.
  A machine can perfectly well prefer to join the cafe network when nothing
  else is around and still rank it below a cable.

So they stay two words, and **a network's metric deliberately does not
influence SSID selection.** That remains `priority`'s, and remains the
supplicant's, per
[0016](0016-which-half-of-a-supplicant-could-ever-be-ours.md).

## Where the association comes from

The planner needs to know which network a radio is on, and could not: the
resolved association existed only on the socket's `wifi status` reply, not in
`Observed`. `ObservedLink` gains a `network`, filled by the observation.

**From the supplicant's control socket, not from nl80211**, though nl80211
would be backend-independent and would work under iwd. Two reasons, and the
first is the one that decided it:

- **netcfgd already answers this exact question through this exact socket**,
  to serve `wifi status`. A second source can disagree with the first, and the
  disagreement would surface as a route metric that contradicts what the
  window says the machine is associated with -- a symptom nobody would trace
  back to having two association readers.
- **The cost is one command, not one connection.** `ask_supplicants` already
  opens these sockets every observation to check they answer, so the
  association is read on the connection that check already makes. Written as
  two passes first, which quietly doubled the connects per supplicant per
  cycle -- cheap, but paid on every observation forever, and for a fact the
  first connection was already in a position to carry.

The resolution rule itself -- SSID, or BSSID for a network identified by
address rather than by name -- moved into `netcfgd_model::wifi::network_for`
so that the socket and the observation share one copy rather than keeping two
that could drift.

**A backend that is not wpa_supplicant leaves the field absent**, and absent
means the interface's own preference stands. That is a graceful degradation
rather than a gap: under iwd the feature is inert and nothing else changes.
If iwd support becomes real, the fix is an association reader beside this one,
not a redesign -- `network_for` is already the shared half.

## What was not decided

**Whether a metric should also apply when the network is not associated.** It
cannot: the number describes routes that only exist while the machine is on
that network. Stated because it reads like an omission and is not.

**Whether an interface's `preference` should be expressible per network in the
other direction** -- a network saying "never carry the default route" rather
than a number. That is a policy question, not a ranking one, and nothing has
asked for it yet.
