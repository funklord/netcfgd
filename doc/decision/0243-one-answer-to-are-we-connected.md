# 0243: one answer to "are we connected"

Status: accepted
Date: 2026-09-15
Milestone: M9; the connectivity verdict

## The question

> Do we have a main status of "connected/not connected"? And a string of what
> we are "mainly" connected to? This should probably be configurable and act as
> the main source for something like a singular standard systray icon.

No. `Request::Status` returns the raw observation and no verdict, so every
client invented one:

| where | vocabulary |
|---|---|
| `gui/src/tray.cpp` | `ncfg_reach` -- routed / local / offline |
| `adapter/netcfgd-tde/ncfg_tde_connection.cpp` | the same, transcribed into TQt3 |
| `adapter/netcfgd-nm/src/state.rs` | `any_connected()` -> `CONNECTED_GLOBAL` |
| the text interface | nothing at all |

**0146 already decided what the rungs mean.** What it did not decide was where
they are computed, and four copies drifted -- which is the argument
`wifi::network_for` makes for living in the model, "here rather than in either
caller, because there are two", with four callers in three languages.

## Three faults the copies were hiding

**The shim was not a fourth copy of the rule, it was a weaker one.**
`any_connected` asked whether any link was up, had carrier and held a
non-link-local address. No route anywhere in it -- which is the exact claim 0146
removed from the tray, still live on the D-Bus surface every desktop reads. A
machine that fails every request was being announced as `CONNECTED_GLOBAL`.

**Both trays counted interfaces that are administratively down.** The wired path
skipped `lo` and nothing else, so a wired-only machine with docker installed and
no network at all drew the amber "locally connected" icon and named a bridge to
nowhere. Measured on the reporting machine, where `docker0` is down and holds
`172.17.0.1/16`.

**None of them consulted the probe.** `ObservedLink::reachable` is netcfgd's own
verdict on whether traffic actually arrives, and a captive portal read as
connected in all four -- including the shim, whose comment says it cannot tell
the difference. Where a probe is configured, it can.

## What replaced them

`netcfgd_model::connectivity::overall` returns both halves the report asked
for: a rung, and the link it got there through.

**Four rungs, not a boolean.** `Offline`, `Local`, `Routed`, `Online` --
0146's three, plus the one a probe can establish. `connected()` is derived from
them in one place, because collapsing them per caller is how the middle rung got
lost the first time. The middle rung exists because it was once reported as
connected: a machine holding an address with nothing to route through fails
every request while looking configured.

**The primary is the lowest-metric default route**, and its label is the
`network` block's id where the link is an associated radio, the interface's own
name otherwise. The Qt tray deliberately declined to pick a link -- "which one
carries the traffic is the kernel's business and a metric's" -- which is right
for an icon and insufficient for a string. The metric is the principled
tiebreak and netcfgd already owns it.

**Configurable as `global { connectivity { requires, ignore } }`.** `requires`
is `route` (the default), `probe` (for a captive portal), or `address` (for a
machine whose job is its own subnet). `ignore` is which links never count.

## The default group is every link except the absurd ones

`ignore` defaults to `docker*`, `br-*`, `veth*`, `virbr*`, `vnet*`, with a
trailing `*` meaning a prefix and nothing else meaning anything -- this is a
short list of families, not a matching language. `lo` is hardcoded and not in
the list, because it is not a policy question.

**What is absent matters as much.** WireGuard, `tun` and `tap` are not excluded:
a laptop whose real uplink is a VPN is ordinary, and excluding them by default
would be netcfgd deciding somebody's network for them. Writing `ignore`
**replaces** the default rather than adding to it, so an operator who needs one
of these families counted can have it.

A bare `*` is refused rather than honoured. A document that ignores every link
is asking for a verdict that cannot be computed, and answering "offline" for
ever is the worst way to tell it so.

## A sabotage that passed because an earlier assertion stopped being one

Six sabotages, five caught. The sixth is a variant worth naming.

`Policy::counts` requires a link to be `up`, and the test covering it used
`docker0` -- which was the reporting machine's real example. Then the default
ignore list gained `docker*`, and from that moment the assertion was carried by
the *name* rather than by the `up` check: removing `link.up` entirely changed
nothing and the test passed.

**Not a missing test. A test that stopped testing what it said, because
something else changed.** Nothing announces that: it still passes, it still
reads as though it covers the rule, and only a sabotage aimed at that exact
line finds out. The fix is an interface the ignore list says nothing about --
a down `eth1` holding a stale address, which is the case that would report a
machine locally connected.

Worth separating from the nine first-run passes before it. Those were fixes that
went in with nothing holding them. This was a fix that *had* something holding
it, until a later change in the same session quietly took it away.

## The grouping this is the first piece of

Discussed while this was being built, and recorded because the shape of what is
here was chosen to fit it rather than to be redone.

**The generic thing is a `linkset`**: a named set of links, exactly one in use
at a time, chosen on probe and metric. Several coexist, each reaching a
different network. This is ordinary failover and redundancy; what netcfgd offers
is that it is scripted and visualised rather than automation-first.

**`uplink` is a `linkset` with more assumptions** -- it carries the default
route, there is at most one, and it is what `connected` refers to. The word is
already the tree's: 114 occurrences across the docs and source, in ten decision
records, always meaning this.

**The list is self-referential: a linkset is itself a link.** That composes --
a linkset can be a bond member, or a member of another linkset -- and it means
being a group should usually disable a link from ordinary link operations,
with exceptions. The consequence for what is here, recorded so it is not
rediscovered: `overall` must not count both a group and its active member, since
both would hold the default route. The group is what counts and the members are
behind it.

What exists today is the reporting half of the default linkset, unnamed. The
acting half -- bringing one member down, depreferring the others -- is the work,
and it is a separate round.

## The TDE tray keeps its own words, and only its verdict moved

Worth recording because it was nearly done the other way. That file was being
written by a second session while this was being built -- its
`adapter/tde: report reachability` landed forty minutes into this round, adding
120 lines that make `state_line` derive the three rungs, for the same reason
this decision exists and by transcribing the Qt tray's reading.

Replacing that function wholesale, as the first attempt did, removed 95 of those
lines -- including a tooltip richer than anything here: the wired path names the
interfaces and their addresses, the radio path gives the supplicant's own state,
the network and the block it came from. **That is a trade nobody asked for**: a
gain in correctness paid for with a loss in what the operator reads, made
unilaterally on somebody else's work an hour after they wrote it.

So the edit is additive instead. `daemon_reach` takes the rung the caller
derived and returns the daemon's, and the two call sites pass their own answer
through it. The verdict is centralised, which is the whole point; the words stay
where they were written.

**It is also the one place the old derivation is kept**, deliberately, as the
fallback for a netcfgd older than the tray -- these are separate packages.
Reporting the previous answer beats reporting none. It is a compatibility path
and not a second opinion, and it is marked as such where it lives.

## Not done

The text interface still shows no verdict. It has the client API now and is the
cheapest of the four to convert; it was left because it never had one to be
wrong.
