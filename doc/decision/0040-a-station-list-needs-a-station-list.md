# 0040: A station list needs a station list

Status: accepted
Date: 2026-07-31
Milestone: completes what 0039 started

## Context

Decision 0039 gave an access point a deny list. That is half a feature: the
operation an operator actually wants is "that one, off this access point", and
the addresses in an `access_control` block have to come from somewhere. Typing
a MAC address from memory is not a workflow.

So netcfgd reads back who is associated, and shows it.

## A live query, not an observation

`ApStations` sits beside `WifiScan` and `WifiStatus` rather than becoming a
field of `Observed`.

There is no desired station list to reconcile against -- who associates is
decided by people walking around with laptops -- so a station in the
observation would be state the planner could come to depend on. A plan that
changes with who is in the building is not a plan. Keeping it out also keeps
the cost off the reconcile loop: the walk is a round trip per station, and the
reconcile loop runs on every netlink event.

## The tier is Observe, and what that exposes is worth naming

A station list is other people's hardware addresses and how strong their signal
is, which is a proximity sensor. That is not the same kind of reading as "what
addresses does eth0 have", even though both are reading.

It is `Observe` anyway, because the alternative is worse in both directions. A
monitoring display is the thing this feature is *for*, and a tier that could
change the network in order to see it is decision 0013's "Admin wearing a hat".
A separate tier would be more precise and would add a principal to the model
for one verb.

Under the default policy `observe` is root. A site that opens it to `any` is
opening this too, and the exposure is written into `tier_of` where somebody
making that change will read it.

## What hostapd will and will not say

Read out of hostapd 2.10's `src/ap/ctrl_iface_ap.c` rather than from its
documentation, which changed the implementation in two places:

- **Every field except the address is optional.** `hostapd_get_sta_info`
  writes nothing at all when `hostapd_drv_read_sta_data` fails, so a station
  with no `signal=`, no `rx_bytes=` and no `connected_time=` is a normal reply.
  A parser that required them would drop a client that is really there, which
  is the worst way for this feature to be wrong. The CLI shows dashes.
- **The walk ends on an empty reply.** `hostapd_ctrl_iface_sta_mib` returns
  zero bytes for a null station, so `STA-FIRST` with nobody associated and
  `STA-NEXT <last>` at the end of the list are the same answer. `FAIL` is the
  third ending, for an address hostapd does not know.

There is **no hostname**. hostapd knows hardware addresses; a friendly name
would have to come from DHCP leases, and netcfgd runs no DHCP server. Showing
a MAC and calling it a client is honest; inventing a name is not.

The walk is bounded at 2007 iterations rather than looping until the reply
stops. hostapd terminates its own list correctly, but this is one daemon
reading another's answers, and a reply echoing an address back unchanged would
spin forever. 2007 is hostapd's own `aid` space, so a longer list is hostapd
misbehaving.

## The two halves, shown as one thing

The report carries the access point's ACL policy, and each station carries
whether the list names it. That combination is the point rather than a
convenience: under `deny`, a station that is listed **and connected** means
hostapd read the list once at startup and was never told it changed. The CLI
marks it with an arrow and says so; the TUI marks it `!`.

This is 0039's open gap made visible instead of silent. Until the ACL is
converged over the control socket, an operator editing a deny list has no way
to know it is not in force -- and a deny list that looks applied and is not is
worse than no deny list.

## The radio is faked and the protocol is not

`tests/live/ap.sh` drives a real hostapd, which is what proves netcfgd
generates a file it accepts. It cannot go further: a hostapd with no radio has
no clients.

So `fake_hostapd.py` answers the walk with replies copied from hostapd's
source, the same trade `fake_supplicant.py` already makes and for the same
reason -- the one thing this repository cannot produce on demand is a radio.
`tests/live/stations.sh` then checks the half ap.sh cannot reach. Driving a
real association needs `mac80211_hwsim`, which needs real root, which is what
`tests/live/hwsim.sh` is for.

## Two things this found on the way

**The TUI's wifi pane has never worked.** It read `entries` from the scan
response; the field is `access_points`, and always was. Every scan rendered as
"(no scan; press r to rescan)" from the commit that added the TUI. Nothing
caught it because `tests/live/tui.py` asserts that pressing `w` shows "no
scan", which the bug satisfied perfectly. Fixed, with a unit test that reads
the field the daemon actually sends and a proto test pinning the wire shape.

**The RSS gate was about to fail on noise.** Five runs of an identical binary
spanned 7464..7736 KB before this change and 7588..8168 after, against a limit
of 8192 -- a ~600 KB noise band with peaks landing 24 KB under the ceiling.
The feature accounts for about 250 KB of the mean; the rest is that nothing had
re-measured since the comment saying "measured at 5400 KB". Raised to 9216 with
the measurements written down, because a gate that goes red on spread rather
than on regression teaches people to re-run the build.
