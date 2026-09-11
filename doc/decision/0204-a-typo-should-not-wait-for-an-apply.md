# 0204: a typo should not wait for an apply

Status: accepted
Date: 2026-09-11
Milestone: M8; the wifi regulatory domain and channel audit

## What is right, and it is the hard part

The channel logic is careful and its reasoning is written where it is done.
`band` decides when present, the channel decides when it is not, and a channel
in neither band is refused rather than passed to hostapd to fail on later --
"inferring and skipping the check is how channel 20 would have become
`hw_mode=a`, which is a band it is not in".

**The 5 GHz list is a range rather than the exact set, on purpose**: which
channels are usable is a regulatory question the kernel answers, and 149 is
legal in one country and not the next. What netcfgd rejects is a number that is
in no band at all, which is a typo rather than a regulatory refusal. That line
is drawn in the right place and this audit does not move it.

`regdom` on an access point becomes `country_code` and `ieee80211d=1`, checked
against a real hostapd in `ap.sh`. `regdom` on a *device* is understood and not
acted on, and the planner says so.

## The fault: both were checked too late

`band` and `regdom` were `as_string` in the compiler -- any text compiled -- and
the renderer decided. The renderer's messages are good:

```text
`5g` is not a band this build knows. Use "2.4" or "5", or leave `band` out
and let the channel number say which
`Sweden` is not a regulatory domain; it is an ISO 3166-1 alpha-2 country
code, such as "SE"
```

but it said them at **apply**, by which time the interface is up and the
operator is reading a failed action rather than a config diagnostic:

```text
ok   link.up ap0  enabled: true (was false)
FAIL backend.start ap0  access_point: AccessPoint (was <absent>)
ncfg: stopped at action 2 (backend.start); 2 done, 1 not attempted
```

**And `netcfgd.conf.example` said `band = "5g"`.** The documented access point
could not be started. Compiling the block found nothing and planning it found
nothing, which is the fourth fault in that file this run.

Both checks moved to the compiler, where every other closed set is checked. The
renderer keeps its own, because it is reachable from a document that did not
come through this compiler.

**`6` is accepted by the compiler and refused by the renderer**, deliberately.
"Not a band" and "a band this build cannot do" are different answers and the
second must stay distinguishable from the first.

## What this did to the gate

0200's gate compiles each block of the example. A render-time refusal was
invisible to it, which is why it passed a file telling people to write `5g` --
the second blind spot found in it, after "valid and inert" in 0201.

Moving the check converted that class into one the gate catches. Restoring
`"5g"` now fails it by file, line and diagnostic:

```text
example-gate: doc/netcfgd.conf.example:532: access_point "Home" {
example-gate:   netcfgd.conf:4:2: `5g` is not a band
```

That is the more useful half of this decision. A gate gets better by moving
checks into its reach, not only by widening the gate.

## Verification

A compile test asserting both refusals name what is wrong *and* what is right
-- "2.4" and "5" for the band, "alpha-2" for the domain -- and that the
accepted values still compile, which is the half that stops a check from
refusing everything. `6` is in that list for the reason above.

Sabotage: making the band arm accept anything takes it red.

Scripted before committing this time, rather than after, which 0203 had to be
written about.
