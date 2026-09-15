# 0241: the lease that was taken and thrown away

Status: accepted
Date: 2026-09-15
Milestone: M9; wakeup latency

## Reported

> on wakeup we need to be faster in detecting that networks have changed, it
> took almost 30 seconds

Measured on the reporting machine rather than reasoned about, from the journal
of the resume at 11:03:49 on 2026-09-15, where it moved from `OpenPC.se`
(`metric = 100`) to `EMP-XYLEM` (`metric = 200`):

```text
11:03:49.38  resume; carrier lost, routes deleted
11:03:51.66  associated to EMP-XYLEM; carrier acquired        +2.3s
11:03:52.42  dhcpcd rebinding 10.78.60.134
11:03:52.48  probing address 10.78.60.134/22
11:03:57.83  leased, routes added, metric 100                 +8.5s
11:03:57.85  netcfgd stops that client and starts another     +8.5s
11:03:58.38  soliciting a DHCP lease
11:03:58.56  probing address 10.78.60.134/22
11:04:04.12  leased, routes added                            +14.7s
11:04:08.10  netcfgd logs `joined a0:a4:7f:23:6a:6f`          +18.7s
```

**Nineteen milliseconds.** That is the gap between the client succeeding and
netcfgd killing it. The whole of 52.4 to 57.8 -- a rebind, an offer and an ARP
probe -- was done, thrown away, and done again.

Two separate faults, and neither is the suspend.

## The trigger was the one thing that cannot exist yet

`restart_for_metric` is right about what it is for. netcfgd passes the route
metric to the DHCP client once, as `-m`, and the client installs the lease's
default route with it -- so a radio that moves to a network asking for a
different metric keeps the old one, and the client has to be replaced. Its own
documentation explains why it compares the route:

```quote from=crates/netcfgd-plan/src/lib.rs
Compared against the route rather than against a record, because the route is
what the metric is for and is already observed. A record of what the client was
started with would be a second thing to keep true
```

That reasoning is sound and the conclusion it reaches is late. **The route
cannot exist until the exchange that installs it has finished**, so the one
signal netcfgd watched was guaranteed to arrive only after the expensive thing
had already happened. The cost is not a constant: it is however long a DHCP
exchange takes, doubled, every time a radio moves between networks whose metrics
differ.

### The first way out did not work, and the machine said so in one command

The draft asked the client. **The running client says what it was started
with, in its own `/proc/<pid>/cmdline`** -- the process describing itself rather
than netcfgd remembering, which is the distinction 10.131 is about and looked
like the right side of it. netcfgd already reads `cmdline` for this kind of
question: `pid_by_marker` finds a supplicant by the mark in its `argv` because a
pid file is "an index into a fact rather than the fact itself".

**dhcpcd rewrites its command line.** Every one of its processes reads
`dhcpcd: <iface> [ip4]` within moments of starting, and nothing netcfgd passed
survives there. Measured on the reporting machine: no dhcpcd carries `-m` in its
`argv` at all. The reader would have returned `None` for every client on every
machine, the planner would have fallen back to the route, and the whole change
would have been inert -- while looking exactly like a tree with no fault in it.

It was written, it passed unit tests against a directory, `make check` was
green, and it was one command away from being installed. What caught it was
checking the live machine before the install, because the one thing that could
disturb it was netcfgd deciding the running client had the wrong metric.

**And the tree already said so**, in `backend_pid_file`, about these two clients
and no others:

```quote from=crates/netcfgd-apply/src/kernel.rs
The interface name is the weakest marker netcfgd uses and is what these two
clients give it -- neither is invoked with a path netcfgd chose that ends up in
its command line.
```

That is the campaign's own shape, committed by the person auditing for it: **a
proxy for the real question**, where "what is in `/proc/<pid>/cmdline`" stood in
for "what was this process started with", true of a supplicant and false here.
The evidence was in the repository and went unread.

### What it is instead

The record netcfgd already keeps for its other backends. `started_with` reads a
running access point's settings back out of the configuration netcfgd rendered
for it, and `read_advertised` does the same for radvd, both on the stated
grounds that the file netcfgd wrote is its account of what it started the daemon
with.

A DHCP client gets the same, with one difference that matters: it is written on
the path that actually spawns a client and nowhere else. Those two read back a
*rendered configuration*, which an apply may rewrite without restarting
anything -- so the record could drift into agreeing with a document the running
client never saw, and the comparison would be vacuous exactly when it mattered.
`<run>/dhcpcd/<iface>.metric` is written after the spawn succeeds and removed
when the network asks for no metric.

**Both signals, not one**: the record says what the client was *told* and is
there at once; the route says what it *did* and is the only way to see a client
that ignored `-m`. Neither subsumes the other, and `RESTART_LIMIT` bounds them
together on the counter it already used.

**One function builds the path for both sides**, rather than two that a test
proves agree. A silent absence is this record's failure mode -- it is precisely
what the first draft produced -- and a writer and reader that could disagree
would produce it again.

## The other eighteen seconds were the event burst

`joined a0:a4:7f:23:6a:6f` is logged at 11:04:08.10 for an event the supplicant
emitted at 11:03:51.66 -- **16.4 seconds late**. That is 0240's defect, seen in
the wild: the watcher took one event per pass, a resume produces a burst of
thirty or more, and `p2p-dev-wlp0s20f3` sitting quiet in the control directory
made every pass wait out its timeout. Four events a second through a burst.

Already fixed and installed; this record names it because the journal above is
the first measurement of what it cost on real hardware rather than on simulated
radios.

## What was not wrong

**Nothing needs to detect the suspend.** netcfgd was awake and reconciling the
whole time -- it acted nineteen milliseconds after the route appeared, which is
not the behaviour of a daemon that had not noticed. The netlink socket delivers
the carrier change at 51.66 and the loop's own tick is five seconds, so the
observation was never more than that behind. A `PrepareForSleep` subscription or
a `CLOCK_BOOTTIME` jump detector would have added a dependency and bought
nothing: the loop was not asleep, it was waiting for a route.

Worth writing down because it was the first thing to reach for and it was wrong.

## Checked against a real client, not only a directory

`hwsim.sh` gives its first network a metric so there is an `-m` to record, and
asserts two things after the lease: that the record is there and says 300, and
that the route the client installed carries 300. The second is not decoration --
a record of a metric the client ignored would be worse than no record.

Removing the write makes the first fail and leaves the second passing, which is
the shape a reader should expect: the client did the right thing and netcfgd
forgot what it had asked for.

The first version of this check was in the wrong place entirely -- the preference
phase, where the supplicant restart has taken the DHCP client with it and there
is no client and no route at all. It failed, and the diagnostic it printed said
so in one line. Moved rather than argued with.

## Nothing tested this rule, in either direction

`restart_for_metric` had no test. Neither did the metric comparison it exists
for. Two now, and a third case inside the second:

- a client whose `argv` names another network's metric is replaced with no route
  installed at all;
- one whose `argv` names this network's metric is left alone;
- one whose metric netcfgd cannot read is *also* left alone -- "cannot tell" is
  not "wrong", and reading it as wrong would restart every DHCP client on every
  machine five times and then warn about it.

**And the first version's third case passed a sabotage.** The rule was written
as a `bool`, and the caller reached back for the number with
`unwrap_or(wanted)`; breaking the explicit `is_some_and` still left the
`unwrap_or` producing the right answer. The unreadable case was handled twice,
once on purpose and once by accident, and the test could not tell which was
holding it. Rewritten to return the offending metric, so there is one
expression and no second way to spell "nothing to report" -- after which all
three sabotages fail as they should.

That is the tenth first-run sabotage pass of this campaign, and the second in a
row where what it corrected was the shape of the code rather than a missing
assertion.

## The harness could not have seen this either

`started_backend` in `netcfgd-plan`'s fixtures builds the observed side from the
document, and the warning at the head of that function is about exactly this
trap. Setting `started_metric` from the document's metric would make the
comparison agree by construction, which is how 0222's channel defect stayed
invisible before and after it was fixed. It is `None` there -- "netcfgd cannot
tell", which plans no restart and is a converged machine -- and the two tests
that care about the mismatch state a value.

The schema witness does carry one, on the DHCP kind and nowhere else, for the
reason the access-control block is set on the access point and nowhere else: an
`Option` left empty in every sample pins nothing, and the field could be renamed
without the schema moving. Additive, so a minor bump.

## What this does not fix

The supplicant's own 2.3 seconds to reassociate after resume. That is
`wpa_supplicant` scanning and authenticating -- on this network a full PEAP
exchange with the authentication server -- and netcfgd has no part in it.
`okc` (0228) is meant to make the second such exchange cheaper, and 0240 records
that the first radio ever asked refused the PMKID with status 53.
