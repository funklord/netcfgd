# 0202: a station cannot be a bridge port

Status: accepted
Date: 2026-09-11
Milestone: M8; the wifi bridge and VLAN audit

## What was already right

The bridge and VLAN machinery is applied rather than accepted: `stp`,
`forward_delay`, `hello_time`, `ageing_time` and `vlan_filtering` all reach the
kernel, and per-port VLANs on a bridge without `vlan_filtering = true` is a
real error naming its own cause rather than a silent no-op. None of that is
changed here.

## A radio joining networks in a bridge

netcfgd planned it like any other member:

```text
0  link.create br0  kind: bridge (was <absent>)
1  link.set_master eth0  master: br0 (was <absent>)
3  link.set_master wlan0  master: br0 (was <absent>)
```

with no warning. **The kernel accepts it and the radio cannot carry it.**

The reason is the frame format rather than anything netcfgd or the kernel does.
A station associates in 802.11's three-address mode, where a frame carries the
access point, the sender and the destination and has nowhere to say "this came
from somewhere behind me". A frame the bridge forwards from another port
arrives at the access point sourced from an address that never associated, and
is dropped. Four-address mode (WDS) is what carries it and both ends must agree
on it; where that is not available the answer is to route or NAT between the
radio and the bridge rather than to bridge at all.

So the bridge comes up, looks configured, and moves nothing across the wifi --
which is the shape of every fault in this audit's neighbourhood: each operation
succeeds and the outcome does not exist.

**An access point is the opposite case and must not be warned about.** Bridging
a hostapd radio into a LAN is the ordinary way to put wireless clients on the
same subnet as the wired ones, and there the radio holds the associations. The
planner already knew the difference: `radios` is the interfaces that are
actually wireless and netcfgd manages, and an `access_point` naming the device
is what makes it the serving end.

## The warning from 0201 was wrong about exactly this

0201 added "an access point with no address serves nobody", and a bridged
access point **has** no address -- the bridge holds it, which is correct and
usual. That warning therefore called the right arrangement broken, and it was
committed and installed before this audit found it.

It is the same fault the warning is about, made by the warning: **a true
statement about one interface offered as a verdict on the whole.** An hour
between shipping it and catching it, and it was caught only because the next
audit happened to be about bridges.

Fixed by asking whether the device is a bridge member before asking whether it
is addressed, and both directions are now checks rather than an argument.

## What is not claimed

hostapd's own `bridge=` is never set by netcfgd. netcfgd enslaves the interface
itself, which is enough for the ordinary case, and `bridge=` additionally
matters for `wds_bridge` and per-station VLAN -- neither of which netcfgd
offers. **Not asserted as a fault here**, because it was not reproduced: there
is no radio in this suite to reproduce it on, and a decision recording a
suspicion as a finding is worse than one that says where it stopped.

## Verification

Four checks in `ap.sh`, staged through `NCFG_SYS_CLASS_NET` -- a `wireless`
directory is the whole of what makes an interface a radio to netcfgd, which is
what lets this run without one.

The bridged access point is checked first and twice: not told it has no
address, and not told a station cannot bridge, because it is not one. Then the
same configuration with the `access_point` block deleted, which turns the same
radio into a station and must be warned, and must be told what does carry it.

Sabotage: removing the station warning takes the two station checks red;
removing the bridge exemption restores the 0201 false positive and takes the
first check red, which is the regression this decision is half about.

## And a third fault, in the gate that caught the second

`probe_gate.py` refused the new test with "backgrounds a daemon and never reads
`$!`". It was wrong. The line ends in `&&` -- a continuation -- and the gate
tested `endswith("&")`, which `&&` satisfies; it matched because the *path* in
the line contained `netcfgd`. A line that starts nothing was read as starting a
daemon.

Fixed in the gate rather than worked around in the script, since rewording the
line would leave it mis-firing for whoever meets it next.

**Both attempts to prove the fix had not blunted it were invalid**, which is
worth writing down because each looked fine:

- appending a backgrounded command to `ap.sh` changed nothing, because that
  file already reads `$!` elsewhere, so the condition the gate failed on was
  never reached;
- exercising the predicate directly, the first case asserted that
  `"$ncfg" plan &` should match. It should not: `ncfg` is the client and
  `DAEMONS` is about daemons. The gate was right and the expectation was wrong.

The predicate now passes seven cases: two real backgrounded daemons match, and
the client, a `&&` continuation whose path says `netcfgd`, a `&&` mid-line, a
comment and a backgrounded non-daemon do not.
