# 0179: a stop netcfgd cannot make, and does not check

Status: accepted
Date: 2026-09-09
Milestone: M8; found on the reporting machine within a minute of giving two
wifi networks a `metric`, which is the first thing that ever made netcfgd stop
a DHCP client there

## The report

> set metric on both networks and switch to netcfgd

Both networks took a `metric`, the switch to netcfgd succeeded, and the route
kept the metric dhcpcd had chosen for itself:

    default via 10.0.0.1 proto dhcp src 10.0.125.56 metric 3003

`ncfg plan` said exactly what 0053 and the metric work promised it would:

    0  backend.stop wlp0s20f3  route.metric: 100 (was 3003)
    1  backend.start wlp0s20f3  route.metric: 100 (was 3003)

and the journal said what actually happened, twelve times a minute:

    netcfgd[...]: sending signal ALRM to pid 1354671
    netcfgd[...]: kill: Operation not permitted
    netcfgd[...]: netcfgd: adopted the dhcp client already running on
                  wlp0s20f3; it is netcfgd's, by the
                  `-f /run/netcfgd/dhcpcd/wlp0s20f3-4.conf` it recites

## Root is not enough

dhcpcd is built with PRIVSEP, and its main process runs as user `dhcpcd` --
which is the same fact the unit already carries `CAP_SYS_CHROOT`, `CAP_SETUID`
and `CAP_SETGID` for. **Signalling a process whose uid differs from the
sender's needs `CAP_KILL`**: being uid 0 is not a separate power, it is that
capability, and a bounding set that omits it withholds it from root as
completely as from anybody else.

Measured on the machine, both ways:

    # kill -0 1354671                       -> succeeds
    # capsh --drop=cap_kill -- -c 'kill -0 1354671'
    kill: (1354671) - Operation not permitted

`dhcpcd -4 -k <iface>` is a second dhcpcd that reads the pid file and signals
the first. It inherits netcfgd's set, so it inherits the refusal.

**This was never about the metric.** Every `backend.stop` for a DHCP client on
every systemd machine was a no-op: taking `dhcp` out of a `config`, switching
networks, `ncfg wifi disconnect`, a `restart_wedged`. The metric is only what
made netcfgd ask for one on a machine somebody was watching.

## Exit 1 cannot tell you which failure it is

The status of `dhcpcd -k` is deliberately not read, and 0070 says why: on a
machine whose client is udhcpc, "dhcpcd is not running" is the ordinary answer
and it is exit 1. That reasoning is still right, and it is also what let this
hide -- because "it is running and I may not signal it" is exit 1 too.

So the exit status cannot answer the question and **the control socket can**.
`confirm_dhcpcd_stopped` asks the same question the adoption asks (0143): is
there a dhcpcd out there reciting the `-f` netcfgd started it with? If there
still is after three seconds, the stop failed and says so, naming the
capability. A dhcpcd holding somebody else's config file is not this stop's to
account for and is left to 0141.

## Why a failed stop became a loop rather than an error

The start that follows a stop adopts a client that is still running -- which is
0143 working exactly as intended. The observation then reports the backend as
up, so the restart counter that bounds a restart is cleared as "stayed up"
(0079), and the next reconcile makes the same plan five seconds later. Three
correct mechanisms composing into a permanent loop that reports success at
every step, which is the same shape 0140's trap had.

**The bound that survives is the report, not the counter.** A stop that returns
an error stops the pair being called a success, and it puts one line in the
journal that names the cause instead of 78 that name nothing.

## What is checked

* `tests/live/sandbox_writes.sh` imposes the unit's own
  `CapabilityBoundingSet=` and `AmbientCapabilities=` on a transient unit and
  requires that a child can signal a process running as another uid -- with the
  control that matters: the same probe under the same set with `CAP_KILL`
  removed has to fail. Taking the capability out of the unit turns the check
  red.
* `tests/live/dhcpcd.sh` runs the real stop under `capsh --drop=cap_kill`
  against a dhcpcd that has genuinely dropped privileges -- the skips at the top
  of that script exist to guarantee it has -- and requires netcfgd to refuse to
  call it stopped, and the client to still be there afterwards. Removing
  `confirm_dhcpcd_stopped` turns the first of those red while the second stays
  green, which is the two of them measuring different things.

## The general lesson, which is 0176's and 0178's again

**A sandbox withholds capabilities from root silently, and the program's own
report of success is written before anything checks.** Three faults in three
days with one shape: `ProtectSystem=full` making a grant inert (0176), `/run`
`noexec` making a hook unrunnable (0178), and now a bounding set making a
signal impossible. In all three netcfgd said it had done the thing, and in all
three the tests passed because they ran the code without the sandbox that
breaks it.

The countermeasure is the one this file has now used three times: **have the
test ask systemd to impose the unit's own parsed properties**, and pair every
grant with a control that fails without it.
