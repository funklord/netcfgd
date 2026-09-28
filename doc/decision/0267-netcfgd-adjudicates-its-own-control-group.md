# 0267: netcfgd adjudicates its own control group

Status: accepted
Date: 2026-09-28
Milestone: M9; the C port

## What this decides

**At startup, before anything is adopted or applied, netcfgd reads its own
control group and says of each process it finds whether the previous run
recorded it.** One `NOTE` line and a line per process when everything is
accounted for; an `ERROR` naming each process that is not.

It signals nothing and stops nothing. 0177 decides when an orphan is
terminated and decides it per backend, with a marker and a reachability test.
This is a narrower instrument that reports and leaves.

## The problem, and why it is not the noise

`KillMode=process` is in the packaged unit deliberately (0134, 0142): a stop
leaves the supplicant, the DHCP client and the tunnels running, so an upgrade
does not take the network down. systemd reports that arrangement on every
start:

    netcfgd.service: Found left-over process 3061114 (dhcpcd) in control
      group while starting unit. Ignoring.
    netcfgd.service: This usually indicates unclean termination of a previous
      run, or service implementation deficiencies.

Both sentences are systemd's honest reading of what it sees and neither is true
here. **The cost is not that the lines are noisy. It is that they are also
exactly what a real unclean stop looks like.**

0177 paid for that once, on a real machine: netcfgd started beside an orphaned
supplicant of its own, systemd logged that same line, and the orphan and the
new supplicant deauthenticated each other until the association went -- taking
the address and the default route with it. The message was the available signal
and it is indistinguishable from the message printed every ordinary restart.

## Why the unit cannot fix it

Measured on systemd 257 with four throwaway user units, each started, stopped
and started again, counting the manager's own lines between journal cursors.
The control is the first row and it is what makes the rest readable:

    control: nothing survives      found-leftover=0   remains-running=0
    baseline: child survives       found-leftover=1   remains-running=1
    Delegate=yes                   found-leftover=1   remains-running=1
    Delegate=yes + sub-cgroup      found-leftover=1   remains-running=1

**No directive suppresses it, and the check recurses** -- a survivor moved into
a delegated sub-cgroup of the unit is found just the same. The only arrangement
that silences systemd is one where nothing of netcfgd's remains anywhere under
the unit's cgroup, which is precisely what `KillMode=process` exists to
prevent.

An earlier run of this matrix reported 8 warnings for every row including the
control. That was wrong and the control is what caught it: leftovers from one
trial were still in the cgroup when the next started, so each trial was partly
measuring its predecessor. The harness now refuses to run a trial that does not
start with an empty group, and the numbers above are from the version that
refuses.

## Why netcfgd can

systemd names a pid and cannot say whose it is. netcfgd can: it knows which
backends it started and it wrote their pid files, and 0177 turns on exactly
that distinction -- *"does netcfgd still have a record of it"*.

Three verdicts, and the middle one is the whole reason this is not a one-line
comparison:

    RECORDED      a pid the previous run wrote into a pid file under its run
                  directory
    HELPER        reached from a recorded pid by its parent chain
    UNACCOUNTED   neither

**HELPER exists because dhcpcd is four processes.** The client forks a
privileged proxy, a control proxy and a BPF helper; none of them appears in any
record anywhere, and all of them inherit the cgroup -- which `process.h` already
says in as many words. A classifier without the walk reports four unaccounted
processes on a healthy machine, which is the noise problem rebuilt one layer up.

**The walk follows parents only through processes that are in the control
group.** Init reparents an orphan, so every orphan's chain reaches pid 1; a walk
that followed it would judge a process by whatever pid 1 happens to be. It is
bounded as well, because the parent numbers come from `/proc` and two reads can
catch the table mid-change -- an unbounded loop here is a daemon that never
starts.

## Why it runs before the first pass

The question is what netcfgd *inherited*. Adoption is what turns an inherited
process back into netcfgd's, so a report taken after the first pass would call
every survivor accounted for and could never see the case this exists for.

## What it deliberately does not do

**It does not decide whether a pid file is telling the truth.** A pid file may
name a process that has gone, and pids are recycled. That does not matter here
and the reason is worth keeping: a recorded pid only ever reaches a verdict if
it is *also* in the control group, and a recycled pid that is in netcfgd's
control group is netcfgd's own child. The failure this could produce is
under-reporting, which is the safe direction for something that exists to raise
an alarm.

**It does not run where there is no service manager.** `ncfg_process_in_our_service`
answers false when netcfgd is run from a shell or under `unshare`, which is
every run of the live suite, so the report is silent there rather than wrong.

## The alternative, and whose it is

The other answer is to move the backends out of the unit's cgroup into
transient scopes, so the cgroup is empty at stop and systemd's warning becomes
meaningful again. It removes the noise at the source and this does not.

It was not taken, and not because it is worse. It needs netcfgd to ask systemd
over D-Bus to place each backend in a scope -- a systemd-only spawn path in a
daemon that also supports OpenRC, procd and sysvinit, and one the unit's own
header deliberately avoided when it declined `Type=notify` rather than link
libsystemd. It changes the process model for all six backend kinds and who
reaps them. That is a decision with its own record, not a change to make while
fixing a log line.

**The two compose rather than competing.** Even with scopes, systemd names a
pid without saying whose it is, and a process netcfgd forked and then lost
would still be in the cgroup -- which is the case this reports.

## What it cost

    binary        1145296 -> 1145832 bytes   (+536, inside the 3% tolerance)
    tests         c/tests/leftovers_test.c, 16 checks

The test drives the classifier over the table this machine actually produced on
2026-09-28 -- one supplicant, one dhcpcd and its three helpers -- and its last
case is the sabotage: the same table with the anchor's record removed must turn
four processes unaccounted. The walk was then deleted and the suite watched
failing exactly the four helper checks, through the check under test rather
than through anything upstream of it.
