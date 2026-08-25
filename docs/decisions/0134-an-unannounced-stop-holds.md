# 0134: an unannounced stop holds

Status: accepted
Date: 2026-08-25
Milestone: not scheduled; settles one question inside a feature still to be
designed

Decided by the copyright holder ahead of the implementation, which is the point
of recording it now: this is the question that shapes the rest of the design,
and answering it late means answering it under pressure from whatever has
already been built.

## Context

netcfgd is to become updatable without tearing down what runs underneath it --
the case named being a VPN over wifi, several layers deep. The requirement and
its measurements are in `project.md` section 10; this record settles one
question out of it.

Stopping splits three ways, and only two of them can announce themselves:

| how netcfgd stops | announced? |
|---|---|
| package upgrade, deliberate restart | yes -- dpkg passes the reason, an operator can say so |
| deliberate removal, an operator stopping it for good | yes -- `prerm` already acts on `remove` and `deconfigure` |
| a crash, an OOM kill, a `kill -9`, a power-loss reboot | **never** |

The third row is the one that needs a default, and it takes the second row with
it whenever somebody stops the daemon without going through whatever channel
gets designed.

## Decision

**An unannounced stop holds.** netcfgd leaves the network exactly as it is, and
the copy that starts next adopts what it finds rather than rebuilding it.

Releasing -- tearing down links, addresses, routes and backends -- happens only
when something says so.

## Why, and the argument is asymmetry rather than preference

**The two failure modes are not the same size.**

Hold when release was wanted leaves a machine configured with nobody managing
it. That is visible, recoverable, and fixable by the operator at their leisure:
the configuration is still described by files under `/etc/netcfgd`, and
starting netcfgd again puts it back in charge.

Release when hold was wanted takes the network down -- **including, in the case
that motivated this, the connection the operator would have used to put it
back.** A VPN over wifi is very often how somebody is reaching the machine at
all. That failure is not recoverable remotely, and on an embedded target with
no console it is not recoverable at all.

**A crash must not take the network with it.** This is the strongest form of
the argument and it decides the matter on its own. A daemon that tears down on
exit converts every one of its own bugs into an outage, which is precisely
backwards: the whole value of a configuration daemon that has already done its
work is that the work survives the daemon. Since a crash cannot announce
itself, the unannounced default *is* the crash behaviour, and there is no
version of "release on crash" worth having.

**It matches what the tree already does**, which is worth saying because it
means this decision costs nothing to adopt today. No `SIGTERM` teardown exists
in the daemon and no `ExecStop` exists in the unit, so killing netcfgd already
leaves everything up. What changes is that this stops being an absence of code
and becomes a property with a reason, which is what lets a test assert it and
stops a future graceful-shutdown patch from removing it by accident.

**And the packaging already agrees.** `prerm` stops the service for `remove`
and `deconfigure` only, under a header saying that pulling a package is not an
instruction to take the network away. That is the same judgement, made earlier
and in a smaller place.

## What this does not decide

**It is not a licence to skip reconciliation.** Adopting state on startup means
not *rebuilding* what is already correct; it does not mean not checking.
[0132](0132-netcfgd-applies-its-configuration.md) stands unchanged -- netcfgd
applies its configuration, and re-applies a setting that has deviated. A daemon
that adopts a link and then never looks at it again has replaced one failure
with another.

**It does not say how an announcement is made.** Control socket request, an
argument to a stop path, a file in `/run` -- all still open, and all still
wanted, because a deliberate final stop should be able to say so.

**It does not resolve the `/run` question.** Constraint 1 declares runtime
state derived and disposable, and adoption makes it load-bearing across a
restart. `RuntimeDirectory=netcfgd` currently has no
`RuntimeDirectoryPreserve=`, so systemd deletes it on stop. Holding the
*network* does not help if netcfgd cannot tell which parts of it are its own,
and that is the next question rather than this one.

## Consequences

**"netcfgd is not running" stops implying "the network is unconfigured".** Any
documentation, diagnostic or test that reasons from the daemon's absence to the
network's state is now wrong, and that reasoning should be looked for rather
than waited for.

**Ownership becomes the thing that must survive, not the configuration.** The
configuration survives by not being touched. What a restarted netcfgd needs is
the record of what it created, which is exactly what `/run` holds and exactly
what a restart currently deletes.

**Teardown becomes an explicit act with a name.** Whatever channel is designed,
it is now the only way to get a release, which makes it reviewable -- one place
that can take the network down, rather than an exit path that always could.

## Alternatives considered

**Release by default, hold when told.** Rejected on the asymmetry above. It
also has the property that the safe behaviour requires somebody to remember
something, and the dangerous behaviour is what happens when they do not.

**Infer the intent from the signal -- hold on `SIGTERM`, release on
`SIGQUIT`.** Rejected. It reads as a design and is a guess wearing one: the
sender's intent is not encoded in which signal init happened to send, an OOM
kill and a crash carry no signal netcfgd can catch at all, and it would make
`systemctl stop` and a supervisor's timeout mean different things for reasons
nobody could see from the outside.

**Leave it undecided until the feature is built.** Rejected because this
question shapes the rest of it. Whether ownership records must survive a
restart, whether the unit needs `RuntimeDirectoryPreserve=`, and whether a
teardown path exists at all are all downstream of it, and a design that settles
them first will have answered this one by implication without anybody noticing.
