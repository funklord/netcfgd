# 0198: two faults that were cancelling out

Status: accepted
Date: 2026-09-10
Milestone: M8; found in the log of a switch that otherwise worked

## What the machine said

netcfgd was selected, joined `OpenPC.se`, took a lease, and then:

```text
dhcpcd (pid 2538344) keeps rewriting resolv.conf and is run by a service
manager, so netcfgd is not signalling it
  a killed service is restarted; stand it down with Conflicts= -- see
  packaging/systemd/netcfgd-exclusive.conf
resolv.conf has been taken back 3 times and netcfgd found nothing it could signal
```

netcfgd declining to signal a process **it had started itself**, and advising
the operator to stand it down with `Conflicts=`.

## The first fault

```rust
pub fn is_service_supervised(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .is_ok_and(|text| text.lines().any(|line| line.contains(".service")))
}
```

The guard exists so netcfgd does not fight *another* supervisor: a killed
`systemd-resolved` comes straight back, and the answer for those is
`Conflicts=` rather than a signal. But every process netcfgd spawns inherits
netcfgd's own cgroup, and netcfgd's own cgroup is
`0::/system.slice/netcfgd.service` -- which contains `.service`. So the test
answered "yes, a service manager runs it" about netcfgd's own child.

Asking *whose* service rather than *any* service is the fix, and it is a
one-line change of question.

## The second fault, which the first was hiding

`sweep` already skips netcfgd's own processes, before it ever reaches the
supervision check:

```rust
if mine.contains(&pid) { continue; }
```

`ours()` builds that set from pid files under netcfgd's own run directory. On
the reporting machine:

```text
/run/dhcpcd/wlp0s20f3-4.pid           <- dhcpcd's, where netcfgd does not look
/run/netcfgd/supplicant/wlp0s20f3.pid <- the only pid netcfgd knows
```

**dhcpcd writes its pid file to its own run directory**, so netcfgd's DHCP
client was never in `ours()` at all, and the sweep had been treating it as a
foreign writer since the sweep was written. The only reason that never cost
anything is that the broken supervision check said "leave it alone" -- for
entirely the wrong reason.

**Fixing either one alone makes netcfgd terminate the client holding this
machine's lease.** `resolv_defended.sh`'s own header calls that "the worst
outcome available". Two faults, each harmless only while the other stood.

## Both halves, and they have to stay exclusive

`in_our_service(pid)` is a positive identification of netcfgd's own children,
and the cgroup answers where a pid file cannot: dhcpcd forks a privileged
proxy, a control proxy and a BPF helper, none of which appear in any pid file
and all of which inherit the cgroup.

`is_service_supervised(pid)` now means what its name always claimed --
somebody *else's* service.

A process cannot be both, and a test asserts it over every combination,
because the two guard the same sweep with opposite effects: one skips, one
terminates, and an overlap is netcfgd killing its own client.

Both answer **false where netcfgd is not under a service manager** -- run from
a shell, or under `unshare` as the live suite does -- which leaves the existing
identification doing the work it already does there, and is why
`resolv_defended.sh` still passes unchanged.

## What is not fixed here

**dhcpcd's pid file is still somewhere netcfgd does not look.** The cgroup
check covers it on any systemd machine, which is where the fault was found,
and covers the privsep children a pid file never would. On a machine running
netcfgd outside a service manager the gap remains, and the honest place to
close it is wherever netcfgd decides dhcpcd's run directory -- a bigger change
than this one, and one that wants its own measurement rather than being
smuggled into a bug fix.
