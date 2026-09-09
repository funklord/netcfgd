# 0188: a network daemon does not give up restarting

Status: accepted
Date: 2026-09-10
Milestone: M8; the ninth audit, and the one that found the checks themselves
had been running half-shut

## The question

> now check the shutdown and restart errors too

## What was already right, and is now asserted

netcfgd has **no signal handler and no `ExecStop`**, which is deliberate:
0134's argument is that stopping the daemon must not take the network down.
Deliberate is a claim, and nothing checked it. Measured, and now in
`tests/live/restart.sh`:

* `SIGTERM` to exit is **20 ms**, so the unit's 90-second `TimeoutStopSec`
  never comes into it. A daemon that started blocking on the way out would
  push every reboot and every upgrade by up to that long, silently.
* The address and the route are **still there** after the daemon stops.
* A restart walks over its own leftovers -- socket, both lock files, the
  recorded state -- and the machine stays configured.
* `SIGKILL` mid-apply leaves **no lock held**, because `flock` is held by the
  open file description and the kernel drops it when the process dies. 0184
  chose it over a lock file for exactly this, and this is that argument
  turned into a check.

One thing measured and left alone: a `pre_up` hook sleeping when the daemon
is killed **keeps running**. That is the same `KillMode=process` bargain the
supplicant and the DHCP client are held by, and what a hook should do about
it is an operator's question.

## The fault: a start limit on the daemon that carries the network

`Restart=on-failure` with `RestartSec=2`, and systemd's default start limit of
five starts in ten seconds. netcfgd spends that budget in **eight seconds**.
Measured on a transient unit carrying exactly those settings:

    ncfg-cliff-probe.service: Start request repeated too quickly.
    Active: failed (Result: exit-code)

The end state is a machine with **no network daemon and nothing that will
ever try again**, until somebody -- who probably has no network -- runs
`systemctl reset-failed`. And what reaches that path is environmental rather
than about the configuration: a run directory not ready, a stale socket, a
filesystem still mounting. Those are the cases where trying again in two
seconds works. A configuration that does not compile is deliberately not one
of them: netcfgd runs with none and says so.

`StartLimitIntervalSec=0`. The cost is one line every two seconds in the
journal for a daemon that is genuinely broken -- a machine somebody has to fix
either way, and the loud version says what is wrong every time rather than
once, eight seconds after boot, in a message about rate limiting.

**And the key belongs in `[Unit]`.** In `[Service]` systemd ignores it:
`Unknown key 'StartLimitIntervalSec' in section [Service], ignoring`. It was
written there first, and `make packaging` -- which already runs
`systemd-analyze verify` and fails on any output -- caught it.

## What this audit really found: the checks were being run in pieces

`make check` was **red**, and had been for most of a day, while every report
said the gates passed. Three separate faults, all mine, all invisible to the
way I was checking:

* `make packaging` extracted `^Exec[A-Za-z]*=` as programs that must be
  installed, so 0178's `ExecPaths=/run/netcfgd` made it report a run directory
  as an uninstalled binary. The extraction now names the `Exec*` keys that
  hold a program.
* `make clippy` runs `--workspace --all-targets -- -D warnings`. What I ran
  was `cargo clippy --all-targets` with the output grepped for `^error`, which
  is neither. It was failing on a `print_literal` in a skip message, on
  `REPORT_DHCPCD6` becoming dead when 0178 moved the report path into the
  shipped hook, and on a doc comment my own edit had displaced -- I inserted a
  constant between `KernelExecutor`'s doc comment and the struct, so the
  comment documented the constant and the struct had none.

Every one of those was introduced by a commit that reported "11 gates pass".
The gates did pass. **`make check` runs twenty things, and eleven of them are
the gates.** The lesson is the one this tree keeps writing down about
measurement: a check that is run in pieces is a different check, and the
pieces that are easy to run are not the ones that were failing.
