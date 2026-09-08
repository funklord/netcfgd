# 0178: a generated hook cannot live where it cannot run

Status: accepted
Date: 2026-09-08
Milestone: M8; found with root on the machine 10.66 and 10.67 were written for,
after a switch to netcfgd left it with no name resolution

## The report

> netcfgd keeps rewriting an empty resolv.conf making it impossible to fix what
> ever problem it has.

The switch itself had worked -- associated, leased, routed. What did not work
was DNS, and the cause is not in the DNS code.

## `/run` is `noexec`

    /run rw,nosuid,nodev,noexec,relatime,size=3255096k,mode=755

No `/etc/fstab` entry: **systemd mounts it that way itself**, and has by default
since v256. This machine runs systemd 257, so this is the ordinary state of an
ordinary Debian install rather than a hardening choice somebody made.

netcfgd wrote dhcpcd's hook per interface into
`/run/netcfgd/dhcpcd/<iface>.script`, `chmod 0755`, and passed it with `-c`.
dhcpcd could not execute it:

    dhcpcd: script_runreason: Permission denied

**1,350 of those in this machine's journal**, from the day netcfgd first ran a
dhcpcd there. The message is dhcpcd's own and goes to the journal; netcfgd sees
no failure, because from netcfgd's side the client started and got a lease.

**The hook is the only route a lease's nameservers have into netcfgd.** So the
DNS delivery had no servers, `write_resolv_conf` wrote a resolver file with no
`nameserver` line in it, and `resolv_guard` then defended that emptiness by
signalling whatever put a resolver back. A machine with no name resolution and a
daemon keeping it that way cannot be repaired by the ordinary means.

**Four scripts, not one.** `write_dhcpcd_script`, its `DHCPv6` sibling,
`write_udhcpc_script`, `write_pd_hook` and `write_ppp_scripts` all
`set_permissions(0o755)` under `/run/netcfgd`. On a machine whose `/run` is
`noexec` none of them can run, so no lease nameservers arrive from any client
and no user hook ever fires.

## Decision

**Ship the dhcpcd hook, at `/usr/libexec/netcfgd/dhcpcd-hook`.**

`libexec` and not `share`, because it is run rather than read; installed by
`make install` and therefore present in every package. The daemon looks it up
with `dhcpcd_hook_path()` and **refuses to start the client when it is absent**,
naming the file -- because a missing hook is the same silent outcome as an
unexecutable one, and the whole cost of this defect was that nothing said
anything.

## What the hook cannot be told, which shaped it

The shipped script has to find its own report path, and dhcpcd gives it almost
nothing. All three of these were measured rather than assumed:

- **The environment does not carry netcfgd's.** dhcpcd builds a clean
  environment for hooks: `interface`, `reason`, `pid`, the interface flags,
  `PATH` and `PWD`. An exported `NCFG_RUN_DIR` does not arrive.
- **`dhcpcd.conf` has an `env` directive but no `include`.** Using it would mean
  netcfgd writing its own configuration in place of the operator's, where today
  it symlinks to it so a running client can be asked which config it was started
  with ([0143](0143-ask-the-client-what-it-was-started-with.md)).
- **`$pid` is not a usable handle.** Reading `NCFG_RUN_DIR` back out of
  `/proc/$pid/environ` returned nothing, and the pid itself came back stale.

So the hook derives everything it can -- the interface from `$interface`, and
which report to write from whether `$reason` ends in `6` -- and takes its root
from `/run/netcfgd`, which is where netcfgd puts it. `NCFG_RUN_DIR` is honoured
for the case where the script is driven directly; under dhcpcd it is always
unset.

**A test that wants a different run directory has to make that path be it**,
which inside a mount namespace with a tmpfs over `/run` it can.
`tests/live/dhcpcd.sh` now does, which `tests/live/dhcpcd_orphan.sh` already
did. That is the right direction for the difference to be resolved in: the test
now drives the paths a real machine does, rather than netcfgd carrying a
mechanism that exists only for a test.

## What proves it

`tests/live/dhcpcd.sh` mounts its tmpfs over `/run` with `nosuid,nodev,noexec`
-- **the flags the machine actually uses**, where it used to mount a plain
tmpfs and therefore ran every one of its checks against a `/run` no real
machine has. With the shipped hook: 38 checks, all passing. With the hook copied
back under `/run` and `NCFG_DHCPCD_HOOK` pointed at it: 12 red, and they are
exactly the report and nameserver checks.

That pair is the evidence. The suite passed throughout the period this defect
was shipping, because the one property that mattered was the one it did not
reproduce.

## Consequences

- **`dhcpcd_script` and `write_dhcpcd_script` are gone.** The unit test that
  read the generated string now reads the shipped file, which is a better test:
  it inspects the artifact that actually runs.
- **`REPORT_DHCPCD6` is now held in two places** -- the constant and the shipped
  script, which computes its own path. That is the two-lists shape this tree
  keeps finding, so the test asserts the hook contains the constant rather than
  trusting them to stay in step.
- **The other four scripts are unchanged and still broken on such a machine.**
  udhcpc, the PD hook and the two ppp scripts have the same fault by the same
  route. They are not fixed here because each carries more than a report --
  udhcpc's does the addressing -- and turning them into shipped hooks is its own
  piece of work. Named here so the omission is deliberate rather than forgotten.
- **Superseded as the *general* answer, the same day, and kept as the right one
  for a generated script.** `ExecPaths=/run/netcfgd` re-permits execution inside
  netcfgd's own runtime directory, children included, and fixes all five scripts
  at once. It was not found until the fifth of them forced the question, because
  an inline hook body is the operator's content and has no artifact to ship --
  so the grant has to exist for that case whatever else is done. Shipping this
  hook remains worth having (a static artifact beats a regenerated one, and it
  is one fewer thing written at runtime), but it is no longer what makes dhcpcd
  work. Recorded rather than reframed: the decision below was reached without
  knowing about `ExecPaths=`.
- **User hooks are the fifth, and the most visible.** `PendingHooks`
  materialises every configured hook into `<run>/hooks/` at mode `0700` and
  spawns it, so no `pre_up`, `post_up`, `pre_down` or `post_down` runs on a
  default systemd machine. It fails loudly, unlike this one -- netcfgd spawns
  them itself and sees the `EACCES` -- but it fails absolutely, and
  `tests/live/hooks.sh` cannot see it because it points `NCFG_RUN_DIR` at
  `/tmp`. That is the same blind spot `dhcpcd.sh` had, and closing it is the
  same one-line change to how the suite mounts `/run`.

## Alternatives rejected

- **`StateDirectory=netcfgd`, generating into `/var/lib/netcfgd`.** Smallest
  change and it works: `/var/lib` is exec. It puts generated executables outside
  `/run` against constraint 1, and it keeps the per-interface generation this
  removes. Offered to the copyright holder and not chosen.
- **Reading dhcpcd's own lease file** instead of a hook. Loses the one contract
  `doc/interface-report.md` documents for every client rather than for dhcpcd
  alone.
- **Mounting netcfgd's runtime directory `exec`.** Fights the init system's
  default on every machine, and a unit that quietly re-permits execution under
  `/run` is a worse thing to ship than a script in `libexec`.
