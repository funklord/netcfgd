# 0070: a client is stopped the way it was started

Status: accepted
Date: 2026-08-03
Milestone: the last item on the laptop list that only needed a machine with the package

## Context

project.md said it plainly: **dhcpcd's generated script has never been run by
dhcpcd.** Its shape was read out of dhcpcd 10.1.0's own `20-resolv.conf`, its `-c`
option out of the manual page, and `sh -n` plus assertions covered the text -- which
proves the script is shell, not that dhcpcd runs it. The note ended "a machine with
the package would close this in one run". This is that run, and the run found a
defect nothing else could have.

**netcfgd could not stop a dhcpcd.** It starts one with `-4`, and dhcpcd puts the
family in the name of its pid file:

```
# dhcpcd -4 -b -c <hook> cli
# ls /run/dhcpcd
cli-4.pid  cli-4.sock  cli-4.unpriv.sock
# dhcpcd -k cli
dhcpcd is not running          <- exit 1
```

`-k` without the family looks for `cli.pid`, does not find it, and says so. netcfgd
ran exactly that, and **ignored the status** -- correctly, because "dhcpcd is not
running" is also what every machine whose client is udhcpc says. So dropping
`config = "dhcp"` from a document, tearing an interface down, or recreating one
([0059](0059-an-interface-is-remade-when-the-kernel-will-not-change-it.md)) reported
a stopped backend while a real dhcpcd kept the address, kept renewing the lease, and
would keep doing so until the machine was rebooted.

It is the same defect [0065](0065-udhcpc-needs-a-script-and-netcfgd-writes-it.md)
found on the other client, which is the part worth noticing: 0065 fixed "a udhcpc
cannot be stopped" and left "a dhcpcd cannot be stopped either" standing, because
the client it could drive was the one it tested.

## Decision

**One constant names the family, and both the start and the stop use it.**

```rust
const DHCPCD_FAMILY: &str = "-4";
fn dhcpcd_start_args(iface, metric, hook) -> Vec<String>
fn dhcpcd_stop_args(iface)               -> Vec<String>
```

Two lists of the same thing have already drifted in this repository -- the CLI kept
three copies of "which flags take a value" -- and the answer there is the answer
here: a unit test iterates the start arguments, finds the one family flag, and
asserts the stop names it too. Removing the `-4` from the stop fails that test by
name, and fails three checks in the live script for the reason an operator would
notice: the client is still running, the address is still on the interface, and a
nameserver from a lease that has been given up is still in the report.

The status stays unchecked, and the comment now says why rather than leaving the
next reader to work it out.

## The test, and why it makes its own namespaces

`tests/live/dhcpcd.sh` drives a real dhcpcd against a real `busybox udhcpd` over a
veth pair. Every other live script here runs under `unshare -rn` from the Makefile;
this one cannot, and the reason is worth writing down because it will come up again
for any daemon that separates privileges:

**dhcpcd drops privileges to an unprivileged user, and a user namespace with one
mapped uid has nobody to become.** `failed to drop privileges: Operation not
permitted`, and it exits before it sends a packet. Real root works, and so does
`unshare --map-root-user --map-auto`, which maps the subordinate uids from
`/etc/subuid` and needs `newuidmap`. Both are probed, and a machine with neither
gets the reason rather than a broken run.

It unshares the mount and UTS namespaces too, and that is safety rather than
tidiness. dhcpcd's run directory and lease database are compiled in and no option
moves them, so a tmpfs over `/run` and `/var/lib/dhcpcd` is what keeps the machine's
own dhcpcd -- its control sockets, its pid files, its leases -- untouched.

**And it runs dhcpcd once with its own hooks first**, which is the counter-proof.
An assertion that netcfgd's `-c` stopped something is worth nothing until that
something has been seen to happen:

```
ok   dhcpcd's own hooks take the hostname from the lease      (leased-name.lan.example)
ok   and rewrite the resolver file netcfgd's DNS backend owns (nameserver 10.44.0.53)
ok   netcfgd's hook leaves the hostname alone                 (localhost)
ok   and leaves /etc/resolv.conf to whoever owns it
```

That is [0061](0061-a-key-that-compiles-does-something-or-says-it-does-not.md)'s
refusal of `hostname = "dhcp"` and [0066](0066-a-lease-reports-its-nameservers.md)'s
`resolv.conf` contention, both measured instead of asserted. The hostname is safe to
let dhcpcd change because the UTS namespace is private; `/etc/resolv.conf` is safe
because a bind mount shadows it.

**The address arriving is not the hook having run.** dhcpcd installs the address and
the routes itself and calls the hook afterwards, so a wait on the address followed by
an assertion about the hook is a race -- it lost one run in three. The counter-proof
now waits for what the hook does. The netcfgd half waits too, and there for a second
reason: the assertions there are that the hook did *not* set the hostname and did
*not* write `/etc/resolv.conf`, and a hook that has not run yet satisfies both
perfectly. Waiting until it has demonstrably done its one job -- written the report
-- is what stops two negative checks passing for the wrong reason, which is section
9's first corollary in its usual disguise.

## Consequences

- A `backend.stop` stops a dhcpcd, and the address, the routes and the report go
  with it. The report going is the first time the `STOP` branch of the generated
  hook has ever run.
- **`preference` reaches the lease's default route.** netcfgd does not install that
  route -- the client does -- so a document's ranking can only reach it through
  `dhcpcd -m`, and busybox udhcpc has no equivalent. `dhcp.sh` cannot make this
  assertion; this one does.
- **`dhcp.sh` now pins which client it drives.** netcfgd prefers dhcpcd, so on any
  machine whose PATH has sbin -- a root shell, the privileged container -- the
  busybox script was driving dhcpcd, and under `unshare -rn` that meant the whole
  script failing at the first apply for a reason having nothing to do with what it
  tests. The daemon is handed the machine's PATH with every directory holding a
  dhcpcd removed. Handing it a PATH with busybox alone was tried first and broke the
  generated script, which needs `ip`.
- `+0 KB`: one constant and two functions where there were two inline argument
  lists.

## What is still open

**Nothing tells netcfgd that a client it started has died.** A dhcpcd killed from
outside leaves netcfgd believing the backend is running until the next observation
disagrees, and the observation is of addresses rather than of processes. That is the
shape [0053](0053-a-file-netcfgd-does-not-read-can-still-be-hashed.md) guessed at --
a backend netcfgd did not start, or no longer has -- and it is still a suspicion
rather than a plan.

**A DHCPv6 client is not stopped at all.** `stop_backend` has an arm for `Dhcp4`
and one for the supplicant, and everything else -- `Dhcp6` included -- returns
"stopping the `Dhcp6` backend is not implemented in this build". That is honest
rather than silent, which is the difference between it and the defect above: an
apply that drops `config = "dhcp6"` fails and says so. Closing it is its own
decision, because the two clients differ. dhcpcd would take `-6 -k` and the family
rule here applies unchanged -- its pid file will be `<iface>-6.pid`. odhcp6c
daemonises with `-d`, writes no pid file, and has no control socket, so stopping one
means netcfgd recording the pid it started, the way it does for udhcpc (0065) and
checks against `/proc/<pid>/cmdline`. Neither should be written without a live test,
and `delegation.sh` -- which needs real root for port 546 -- is where that test
would go.
