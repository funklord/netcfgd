# 0166: what cannot be attributed is killed by name

Status: accepted
Date: 2026-09-06
Milestone: M8; closes the item
[0165](0165-the-file-netcfgd-owns-is-defended.md) left open

## The instruction

"You need to overwrite resolv.conf no matter what, if another process tries to
stop you kill it."

0165 made netcfgd notice a foreign write and put its own file back, which wins
every round. It deliberately stopped there and recorded the killing as not
done. This is that half.

## What a kill can and cannot buy

**Against a supervised daemon it buys seconds.** `systemd-resolved.service`
carries `Restart=`, so a signal is answered by the supervisor putting it back,
and netcfgd would be fighting something that cannot lose. 0165's answer for
those stands and is `Conflicts=` in `netcfgd-exclusive.conf`. This one reports
such a process by name and does not signal it, saying which mechanism applies
instead -- which is worth more than a signal that achieves nothing.

**Against anything else a kill holds**, and that is what this does.

## The part that is blunt, stated rather than discovered

**netcfgd cannot tell who wrote the file.** There is no way to ask the kernel
which process last wrote a path; `fanotify` can report a writer's pid and needs
`CAP_SYS_ADMIN`, which netcfgd does not take and should not start taking to
defend a text file.

So what the sweep does is signal **every known resolver-writing program netcfgd
did not start**, not the one that is interfering. An idle `dhclient` that has
written nothing is terminated alongside the one that will not stop, and
`tests/live/resolv_defended.sh` asserts exactly that rather than leaving it to
be found.

It is defensible: on a machine told that netcfgd owns `resolv.conf`, a foreign
DHCP client that is running *will* write that file when its lease renews, so
"is interfering" and "is about to" are closer than they read. It is still a
bystander at the moment it is killed, and that is the cost of the instruction
being carried out at all.

## Decision

**Three gates, and all three must open.**

1. **netcfgd owns the file** -- `dns_mode = "write_resolv_conf"`. Every other
   mode hands the file to a resolver that owns it, and killing that resolver
   would be killing the thing netcfgd asked to do the work.
2. **The file has been taken back `PATIENCE` times in a row**, three. One
   foreign write is ordinary -- a lease, a hook, an operator with an editor --
   and netcfgd simply puts its own back. The count resets on any drift pass
   that did not have to reclaim, so "three in a row" cannot be reached by three
   unrelated writes a week apart.
3. **The process is not netcfgd's and not supervised.** The pids netcfgd
   recorded starting are excluded first, because `dhcpcd` is on the list of
   writers and netcfgd starts its own -- killing that to defend a file its own
   lease filled in would be the worst outcome available.

Matched on `/proc/<pid>/comm` rather than argv: `comm` is the kernel's name for
the executable, where argv is whatever a wrapper passed. **It is truncated to
15 characters**, which is why the list carries `systemd-resolve`; a name one
character too long never matches, and the sweep would report nothing while
looking as though it had looked.

## Consequences

- `tests/live/resolv_defended.sh` proves the three gates: a single write kills
  nobody, a persistent writer is terminated, a process netcfgd started is not,
  and the bystander of the same program is -- pinned so a later narrowing is a
  deliberate change with a failing test rather than a silent one.
- **It runs in its own pid namespace and must keep doing so.** The rest of the
  suite runs under `unshare -rn`, a *network* namespace, where `/proc` still
  shows every process on the machine -- so exercising this there would
  terminate the developer's real NetworkManager. `unshare -rnp --fork
  --mount-proc` is what makes it safe to run at all, and the Makefile invokes
  it bare for that reason.
- Each gate was made to fail: removing the own-pid exclusion kills netcfgd's
  own client, and `PATIENCE = 1` terminates somebody for a single write.

## What this does not do

It does not stop a supervised daemon, by design. It does not identify the
writer, because nothing available can. And it does not fire on a machine using
any other DNS mode, which is most of them.
