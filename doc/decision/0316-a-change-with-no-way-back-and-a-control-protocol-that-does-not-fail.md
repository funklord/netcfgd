# 0316: a change with no way back, and a control protocol that does not fail

Status: accepted
Date: 2026-11-06
Milestone: fuzznet integration (project.md 10.738)
Amends: [0312](0312-the-control-vocabulary-is-one-fuzznet-procedure.md), whose refusal of a remote apply without a window gains one exception; answers what [0309](0309-one-protocol-the-local-socket-is-fuzznets-too.md)'s last step waited on

## The holder's words

"There are directives that cannot be rolled back, and situations where rolling back
breaks everything and must not happen. So for those rare reasons we need a remote
apply without confirmation. log it loudly and make it harder to reach."

"fuzznet must not be able to fail in this way. It is a vital control protocol. Even if
we can't write, we must have all core functionality working in RAM. And we must start
pruning history so we don't start filling RAM and have to oom-die. In any case this is
the job of fuzznet to ensure, and yours to detect and notify if there is such an
issue."

## A remote apply with no way back

`ncfg apply --at HOST --no-rollback HOST --reason TEXT`. Hard to reach by these:

- HOST is said twice and must match, so a recalled line cannot land on another machine.
- A reason is required, and the host refuses an apply without one.
- It is one host at a time: many hosts are refused. Neither GUI nor TUI offers it.
- It is refused while a confirm window is open, as that window would undo it on closing.

The target logs at error level who asked and why, before anything runs and whether or
not it goes on to run, then that it stands. The caller is told nothing will undo it.

**A window of no seconds is no window.** `--confirm-within 0` passed both refusals from
0312, each of which asked only whether a value was present, so a remote apply could
already run with no window and no trace. Both now ask for more than zero.

## fuzznet does not fail

Keeping the protocol up with no writable store, in RAM, with history pruned, is
fuzznet's. netcfgd detects and says: `netcfgd.sock` is not kept as a fallback, so 0309's
last step waits on fuzznet's guarantee and not on a choice here.

Detection reads `statvfs` every ten seconds and writes nothing, since proving a store
takes a write would wear a router's flash. Trouble is an error in the log, said again
hourly, and `<run>/node-problem`, which `ncfg status` prints and which goes with the
trouble.

## Rejected

- **A setting on the target that opts in to no-rollback.** The machine that needs one
  may be one nobody prepared. The admin tier already gates who may apply at all.
- **Keeping `netcfgd.sock` for a daemon with no fuzznet.** The holder: fuzznet must not
  be able to fail this way.
