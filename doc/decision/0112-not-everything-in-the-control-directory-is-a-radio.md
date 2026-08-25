# 0112: not everything in the control directory is a radio

Status: accepted
Date: 2026-08-05
Milestone: sweeping the shape 0111 fixed in one place

## Context

0111 gave a stop its own deadline after measuring what the default cost the
reconcile loop. The obvious next question is whether anything else in the tree
has the same shape, and the project's own habit answers it: *swept by pattern
rather than one at a time, because the ones not yet bitten are the point.*

Three places still took `Client::connect` and its ten-second default. Two are
correct -- `ncfg wifi` is an operator's command where a scan legitimately takes
that long, and `populate_supplicant` talks to a supplicant it has just started.
The third is the roam watcher, and reading it turned up something other than a
timeout.

## What it found

The watcher rescans the control directory each pass for radios it is not yet
attached to. It took **every entry** as an interface name:

```rust
let Some(interface) = entry.file_name().to_str()... else { continue };
if watching.iter().any(|(known, _, _)| *known == interface) { continue; }
let Ok(client) = netcfgd_supplicant::Client::connect(&ctrl_dir, &interface) else ...
```

But not every entry is an interface. A datagram client has nowhere to be replied
to unless it binds an address of its own, and `connect_within` binds it *in that
same directory* -- `netcfgd-<pid>-<serial>` -- because that is the directory both
ends are known to be able to write. So netcfgd's own in-flight connections
appear in the listing beside the supplicants, and the watcher connects to them.

Measured, with a socket of exactly that name bound by a process that serves
nothing:

```
what the stray reply socket received:
  bound
  received: PING
  received: PING
  received: PING
```

Three in twenty-five seconds -- one per timeout, for as long as the entry
exists. Two distinct harms, and the second is the serious one:

- **The watcher blocks for the full timeout, every pass.** The far end is a live
  process that is not a server, so nothing answers and nothing refuses. A thread
  that exists to deliver roam events promptly spends its time waiting on a
  socket that was never going to answer, and the radios that *are* working wait
  behind it.
- **The `PING` is delivered into another client's reply queue.** That client is
  in `request`, blocked in `recv`, waiting for the answer to a command it really
  sent. `PING` is not an event, so `request` returns `Reply::parse("PING")` --
  the wrong answer to a real command, with nothing anywhere reporting an error.

The window for the second is the lifetime of any client connection in the same
directory, which includes the daemon's own observations and
`populate_supplicant`. Same process, same directory, concurrent threads.

## Decision

**One place knows what netcfgd's reply sockets are called, and readers ask it.**
`is_reply_socket` is a prefix test beside the `format!` that produces the name,
and the watcher skips anything it matches. A prefix rather than a parse: the pid
and the serial are the client module's business, and a reader only needs to know
the entry is not an interface.

**And the watcher's connect gets `STOP_TIMEOUT`.** What survives the filter is a
real supplicant, and a wedged one would still cost this thread ten seconds a
pass. Same reasoning as 0111 and 0085, in the third place it has now applied.

Rejected: having the client bind its reply socket somewhere else, `/tmp` say.
That moves a known-writable path to a guessed one, and the directory was chosen
because both ends can write it. The problem is not where the socket is; it is
that a reader assumed every entry was something else.

## The gates

**Live, in `roam.sh`**, which is where the watcher is exercised. A socket named
exactly as `Client::connect` names one, bound by a process that answers nothing,
must receive nothing. Removing the filter turns it red -- two `PING`s inside the
two seconds the check waits.

The pid in that name is deliberately one that is not running. What makes a reply
socket answer nothing is that **nobody is serving it**, which is equally true of
a live client, and staging a live client from a shell script would race.

**A unit test pins the coupling**, which spans two places: what the client
*names* its socket and what a reader *skips*. So it observes the name from
another thread while a connect is in flight, rather than asserting the literal
prefix -- a test that asserted the prefix alone would keep passing if the naming
moved.

Both halves were checked by breaking them. Renaming the bound socket fails with
`reply-668938-0 was bound in the control directory and would be taken for an
interface`. Removing the server socket the connect needs -- which makes it
return `NotFound` before binding anything -- fails with `the connect bound no
reply socket, so this test checked nothing`.

That second guard exists because the first version of this test did not have it
and asserted nothing at all while passing. `connect_within` checks the remote
exists before it binds, so with no server there is no reply socket to observe,
and the loop over what was seen ran zero times. It looked exactly like a passing
test.

## What this says about the method

**A directory listing is an interface, and it had no schema.** Everything else
netcfgd reads has a shape it checks -- a pid file is parsed, a lease is
key/value, a control reply is `Reply::parse`. A `read_dir` looks like it needs
none, so nobody wrote one down, and the entries netcfgd itself creates were the
ones that broke it.

**The vacuous test is the recurring failure here**, and this is the second time
in two days: a warm-up that timed out looked like one that worked (0110's
`start_fake`), and now a test whose subject was never constructed. Both passed.
The habit that catches them is not review -- it is breaking the gate on purpose
and reading *which* assertion fires, because a gate that stays green under the
break was never testing the thing.
