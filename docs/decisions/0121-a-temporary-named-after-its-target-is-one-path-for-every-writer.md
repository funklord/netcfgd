# 0121: a temporary named after its target is one path for every writer

Status: accepted
Date: 2026-08-08
Milestone: reading the code the open `qdisc.sh` failure points at

## Context

The brief's open items name one mechanism to check first, and say why:

> **`state::write_owned` has no locking, and two processes call it.** `ncfg
> apply` writes it from `netcfgd-cli`, and the daemon writes it from five
> places. It is a read-modify-write of one file, so a lost update is
> structurally possible.

Reading that path found a second defect underneath the one it names, in the
write itself rather than in the read-modify-write around it. This record is
about the second. The first is untouched and still open.

## What was there

Three functions in this tree write a file by putting the bytes in a temporary
and renaming it over the target. They were written at different times and they
disagree about the one thing that decides whether the technique works for more
than one writer -- what the temporary is called.

| where | temporary | distinguishes |
|---|---|---|
| `state::write_atomic`, every `/run` file | `<name>.tmp` | nobody |
| `netcfgd-dns`, `resolv.conf` and the forwarder configs | `<stem>.netcfgd.tmp` | nobody |
| `config::write_atomically`, `/etc` and the secrets | `.<name>.<pid>` | processes, not threads |

Rename is atomic, so each of these is correct against a *reader*: nothing ever
observes half a file. None of them is correct against another *writer*, which
is a different property that the word "atomic" in all three doc comments was
quietly standing in for.

Two writers is not hypothetical here. netcfgd applies from two processes --
`ncfg apply` builds a plan and runs an executor in its own process, and the
daemon converges on inotify, on netlink events and on a socket request -- and
both of them write `/run/netcfgd/owned.json`, and either may deliver DNS.

Interleaved on one temporary, the sequence is:

```
  A: write(tmp, A's bytes)
  B: write(tmp, B's bytes)        <- A's bytes are gone
  A: rename(tmp, target)          <- B's bytes land under A's rename
  B: rename(tmp, target)          <- ENOENT
```

So one writer silently publishes the other's content, and the other is told it
could not replace a file it had in fact written perfectly well. Five of the six
`write_owned` call sites discard that error with `let _ =`, and the sixth
prints it.

## What was done

One name shape for all three, carrying the process **and** a counter:
`.<name>.<pid>.<n>`. The pid because the other writer is another process; the
counter because it need not be -- two threads in one process share a pid, so a
pid-only name is a helper whose safety depends on which caller reaches it.

`state::write_atomic` now calls `config::write_atomically` rather than carrying
its own body, which also gives every `/run` file the `sync_all` that its own
doc comment cited design section 17 for and did not do. The mode passed is
`0o666`, which is what `fs::write` opens with, so the umask decides exactly as
before: `owned.json` carries secret *digests* (0055), and tightening it is a
decision to take deliberately rather than one to smuggle inside a concurrency
fix.

`netcfgd-dns` keeps its own copy, because that crate depends on `netcfgd-model`
and nothing else and 0030's containment is worth more than twenty lines -- but
its two call sites now share one function instead of repeating the write. Its
staging name gained a leading dot as well, which is the stronger of the two
guarantees available: `unbound.conf.d/*.conf` does not glob a name beginning
with a dot, and dnsmasq's `conf-dir` skips one unconditionally, where the
extension it relied on before is the part dnsmasq documents as configurable.

## Why this is worth a record

**The rule was already written down in this repository, for tests.**
`netcfgd-testdir` exists because test directories collided, and it says:

> The process id alone is not enough -- tests in one binary share it, and they
> run in parallel by default -- and a fixed name is worse still: two tests
> racing on one directory is a failure that only appears under load.

That is this defect exactly, stated correctly, about temporary directories for
tests, while the code that writes the machine's network state did the worse of
the two things it warns against. A rule learned in the test harness does not
propagate to the production path by itself.

**And the drift was invisible because each copy read as correct.** Every one of
the three comments says "temp file plus rename" and gives the reader argument
for it, which is true. Nothing in any of them mentions a second writer, so
there was no sentence to disagree with.

## What this does not claim

**It is not established that this is `qdisc.sh`'s intermittent failure.** That
failure is a plan that keeps proposing `qdisc.reset veth0` against an ownership
record that still claims the interface, and both this defect and the unlocked
read-modify-write above it can land stale content in `owned.json`. Which one
does it, or whether either does, is unmeasured -- and this file exists partly
because two earlier fixes for that failure were committed with explanations
that turned out to be wrong (0205343's correction of aef59b9). A fifth full
`make live-container` run passed, so the count is two failures in five and the
instrumentation added for it has still never fired.

## Verified

Two tests, one per implementation, each running two threads over one target for
two hundred rounds and asserting that no writer is failed by the other and that
the survivor is one writer's content whole.

Both fail against the code they replaced, on the first round, with exactly the
predicted error:

```
  could not replace .../resolv.conf: No such file or directory (os error 2)
```

Threads rather than processes deliberately: a two-process test would have
passed against `config::write_atomically`'s pid-only name and left the thread
case to be found later.
