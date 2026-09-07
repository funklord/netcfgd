# 0172: a network you can add is one you can forget

Status: accepted
Date: 2026-09-07
Milestone: M8; completes
[0117](0117-adding-a-network-is-a-typed-request-not-a-written-file.md) and
[0124](0124-adding-a-network-is-the-wifi-tier-because-0117-made-it-safe.md),
and applies
[0127](0127-netcfgd-is-the-only-writer-and-the-socket-carries-the-rest.md)'s
rule to the direction nobody had built

## What was missing

`ncfg wifi add` writes a network. Nothing removed one.

The removal existed, spelled `ncfg config rm wifi-<id>` -- correct, and made
of netcfgd's own file layout. That is the thing 0127 keeps out of clients: a
name a client can only produce by knowing where netcfgd files a wifi profile
and what it calls it. So:

  * the gui showed a **saved networks** table with `view / change` and `add by
    hand` above it and no way to remove a row, because there was no verb for
    it and spelling `wifi-<id>` in a view would have been the client keeping a
    path;
  * the cli's own answer was a different noun (`config`) for a thing the
    operator had created with `wifi`;
  * the credential was nobody's job. Removing the block by hand leaves the
    passphrase in `/etc/netcfgd/secrets`, which is precisely the fault the
    secrets view exists to name -- "a credential still on the machine after
    whatever wanted it was deleted".

## Decided

`Request::WifiForget { id }`, at the **`wifi` tier**, by 0124's own argument:
the message carries an id and nothing else, so its shape is the bound. It can
name no hook, no path, no `run_as` and no control policy, and what it removes
is one `network` block plus a credential nothing else refers to -- strictly
less reach than `WifiAdd`, which writes both. A tier that may create a network
and not remove it leaves a caller able to fill a machine with networks it
cannot take back.

**The credential goes when nothing else refers to it.** The question is asked
of the configuration *after* the block has gone, and of the whole document
rather than of the other networks -- a passphrase shared with an
`access_point` block is still in use. It is asked through the same walk the
secrets list uses (`references`, which destructures `Document` so a new place
to keep a credential is a compile error rather than a silent gap), pointed at
one block instead of all of them.

**It fails closed.** If the configuration cannot be read back after the
removal, every credential is kept. A credential removed on a guess is
unrecoverable in the way 0042 describes; one left behind is a row in a tab.

**The drop-in first, then the credential.** The other order would take a
passphrase away from a network that is still configured, which is the one
outcome here nobody can undo.

**A network netcfgd did not write the file for is refused**, not silently
half-removed. `remove_drop_in` reports whether anything was there, and a
network configured by hand in somebody's own file is theirs to edit.

## The protocol minor moves, for the first time

1.0 -> 1.1. The field exists so a client can tell whether a verb is there, and
this is the first change that gives it something to say. The addition removes
nothing, so an older client is unaffected; a major stays reserved for a change
that makes an old client wrong rather than merely incomplete.

## What is wired, and what is not

The verb, the daemon, the C client, `ncfg wifi forget` and
`ncfg_connection::wifi_forget` are done and exercised. **The gui's own button
is not**, and the reason is not design: `gui/src/wifi_view.{h,cpp}` are owned
by another user on this machine and could not be written. The controls, the
confirmation and its test are the remaining work, and the connection method
they call is already there.

## Measured

    forget over the socket        the block and the credential both gone
    forget an unknown id          refused, naming the ids there are
    forget it twice               refused, saying there are none
    a shared credential           kept, and said so
    the last user of one          removed, and said so

`tests/live/wifi_journey.sh` drives the whole journey against a running
daemon; with the credential walk stubbed out, exactly one check goes red --
"and the credential went with it".
