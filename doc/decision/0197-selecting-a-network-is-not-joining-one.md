# 0197: selecting a network is not joining one

Status: accepted
Date: 2026-09-10
Milestone: M8; the wifi connect and disconnect audit

## What was returned

```rust
match client.command(&format!("SELECT_NETWORK {id}")) {
    Ok(()) => Response::Ok,
    Err(error) => Response::error(format!("cannot join `{wanted}`: {error}")),
}
```

**`OK` to `SELECT_NETWORK` means the supplicant accepted the command.** What
follows it is the authentication, the association, the four-way handshake and,
on an enterprise network, an entire TLS exchange with a server somewhere else --
and every way any of that fails arrives as an *event*, never as a reply.

netcfgd called the acknowledgement success, and `ncfg wifi connect` printed:

```
joining; `ncfg wifi status` says whether it worked
```

which is the program admitting, in its own success message, that it does not
know the answer to the question it was just asked.

**On the network that started this work that answer was forty-five consecutive
authentication failures.** `ncfg wifi connect` would have said "joining" to
every one of them.

## The same shape, three times

This is the third instance of one mistake, and worth naming as a pattern rather
than as three bugs:

- **0194**: `SCAN` returns at once and `SCAN_RESULTS` reads a cache, so the
  scan was always the previous one.
- **0195**: `systemctl start` returns when the unit starts, not when the
  machine is on a network, so the switcher announced success 13 minutes early.
- **0197**: `SELECT_NETWORK` returns when the command is taken, not when the
  radio has joined.

In each, an asynchronous operation's *acknowledgement* was reported as its
*outcome*. The fix is the same each time: attach first, do the thing, wait for
the event that says what happened, and say that instead.

## What is waited for

`CTRL-EVENT-CONNECTED` is success. `CTRL-EVENT-SSID-TEMP-DISABLED` carries the
supplicant's own `reason` -- `WRONG_KEY` and `CONN_FAILED` send a person to
different places, so it is passed through rather than rewritten -- and
`AUTH-REJECT`/`ASSOC-REJECT` are a refusal by the access point, which is a
different fault from a credential netcfgd got wrong.

**`CTRL-EVENT-DISCONNECTED` is deliberately not a failure.** `SELECT_NETWORK`
leaves whatever the radio was on, so a disconnect is the ordinary *first step*
of a join; treating it as the outcome would fail every successful switch from
one network to another.

Twenty seconds. Association is milliseconds and a successful PEAP join measured
a little over two, so this is generous for the slow case -- and it only has to
outlast the *first* failure rather than the last, since a supplicant that
cannot authenticate says so within a second or two and then waits ten before
trying again.

## Off the reconcile loop, like the scan

A join now waits on a radio, so it gets the thread 0194 gave the scan, for the
reason 0111 gives: answering it on the reconcile loop would hold that loop for
as long as an EAP handshake takes. The unreachable `answer()` arm says so
rather than joining, because a join routed back through it would work and would
quietly restore the stall.

## Verification

Five checks in `tests/live/wifi_trouble.sh`: a join that works says so **in the
past tense** and does not say it is still trying; a join that fails is reported
as a failure, carries the supplicant's own reason, and carries the attempt
count from the event rather than one netcfgd invented.

`fake_supplicant.py` gains the half it lacked -- a real supplicant answers
`SELECT_NETWORK` with OK *and then* sends an event -- with `FAIL_NEXT_JOIN` as
a mode, for the reason `FAIL_NEXT_SCAN` is one.

Removing the wait takes the three failure checks red. The success check stays
green under that sabotage, which is correct and is why it is not the only one:
returning `Ok` unconditionally passes "it worked" every time, and only the
failure cases can tell the difference.

`wifi_journey.sh` asserted the old wording. Its check now looks for **joined**
rather than **joining**, which is a stronger assertion than it could previously
make: before this, that line could only say a command had been sent.
