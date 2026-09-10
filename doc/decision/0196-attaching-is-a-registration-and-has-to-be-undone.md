# 0196: attaching is a registration, and has to be undone

Status: accepted
Date: 2026-09-10
Milestone: M8; the wifi connect and disconnect audit

## What the supplicant was saying

```
CTRL_IFACE: Detach monitor that cannot receive messages: /run/wpa_supplicant/netcfgd-2466975-516
CTRL_IFACE: Detach monitor that cannot receive messages: /run/wpa_supplicant/netcfgd-2466975-482
```

`ATTACH` registers a connection inside `wpa_supplicant` as a monitor, and
**removing the socket underneath it unregisters nothing**. The supplicant finds
out only when it next tries to deliver an event, fails, and drops the
registration then -- which is what those lines are.

Harmless when it happens once. It stopped happening once in 0194: a scan now
attaches, waits for `CTRL-EVENT-SCAN-RESULTS`, and drops the connection, so
**every `ncfg wifi scan` leaves a dead monitor behind**. The serials above are
482 and 516 of a single daemon's life.

The cost is not the registration but the delivery: every event the supplicant
emits walks its monitor list, and each dead entry is a failed send before it is
swept. netcfgd is the program that made the list long.

The roam watcher attaches too, and does not need this: it holds its connection
for the life of the daemon, so its monitor dies with the process. The
distinction is lifetime, not correctness -- which is exactly why the fix
belongs in `Drop` rather than at the one call site that currently needs it.

## Sent, not asked

`Drop` sends `DETACH` and does not wait for the answer.

`command("DETACH")` would wait for `OK`, up to this connection's timeout --
**ten seconds** against a supplicant that has stopped answering, on a code path
whose entire job is to let go. A `Client` is dropped while a scan is being
served, while an apply is unwinding, and while the daemon is shutting down;
none of those can afford a blocking cleanup, and 0111 is the record of what a
blocking wait on this socket costs.

Cleanup that can be missed beats cleanup that can block, and the supplicant's
own sweep is the backstop either way: a `DETACH` that is dropped leaves exactly
the situation this decision is about, which is survivable, whereas a ten-second
stall in `Drop` is not.

Tracked with an `AtomicBool` set by a successful `attach()`, so a connection
that never attached sends nothing.

## Verification

`tests/live/wifi_trouble.sh` counts what the fake supplicant was sent:
`ATTACH` minus `DETACH` must be exactly one -- the roam watcher's, which is
held for the daemon's life and correctly never detaches. Every scan's must be
paired.

Removing the send takes it red, at two unpaired attaches after the scans that
test drives.
