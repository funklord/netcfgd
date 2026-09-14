# 0238: the switch that is watched and not touched

Status: accepted
Date: 2026-09-14
Milestone: M9; the wifi power and rfkill audit, second pass

## Re-checking what the first pass assumed

0219 audited this area. Its "what it found sound" list is the assumption set,
and 0230's lesson is that an existing conclusion is not a source. Each was
re-checked against the code and the machine:

- **the record's growth is handled.** `next_event` reads into a 64-byte buffer
  and accepts anything at least `RECORD` long, so a kernel writing
  `rfkill_event_ext` delivers a whole record and the surplus is ignored. Holds.
- **a switch is matched to an interface by the phy's name**, sorted, with
  `continue` rather than `?` on an unreadable entry. Holds.
- **a blocked radio is warned about by name, with the remedy differing by
  switch.** Holds, and the difference is real: a hard block gets "a hardware
  switch, which nothing in software can clear" and a soft one gets "`rfkill
  unblock wifi` clears". Both `soft` and `hard` are parsed from the record.

The watcher itself is well made. It sends `KernelChanged` rather than inventing
a command, because "what changed is something an observation reads", and its
documentation states the fact the rest of this decision turns on: *blocking* a
radio usually shows up on netlink, *unblocking* one produces nothing.

The code is sound. What was wrong is what is said about it, in two places.

## The README promised a switch netcfgd will not touch

The feature table read:

```text
| radio on/off | over the control socket, which the GUI and the tray use;
                 rfkill state is observed and streamed as events |
```

"Radio on/off" is the toggle every other wifi interface has, and it is the one
thing netcfgd deliberately does not do. 0062 decided a blocked radio is
**reported and not unblocked**, and `/dev/rfkill` is opened read-only precisely
so the write path cannot be reached -- the comment on that `File::open` says so.

What the control socket actually carries is `RadioSet`, reached as `ncfg wifi
activate` and `deactivate`, and it decides *which radio netcfgd takes on*. That
is a different question from whether the radio is powered, and putting the two
in one cell invites a reader to conclude netcfgd can do the second because it
can do the first.

**The clients get this right and only the README does not**, which is worth
recording because it is the opposite of the usual direction. The GUI's button
says "activate radio". The tray says "Disconnect wifi". Both are exact. The
table that people read to decide whether netcfgd does what they need was the one
place that overclaimed.

## And a decision record of mine was wrong

0234 said:

> `roam` and `rfkill` have no backstop and would go quiet.

The loop re-observes on a tick -- `if kernel_changed || config_changed ||
probe_changed || ticked` -- so a dead rfkill watcher costs promptness and not
detection. A flipped switch is noticed within the tick rather than as it
happens, which is what the watcher exists to improve, not to enable.
`spawn_rfkill_watcher`'s own documentation says so in the file 0234 was written
from: *"an observation runs on a netlink event or on the loop's five-second
backstop"*.

`roam` was too broad as well. `Command::Roamed` drives the roam hooks and
nothing else; the observation reads the associated address on its own path. So a
dead roam watcher costs the hooks and 0225's supplicant diagnostics, not
netcfgd's knowledge of which access point it is on.

The uncomfortable part is the timing. 0233 gave the loop its own tick. 0234 was
written immediately after, by the same pass, and asserted that two watchers had
no backstop -- one round after adding the backstop. The line to have read was
three hundred above the one being edited.

Both corrected in place rather than left standing, for 0235's reason: a record
that states a thing the code contradicts stops the next reader from checking.

## What is still not done, and was not reopened

`ncfg wifi activate` on a blocked radio answers plain success. 0219 recorded why
fixing it properly is a protocol change -- a response variant carrying a caveat
alongside success, then the schema witness, the C client and the GUI -- and that
the alternatives are worse: logging puts it in the journal rather than in front
of the person who typed the command, and fixing only the command-line client
leaves the GUI as it is, which is the split 0217 is about.

That reasoning still holds and this pass does not overturn it. Naming it again
here so the next pass over this area does not have to rediscover that it was
considered.

## Nothing to sabotage

No behaviour changed. Both fixes are sentences: one in the README, one in a
decision record. The check that they are right is that the code says what they
now say -- `File::open` for the device, `RadioSet` for the command, line 358 for
the tick -- and each is cited above rather than summarised.
