# 0041: A station list converges over the control socket

Status: accepted
Date: 2026-07-31
Milestone: closes what 0039 left open

## Context

Decision 0039 gave an access point a station list and 0040 gave it a live view
of who is on the radio. Between them they left one gap, and 0040 made it
visible on purpose: hostapd reads `deny_mac_file` once, at startup, so an
edited `access_control` block did nothing at all until somebody restarted the
access point. `ncfg wifi clients` marked a station that was on the deny list
and connected anyway, which was honest and was not a fix.

Restarting is the wrong repair. It deauthenticates every client on the radio,
and this feature exists to make a handoff smooth. So the live list is converged
over hostapd's control socket instead, the way any other observed state is
reconciled against the document.

## What hostapd's source said that changed the design

0039 sketched this from `strings` on the 2.10 binary. Reading
`hostapd/ctrl_iface.c` and `hostapd/config_file.c` changed it in three places,
each of which would have been a defect.

**`DENY_ACL ADD_MAC` disconnects the station by itself.** The command calls
`hostapd_disassoc_deny_mac`, which walks `hapd->sta_list` and disconnects
everything now on the list; `ACCEPT_ACL DEL_MAC` and `ACCEPT_ACL CLEAR` call
`hostapd_disassoc_accept_mac` for the same reason. 0039 said netcfgd would need
`DEAUTHENTICATE` to "shake loose a station that has just been denied". It does
not, and sending one would be a second deauthentication of a station that has
already gone. No `DEAUTHENTICATE` is sent anywhere.

**`SET deny_mac_file <path>` appends; it does not replace.**
`hostapd_config_read_maclist` only ever *adds* -- the sole removal is a line
prefixed with `-`, and nothing clears the list first. Re-pointing hostapd at
the file netcfgd has already regenerated is the obvious implementation and is
wrong: every previously denied station would stay denied forever, which is the
exact failure this decision exists to remove. So convergence walks the
difference with `ADD_MAC` and `DEL_MAC`.

**Both lists are consulted, whatever `macaddr_acl` says.**
`hostapd_check_acl` checks the accept list *first* and the deny list second;
`macaddr_acl` decides only what happens to an address in neither. So the list
the policy does not name is not inert -- a station left on the accept list is
accepted despite the deny list naming it. netcfgd converges **both** lists: the
one the policy names to the document's stations, the other to empty. Leaving
the unused one alone would leave a deny list that looks applied and is not,
which is worse than no deny list.

## `CLEAR` is never sent

Emptying a deny list and refilling it is a window, however short, in which every
denied station may associate. `ACCEPT_ACL CLEAR` is avoided symmetrically: under
`macaddr_acl=1` an empty accept list is a network nobody can join. The
per-address commands pass through neither state, and both are idempotent --
`ADD_MAC` for an address already present and `DEL_MAC` for one that is absent
each answer `OK`, and `DEL_MAC` against an empty list returns before it parses.

## One action per station

`access_control.add` and `access_control.del` carry one address each, because
hostapd's control socket does. That is the opposite call from `nat.replace`
(decision 0022) for the opposite reason: an nftables change *is* one
transaction, so splitting it would describe states the kernel never passes
through, while joining these would describe one action that half happened.

Their disruptiveness is directional, and hostapd decides it rather than
netcfgd: the two directions that *narrow* admission -- adding to the deny list,
removing from the accept list -- are the two that disassociate, so those are
disruptive and the other two are not. A guard on the radio therefore blocks
exactly the edit that takes somebody off the network, which is what an operator
adding a station to a deny list is doing deliberately and what an operator
deleting the wrong line from an allow list is doing by accident.

## The policy is recorded, because it cannot be observed

`macaddr_acl` is the one part of an `access_control` block that cannot be
converged in place. It is settable with `SET`, but nothing disassociates on the
change and nothing reports it back -- `GET_CONFIG` returns the SSID, the BSSID
and the ciphers and says nothing about it. netcfgd would be converging a value
it could never confirm.

Converging the lists *without* it is the dangerous option, and this is the
failure the whole record exists to prevent: a document changed from `deny` to
`allow` would have its stations written into the accept list while hostapd was
still running `macaddr_acl=0`, so every unlisted station would be accepted --
an open network, reported as applied.

So netcfgd records what it started hostapd with, in the generated station list
itself:

```
# netcfgd policy: deny
00:11:22:33:44:55
```

`hostapd_config_read_maclist` skips any line whose first byte is `#`, so the
record costs nothing and hostapd never sees it. Two constraints come from the
same function and are both load-bearing: the `#` must be at column zero, and
the line must fit in the 128-byte `fgets` buffer -- a longer one arrives split,
and the tail is parsed as an address, fails, and takes the access point down at
startup. Both are checked, the second against a real hostapd 2.10 in both
directions.

It goes in this file rather than the generated `.conf`, which also carries the
value, because this one is mode 0644 and holds no secret: reading the other back
would mean opening a file with a passphrase in it to learn one integer.

The file is written by `start` and by nothing else, so while hostapd is running
it says what hostapd read. Once the process has exited it is a leftover, which
is why the observation asks only about backends netcfgd believes are running.

### Three answers, not two

The record's *absence* is informative, so `ObservedPolicy` has three values
rather than being an `Option`:

- **No file** -- `write_acl` removes it when the document carries no
  `access_control` block, so this says hostapd was started without one.
- **A file with no record** -- written by a netcfgd from before this existed.
  Nothing may be converged: under `deny` an emptied accept list is nothing and
  under `allow` it is a lockout, and there is no way to tell which. The planner
  says so and stops.
- **A file with a record** -- that policy.

Conflating the first two would make an unreadable `/run` look like "no policy"
and restart an access point over a permissions problem.

## A changed policy restarts, and says what that costs

Any change the socket cannot make -- `deny` to `allow`, either to no block at
all -- is a `backend.stop` then a `backend.start`, with a warning naming the
deauthentication. That is honest about the price instead of hiding it, and it
is the *only* part of an access point's configuration that anything notices
changing today: an edited SSID or channel is still invisible to the planner.
That gap is older and wider than this, and is not closed here.

## The reconcile loop gets a deadline of its own

Reading the lists puts a control-socket round trip in the reconcile loop, which
runs on every netlink event. Decision 0040 kept the station walk out of that
loop because it costs a round trip *per station*; this costs two per access
point, which is bounded by the hardware and is a different question.

The one that is not different is what happens when hostapd is **wedged** --
alive, with its socket bound, and not answering. Nothing fails fast there, so
the loop waits out the client's reply timeout: measured at 10.2 seconds for a
single `ncfg plan`, twice per access point, every event. So `acl::read`
connects with a one-second deadline instead of the ten-second default, which
brings the same measurement to 1.0.

The deadline has to be a parameter of the *connect* rather than something set on
the returned client, and finding that out was the point of measuring. `connect`
opens with a `PING`, so a timeout applied afterwards never covers the one round
trip a wedged daemon is most likely to eat -- the first version of this shortened
nothing at all and measured exactly the same 10.2 seconds.

A second is generous for a local datagram round trip against a process that only
has to format a list it already holds. Being wrong in that direction costs an
observation that says "netcfgd could not ask", which the planner already knows
to do nothing about; being wrong in the other direction stalls the daemon.

## What this is checked against

`tests/live/acl.sh` drives the whole path -- read, plan, send, re-plan -- against
`fake_hostapd.py`, which now implements the two lists the way `ctrl_iface.c`
implements them rather than answering `OK` to everything. The re-plan is the
check that matters: `ADD_MAC` and `DEL_MAC` are idempotent, so a converger that
sent the right commands to the wrong list would look exactly like one that
worked, and only planning again catches it. Swapping the two lists in the reader
was tried, and it does.

`tests/live/ap.sh` feeds the generated file to a real hostapd, which is what
proves the policy record is ignored rather than believed to be.

What none of this reaches is a station actually associating and being kicked.
That needs `mac80211_hwsim` and real root, which is `tests/live/hwsim.sh`.
