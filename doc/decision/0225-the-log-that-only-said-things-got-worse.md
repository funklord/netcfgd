# 0225: the log that only said things got worse

Status: accepted
Date: 2026-09-13
Milestone: M9; the wifi event and reconnect audit

## What was already right

The event vocabulary is read from `wpa_supplicant`'s own format strings rather
than from documentation that does not give them. `connected_bssid` takes the
fifth word positionally, because the prose around it is what a translation would
change and the shape is what the format string fixes. `field` runs a quoted
value to its closing quote rather than to the next space, because `ssid="Guest
Wifi"` is what a router ships with and a whitespace split reports the network as
`"Guest`. Events are separated from replies at the socket, which is the classic
fault in a client of this kind.

The watcher recovers from a supplicant that goes away, re-discovers radios every
pass, and costs one thread for all of them. Three things were wrong, and all
three were silences.

## A log that could only report bad news

Every arm of the event reporter was a failure: a network not being tried, a
station refused, a scan that could not run, a station dropped. The one exception
was `CTRL-EVENT-SSID-REENABLED`, added with this reasoning:

> The recovery half, and it is not decoration: without it the log only ever says
> things got worse, and a network that came back looks exactly like one that is
> still broken.

**The same argument had not been applied to the event that says the radio is
carrying traffic.** `CTRL-EVENT-CONNECTED` fell through to `_ => {}`, described
as "the connect the caller goes on to read" -- true, and the caller reads it to
detect roaming, not to say anything. A roam fires a hook and logs nothing.

So a machine that lost its association at three in the morning and got it back
had the loss in the log and the recovery nowhere: the record read as an outage
that never ended. Confirmed against this machine's own journal, which has the
supplicant's failures and reply-socket sweeps and not one line about the
association it has been holding for days.

One line, at note. A roam gets no second line -- it is two of these with
different addresses, and the hook is what acts.

## A radio nobody could watch, and nothing said so

The watcher attaches to each supplicant, and the comment beside the call already
knew what failure meant:

> Without ATTACH this connection gets replies and no events, and the loop below
> would be a silent no-op forever.

The consequence was written down and never reported. `if client.attach().is_ok()`
dropped the error on the floor, so a radio whose supplicant refused `ATTACH` was
a radio netcfgd had gone quiet about -- no roam detection, and none of the
diagnostics above, which are all read through that connection.

Said once per radio rather than once per pass, and again if the trouble returns.

## An unreadable event is not a supplicant that left

`Err(_) => lost.push(interface)` dropped the connection, under a comment
asserting "the supplicant went away". Both halves were true until 0224 added the
reply-too-large check the day before, which made `InvalidData` reachable: a
datagram bigger than the buffer says something about the message and nothing
about the process that sent it.

Dropping the connection for that costs the re-attach **and the access point the
interface last named** -- after which the next `CONNECTED` reads as a first
association rather than a move, and the roam across it is not reported. A
defect introduced by the previous round's fix, found by reading the consumer of
the thing that round changed.

`supplicant_is_gone` is written as "everything except `InvalidData`" rather than
as a list of the kinds that mean absence -- the opposite of `nothing_is_listening`'s
shape, and deliberately: the safe direction here is to reconnect on an
unrecognised failure, not to hold a connection open to a process that is not
there.

## The reporting could not be checked at all

Every arm ended in a log macro, which writes to the daemon's log and returns
nothing. A test could asserted that the code compiled and no more -- and the arm
this round added would have gone in with nothing holding it, which is the fault
0224 recorded about its own truncation check.

`supplicant_event_line` is the decision -- a severity and a sentence -- and
`report_supplicant_event` is the part that says it. All seven arms are covered
now, including the two that were there before this audit and had never been
answerable.

## The sabotage that was invisible, and why

Three sabotages, then a fourth that did nothing:

| reverted | test | result |
| --- | --- | --- |
| drop the connection on any error | `only_a_real_failure_...` | FAILED |
| stop reporting a successful association | `every_supplicant_event_...` | FAILED |
| never clear the complaint list | `an_unwatchable_radio_...` | **passed** |

The third was a real hole in a test written minutes earlier. `first_complaint`
took only the failure, and the *caller* did the clearing on the success path --
so the test drove the helper through its whole state machine using its own
`retain`, and deleting the caller's line broke nothing. A test that simulates
the call site is not a test of the call site.

Restructured so the success goes through the same function: `complain_about`
takes the outcome, and there is one entry point and one state machine for a test
to reach. The same sabotage now fails, by name -- *"a later failure is news
again, not swallowed by the first"*.

**Fourth instance of this pattern in four audits**, and the first where the
faulty test was written in the same session as the fix it was holding up. 0222
had two fixtures built from the code, 0224 had a third; this one is the same
mistake at one remove -- the fixture was right and the *seam* was wrong.
