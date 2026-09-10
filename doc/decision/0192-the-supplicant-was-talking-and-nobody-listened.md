# 0192: the supplicant was talking and nobody listened

Status: accepted
Date: 2026-09-10
Milestone: M8; the wifi roaming and reconnect audit

## What the audit found

netcfgd attaches to `wpa_supplicant`'s event socket. It has since 0091, it does
it correctly -- `ATTACH` is sent, and roam.sh asserts that it is sent exactly
once -- and the connection is held open for the life of the daemon.

It read one event out of it.

```rust
Ok(Some(event)) => {
    let Some(bssid) = event.connected_bssid() else {
        continue;
    };
```

`connected_bssid()` answers `None` for everything that is not
`CTRL-EVENT-CONNECTED`, so `continue` was the whole handling of every event
that says a link is **failing** rather than working. The stream was being
drained into the floor.

## What that cost, on this machine, this week

`EMP-XYLEM` was configured with `ca_cert ""`, which is a filename and the empty
one, so PEAP failed inside OpenSSL before an inner method was ever proposed
(0189). The supplicant said so, on that socket, forty-five times:

```text
CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="EMP-XYLEM" auth_failures=45 duration=60 reason=CONN_FAILED
```

netcfgd's log for that morning does not mention any of them. What it said was
that `wlp0s20f3` had no carrier: true, and useless. The operator's question was
"why will it not connect", and the program whose job that is had the answer in
its hands and dropped it -- forty-five times, each one carrying the count, the
wait and the supplicant's own word for what gave up. NetworkManager joined the
same access point a minute later, which is how the fault was eventually placed.

**A day, for a fault the machine was announcing every ten seconds.**

## What is read now, and what is still dropped

Four kinds of event become a line, and the rest still go on the floor -- the
DSCP-policy traffic that is most of the stream by volume, the scan
notifications, the EAP progress. Being told everything is the same failure as
being told nothing.

| Event | Level | Why |
| --- | --- | --- |
| `SSID-TEMP-DISABLED` | warning | the supplicant has given up on a network |
| `SSID-REENABLED` | note | it is trying again |
| `AUTH-REJECT`, `ASSOC-REJECT` | warning | the access point refused this station |
| `DISCONNECTED locally_generated=0` | note | the access point ended it |
| `DISCONNECTED locally_generated=1` | verbose | *this machine* ended it |

**Who ended a disconnect is its whole content.** There were forty-three
disconnects in three days here and nearly all of them were this machine
leaving -- netcfgd selecting another network, a rekey, a scan. Those at
verbose; the access point dropping the station at note. The same line at the
same level forty-three times is how a log stops being read.

**Terse on purpose.** The count and the wait climb with each failure, so these
are forty-five distinct lines rather than one repeated, and a paragraph
explaining what a climbing count *means* would have been forty-five paragraphs.
The explanation belongs where it is read once, which is the second half.

## The second half: `LIST_NETWORKS` was also being ignored

`NetworkEntry` has parsed the flags field since it was written. One method ever
read it:

```rust
pub fn is_current(&self) -> bool {
    self.flags.contains("CURRENT")
}
```

So `[DISABLED]` and `[TEMP-DISABLED]` were parsed, carried, and discarded, and
through netcfgd a network the supplicant had given up on looked exactly like
one it was about to join.

`STATUS` cannot close this and never could: it describes the one association
the interface has, so an interface with none reads `SCANNING` whether it is
scanning hopefully or has abandoned every network it was given. Those are the
same three lines of output for two opposite situations, and the second is the
one somebody is running the command about.

`ncfg wifi status` now lists them, with the supplicant's own flags passed
through rather than translated -- `[DISABLED]` is a network somebody turned off
and `[TEMP-DISABLED]` is one the supplicant abandoned by itself, and a release
adding a third should show it rather than drop it. When any of them is
temporary, one sentence says what that means: **a temporary disable is not a
network out of range.** A network out of range is absent from a scan, not
disabled. Getting those two confused is the difference between checking a
passphrase and walking closer to the router.

## The reader underneath, and the space in the name

`Event::field()` reads the `key=value` fields, and is not a
`split_whitespace().find()` for one reason found by reading the format strings:
`ssid=` is quoted, and `printf_encode` leaves a space alone because a space is
printable ASCII. `ssid="Guest Wifi" auth_failures=3` splits on whitespace into
a network called `"Guest` with the failure count lost behind it -- both of the
things the event is read for, destroyed by the reader. Names with spaces in
them are not exotic; they are what a router ships with.

The key is matched at a field boundary too, so `id` is not answered with the
tail of `bssid=a0:a4:7f:23:9a:cf`.

## Verification

`tests/live/wifi_trouble.sh`, wired into `make live`, driving both halves
through `fake_supplicant.py` -- which gained `TROUBLE <text>` to send one event
verbatim and `DISABLE <flags> <ssid>` to hold a network in `LIST_NETWORKS`.
The event texts are copied out of this machine's journal rather than invented:
the format is the supplicant's own, and a test written from the documentation
would be testing the documentation.

Fifteen checks, and they passed on the first run, so each was made to fail
before it was believed. Removing the call to `report_supplicant_event` takes
six of them red; returning an empty `not_trying` takes three; replacing the
field reader with a whitespace split takes three more, including the one that
exists solely for the name with a space in it. The two controls are asserted
from both sides -- before any event, netcfgd says nothing about a network and
the status names nothing it is not trying.
