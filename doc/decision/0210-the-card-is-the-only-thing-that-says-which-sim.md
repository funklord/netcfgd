# 0210: the card is the only thing that says which SIM

Status: accepted
Date: 2026-09-11
Milestone: M9; putting netcfgd on a two-SIM LTE board

[0209](0209-a-helper-nobody-was-running.md) ends by naming what it did not do:
the ICCID is the only reliable discriminator of which SIM source a module is
actually reading, `netcfgd-modem-at` could read it, and it appeared nowhere
netcfgd reported. This is that piece.

## Why it has to be the card

A board that muxes two SIMs **cannot be asked which one is selected**. The mux
is outside the module -- an FSA2567 between two SIM holders and the module's
single UIM interface -- so the module does not know it is there and has no
register that answers. netcfgd knows which source it *asked* for, which is a
different question and is exactly the one that goes wrong: a request that did
not take looks identical to one that did.

And the obvious alternative does not work. An ISD-R probe over `AT+CCHO`
reports absent at **both** mux positions, including one demonstrably holding an
eUICC -- the module blocks it. Measured, on hardware. So: the ICCID or nothing.

## The pairing belongs to the writer

The helper reports two keys, and they are only meaningful together:

```
iccid=8946080023614318322
sim=socket
```

**netcfgd must not make that pairing itself**, and the reason is a window it
cannot see out of. netcfgd publishes a new SIM source the instant it advances;
the module is still reading the old card, and will be until something resets
it. A `status` that paired its own current selection with whatever ICCID last
arrived would therefore file one card under the other's name at exactly the
moment a source changed -- which is the only moment anybody looks.

The helper is the only thing that saw both at one time: it read netcfgd's
published source, drove the modem, and read the card that came back. So it
says.

A report with an `iccid` and no `sim` contributes nothing. That is not an error
-- an older helper writes exactly that -- and the alternative, filling in the
current selection, is the defect above wearing a different hat.

The test drives that window directly: advance to `socket`, deliver a report
that still says `esim`, and check the card lands on `esim`. With the pairing
taken from `chosen` instead, it lands on both and the count goes from one to
two.

## This is the "unknown keys" promise being taken up

`doc/interface-report.md` has always said:

> **Unknown keys are ignored, and this is a promise.** A writer may report
> `mtu=`, `apn=` or anything else it knows [...] That is what lets writers run
> ahead of netcfgd instead of waiting for it.

So this needed no new channel and no new file. The helper reported keys netcfgd
did not understand, and netcfgd caught up. A netcfgd too old for these skips
them; a helper too old to send them costs only the display.

**It stays no addressing.** `netcfgd-modem-at`'s header says it reports none,
and that is unchanged and still right: on ECM the module runs a DHCP server and
the host takes a lease, so a helper reporting an address would be a second
writer for a job the client already does. The report carries these two keys and
nothing else, and on a `config = "dhcp"` interface -- which is what ECM wants --
`takes_reports` is false, so nothing in it can reach a plan. The tests assert
the absence of `address=`, `gateway=` and `dns=` rather than trusting the
sentence.

## What is shown, and what is deliberately not

`ncfg modem` lists the card seen in **each source a helper has reported one
for**, in the document's order, marking the one in use:

```
wwan0  socket  fallen back
    sources: esim, socket
    apn: internet.cxn
    esim card: 8946080801619663722
    socket card: 8946080023614318322  (in use)
```

**Not one line per listed source.** A source netcfgd has never been on has no
card, and the absence is the honest answer rather than a gap to fill: the mux
shows the module one SIM at a time, so learning what is in the other socket
costs a switch, a modem reset and the link. Nothing can show both at once. This
shows both once both have been tried, which is as close as the hardware allows.

The memory is in `Sims`, beside `chosen`, and is **derived and disposable for
the same reason**: it is rebuilt as sources are used and gone after a reboot. A
card can be swapped while the machine is off, and a remembered ICCID that
outlived the card it named would be a confident wrong answer to the one
question this exists to settle.

## The C client had no modem test at all

Adding `cards` to `ncfg_client_modems` meant adding a field to a function
nothing tested. The witness exercised the parser by being parsed, which says it
does not crash and nothing about what it extracted.

A source and an ICCID are two strings that mean nothing apart, so a parser that
transposed them would look exactly like a board reporting odd cards. There is a
test now, and swapping the two `member_text` keys takes it red.

## What this still does not do

It reports the card and not what is on it. IMSI, operator, MSISDN and the
eUICC's profile list are all absent, and the last of those is not netcfgd's to
fix: installing or listing a profile needs an LPA, and on the eUICC measured
`ES10` over `AT+CGLA` answers `6985`, so it cannot be done on the device at
all. `AT+CRSM` is refused by that firmware for every file including `EF_ICCID`,
so anything deeper would have to go through `AT+CCHO` and `AT+CGLA` by hand.

The ICCID is the fact that was worth having, because it is the one that answers
"which SIM is this machine actually on".
