# 0280: the socket witness has a builder, and six lines it cannot produce

Status: accepted
Date: 2026-10-22
Milestone: M9; the C port

## What this decides

`doc/schema/socket.json` is built by `c/tests/socket_witness_test.c`, which
produces each of the file's lines through the encoder the daemon answers with
and compares it byte for byte. It produces **61 of 67**. It refuses to write
the file at all until it can produce every line, so the committed witness is
still the hand-edited one and no partial file can be blessed over it.

Two things changed in the program to get there, and one question is left open
for the copyright holder.

Taken on the copyright holder's instruction, "now build socket.json from the C
too", on 2026-10-22, following 0279.

## What the file is, which decides what "built from the C" can mean

The other three witnesses are one value each: a document, an observation, a
plan, read through the C's reader and written back through its writer.
`socket.json` is **67 sample messages**, and their values -- an ICCID, a BSSID,
a signal in dBm -- are choices somebody made. No program can derive them.

So the builder owns the **bytes** and not the values: each line's value is
constructed in the test, or for a request decoded from the file, and the bytes
are written by the same function the daemon writes them with. That is the half
that goes stale when an encoder changes, and the half a hand-edited witness
cannot check.

**The 41 request lines are decoded from the file and re-encoded**, which is the
path `proto_test` already proves. Constructing forty-one request values a
second time would be a second copy of the samples with nothing holding the two
in step.

## The event writer moves to the protocol, and gains a flag

The witness carries every event twice: wrapped, as a monitor stream delivers
it, and as the payload on its own, which is a shape the decoder also accepts
and the file pins in five lines.

**Only the wrapped form had a writer.** `ncfg_main_event_encode` in
`src/main/daemon_world.c` wrote `"response":"event"` unconditionally, so five
of the witness's lines were a shape this build could read and could never
produce -- and nothing said so, because the decoder accepting both made the
asymmetry invisible from the outside.

It is `ncfg_proto_event_encode(event, wrapped, ...)` in `src/proto/response.c`
now, immediately below the reader whose accepted shapes it has to produce. One
writer with a flag rather than two functions, because two would be two member
orders for one event and the frozen file is a byte comparison. 87 lines left
`src/main/`; nothing else moved, and the wrapped bytes are unchanged -- which
`world_test` and `proto_test` both assert.

## The six it cannot produce, and the decision that is open

The remaining six are the wifi answers: two `wifi_scan`, two `wifi_status`,
`radios` and `ap_stations`. They are blocked twice over.

- **Their encoders are interleaved with reading a live supplicant.**
  `ncfg_wifi_scan` and friends write members as they parse control-socket
  replies, so there is no encoder to call with a value -- the rig is a forked
  `tests/live/fake_supplicant.py` and `fake_hostapd.py`, which
  `daemon_wifi_test.c` stands up.
- **And the fakes answer with other values than these lines carry.** The fake
  supplicant's first network is `HomeFiber` at -53 dBm where the witness says
  `home` at -40; the fake hostapd reports `rx_bytes=100000` and
  `connected_time=3600` where the witness says 4096 and 184. These lines were
  authored by hand in the Rust era and no fixture in this tree reproduces them.

So finishing it is a choice between two things, and **it is the copyright
holder's**: re-author those six lines to what the existing fakes answer, which
rewrites part of a frozen witness and keeps every shape it pins; or add canned
answers to the fakes that reproduce the lines, and stand the supplicant rig up
inside the builder, which keeps the file and costs a forked python process in
`make schema-bless`.

`radios` is the cheap one of the six and is worth naming separately: its values
do match the fake's, and `daemon_wifi_test` already asserts that witness line
by hand. It needs only a live `PING` answer, because `ncfg_supplicant_answers`
asks the process rather than the filesystem.

## Why the refusal is loud and not red

The builder prints what it cannot produce and the reason, and **does not fail**
for it. A gate that stays red while a decision is open is one a reader learns
to walk past, which is the argument `build-and-commit.md` makes about a
workflow left failing.

What is enforced instead is that the number cannot move on its own: `SHORTFALL`
is 6 and is asserted in both directions, so one more unproduced line is a
failure -- an encoder has drifted away from the file -- and one fewer is a
failure too, because then the constant is the stale thing.

## What was seen to fail

- A byte changed in a witness line: that producer claims nothing, the
  shortfall check fires, and the bless arm writes nothing.
- A copy of the witness holding only the 61 producible lines: the write arm
  runs and the result is byte-identical to what it read. The writer is proved,
  so what is missing is six encoders rather than any machinery.
- `SHORTFALL` against 0 unproduced and against 1, which is the ratchet in both
  directions.

## What this leaves wrong

`answer_test.c` carries ten witness lines as string literals of its own, which
are now also produced by the builder. That is not duplication to remove: those
literals are a hand-written expectation, independent of the file, and a
builder checked only against the file it writes would be checking its own
output. Two witnesses, one of them written by hand, is the arrangement
`evidence.md` asks for.
