# 0207: a preference that walks

Status: accepted
Date: 2026-09-11
Milestone: M8; the wifi metric and roaming preference audit

## What was right

The idea behind `metric` is sound and 0154's reasoning holds. A metric counts
up, lower winning, comparable with an interface's `preference`; every backend
that orders networks for joining counts the other way. Asking an operator to
hold two scales at once for one idea was the thing worth removing.

`join_rank` is the single conversion, shared by the supplicant driver and the
NetworkManager shim, and its documentation says exactly why it is shared: "two
copies of a sign flip are two chances to get it backwards and a wrong one is
silent". Subtracting from a ceiling rather than negating is deliberate, so that
0 stays a legitimate best metric and an absurd one floors at last place instead
of wrapping to first.

## The function that prevents a silent error had nothing checking it

`join_rank` was untested. Not indirectly either: the only `priority` in any
test in this tree is a bridge priority and the `<3>` prefix on a control-socket
event.

Sharing one copy stops two backends disagreeing. It does nothing whatever about
the single copy being backwards, and a wrong sign is exactly the failure the
comment describes: the machine prefers the wrong network, silently, and every
diagnostic still looks right. The defence was "there is only one of these",
which is a defence against divergence and not against error.

It has a test now, and the test is about the sign rather than about the
arithmetic: a better metric must outrank a worse one, 0 must not collide with
"no preference", an absurd metric must rank last, and no metric must say
nothing.

## And the conversion that was not one

`settings.rs` scales `join_rank(metric)` into NetworkManager's 0..999 and
`emit.rs` scales back. `emit.rs`'s own comment names the hazard: "Two
conversions that are not inverses would make a profile change its own ranking
every time a desktop client read it back and wrote it out."

They were not inverses. Measured against the real functions:

```text
metric 100 -> autoconnect-priority 974 -> metric 103
```

and it did not settle. Repeated reads and writes -- which is what happens every
time somebody opens a connection in a desktop client and saves it -- walked the
number upward:

```text
100, 103, 107, 111, 115, 119, 124
```

Far enough and it crosses another network's metric, at which point the machine
prefers a network the operator did not choose, with nothing anywhere saying so.
Exactly the failure the comment describes, in the code the comment is attached
to.

**The cause is which end of the band the trip lands on.** 4096 metrics share
1000 priorities, so coming back is a choice of which metric in the band to
name, and truncating chose the edge -- the value that maps to the *next*
priority down when it is sent again. Adding half a band picks the midpoint,
which maps back to the priority it came from, so the second trip is a fixed
point: 100, 101, 101, 101.

Checked over every metric in range: none moves by more than 8, and none moves
twice.

## And a rank of zero is not a rank

Looking for the walk exhaustively rather than at a handful of sampled metrics
turned up a second way the trip loses a preference, at the other end of the
range. The write side scales a rank of 0..4096 into 0..999 by integer
division, so a rank below 4096/999 scales to nothing -- and NetworkManager's
priority 0 is not a low priority, it is *no* priority, which the read side
correctly turns back into no metric at all.

So metrics 4092 and above made the trip and came back unranked. The write
side's own comment opens by refusing exactly this -- clamping "would throw the
ordering away for exactly the networks an operator ranked" -- and the scale it
chose instead did the same thing to the five worst ranks, which are the ones an
operator went furthest out of their way to set.

A floor of 1 costs six metrics of precision at the very bottom and keeps the
ranking. It was found only because the sweep covers every metric; the sampled
values in the first draft of the test all sat comfortably inside the range and
would never have reached it.

## One definition, not two

The round-trip test began by restating `settings.rs`'s arithmetic inside
itself, which is the trap the last section of this record is about, committed
again in the test written to catch it. A check derived from the code it checks
can only agree with it -- and this one would have gone on agreeing after the
write side grew the floor above, because the restatement did not have one.

`autoconnect_priority` is now a function in `settings.rs` that both the
profile writer and the test call. The test has no copy of the arithmetic left
to drift.

## Verification

The round trip is asserted on the real functions rather than a restatement of
them, and on the two properties that matter rather than on equality, which
cannot hold when 4096 values share 1000: **ordering survives** a trip, and the
**second trip is a fixed point**.

Swept over every metric from 0 to `RANK_CEILING` rather than over a sample,
which is what the claim "none moves by more than 8 and none moves twice"
actually asserts, and is what found the rank-of-zero collapse above.

Sabotage, each half of the fix separately:

```text
flip the sign in join_rank      -> the model test goes red
restore the truncation          -> metric 1 moved twice: 1 -> 5 -> 9
remove the floor of 1           -> a ranked network came back unranked
```

The middle one is the walk itself, reported by the second-trip assertion --
the one the old code failed and had nothing asking about.

## The existing test asserted the bug

`per_connection_options_become_the_keys_that_carry_them` pinned
`metric = 3924` for NetworkManager's priority 42, above this comment:

> Asserting the number rather than its presence is what makes the two
> directions provably inverse.

**It proved the opposite.** `settings.rs` turns metric 3924 back into priority
*41*, not 42 -- the edge of the band rather than a point inside it. The
assertion was specific, deliberate, and agreed with the defect; the sentence
claiming it was a proof is what made it look settled.

3922 is the midpoint and does return 42, so the number the assertion pins now
says what the sentence above it always claimed. Both are corrected together,
because leaving the sentence would leave the next reader the same false
assurance.

Worth keeping as a shape: **an exact number in a test is only as good as the
property it was derived from.** This one was derived from the implementation it
was meant to check, so it could only ever agree with it.
