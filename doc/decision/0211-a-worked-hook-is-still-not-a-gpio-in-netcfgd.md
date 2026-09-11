# 0211: a worked hook is still not a GPIO in netcfgd

Status: accepted
Date: 2026-09-11
Milestone: M9; putting netcfgd on a two-SIM LTE board

[0209](0209-a-helper-nobody-was-running.md) and
[0210](0210-the-card-is-the-only-thing-that-says-which-sim.md) left one thing
between netcfgd and a working two-SIM board: netcfgd chooses a SIM source,
publishes it, and something has to move the mux. The only thing shipped was
`sim-select.example`, whose two operative lines were marked `BOARD` and left
blank.

## Filling them in is not the same as netcfgd growing a GPIO

[0150](0150-a-sim-source-is-chosen-the-way-an-uplink-is.md) keeps netcfgd out
of driving hardware, and this does not revisit it. What ships is a second
**example**, installed non-executable beside the first, carrying no line
numbers and no chip that any board must have -- five values at the top, all
overridable from the environment, all of them facts about a board that netcfgd
cannot know.

The difference from the frame is that everything *around* those five values is
now written and tested: the backgrounding, the bounded wait, the kill, the
check after the release, the trap, and the wait for the interface to come back.
Those are not board facts. They are the same on every board with a mux, they
are where the traps are, and leaving them to each operator meant every operator
meeting them separately.

## The four things the example exists to get right

**A `pre_up` hook must return.** `gpioset` in libgpiod v2 holds the line for as
long as it runs -- correctly, since a GPIO request belongs to a process -- so
calling it plainly never comes back, and a `pre_up` that never comes back holds
netcfgd's reconcile until the sixty-second hook timeout kills it, on every
bring-up.

**Releasing a `pca953x` line does not return the pin to an input.** Direction
register and output latch both keep their values, which is what makes
set-then-release work at all. It is driver behaviour rather than a documented
guarantee, so the hook checks after the kill: if a kernel ever restored the
direction, the mux would spring back to whatever the pull-ups say and every
conclusion afterwards would be about the wrong SIM.

**A crash does not fail safe**, for the same reason -- the line stays driven
whichever way it was last set. On the reset line that means "in reset for
ever", so the hook traps `EXIT`, `INT` and `TERM` and drives it back. netcfgd
sends `SIGTERM` at the hook timeout and `SIGKILL` five seconds later; the first
can be caught and the second cannot, which is one more reason the pulse is
short.

**The reset takes the interface away.** The module's `cdc_ether` device
disappears with the USB device and returns when it re-enumerates, and netcfgd
brings the interface up when the hook returns -- so returning early hands it an
interface that is not there. The hook waits.

## Two refusals that go opposite ways, deliberately

**An unknown source name is fatal.** A source netcfgd was configured with and
the hook has no value for exits non-zero, because the alternative is bringing
the interface up on whichever source the mux happened to be left on, which
looks like the fallback working and is the machine ignoring you.

**An interface that does not come back is not.** That exits zero with a loud
message, because failing would abort the bring-up, and an aborted bring-up
never reaches the probe -- which is the thing that tells netcfgd this source
does not work and to try the next. A unit that cannot fall back is a unit
somebody has to physically visit, and this hook exists on boards where that is
expensive.

The difference is worth keeping: one is a configuration error nobody will
discover later, the other is a runtime fact the probe is about to establish
anyway.

## What the test can and cannot say

There is no board here, no `gpio-sim` in this kernel and no `gpiod` installed.
`tests/live/sim_select.sh` fakes the *expander* -- `fake_gpiod.py` models the
two behaviours above and would be wrong without them -- and runs the real hook.

**It does not prove the hook works on a board.** Polarity, line names and the
chip label are that board's, and a `pca953x` behaving differently from the fake
would not be caught. Said plainly in the file, because the alternative is a
green tick somebody reads as hardware coverage.

It does prove everything that is not the hardware, and that turned out to
matter twice.

## The test found a race in the hook, and then a lie in itself

**The hook waited for the line to become an output before killing `gpioset`.**
That is satisfied instantly on the *second* drive of the same line -- it is
already an output, left that way by the first -- so the kill could land on a
process that had not applied the value yet. The reset pulse is exactly that
shape, assert then release, and the failure is a modem held in reset with the
hook reporting success. It waits for a *consumer* now, which is what says the
request actually landed whoever left the line an output.

**And the check named "returns rather than hanging" did not check that.** It
looked for a phrase the hook prints *before* it would block, so the mutation
that calls `gpioset` in the foreground passed it. Only the sabotage pass found
it. Blocking is a duration, so the check is a duration now.

That is the same shape as [0208](0208-the-apn-register-that-answers-with-the-question.md)
and 0210's C client, arrived at from a third direction: **a check is only worth
the property it measures, and a name is not a property.** This one was written
by the same hand as the code, minutes apart, and agreed with it.

## Still not netcfgd's

Provisioning, profile download, `ES10` -- none of it, and on the eUICC measured
none of it is possible on the device anyway. And the five values: an example
that guessed them would be worse than one that leaves them blank, because a
wrong polarity is silent and looks exactly like a working switch.
