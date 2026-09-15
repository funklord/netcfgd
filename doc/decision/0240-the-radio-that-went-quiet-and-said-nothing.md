# 0240: the radio that went quiet, and said nothing

Status: accepted
Date: 2026-09-15
Milestone: M9; the methodology round

## What this round is

Not an audit of an area. The question was why the wifi work took twenty rounds
and so many one-off experiments, and what to change so it does not happen
again. The answer turned out to be mostly about tools this tree already had and
was not using, so the changes are small and the findings they produced are not.

**Two real defects fell out of making the first change**, which is the argument
for it in one sentence.

## The simulator was already there, and half of it was dead

`tests/live/hwsim.sh` loads `mac80211_hwsim` with three radios, moves them into
a private namespace, stands up two access points and has netcfgd associate from
the third. It is the only test in this tree that produces a real association,
and it is in a make target.

Its second half had been failing since 0154. That decision replaced the
per-network `priority` with `metric`, which runs the other way up; the script
still wrote `priority`, so every run since got two compile diagnostics, no
supplicant, and `did not move to the preferred network (on: none)` after forty
seconds of polling. Nothing noticed, because the live scripts are not in `make
check` and nobody reads their output.

Fixed, and the preference check passes. What that buys is not the check itself
-- it is that the file runs to the end, which is where the rest of this is.

## A roam is producible here and nobody had asked for one

0239 changed how netcfgd tells a roam from a network change, and the only
coverage it could get was a fake whose events netcfgd's own author wrote --
including the network id, which that fake had hard-coded to 0 for years.

The radios to produce a real one were already loaded. `hwsim.sh` now:

- moves the station between networks on a running supplicant with `ncfg wifi
  connect`, and asserts that is **not** a roam;
- puts the second access point on the network the station is on, takes the
  first away, and asserts the move that follows **is** one, named by the address
  it moved to.

The negative runs first and on the supplicant the block above leaves running,
deliberately: a network change made by restarting the supplicant would pass it
for the wrong reason, since a fresh supplicant has nothing to have moved from.

Both checks failed on the first run. Neither was 0239's fault.

## The first defect: a dead connection reads as a quiet one

`Client::next_event` only ever receives. A connected unix datagram socket whose
peer has exited does not report that -- the read times out, which is exactly
what a radio with nothing happening on it does. So when a supplicant was
restarted, the watcher kept the entry, the rescan skipped the interface because
it already had one, and **that radio went deaf for the life of the process**:
roam hooks, 0225's authentication diagnostics, refused associations, all of it.

`ncfg apply` restarts a supplicant. So does every configuration change that
repopulates one. This was not a corner.

The path is not the question, because a restarted supplicant unlinks its socket
and binds a new one at the same name. The identity is: `(device, inode)`,
recorded at attach time and checked once per radio per pass. No round trip, and
nothing that can be mistaken for an event.

## The second defect: falling behind is not merely late

With that fixed, the roam still went unreported. `STATUS` showed the station
`COMPLETED` on the second access point; netcfgd's last event was the
assoc-reject before it.

The watcher took **one event per pass**. The 250 ms per radio is a timeout
rather than a delay, so a single busy radio drains fast -- but a second, quiet
radio makes every pass wait the full quarter second, and then the busy one
yields about four events a second. Every machine with a modern wifi driver has
that second radio: `p2p-dev-wlan0` sits in the control directory beside `wlan0`
and says nothing. On the simulated radios it was `p2p-dev-wlan2`.

A supplicant does not emit at four a second. Losing an access point produces a
burst -- the disconnect, a scan, its results, an assoc-reject, a temporary
disable, the reconnect -- and the watcher fell behind on every one.

Falling behind is not merely late. The events queue in the socket's receive
buffer, and when it fills the supplicant's send fails. `wpa_supplicant` answers
a monitor it cannot send to by dropping it, which its own binary spells:

```quote from=tests/live/roam.sh
CTRL_IFACE: Detach monitor that cannot receive messages
```

After that nothing arrives ever again and nothing says so. The socket is open,
the path is unchanged, and the inode check added above cannot see it either --
the supplicant is the one that let go.

Drained now, up to `EVENT_BURST` per radio per pass so one chatty radio cannot
starve the others. What is left over is read milliseconds later.

## The ninth sabotage to pass on its first run

The drain went in with a `roam.sh` burst test that sent thirty events and
required all thirty. Reverting the drain to one-per-pass **passed it**.

The reasoning behind the test was wrong in the way the code had been right by
accident: with one radio and events already queued, every read returns at once,
so one-per-pass drains as fast as draining does. The pacing needs the quiet
second radio. `roam.sh` now starts one, and the same sabotage gets 15 of 33 in
three seconds -- four a second, as predicted.

This is the ninth time in this campaign that a sabotage passed on its first run.
It is also the first time the sabotage corrected the *test's premise* rather
than revealing a missing assertion, which is a better argument for the pass than
any of the previous eight.

## What else changed, and why

**`tool/supplicant_coverage_gate.py`.** Every setting netcfgd sends a supplicant
must have a real one behind it. The four globals -- `sae_pwe`, `okc`,
`rand_addr_lifetime`, `preassoc_mac_addr` -- were each measured by hand in the
round that added them, written into a decision record as prose, and the script
thrown away; the next round had no way to know and measured again.
`tests/live/live.rs` had been driving a real supplicant since M6 and none of the
four was in it. Now 21 settings, all driven, including an enterprise network
whose seven EAP settings had never met the real parser.

**`tool/cited_quote_gate.py`.** Three records in this campaign were found
asserting what the code contradicts, one of them falsified by the round before
it. A record can now mark a quotation with the file it came from and the gate
checks the words are still there. It catches quotations and not paraphrases,
which is written on the tool: what caught all three was somebody reading the
code while writing the next record, and that is a practice rather than a gate.

**`tool/prove-red.sh`.** Runs a new test against the parent commit in a
throwaway worktree -- no stash, nothing touched in a tree other sessions share.
It distinguishes a red that fails an assertion from one that fails to compile,
and says the second proves less. It cannot separate a test from its fix when
they share a file, which is most `#[cfg(test)] mod tests`, and says that too.

**`make installed-diff`.** Twenty-one of the campaign's forty-five commits
touched only documents and each still paid a full build, install and live
verification, decided by unpacking the `.deb` by hand. One command now.

## The shape sweep, and what it found

The campaign audited by subject -- regulatory, channel, hidden SSID, SAE, PSK,
MAC, rfkill, roaming -- and every subject had defects, which means they were
never subject-specific. Sweeping by shape instead:

- **a handle held across time, assumed live because it exists**: one instance
  in the tree, the roam watcher's, fixed above;
- **`/proc/<pid>` as liveness**: all in `process.rs`, and all of them already
  read `cmdline` or `comm` rather than existence, which is 0143's lesson
  applied;
- **absence turned into a value**: two that matter, both deliberate and both
  documented where they are -- the blocked-radio scan returns cached results
  with the reason attached, and an unreadable provenance file is an explanation
  without line numbers rather than no explanation.

One finding from three sweeps, and it was the one this round had already found.
That is a useful result: the shapes are worth sweeping and this tree is not full
of them.

## Still open

`hwsim.sh` logs an association refused with **status 53, `INVALID_PMKID`**, when
the station moves to the second access point. That is opportunistic key caching
-- netcfgd's own `okc=1` (0228) -- being offered and rejected. 0228 says "where
the access points do not share a key the station offers a `PMKID`, the access
point does not recognise it, and a full authentication happens as before"; here
the access point refused the association outright and the station retried. It
does get on, so this is a delay rather than a failure, and the access point is
`wpa_supplicant` in AP mode rather than hostapd. Recorded rather than chased: it
is a claim made without a radio that the first radio contradicted, which is this
round's subject, but it is not this round's change.
