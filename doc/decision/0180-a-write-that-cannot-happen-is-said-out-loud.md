# 0180: a write that cannot happen is said out loud

Status: accepted
Date: 2026-09-09
Milestone: M8; asked for directly, after three faults in one week that were all
the same shape

## The question

> Have you checked all the write errors on all files netcfgd has to write?

The honest answer was no: the ones that had failed had been checked, and
nothing had asked the question of the rest. So it was asked mechanically.

## What the inventory found

Ninety-one writes in the shipped crates, in forty-four functions, once
removals are set aside. Of those, **sixty-three propagate with `?`**, twenty
are handled where they stand, and **four discarded the failure entirely**:

| what | where | what its loss costs |
| --- | --- | --- |
| the supplicant's network fingerprint | `record_supplicant_networks` | a changed passphrase, bssid or network list is never noticed |
| the `WireGuard` key digest | `record_key` | a rotated key is never noticed |
| the preshared-key digests | `record_presets` | the same, per peer |
| the `.ovpn` hash | openvpn's `start` | an edited config never restarts the tunnel |

**Each of the four was a considered decision, and each was right.** A record
that could not be kept must not fail an apply: a device the kernel accepted is
not made wrong by a digest that would not write, and 0079's counter would turn
a full `/run` into a restart loop. The doc comment on the first one says so in
as many words.

**What none of them did was say anything.** The consequence never arrives at
the time; it arrives at some later reconcile, as netcfgd having no opinion
about a file that changed. That is indistinguishable from a correct machine,
which is the property this tree keeps paying for: 0176's grant was inert,
0178's hook could not be executed, 0179's stop could not signal, and all three
reported success.

## The rule

**Report it, then carry on.** The failure goes to the journal naming the file,
the kernel's own words, and what is now not being noticed; the apply still
succeeds. That is the whole change to behaviour, and it costs one line each.

The writers return the complaint rather than printing it, because none of them
knows what it is recording and every caller does -- which is also what makes
them testable without a running daemon.

## What is checked

`tool/write_gate.py` reads every write in the shipped crates and requires each
to propagate, to be handled where it stands, or to be listed in
`tool/write-best-effort.txt` with what its loss costs. **The list is empty**,
and that is the finding rather than the default: after this change nothing in
the tree drops a write's failure without a word. Removals are exempt by rule --
`remove_file` is asked for a state, and the usual error is that the state
already held; forty entries saying so would bury the four that matter.

The gate refuses in both directions, measured: reintroducing one `let _ =`
fails it, and an entry for a write that is no longer silent fails it too, so
the list cannot rot into an allowance nobody rechecks.

Beside each writer, unit tests assert the message **names the file, carries the
kernel's own words, and says what is lost**. They make the refusal with a file
where a directory has to be, which needs no privilege and no mount -- a mode
would not do, because `CAP_DAC_OVERRIDE` walks through one (10.71), and a
read-only mount would confine these to a root run, which is how the privilege
tests came to assert nothing for months.

**Both halves of every writer, because the first hid the second.** The first
version of the plain-record test passed with the write's error discarded: it
was reading `create_dir_all`'s refusal every time and never reached the write.
A directory where the file belongs is the refusal that gets past the first
call. Sabotage confirms each half separately.

## What is still uncovered, said plainly

The `write_all` failing after a successful `open` -- a filesystem that fills up
between the two -- is not reproduced by any test here. It needs a full
filesystem, which needs a mount, which puts it in the live suite rather than
beside the code. The error is propagated and worded; nothing has watched it
arrive.
