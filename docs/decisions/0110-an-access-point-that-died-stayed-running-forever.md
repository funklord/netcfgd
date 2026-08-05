# 0110: an access point that died stayed running forever

Status: accepted
Date: 2026-08-05
Milestone: closing the last corner of "is it still what the document says?"

## Context

Section 10 carried this as deliberate. 0080 gave the supplicant a pid file and
said so in as many words:

> **hostapd is deliberately left out**: it takes `-P` and the same three lines
> would work, and nothing here can run them -- `ap.sh`'s hostapd never starts on
> a dummy, and a real radio needs `hwsim.sh` and real root. Code with no test is
> what this project removes rather than adds.

The reasoning was sound and the conclusion had an expiry date on it. 0109 needed
a hostapd that was running and would not answer, and produced one by sending
`SIGSTOP` to the fake -- which is when it became obvious that the fake can
produce any of these states on demand, including the one nothing had ever asked
netcfgd about.

## What it found

An access point's `running` came from the record and from nowhere else.
`read_backend_liveness` (0078) walks the recorded backends and asks
`backend_pid_file` for a handle; the match had arms for openvpn, radvd, the
supplicant, udhcpc and odhcp6c, and `_ => None` for everything else. `None` means
"netcfgd cannot tell", which correctly leaves the record alone -- so for an
access point the record was never contradicted by anything, ever.

Consequences, in the order they bite:

- **A hostapd that crashed stayed `running: true`** for as long as netcfgd was
  up. The socket it bound is a file and outlives it (0080), the generated
  configuration is still there, and the recorded state agrees with both.
- **The planner therefore had nothing to do.** A document asking for an access
  point, a machine with none, and a reconciler reporting convergence -- which is
  the sentence 0078 was written to make impossible.
- **0079's restart could not fire.** Every other backend that dies gets five
  attempts and then a refusal that says so. An access point got none, because
  restarting is driven by `running` going false.

0085 is not this. A wedged hostapd -- alive, socket bound, not answering -- has
been observed as `answering: false` since then, and deliberately provokes no
restart. A *dead* one is the opposite case and had no answer at all.

## Decision

**netcfgd starts hostapd with `-P`, and an access point joins the liveness
pass.** Three small pieces, and the third is the one that made the first two
possible:

1. `start_args` puts `-B -P <run>/hostapd/<device>.pid <config>` in that order,
   which is hostapd's own usage. Verified against a real hostapd 2.10 rather
   than assumed -- `-P <PID file>` is in its `-h` output.
2. `backend_pid_file` gains an `AccessPoint` arm. The pid file's own path is the
   marker, which is the strongest kind netcfgd uses: netcfgd chose it, it names
   the device, and `-P` puts it in the command line, so `/proc/<pid>/cmdline`
   confirms the pid belongs to *this* access point rather than to whatever
   recycled the number.
3. `stop` removes the pid file, for the reason the supplicant's teardown gives:
   hostapd removes its own on a clean exit, one that was killed leaves it, and a
   stale file would have the next observation asking about somebody else's pid.

**hostapd writes the file after it daemonizes** -- `os_daemonize` calls
`daemon(0, 0)` and only then `fopen` -- so the parent whose exit status `start`
reads is gone before the file appears. That window is left alone and is harmless
for one reason only: 0078's rule that a missing pid file means "cannot tell",
which is not "it is not running". Turning a missing file into a stop would break
this immediately.

## The gates

**The fake gets `--pidfile`, which is what `-P` produces.** Spelled as a flag
taking the path rather than derived from the control directory, and that is the
whole point: the marker netcfgd checks is *the path appearing in the command
line*, so a fake that wrote the file without being told where would confirm a
check that could not work against the real daemon. Same trap 0105 caught with
the fake supplicant.

**`acl.sh` gains the state and its counter-proof.** `SIGKILL` on the fake leaves
the socket and the pid file behind -- every artefact says the access point is
there, and only the pid says otherwise. Five checks: a live access point is
*not* started again (first, because the rest proves nothing without it), the
socket survives, the pid file survives, the observation says `running: false`,
and the plan starts one. Removing the `AccessPoint` arm turns the last two red.

**A unit test pins the argument list**, the way 0108's does for `udhcpc`. It
asserts the pid path as a whole string rather than the presence of `-P`, because
a `-P` pointing somewhere netcfgd does not read would satisfy a looser test and
tell netcfgd nothing. Dropping the flag prints both lists.

## What it cost on the way

**A readiness wait that could match the previous run's output.** `start_fake`
launched the fake with `> "$work/fake.log"` and then waited for `ready` to
appear in that file -- but the redirect is opened by the *child*, after the
fork, while the wait runs in the parent. The first `grep` can win that race and
match the **previous** fake's `ready`, returning before the new process has run
a line of code.

That race was harmless for as long as nothing downstream depended on the new
fake having done any startup work. The pid file is startup work. So the file
still named the fake that had just been killed, netcfgd correctly observed a
dead access point, and every check about a live one failed -- three runs in
eight, moving from check to check depending on which section lost the race.

Removing the log in the parent closes it rather than narrowing it: the file does
not exist until the child opens it, `grep` on a missing file simply fails, and
the loop keeps waiting.

**The instrumentation kept curing it**, which is what took the longest. Every
diagnostic added a few milliseconds to the fake's startup and the failure went
away -- six clean runs, eight clean runs, while the uninstrumented script failed
three in five. A bug that disappears when watched is saying something about
*when* things happen, and that is the reading to take from it rather than
persisting with a larger sample.

**And an inline duplicate went.** The wedged-hostapd section had its own socket
written in Python inside the script, while `fake_hostapd.py` had a `--wedged`
flag nothing used. Left alone it would have inherited the previous fake's pid
file -- naming a killed process -- so every check in that section would have
been about a hostapd netcfgd believes has died rather than one that will not
answer.

## What this says about the method

**A reason not to do something has a shelf life, and nothing tells you when it
expires.** "Nothing here can run it" was true when 0080 wrote it and stopped
being true the moment 0109 needed a fake hostapd in a particular state. Neither
change knew about the other. The item stayed on the list saying "deliberately
left out" with a reason that had quietly become false.

So a deferral is worth re-reading rather than re-trusting, and the trigger is
not a schedule -- it is any change to the thing the reason was about.
