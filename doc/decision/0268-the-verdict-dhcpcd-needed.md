# 0268: the verdict dhcpcd needed

Status: accepted
Date: 2026-09-28
Milestone: M9; the C port

Amends 0267, which stands. The decision there is unchanged; this adds a fourth
verdict it needed and did not have, found before the code was installed.

## What was wrong

0267 classified a process in netcfgd's control group as RECORDED, HELPER of a
recorded one, or UNACCOUNTED -- and UNACCOUNTED prints at `ERROR` as *"it did
not stop cleanly"*.

**On this machine that would have fired on a perfectly healthy daemon**, for
the whole dhcpcd family: the client and its privileged proxy, control proxy and
BPF helper. Four `ERROR` lines per start, on the default configuration.

The cause is one netcfgd already knows and 0267 did not join up. netcfgd writes
a pid file for udhcpc and odhcp6c because it starts them with `-p`; the only
call to `ncfg_dhcp_pid_path` in the start path passes the literal `"udhcpc"`.
**dhcpcd is never given one.** It destroys its argv with `setproctitle`, so it
carries no marker netcfgd could scan for, and 0143 identifies it by asking its
control socket which config file it was started with.

Measured before the fix, after four days of correct running:

    /run/netcfgd/dhcpcd/   one config symlink, no .pid
    owned.json             dhcp4 on wlp0s20f3, running: true

So the record says the backend is running and nothing in it names a process.

**That is the failure 0267 exists to remove, rebuilt one layer up.** A report
that cries wolf on every start of a healthy machine trains its reader exactly
as systemd's line does, and it would do so in netcfgd's own voice, which is
worse -- systemd at least has the excuse of not knowing whose process it is.

## The verdict

    CLAIMED   the record claims a backend on an interface this process names,
              and carries no pid for it

The client matches it by its `setproctitle` title, which names the interface.
Its helpers reach it by the parent walk, so the classifier runs in two passes:
a claimed ancestor anchors a helper exactly as a recorded one does, and a
single pass could not do that because two of dhcpcd's three helpers carry no
interface in their own titles.

**The match is an interface name in a command line, which `dhcp.h` calls the
weakest marker netcfgd uses.** That is not a lapse, it is the one place a weak
marker belongs: it is used only to *withhold* an alarm, never to license an
action. Being wrong means staying quiet about a process that deserved a
mention, in a report nothing acts on automatically -- against a strong marker's
failure, which would be netcfgd signalling something on a guess.

**Whole word, not substring.** `wlan0` is a prefix of `wlan01`, and a claim
about one must not quieten an alarm about the other. That is the one way this
verdict could suppress the wrong thing, so it has a test of its own.

## How it was found

By predicting the output before installing, rather than by installing and
reading it. The prediction was checked against the run directory and the start
path, both of which said the same thing.

Worth recording because the alternative was cheap and wrong: the code built,
passed 16 tests and every gate, and would have looked correct until somebody
read a journal and decided the `[adopt]` lines were noise.

## What it cost

    binary   1145832 -> 1145960 bytes, inside the size gate's 3% tolerance
    tests    16 -> 23 checks

The new cases are the machine's own table with no dhcpcd pid recorded, which
must produce zero alarms, and the `wlan0`/`wlan01` pair. Both were watched
failing with `is_claimed` stubbed to return 0 -- six checks red, through the
check under test.
