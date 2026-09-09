# 0182: `Permission denied` on an exec is two faults

Status: accepted
Date: 2026-09-09
Milestone: M8; the third of three audits, after 0180 (writes) and 0181 (reads)

## The question

> now check the exec and spawn errors too

## What the inventory found, which is mostly good news

Sixteen places in the shipped crates run a program. **Every one of them waits
for it, reads the exit status, and reports a message naming the program.**
Seven distinguish `NotFound` -- "the client is not installed" -- from other
failures, which is the distinction that matters most, and the three-candidate
DHCPv4 loop uses it to try the next client rather than to give up.

Two sites do not read a status and both are right to: `stop_backend`'s
`dhcpcd -k`, where exit 1 means "no dhcpcd is running" on every udhcpc machine
(0070) and the outcome is confirmed on the control socket instead (0179), and
`spawn_despite_etxtbsy`, which is a bounded retry around a race rather than a
run.

Measured end to end, the four ways a client fails already produced four
different messages:

    not installed          no DHCPv4 client found for exec0; install dhcpcd, ...
    not executable         could not run dhcpcd: Permission denied (os error 13)
    on a `noexec` mount    could not run dhcpcd: Permission denied (os error 13)
    ran and failed         dhcpcd on exec0 exited with exit status: 3

## The one that is two

The middle two are the same sentence for **two faults with different
repairs**: a missing executable bit is a `chmod`, and an executable file on a
filesystem mounted `noexec` is a mount option that no `chmod` will ever touch.

That is 0178 one layer up. systemd has mounted `/run` `noexec` by default
since v256; netcfgd wrote dhcpcd's hook there; the journal carried
`script_runreason: Permission denied` **1,350 times** while netcfgd reported
success. It took a day to find with the answer sitting in a mount table.

So `netcfgd_sys::process::exec_refusal` looks: it resolves the program the way
an exec would -- an absolute path as given, a bare name along `PATH` -- and
reads the mode. A file with no executable bit is named with its mode. A file
that has one and was refused anyway can only be the mount, and the message
says so and names the two directories systemd mounts that way.

**It adds nothing where it has nothing to add**: another errno, or a program
that is not there at all, where the caller's own "install one of these" is the
better sentence.

## What is checked

`tests/live/exec_refused.sh` drives all four through a real `ncfg apply` with
`PATH` pointed at a directory it controls, and asserts the messages stay
distinct -- including the two negatives that are the point of the change: a
client that is present but unexecutable **must not** be answered with "install
dhcpcd", and one on a `noexec` mount **must not** be answered with "no
executable bit". Sabotaged back to the kernel's four words, five checks go
red.

The control is in the same script: a client that runs and exits 0 must leave
the apply succeeding. Without it, an apply that could not start anything at
all would satisfy every refusal check above.

Unit tests beside `exec_refusal` cover the mode and the mount branches, and
the two cases where it stays quiet. They need no mount: the function reads
what is on disk, and *that* is what decides which of the two remains.

## The three audits together

0180 writes, 0181 reads, 0182 execs. The pattern across them:

* **Writes**: four silent records. The failure was heard by nobody.
* **Reads**: `is_file()` answering `false` for a file it could not examine, so
  an unreadable configuration became an empty one and netcfgd deconfigured the
  machine. The failure became a false statement.
* **Execs**: sound already, except that one message covered two repairs.

The direction of the risk changes with the operation, and so does the fix: a
write needs to be *heard*, a read needs to not be *guessed*, and an exec needs
to be *diagnosed*.
