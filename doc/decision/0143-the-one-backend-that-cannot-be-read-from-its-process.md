# 0143: the one backend that cannot be read from its process

Status: accepted
Date: 2026-08-27
Milestone: M8; the last of the adoption work

Completes [0140](0140-a-handle-must-be-recoverable-from-the-process.md), whose
mechanism does not reach dhcpcd, and says why in a way 0140 could not have.

## The problem 0140's rule cannot solve

0140's rule is that a handle must be recoverable from the process. It works
because netcfgd starts its supplicant with `-P <path>` and its udhcpc with
`-p <path>`, and both keep that path in their own `argv` for as long as they
live -- so a `/proc` scan for a whole-argv match finds them after the pid file
has gone with `/run/netcfgd`.

**dhcpcd keeps nothing.** It calls `setproctitle`, and measured on a live
orphan:

    /proc/768053/cmdline   ->  "dhcpcd: wlp0s20f3 [ip4]"  (23 bytes, then NULs)
    /proc/768053/environ   ->  4494 bytes, 0 of them non-NUL

against a control process spawned identically that kept 4419 non-NUL bytes and
its marker. The title rewrite consumes the argv block **and the adjacent
environment block**. So an environment marker fails too, and it fails twice
over -- an environment is inherited, so dhcpcd's privsep children and every
hook it forks would carry it, and a scan would match a set rather than a
client.

There is nothing in the process image to find.

## What does survive, and the decision

**dhcpcd's own memory of its `-f` argument.** It stores the string and recites
it verbatim -- symlink and all, no `realpath` -- to anyone that asks
`--getconfigfile` on its control socket.

So: **netcfgd starts dhcpcd with `-f <run>/dhcpcd/<iface>-<family>.conf`, and
recovers ownership by asking for that path back.** A marker held in the
process's own memory, recited through a channel `setproctitle` cannot reach.

### The `-f` target is a symlink to the operator's config

`-f` *replaces* `/etc/dhcpcd.conf` and dhcpcd has no `include` directive, so a
config of netcfgd's own would silently drop whatever the operator had --
`duid`, `persistent`, `require dhcp_server_identifier` and the rest of a stock
Debian file. Pointing at theirs keeps it, and measured, dhcpcd reads the
target's options through the link while reciting the *link's* path when asked.
Exactly the pair of properties this needs.

**A dangling symlink is not a failure.** Measured: dhcpcd logs `read_config:
...: No such file or directory`, takes a normal lease and applies its defaults
-- byte for byte what it already does on a machine with no `/etc/dhcpcd.conf`.
Only the path in the message changes, so netcfgd need not create a target.

**The symlink is re-created on adoption**, which is the other half. The `-f`
string in dhcpcd's memory survives the wipe, so recovery is never blocked -- but
a later `dhcpcd -n` reload would read a dangling path and silently drop the
operator's options. Measured: `NCFG_PROBE` went from `yes` to unset across
exactly that sequence.

## Three things the obvious implementation gets wrong

Each was measured, and each breaks a platform this exists to serve.

**The privileged socket, not the unprivileged one.** dhcpcd 10.5.0 removed
`<iface>-4.unpriv.sock` outright -- "a breaking ABI change", in its own commit
message -- and Debian sid ships 10.5.2 today. netcfgd runs as root, so the
privileged socket is available wherever a socket exists at all and answers this
command identically.

**The length prefix is a native `size_t`.** dhcpcd's `control.c` writes
`iov[0].iov_len = sizeof(size_t)`: eight bytes on amd64, **four** on 32-bit
ARM, big-endian on a big-endian MIPS. A `u64::from_le_bytes` works on the
machine it was written on and on none of the others. netcfgd takes the last run
of printable bytes instead -- a path holds no NUL and no control character, and
dhcpcd sends exactly one string.

**"Read to the first NUL" is also wrong, and this one was written and caught.**
The prefix's low byte is printable for any ordinary path: a 33-byte path gives
`22 00 00 00 00 00 00 00`, and `0x22` is `"`. A scan stopping at the first NUL
stops after one character. There is a unit test carrying the measured bytes.

**Only `--getconfigfile`, and only with a deadline.** `--getinterfaces`,
`--isprivileged` and a bare `-q` each produced no reply *and no close*, past
four seconds, on both sockets. 250 ms is generous: the command is answered by
dhcpcd's separate `[control proxy]`, which replied in 0.00s even with the main
process `SIGSTOP`ped.

## What this does not fix, and it is the part to read

**It is prospective only.** A dhcpcd already running keeps the config path it
started with -- measured, a later invocation does not change it -- so no
existing orphan can be adopted. The machine that produced this investigation
had one running for hours; this prevents the next, it does not cure that one.

**A stranger's dhcpcd stays unstoppable, correctly.** netcfgd refuses and says
so, per 0141's default, and the client keeps renewing until an operator acts.

**`--getconfigfile` is undocumented** -- zero matches over 891 lines of
`dhcpcd.8` -- and 10.5.0's socket removal proves this interface carries no ABI
promise. The parser fails loudly rather than falling through to "unprovable" if
the reply stops parsing, but a future dhcpcd could remove the command and
netcfgd would lose adoption for this backend with no warning.

## Consequences

**0140's rule holds and its mechanism does not generalise.** "A handle must be
recoverable from the process" is right; "from its `argv`" was the
implementation, and 0140 reads as though it were the rule. This is the second
kind of mark, and a program that rewrites its own image needs one.

**netcfgd now names `/etc/dhcpcd.conf`**, which the sandbox gate caught
immediately -- an unclassified `/etc` path in the sources is either a write the
unit must allow or a read somebody should declare. It is classified read-only
beside the supplicant's certificates, and for the same reason: netcfgd never
opens it, it passes a path and another daemon opens it in a sandbox this unit
does not bound.

**The count of clients cannot prove this fix**, and the test says so. A second
`dhcpcd -b` against a running one is a silent no-op -- it prints "sending
commands to dhcpcd process" and exits 0 having started nothing -- so netcfgd
reports success whether it adopted or blindly re-ran. What proves it is the
adoption message and, more importantly, **the refusal of a stranger**: a client
started with a config path netcfgd did not choose must not be adopted, and the
control for that failed exactly as it should when the comparison was widened.

## Alternatives considered

**An environment marker.** Rejected on measurement: the block is destroyed, and
it would be inherited by children even if it were not.

**Persisting the pid outside `/run/netcfgd`.** Rejected by 0135 for the
ownership record and the reasoning carries: a claim that outlives the objects
it describes is worse than no claim.

**Stopping dhcpcd on a clean exit so there is nothing to adopt.** That is
`KillMode` (0142), and it is the current state -- not because it is right, but
because holding what cannot be re-adopted was worse. This record is what makes
the alternative available.
