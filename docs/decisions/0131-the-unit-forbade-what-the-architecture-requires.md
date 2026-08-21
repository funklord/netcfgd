# 0131: The unit forbade what the architecture requires

Status: accepted
Date: 2026-08-21
Milestone: M8, found by an operator pressing a button

Corrects `packaging/systemd/netcfgd.service`, which enforced a promise
[0127](0127-netcfgd-is-the-only-writer-and-the-socket-carries-the-rest.md)
deliberately abandoned.

## What happened

A desktop client reported "cannot write
/etc/netcfgd/conf.d/radio-wlp0s20f3.conf: read-only file system" after a button
press, and the reasonable reading was that the GUI had gone behind the socket's
back and tried to write a file itself. It had not. It sent `radio_set` over the
socket, exactly as 0127 requires; **netcfgd** tried to write, and was refused by
its own systemd sandbox. The message named the path because the daemon's error
travels back to the client verbatim, which is usually the right thing and here
made a correct client look guilty.

## The chain

- **0069** had `ncfg wifi add` write the operator's files directly, and gave
  the reason plainly: "the daemon runs with `ReadOnlyPaths=/etc/netcfgd`, and
  nothing in netcfgd's protocol writes configuration."
- **0127** reversed exactly that. A client cannot write `/etc/netcfgd`, so it
  sends what it has over the socket and **netcfgd** writes it. That is the
  whole collapse: `config_put`, `secret_put`, `config_delete`, `secret_delete`,
  `wifi_add`'s block and credential, and since this milestone `radio_set`.
- **The unit** was not touched, and still carried
  `ReadOnlyPaths=/etc/netcfgd` under the comment "netcfgd is the only authority
  and netcfgd never writes to it, so the init system enforces what the code
  already promises."

So every write 0127 built was refused on every packaged install. Not on a
developer's machine, where the daemon runs from `target/debug` with no unit at
all; not in any test, because every test writes into a temp directory. The
mechanism had never once run in the configuration it ships in.

## The second copy of the mistake

The same file chose `ProtectSystem=full` over `strict` with this reasoning:

> `full`, not `strict`. Strict would make /etc read-only, and the DNS backends
> legitimately write there.

That is backwards. `systemd.exec(5)`: "If set to `full`, the /etc/ directory is
mounted read-only, too." `strict` takes the whole hierarchy. So the setting
delivered precisely the hazard the comment named it to avoid, and
`/etc/resolv.conf`, `/etc/dnsmasq.d/netcfgd.conf` and
`/etc/unbound/unbound.conf.d/netcfgd.conf` were unwritable as well -- a second,
older, unrelated failure that had been sitting behind the same word.

**Two wrong beliefs about one setting, in one file, neither caught by anything.**

## Decision

**`ProtectSystem=full` stays, and the unit allow-lists what netcfgd writes**,
which is the idiom the setting is designed around: harden everything, then name
the exceptions.

```
ReadWritePaths=/etc/netcfgd
ReadWritePaths=-/etc/resolv.conf
ReadWritePaths=-/etc/dnsmasq.d
ReadWritePaths=-/etc/unbound/unbound.conf.d
```

The `-` prefix on the last three: dnsmasq and unbound are packages a machine
need not have, and a unit that refuses to start for want of a directory
belonging to software nobody installed would be worse than the fault it
prevents. `/etc/netcfgd` is unprefixed because the package creates it and every
client write now depends on it -- an install missing it should be loud.

## Why a gate, and what it can check

`tools/sandbox_gate.py`, in `make packaging`. It reads every `/etc` literal in
non-test, non-comment source and requires each to be either allow-listed by the
unit or named in a small read-only list, and it reports an allow-list entry no
source uses.

This is the tree's "two lists agree" shape --  `uninstall_gate.py`,
`dbus_policy_gate.py`, `privilege_gate.py` -- and it is the same failure mode
each of those exists for: two lists kept in step by memory. It has now cost the
worst outcome of the four, because the disagreement was invisible to every test
by construction.

**What it cannot check is whether a path is writable in fact.** That needs the
unit running as root under systemd. What goes stale is the correspondence, and
that is what is checked. Both bugs above fail it: removing the `/etc/netcfgd`
entry reports two paths, removing the `resolv.conf` entry reports one.

**Comments are stripped before scanning**, because `wpa_supplicant`'s README
example `private_key="/etc/cert/user.prv"` appears in a doc comment and a gate
reporting that is a gate somebody adds an ignore list to. Matching is
component-wise prefix, because that is what a bind mount does --
`/etc/dnsmasq.d` covers the file under it, and `/etc/netcfgd` does not cover
`/etc/netcfgd-other`.

## Consequences

**0069's premise is formally gone.** Its reasoning was already superseded by
0127; what survived was the sentence in a unit file, and that is now corrected
rather than left to be read as current.

**The other init systems were checked and need nothing.** OpenRC and procd
impose no filesystem namespace, so there is no allow-list to keep in step --
which is also why this went unnoticed by anyone running netcfgd there.

**A daemon's error reaching a client verbatim stays right**, and this is the
argument for it rather than against: the message named the file and the reason,
which is what made the fault findable in one step. What it cost was a moment's
suspicion of the client, and the alternative -- a client rewording what the
daemon said -- would have cost the path.
