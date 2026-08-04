# 0069: Adding a network is writing a file

Status: accepted
Date: 2026-08-03
Milestone: the last of the laptop list

## Context

`ncfg wifi connect ID` joins a network the configuration already describes, and
until now there was no way to make it describe one. Joining a café's wireless
meant opening an editor as root, writing a `network` block, writing a passphrase
into `/etc/netcfgd/secrets/` and remembering `chmod 600` -- on the machine that
has no network yet, which is the machine least able to look up how.

Every other `ncfg wifi` subcommand asks the daemon. This one cannot: the daemon
runs with `ReadOnlyPaths=/etc/netcfgd`, and nothing in netcfgd's protocol writes
configuration. Nor should it -- 0030 settled the shape when the NetworkManager
shim needed the same thing, and the answer was that a client writes the
operator's configuration directly and the daemon notices by inotify.

## Decision

**`ncfg wifi add SSID` writes the two files an operator would have written**, and
nothing else changes: one `network` block in `conf.d/wifi-<id>.conf`, the
passphrase in `secrets/<id>` at mode 0600, and a `@secret:` reference between
them. There is no state, no registry and no marker: forgetting a network is
`rm` on that file, and editing one is an editor.

```
$ ncfg wifi add HomeFiber
passphrase for `HomeFiber`:
wrote /etc/netcfgd/conf.d/wifi-HomeFiber.conf
wrote /etc/netcfgd/secrets/HomeFiber (mode 0600)
`ncfg plan` shows what it changes; `ncfg wifi connect HomeFiber` joins it now
```

Five things this settles, each of which could have gone another way.

**The passphrase is never an argument.** `ps` shows an argument to every user on
the machine and the shell writes it to a history file, and neither is undone by
noticing afterwards. On a terminal it is prompted for with echo off; on a pipe it
is one line of standard input, which is what makes the command scriptable without
a passphrase ever reaching a command line. There is deliberately no
`--passphrase` flag to be talked into, and `tests/live/wifi_add.py` asserts that
there is not.

**Echo off belongs in the audited crate.** `netcfgd-sys::term` gained an
`EchoOff` guard -- `tcgetattr`, clear `ECHO`, restore on drop -- next to
`is_terminal` and `size`, because that module's own header says why it exists:
constraint 4 confines `unsafe` to one crate, and that crate is where the libc
boundary lives rather than where netlink lives.

The termination signals are blocked for exactly as long as echo is off, using the
`Signals` type that exists because a killed TUI once left a shell with `ECHO` and
`ICANON` both cleared. So `^C` at a passphrase prompt aborts the command *after*
the terminal is restored rather than instead of it. `TCSAFLUSH` on both calls,
which discards anything typed before the prompt took effect -- otherwise a
keystroke that arrived in the gap is echoed and becomes part of the passphrase.

**An id is a label, a filename and a secret name at once, and the strictest wins.**
A quote or a backslash would have to be escaped in the block; a control character
in a config file is never intentional; a `/` or a `..` is refused because the
secret's name is a path under `secrets/` and a configuration that could name any
path could read `/etc/shadow` as a passphrase. An SSID that fails any of those is
refused with the fix -- `--id` gives a plain label and the SSID is written out
exactly, as hex, which is the mechanism the DSL already had for a name that is
not text. Non-ASCII labels are fine and there is a test for one.

**The passphrase is checked where it can still be fixed.** 8 to 63 characters and
no control characters: exactly what `netcfgd-supplicant` refuses before it sends
one. Refused there, the failure is a bare `FAIL` at association time, half an
hour after the file was written. The length is reported and the value never is,
which is `netcfgd-secret`'s rule everywhere.

**What it writes, it reads back.** After writing, the whole configuration is
compiled again through the same loader the daemon uses -- drop-in ordering,
includes and all -- and if it does not compile, or does not contain the network
that was asked for, both files are removed and the compiler's diagnostic is the
error message. A generated config file that does not compile is worse than no
file at all, because it takes every other interface on the machine with it.

## What is written down and what is not

Four flags: `--id`, `--open`, `--wpa2`/`--wpa3`, `--hidden`, `--priority`. What
earns a flag is what a network cannot be *joined* without -- `hidden`, because
without `scan_ssid=1` a hidden network simply never appears; the security, because
there is no guessing it -- plus what has to be decided while the passphrase is in
hand, and the one thing an operator adding a second network immediately wants.

Everything else is an edit away in a file whose path the command prints. In
particular **the defaults are written out nowhere**: netcfgd's PSK default already
negotiates WPA2 and WPA3 both, `autoconnect` is already on, `metered` is already
off, and a generated file that restated them would be a list of things to wonder
about. `--wpa2` exists for an access point that mishandles the transitional mode,
which is a real thing and not the default case.

An `--open` network says out loud that it has no security, because an operator who
meant `--wpa2` and typed `--open` gets a network that works and a laptop that
talks in the clear.

## Two things the command says that no gate could

**A network profile is not bound to a device.** So a configuration with no radio
in it compiles perfectly, joins nothing, and looks entirely correct -- which is
0061's rule again: a thing that compiles either does something or says it does
not. When no device in the configuration has a `wifi` block, the command says so
and gives the two lines that fix it. It is a note rather than a refusal: adding
the network first and the radio second is a reasonable order to work in.

**A machine with no configuration at all is the case this is for.** Every other
`ncfg` command has nothing to do without one and says so. This one treats an
empty config directory as an empty document and writes the first network into it,
because refusing to add the first network on the grounds that there are no
networks would be a fine joke and a useless tool.

## What this found

**Three argument parsers, two of them wrong.** `parse_options` walked the
arguments knowing which flags take a value; a separate `positional` helper walked
them again with its *own* list of the same thing; and `explain` did neither,
taking arguments up to the first `--`. The lists had already drifted --
`--factory-dir` and `--strand-credentials` were missing from the helper's -- so
`ncfg wifi --factory-dir /some/dir scan` read the directory as a subcommand, and
`ncfg explain --json interface eth0` found no subject at all. One walk now returns
both the options and the positionals, which cannot disagree with itself, and a
test asserts every value-taking option consumes its value.

**`secrets/` had no owner.** `make install` deliberately does not create it
(constraint 2: the filesystem reflects use), so its mode belongs to whichever
command first needs it -- and until now nothing did, which meant nothing had ever
decided. It is created 0700, so the directory does not list which networks a
machine remembers to every user on it. An existing one is left exactly as it is,
mode included: that mode is the operator's, and quietly tightening it would break
a machine that had deliberately opened it to a group.

## Consequences

- A laptop can join a network with one command and no editor, which was the last
  item on the list in project.md section 10 that needed root and an editor.
- The write is atomic, through a temporary file in the same directory carrying its
  final mode from the moment it exists -- so a secret is never briefly
  world-readable under another name, and the daemon's inotify watch never sees
  half a file. That is `netcfgd-nm`'s `write_atomically`, reimplemented in
  `netcfgd-host::config` rather than shared: the shim depends on `netcfgd-proto`
  and `netcfgd-model` and nothing else on purpose (0030), and the packaging gate
  enforces it.
- `tests/live/wifi_add.py` drives a real pty, because a pipe has no echo to turn
  off: a test that drove standard input through one would pass whether the code
  cleared `ECHO` or not. Sixteen checks, including that the passphrase appears in
  neither the terminal, the config file, nor `ncfg show`.
- Every gate here has been seen to fail. Echo left on, the secret written 0644,
  the directory left at the umask, a block rendered without its closing brace, and
  the duplicate check deleted -- five deliberate breaks, five failures in the
  right check, and the rollback proved by the fourth: the command refused, quoted
  `unclosed block \`network\`` with the file and line, and left both directories
  empty.
- `+20 KB` installed.

## What is left

**`ncfg secret set NAME` still does not exist**, and until this session the
compiler's own diagnostic for a missing passphrase told the reader to run it --
0061's disease in a help string rather than in a config key. The help now names
the file and the mode, and `ncfg wifi add` for the one case that is automated.
Design section 3.3 specifies the command, this one now contains everything it
needs -- an atomic 0600 write and a no-echo prompt -- and a passphrase for a
WireGuard peer or a DSL line still has to be written by hand. It is a small
command and a separate one.

**An enterprise network cannot be added this way.** `wifi { eap = ... }` wants an
identity, a method, a CA certificate and sometimes a client certificate, which is
a form and not a flag list; `dot1x` on a wired port is the same shape. Both remain
an editor's job, which is the honest answer rather than six more flags.

**Nothing removes a network.** `rm` on the file is the whole of it and the command
says so, but an `ncfg wifi forget ID` that also removed the secret -- the way the
shim's delete path does -- would stop a passphrase outliving the network nobody
refers to any more.
