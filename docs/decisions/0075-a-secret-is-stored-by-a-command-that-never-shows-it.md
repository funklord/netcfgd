# 0075: a secret is stored by a command that never shows it

Status: accepted
Date: 2026-08-03
Milestone: the laptop list, and the last credential that needed an editor

## Context

Section 2's rule is that the desired-state document never contains secret
material: `private_key = "@secret:wg-key"` is an indirection, and the `file`
provider reads `<config-dir>/secrets/wg-key`. Writing that file was an editor, a
`chmod 600`, and remembering both.

[0069](0069-adding-a-network-is-writing-a-file.md) built every piece of the answer
for wireless -- an atomic 0600 write, a directory created 0700 on first use, a
prompt with echo off and the signals blocked around it -- and left the general
case: *"`ncfg secret set NAME` does not exist, and until 0069 the compiler's
diagnostic for a missing passphrase told the reader to run it."* Design section 3.3
had specified the command; nothing implemented it; the help pointed at it anyway.
That is [0061](0061-a-key-that-compiles-does-something-or-says-it-does-not.md)'s
disease in a help string, and 0069 could only fix it by pointing somewhere else.

## Decision

**`ncfg secret set NAME`**, and nothing else.

- **The value is never an argument.** `ps` shows an argument to every user on the
  machine and the shell writes it to a history file. It is typed at a prompt with
  echo off, or read as one line of standard input, which is what makes it
  scriptable. A second positional argument is refused *by name*, because
  `ncfg secret set vpn hunter2` is the thing somebody will try.
- **0600 from the moment the file exists**, set on the open rather than by a
  `chmod` afterwards -- the window between the two is a window. The directory is
  created 0700 if this is the first thing to need it, and an existing one is left
  exactly as it is, mode included: its mode is the operator's.
- **An existing secret is refused, not replaced**, unless `--replace` says so.
  "Set" reads as "overwrite" and for most things it could be, but one of the
  credentials this stores is a WireGuard private key, which
  [0042](0042-only-a-key-nobody-can-revoke-stops-a-plan.md) calls the one thing on
  a machine that nobody can get back. A flag is cheap; that is not.
- **It says what refers to the name.** A secret whose name does not match the
  reference in the document is a file nothing will ever read, and the failure
  arrives later as "no such secret" from a backend. The report walks the compiled
  document -- WireGuard private and preshared keys, PPPoE passwords, 802.1X
  passwords and client keys, wifi PSKs and EAP -- and prints either `used by:
  interface wg0 (private key)` or `note: nothing in the configuration refers to
  `@secret:NAME` yet`. Never the value, and never its length.
- **There is no `get`.** Asking for one gets a sentence rather than an unknown
  subcommand: a secret goes to the backend that needs it and nowhere else, which
  is the whole point of the indirection. Removing one is `rm`, which is 0069's
  answer for forgetting a network and is honest here for the same reason -- there
  is nothing a command could add beyond a longer way to spell it.

**The reader moved rather than being written again.** 0069's prompt -- echo off,
termination signals blocked for exactly as long, restored in the right order --
now lives in one place and both commands call it. The WPA length rules stayed with
wireless, where they belong. Breaking the guard shows the move was real: the
passphrase appears in the transcript of *both* commands, in one patch.

**And the two diagnostics that pointed elsewhere now point here.** The compiler's
help for a bare credential names `ncfg secret set NAME` again -- true this time --
and `netcfgd-secret`'s "not found" says how to store one. That is the moment
somebody needs the command, and a message that names it is worth more than a
manual page nobody is reading at 23:00.

## What the test is worth

The unit tests cover the reference walk with one secret used four different ways
(a peer's preshared key, a PPPoE password, a WireGuard private key and a wifi PSK
in one document), the refusal to overwrite, and the refusal of a value on the
command line.

**The no-echo property needs a pty**, which is why `wifi_add.py` exists at all
(0069) and why it now drives this command too: a pipe has no `ECHO` to clear, so
every check would pass identically on a command that never turned it off. What is
tested there is the *wiring* rather than the mechanism -- and removing the guard
turns four checks red across both commands, with the value visible in the
transcript, which is the same patch proving the reader is genuinely shared.

## Consequences

- A WireGuard key, a DSL password or an 802.1X client key can be stored without an
  editor, and without a `chmod` anybody can forget.
- `+16 KB`, ratcheted. Most of it is the report.

## What is still open

**An enterprise network still cannot be added from the command line.** `eap` wants
an identity, a method and certificates, which is a form and not a flag list -- and
the same is true of `dot1x` on a wired port. This command stores the *credential*
those blocks refer to, which is the half that needed a prompt; the block itself is
still an editor's job, and that is a shape question rather than a missing command.

**Nothing checks that a stored secret is the right kind.** A WireGuard private key
is 44 characters of base64 and a PSK is 8 to 63 characters; this refuses only an
empty value. The wireless path checks its own rules because
`netcfgd-supplicant` knows them -- a general command would need a table of what
each reference expects, which is worth having only once something has got it
wrong.
