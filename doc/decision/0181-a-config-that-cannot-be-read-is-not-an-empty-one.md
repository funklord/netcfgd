# 0181: a config that cannot be read is not an empty one

Status: accepted
Date: 2026-09-09
Milestone: M8; the read side of 0180's question, asked immediately after it

## The question

> now check the read errors too

0180 inventoried every write. This is the same pass over every read, and the
finding is worse, because the failure modes are not symmetrical.

**A write that fails loses something netcfgd wanted to keep. A read that fails
can produce a false statement about the machine** -- and netcfgd acts on
statements.

## What the inventory found

Ninety-seven reads in the shipped crates: twelve propagate, thirty-two are
handled where they stand, and fifty-three drop the error. **Nearly all of
those fifty-three are right**, and the reason is that absence is usually the
answer: no pid file means nothing is running, no record means netcfgd has
nothing to compare against. The rule is already written down on
`dhcpcd_control::config_file_of` -- *"`None` is not 'somebody else's', it is
'netcfgd could not tell', and the caller must treat the two differently"* --
and the observation code follows it carefully. `read_wireguard_currency` and
its three siblings all leave `None` for a record they cannot read, and say why.

There is a second population the `fs::` search does not reach: **forty-seven
`exists()`, `is_file()` and `is_dir()` calls**, which swallow the error by
construction. That is where the fault was.

## Measured, on a real interface

`/etc/netcfgd/netcfgd.conf` made a symlink to itself:

    $ ncfg apply
    ok   addr.del read0  addressing: <absent> (was 10.11.0.1/24)
    $ echo $?
    0

The loader's gate was `if main.is_file()`, which answers `false` for a file it
cannot examine. So an unreadable configuration became **an empty
configuration**, and an empty configuration is not nothing -- it is the
statement *nothing on this machine is netcfgd's*, which netcfgd then acted on
by taking the address off the interface and reporting success.

Four ways to reach it, none requiring a strange machine: a symlink loop, a
dangling symlink (a config on a disk that is not mounted -- the most likely of
the four), a directory in place of the file, and any `EIO` from the disk. The
same gate guarded `conf.d`, so the wifi networks and the DNS policy could
vanish from the document the same way.

## The rule

**Three states, kept apart, where `is_file` has two.**

* not there -- skip it. A machine with no `/etc/netcfgd` is an ordinary
  machine, and `load`'s doc comment has always promised that an absent config
  is not an error.
* there -- read it. If it turns out not to be a regular file, `add_file`
  refuses with the sentence it already had about devices and fifos.
* **cannot tell -- refuse, naming the path and the kernel's own words.**

`present()` does that, and looks at the link itself before resolving it:
`metadata` follows a symlink and answers `NotFound` for a dangling one, which
would have put the likeliest case back in the "not there" bucket.

## The same shape, one crate over

`netcfgd-secret` mapped *every* `metadata` failure to `NotFound`, whose message
ends with "`ncfg secret set <name>` stores one". That is right for a secret
nobody has stored and **wrong for one sitting behind a permission error or a
symlink loop** -- wrong, and destructive if the advice is taken, because
storing over it replaces a credential that was there. Now only `ENOENT` says
missing; anything else says what the kernel said.

## What is checked

* `tests/live/config_unreadable.sh` drives all four unreadable shapes against a
  real interface and requires the apply to refuse, to name the path, and **the
  address to still be there afterwards**. Sabotaged back to `is_file()`, eight
  checks go red, including the one that matters: the interface loses its
  address.
* Unit tests beside `load` for each shape, and beside the secret store for the
  mislabelled read -- symlink loops throughout, because they need no privilege
  and no mount, where a mode is walked straight through by root (10.71).
* The control is in the same script and is not optional: **an absent config
  still applies, and still takes the address back.** The fix could easily have
  been "refuse whatever is not a readable regular file", which would break
  every machine that has no netcfgd configuration at all.

## What was looked at and deliberately left

`network_manager_claims` treats a device file it cannot read as unclaimed. The
alternative -- unreadable means claimed -- would have netcfgd refuse an
interface on any transient read error under a daemon that is running, which is
worse than the case being fixed. It is gated behind `daemon_is_running`, which
*does* fail closed: an unreadable `/proc` returns "running", keeping the guard
rather than starting a second supplicant on somebody else's radio. That
asymmetry is deliberate and now written down.
