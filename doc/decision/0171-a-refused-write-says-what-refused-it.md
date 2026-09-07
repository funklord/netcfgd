# 0171: a refused write says what refused it, and who else could have done it

Status: accepted
Date: 2026-09-07
Milestone: M8; completes the collapse
[0127](0127-netcfgd-is-the-only-writer-and-the-socket-carries-the-rest.md) built
and repairs the drift [0161](0161-the-sandbox-grants-a-file-not-a-directory.md)
left between two copies of one fallback

## The report

"Fix all the `cannot write` bugs when changing config in netcfgd. Because it
happens every time I try to change anything."

## What was measured

Every configuration-changing verb, run against a directory it may not write,
with no daemon listening:

    config put      could not write .../conf.d/thing.conf:
                    No such file or directory (os error 2)
    config rm       could not remove .../conf.d/existing.conf: Permission denied
    profile save    could not create .../profile/office: Permission denied
    secret set      could not create .../secrets: Permission denied
    wifi add        cannot write ... and nothing is listening on ... -- so there
                    is nowhere to put this network. Start netcfgd, or run this
                    as somebody who can write the configuration

Five verbs, one situation, five answers, and the first one is not true.

## Four faults, one family

**1. The fallback spoke over the cause.** `write_atomically` stages a
temporary beside the target and falls back to writing in place when the
directory refuses it. The fallback opens an *existing* file on purpose (0161).
For a file that is not there yet it therefore answers `ENOENT` -- and that
answer replaced the `EROFS` or `EACCES` that was the real reason. The
operator is told a file they have just asked to create is missing, and the
directory that refused them is not mentioned.

`netcfgd-dns`'s copy of this fallback takes the staging error as an argument
and names both halves. `netcfgd-host`'s did not. The note on the host copy
says why that matters -- "Two copies of one rule is how they come to
disagree" -- and they had.

**2. A read-only filesystem was not a refusal.** `InstallError::denied` was
set "from `ErrorKind::PermissionDenied` and from nothing else", so the one
message that names both halves was switched off in exactly the case this
tree keeps meeting: `ProtectSystem=` is a mount, not a mode, and it answers
`EROFS`.

**3. Only `wifi add` had the second half.** A refusal and "there is no daemon
to ask" are two different things to do about one failure. Every other verb
said the first only, so a reader went looking for a permission to grant when
starting netcfgd would have done.

**4. `ncfg profile save` never asked the daemon at all.** Alone among the
write verbs it wrote locally whatever was listening. `Request::ProfileSave`
exists, the daemon serves it, the authorizer places it at the `admin` tier --
and nothing sent it. An unprivileged operator with netcfgd running got
`could not create /etc/netcfgd/profile/<name>: Permission denied` for a
request that would have worked.

## Decided

- The fallback carries the staging error and every failure names it. The
  composed message names the **directory**, gives the kernel's word for the
  refusal, says whether the file was there to write in place, and -- for
  `EROFS` only -- says that a systemd unit grants a path with
  `ReadWritePaths=`. The `io::ErrorKind` is the staging error's, so callers
  classify the refusal that happened rather than an artifact of the fallback.
- `denied` counts `ReadOnlyFilesystem` as well as `PermissionDenied`.
- The second half is one function, `refused_locally`, used by `config put`,
  `config rm`, `profile save`, `secret set` and `wifi add` -- which loses the
  hand-written copy `wifi add` carried. It fires **only** on a refusal: a
  drop-in rejected for not compiling has nothing to do with who may write,
  and telling that reader to start a daemon would send them to a daemon that
  refuses the same text.
- `ncfg profile save` takes the socket first, like every other write verb.

## And one the fix uncovered

Saving a profile on a machine whose base configuration has a `global` block
was refused outright:

    /etc/netcfgd/profile/weekend/00-saved.conf:10:2: `control` is already
    set in `global`

The snapshot is the effective document rendered back out, and the renderer
marks a redefined `interface`, `device`, `network` or `bluetooth` block
`override` while never marking `global` one -- deliberately, since 0147 makes
`global` a singleton whose sub-blocks merge and an `override global` would
discard the parts the snapshot does not mention. So the snapshot restated
`control` and collided with the base.

**Every machine whose desktop client can reach the daemon has a `global
{ control { ... } }` block**, because that is what 0127 requires to grant it.
`ncfg profile save` therefore did not work on the machines most likely to run
it, and `tests/live/profile.sh` could not have caught it while it did not
exercise `save` -- the test's own configuration must set that block for the
same reason.

What the base already says identically is now dropped from the snapshot
before rendering. The effective document is unchanged, because the profile
layers on the base and the base still supplies it -- which is what the
existing proof checks. The trimmed copy is used for rendering **only**: the
proof compares against what was really running, since comparing against the
trimmed copy would agree with whatever the trimming did, including with a
mistake in it.

**The half left open** is a profile carrying a `global` setting the base also
sets to something *else*. The language has no way to say that today, and
giving it one is a decision about `global` and `override` that belongs to the
copyright holder rather than to this record. It is refused with the existing
message rather than written out broken. project.md 10.58.

## Measured

    reverted                          which check goes red
    the fallback's own error          6 of the 7 new checks in sandbox_writes.sh
    denied without EROFS              "and that there was nobody to ask instead"
    the socket-first save             "saving asks the daemon rather than
                                       writing the file itself"
    the global trimming               all four new checks in profile.sh
