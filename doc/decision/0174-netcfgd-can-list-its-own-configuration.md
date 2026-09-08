# 0174: netcfgd can list its own configuration

Status: accepted
Date: 2026-09-08
Milestone: M8; the listing
[0127](0127-netcfgd-is-the-only-writer-and-the-socket-carries-the-rest.md)
implied and did not build, and what makes
[0172](0172-a-network-you-can-add-is-one-you-can-forget.md)'s argument true for
drop-ins as well as networks

## What was missing

netcfgd lists the probes it holds, the profiles it holds and the credentials
it holds. It could not list its own configuration.

So a client could write a drop-in with `config_put`, remove one with
`config_delete`, and never find out what was there -- which left the removal
reachable only by somebody who already knew the name. The window wrote
drop-ins from two dialogs and showed them nowhere, and 0172's own record says
why that matters: **a list a client can add to and never see is a list it
cannot manage.**

## Decided

`Request::ConfigList` -> `Response::Configs { configs: Vec<ConfigFile> }`, at
the **`observe`** tier.

**`observe`, not `admin`.** Reading which files netcfgd reads adds nothing a
local user does not have: the files are world-readable on disk and the
compiled result is already in `Show`. What it adds is *provenance* -- which
file each part came from -- which is exactly what `Explain` gives per
interface and is `observe` for the same reason. A display that needed a
writing tier to show what is configured is a display that ends up being given
one.

**The text comes with the listing**, for `ProbeList`'s reason: a client needs
it to show one, these are a few hundred bytes, and a second round trip per
file would mean a list and a body that could disagree. Nothing secret is in
them -- a credential is `@secret:name` in the configuration and its value
lives in the store, which no request returns.

**Built on `writable_files`**, which is that function's whole point: it
enumerates what the *loader* reads, so a listing with a rule of its own would
show a machine a file set it is not running. `notes.txt` in `conf.d` is
correctly absent, because the loader takes `*.conf`.

**The order is the answer, not a detail of it.** A later file overrides an
earlier one, so the sequence is what settles "which of these two won" -- which
is why the view draws an `order` column and does not sort by name.

## `netcfgd.conf` is listed and has no name

It carries an empty `name` and `removable` false. It is not a drop-in, no
request writes or removes it, and giving it a name would offer a client a verb
that does not exist for it. **That pair is the thing the view has to get
right**, and it is what the probe's sabotage is aimed at: with `removable`
forced true, the button goes live on the machine's own configuration and one
check fails.

## The tab

`configuration -> files`: the listing, an `order` column, and a read-only pane
showing the selected file.

**Read and remove, not edit.** Writing a drop-in is what the interface and
network dialogs do, each in the vocabulary of the thing being configured. A
text box here would be a second way to write configuration whose only
advantage is that it can express anything -- which is what `check_content`
exists to refuse. Removing needs no vocabulary: it is a name.

## Protocol version

1.1 -> 1.2. An addition, so an older client is unaffected and a newer one can
tell the verb is there.

## Measured

    reverted                      which check goes red
    `removable` forced true       "choosing netcfgd.conf does not offer to
                                   remove it"
    the confirmation bypassed     "answering no keeps the drop-in"

`gui/tests/live/live_config.cpp` drives the tab against a real daemon and
asserts the removal through the daemon rather than the table, so "the row
went" and "the file went" stay two claims.
