# 0313: every fuzznet program is whole, and netcfgd brings its own user's node

Status: accepted
Date: 2026-11-06
Milestone: fuzznet integration (project.md 10.734 to 10.736)
Amends: [0308](0308-fuzznet-is-linked-into-netcfgd.md) and [0311](0311-fuzznet-is-the-store-and-the-estate-is-the-fleet.md), which left the user's node to a fuzznetd

## The holder's words

> We want to retain netcfgd, All fuzznet-based software has full functionality
> and is able to coexist even when they write the same files and deal with the
> same estate, fuzzypickles does not install fuzznetd, we use it for testing the
> aforementioned coexistence. A fuzznet client and a node are the same thing
> just hardcoded differently and with different code surrounding the cores.

> netcfgd clients need to ALSO be able to connect to a remote netcfgd, for the
> phone client this would be the default and only type of connection. For
> desktop we make local the default as remote is unusual but not impossible.

> But we keep the phone and desktop GUI the same with minor differences
> controlled by mobile or desktop modes like other GUI software here, but some
> things hardcoded like the non-existence of a local root node and prompting for
> remotes on mobile.

## What changes

- **Nothing netcfgd needs is another product's.** 0311's first model named "a
  fuzznetd running as its user", and `--at`, `ncfg nodes` and the fleet view all
  went through one, which nothing installs. The user's node is now `ncfg node`:
  fuzznet's node with netcfgd's numbers, in the program already installed, so it
  costs no size. The phone carries the same core as `libncfgnode.so`.
- **fuzznetd stays in this tree as a witness.** Tests run it, under another
  product's number, on the same store, to show the coexistence.
- **Local is the desktop's default, and needs no node.** Asking for a host
  (`--at`, `ncfg join`, the window's node box) starts this user's node, which is
  left up as an agent is. A verb of this machine never starts one.
- **A phone connects to hosts and nothing else**: no local root node, and its
  first screen prompts for one.
- **One window, in a layout.** `--layout auto|desktop|mobile`, the device's by
  default, as bbq-predictor's. What a device has at all is compiled in and is not
  a mode (`gui/src/layout.h`).

## Rejected

- **A second program, as fzpd is.** netcfgd and `ncfg` are already one binary with
  the whole node linked, so a third name for it would only add an install. The
  phone needs a separate `main` because the daemon is no use there.
- **Starting the node for every client.** Somebody with one machine has no use for
  a process that listens for an estate they are not in.
- **Asking the screen for the layout.** bbq-predictor's reason holds: a touchscreen
  desktop and a tablet in a keyboard case are what it gets wrong.

## Not decided

Whether the node should also be a user unit, for a person who wants it up from
login. Starting on demand serves everything built today.
