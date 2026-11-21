# 0327: three tiers -- view, laptop, root

Status: accepted
Date: 2026-11-21
Milestone: M8's desktop half
Supersedes: the tier names of [0013](0013-three-things-a-caller-may-be-allowed-to-do.md),
and the argument in it and in `authorize.c` that `admin` is survivable

## Context

The holder deferred an overhaul of the permission system with the shape
already given (project.md, *Open: the permission system needs an
overhaul*), and released it on 2026-11-21: "go ahead with the permission
overhaul".

The argument in that section, kept here because it is what decides every
placement below: **configuration access to a network configuration tool
is root on that machine.** The default route, the resolvers, NAT,
forwarding, and which access point an `@secret:` is offered to are all
ordinary configuration, and each one is a man in the middle. A machine
whose traffic somebody else chooses reaches root by an ordinary path -- a
poisoned resolver, a poisoned package source. **Remote configuration access
to several hosts is root on all of them.**

The tiers said otherwise. `observe`, `wifi` and `admin` read as a gradient
of danger, and `authorize.c` argued `admin` was survivable because
`ncfg_authz_check_content` refuses hooks and probes from a caller who is
not root. It does refuse them, and the machine is still lost by the
indirect route. A machine with `admin = "group:netcfgd"` (this one, on the
day) has handed that group root while its file called the setting a middle
one.

## Decision

**Three tiers, named for what they are.**

- **`view`** -- reading, and nothing else. Every request `observe` held.
- **`laptop`** -- what a person at their own machine must be able to do:
  join and leave networks, add and forget one, take a radio or a tunnel up
  and down. Every request `wifi` held. Wide and dangerous, and necessary
  anyway; **what bounds it is the shape of what it can send** -- typed
  requests carrying no configuration text, 0117's principle used as the
  boundary rather than as a mitigation.
- **`root`** -- everything else, called root with no pretence that it is
  less. Every request `admin` held. Opening it to a group is handing that
  group root, and the file now says so in the word it uses.

**The tiers nest.** A caller who satisfies `root`'s principal holds
`laptop` and `view` too, and one who satisfies `laptop` holds `view`. Each
of the three was independently assigned before, so `admin = "any"` beside
`observe = "root"` let anybody apply and nobody look -- a policy no site
means. The same holds for `remote`: `root = true` opens the lower two
remotely as well. The principals are still written one per tier; what
changed is that a higher grant includes the lower.

**The old words are still read.** `observe`, `wifi` and `admin` in a
`control` or `remote` block set `view`, `laptop` and `root`. A
configuration file records choices (working-practice), and `admin =
"group:netcfgd"` was a choice somebody made; reading it as `root =
"group:netcfgd"` keeps that choice exactly. The compiler has no warning
channel -- a diagnostic fails the compile, and failing a working machine's
policy on upgrade is the wrong trade -- so the old words are read quietly,
and everything netcfgd writes or shows (`ncfg control`, `show`, the GUI)
uses the new ones.

**On the wire the new names are the only ones sent**: `hello`'s `tiers`
and the document's `globals.control` and `globals.remote`. The schema
version stays where it is: [0038](0038-versioning-starts-at-the-first-release.md)
pins it until netcfgd ships, there being no consumer to promise anything
to. The client library reads both spellings in `tiers`, so a newer GUI
against an older daemon still knows what it holds.

**`ncfg_authz_check_content` stays, and its claim shrinks.** It refuses
hooks, `run_as` and probe scripts to anybody but uid 0 on this machine,
including a caller holding the `root` tier through a group. That closes
the *direct* route -- a program netcfgd runs as root, chosen by the caller
-- and nothing more; the comments no longer say it makes a tier safe.
Keeping it costs nothing, and removing a protection is not something to do
in passing. Its refusal says "uid 0" so it is not read as the tier.

## What this settles that was open

- **Showing a stored credential stops being a question at the `root`
  tier.** A caller who can choose the machine's resolvers and repoint an
  SSID gains nothing from being shown a passphrase. It stays a question for
  `laptop`, which is the one meant to be less.
- **`wifi_add` at `laptop` beside `config_put` and `secret_put` at `root`**
  is no longer an inversion: the tier is bounded by the shape of its
  requests, and the two writes that take text are root because text is.
- **`dns { mode }`, `nat`, and repointing an `@secret:`** are all `root`,
  and `root` no longer claims to be less than root, so the three items the
  open section listed as inversions are each where they belong.
- **`ap_stations` stays in `view`**, and the protocol document keeps
  saying what it exposes: other people's hardware addresses, signal
  strengths and DHCP names. The shipped policy opens `view` to the
  `netcfgd` group (0118), not to `any`.

## Rejected

- **Keeping the old words and changing only the comments.** The file is
  what an operator reads; `admin = "group:x"` would go on reading as a
  middle setting, which is the whole fault.
- **Making `root` mean uid 0 only**, with no principal. A site that
  genuinely wants a group of operators to configure its machines -- the
  fleet case -- would then have to give them uid 0, which is more than the
  tier hands out, not less.
- **Independent tiers kept as they were.** Nothing a site writes needs a
  writer who cannot read.
