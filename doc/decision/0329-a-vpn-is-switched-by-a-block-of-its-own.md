# 0329: a VPN is switched by a block of its own

Status: accepted
Date: 2026-11-21
Milestone: M8, the desktop
Rests on: [0327](0327-three-tiers-view-laptop-root.md), which put a VPN on and off in the `laptop` tier

## The holder's words

"with (a), the switch block" (2026-11-21), choosing among the three options project.md
10.871 set out for turning a WireGuard or OpenVPN tunnel on and off.

## Context

0327 decided the tier: a person at their own machine may turn their VPN on and off.
The mechanism was a language question. `ncfg tunnel up|down` answered only an IPsec
`xfrm` device, by asking strongSwan; WireGuard and OpenVPN netcfgd runs itself, so
"off" for them is configuration. And a drop-in cannot change one key of an
`interface` block: a second block must say `override`, which replaces the first
wholesale (merge.c, section 3), so turning a VPN off would have meant restating the
operator's whole block.

## Decision

**`switch NAME { up = BOOL }`, a top-level block that sets interface `NAME`'s
`enabled`.**

- **It lowers to nothing of its own.** The interface's `enabled` is what it sets, after
  every block is read, so a drop-in read before the file holding the interface still
  finds it. The planner, the document and every client read one field as before. A
  switch naming no interface is refused: one that did nothing would be a VPN somebody
  believes is off.
- **`ncfg tunnel down NAME` on a `wireguard` or `openvpn` device writes
  `conf.d/tunnel-NAME.conf`** holding `switch NAME { up = false }`, as `ncfg wifi
  activate` writes `radio-NAME`. `up` removes the file, which gives the operator's
  word back; if that word is `enabled = false`, it writes `up = true` instead, rather
  than leave the tunnel off having said it was turned on. An `xfrm` device is still
  asked of strongSwan. Both are `tunnel_set` at the `laptop` tier, and the GUI's
  devices tab offers the two buttons on all three kinds.
- **Applied before the answer.** `on_drift` defaults to `report`, so a written switch
  nothing ran would leave a VPN the window calls off carrying traffic. The daemon
  applies the whole interface's part of the plan -- link, addresses, routes, and for
  OpenVPN the daemon -- where a radio's activation applies only its supplicant,
  because a radio's plan holds a DHCP client that cannot lease before association and
  a tunnel's holds nothing like it.
- **An interface held down stops its session daemon.** `enabled = false` only took the
  link down, which is off for WireGuard and not for OpenVPN or PPPoE: their daemons
  keep the session behind a down link and raise it again. `plan/session.c` now
  neither starts nor keeps a session whose interface block is held down. This also
  changes `enabled = false` written by hand on a `pppoe` or `openvpn` interface,
  which now hangs up -- what it should always have meant.
- **`up` is a key here although it is a hook phase.** The parser took a phase's name
  as a hook before looking at the next token; a phase word followed by `=` is now
  read as a key. Nothing a hook could be was taken away: `up = ...` was a parse
  error.

## Rejected

- **(b) `amend interface wg0 { enabled = false }`**, a key-level merge form. Section
  3's rule is against *silent* last-wins, which an explicit word would not break,
  but no block has had one, and it would invite amending any key of any block.
- **(c) a `global { held_down = [...] }` list** in one file netcfgd rewrites whole.
  A read-modify-write of a shared list, where a file per tunnel needs none.
- **Writing a whole `override interface` block.** It restates the operator's block,
  so their next edit of the original is silently shadowed.
