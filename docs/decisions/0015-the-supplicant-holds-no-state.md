# 0015: the supplicant holds no state

Status: accepted
Date: 2026-07-29
Milestone: M3

## Context

Constraint 1: config files under `/etc/netcfgd` are the only authority.
Everything netcfgd does traces to one, and `/run` is derived and disposable.

Wifi is the first feature where that is not free. Both Linux supplicants keep
their own network database -- credentials, priorities, which network is
enabled -- and both will act on it without being asked. Left alone, a
supplicant is a second source of truth that writes itself, and the failure it
produces is the worst kind for this project: `ncfg plan` reports nothing to do
while the machine associates with a network `/etc/netcfgd` has never heard of,
and `ncfg explain` has no honest answer.

wpa_supplicant can be told not to do this. iwd cannot, which is decision
0014's real reason.

## Decision

**wpa_supplicant runs with no persistent configuration, and netcfgd supplies
every network over the control socket.**

- Started with a control interface and no config file, or with a minimal one
  containing nothing but `ctrl_interface`.
- `update_config=0`, **set explicitly**. It is the default, and relying on a
  default for the property that keeps constraint 1 true is how the property
  quietly stops holding after somebody's distribution patches a config
  template.
- Networks arrive by `ADD_NETWORK` / `SET_NETWORK` / `ENABLE_NETWORK` at apply
  time, from the compiled document, and are removed by `REMOVE_NETWORK` when
  the document stops asking for them.
- On startup netcfgd calls `REMOVE_NETWORK all` before adding anything, so a
  supplicant that was started by something else, or survived a crash, does not
  contribute networks nobody can account for.

The supplicant becomes what netcfgd needs it to be: a mechanism that performs
association and key management, holding no opinion about which network it
should be on.

## Consequences

**The document really is the only authority**, including for wifi, and
`ncfg explain` can say so without qualification. That sentence is the whole
reason for this record.

**Restarting the supplicant loses nothing**, because there was nothing to
lose. netcfgd re-populates it from the document, which is the same path used
at boot -- so the recovery path is the normal path rather than a special case
that only runs when something has already gone wrong.

**A user cannot join a network with `wpa_cli` and have it stick.** That is
intended and will surprise somebody: the association works, and then netcfgd's
next reconcile removes a network the document does not contain. The drift
report has to name what happened and point at the config, or it will read as a
bug. This is the wifi instance of the same rule that governs a hand-added
address.

**netcfgd is responsible for the supplicant's lifetime.** Nothing else is
going to start a supplicant with no configuration, so netcfgd starts it, and
the `backend.start` machinery from M1 already models that.

## Alternatives considered

**Let wpa_supplicant keep its own config and reconcile against it.** Rejected.
It makes `wpa_supplicant.conf` a second config file that netcfgd would have to
parse, own, and fight over with every other tool on the machine -- and the
project exists partly because NetworkManager splits truth between keyfiles and
internal state.

**Write the supplicant's config file from the document at apply time.**
Tempting, because it is how most tools do this, and rejected because it makes
netcfgd's authority depend on nobody else editing that file. The control
socket has no such ambiguity: the running supplicant's network list came from
netcfgd this boot or it does not exist.

**Rely on `update_config=0` being the default.** Rejected above. A silent
default is not a control.
