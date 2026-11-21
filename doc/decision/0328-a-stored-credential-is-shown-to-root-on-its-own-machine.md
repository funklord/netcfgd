# 0328: a stored credential is shown to `root`, on its own machine

Status: accepted
Date: 2026-11-21
Milestone: M8, the desktop
Amends: [0075](0075-a-secret-is-stored-by-a-command-that-never-shows-it.md), whose "there is no `get`" now holds for everybody but the `root` tier; rests on [0327](0327-three-tiers-view-laptop-root.md) and [0029](0029-a-profile-is-a-projection-and-secrets-do-not-travel.md)

## The holder's words

"We make the passwords hidden from everyone except admin." (2026-11-21, answering
the question project.md had asked that morning: whether netcfgd should show a stored
credential at all.)

## Context

0075 stored credentials by a command that never shows them, and said there is no
`get`: a secret goes to the backend that needs it and nowhere else. That was written
while the tiers pretended `admin` was less than root. 0327 ended the pretence: a
caller at the `root` tier chooses the resolvers, the routes and which access point a
credential is offered to, so being shown a passphrase gives them nothing they did not
have. What it costs them not to have it is real -- somebody at their own laptop who
wants to give a guest the wifi password, which NetworkManager's applet does behind an
authentication prompt, was told to go and read a 0600 file as root.

## Decision

**`secret_get NAME` answers `{"response":"secret","name":...,"value":...}` to the
`root` tier, and to nobody else.**

- **`root`, because that is where showing one stops being a question.** `view` and
  `laptop` are refused by the tier gate like any other request above them. `laptop`
  may still *add* a network with a passphrase (`wifi_add`, [0124](0124-adding-a-network-is-the-wifi-tier-because-0117-made-it-safe.md)) and never read one
  back, which is the half of 0075 that keeps its reason.
- **Never from off the machine, whatever `remote` opens.** A remote `root = true` is
  root here for everything else; this one request is refused by kind before the
  remote policy is asked. A credential travelling over the estate is a different
  thing from a credential shown on the screen of the machine that holds it, and 0029
  already said the first does not happen. This also covers `ncfg secret get --at
  HOST`.
- **Read through the resolver**, as a backend reads it, so `NAME` means exactly what
  `@secret:NAME` means in the configuration. The daemon's copy is wiped when the
  answer is written; `ncfg`'s copies are wiped before they are freed.
- **`ncfg secret get NAME`** prints the value and a newline and nothing else, so a
  script can take it; `--json` names it as well. It asks the daemon and never reads
  the file itself, so a member of a group holding `root` gets the same answer as root,
  and anybody else the same refusal they get for everything else at that tier.
- **A value holding a NUL is refused by `ncfg`**, rather than printed short: a line
  cannot carry it, and root can read the file.

## Rejected

- **Leaving 0075 as it was.** The holder decided otherwise, and 0327 had already
  removed the argument that made `admin` a tier worth hiding a passphrase from.
- **Opening it to `laptop`.** That tier is the one meant to be less; showing a
  credential to it would make every caller who may join a network a caller who may
  read every stored key, the WireGuard private key 0042 calls irreplaceable included.
- **Letting the remote policy open it.** See above: a remote root can do everything
  else to this machine, and still the value does not cross the estate.
