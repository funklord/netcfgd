# 0120: The red frame is a process boundary, not a mode

Status: accepted
Date: 2026-08-07
Supersedes part of [0118](0118-two-ways-to-be-allowed-and-one-of-them-is-visible.md)

## Context

0118 said the access tab is "read-only until the operator authenticates as
root, and while it is live it is **surrounded by a red frame**", on KDE 3.5's
pattern. The implementation did not do that. `unlock()` opened the editors and
reddened the frame immediately, with nothing authenticated and no privileged
process anywhere; `pkexec` ran later, at Apply. The document described one
thing and the code did another, and the gap was found by reading the reference
rather than by any gate.

**So the reference was read.** TDE's Control Center is KDE 3.5's, and
`ConfigModule::runAsRoot()` in `kcontrol/kcontrol/modules.cpp` is the whole
pattern:

```cpp
_embedFrame = new TQVBox( parentWidget );
_embedFrame->setFrameStyle( TQFrame::Box | TQFrame::Raised );
TQPalette pal( red );
pal.setColor( TQColorGroup::Background, parentWidget->colorGroup().background() );
_embedFrame->setPalette( pal );
_embedFrame->setLineWidth( 2 );
_embedFrame->setMidLineWidth( 2 );
```

and immediately after it, the thing the frame is drawn *around*:

```cpp
*_rootProcess << tdesu << "--nonewdcop" << "--n";
*_rootProcess << QString("%1 %2 --embed %3 ...").arg(tdecmshell)...
```

`tdesu` prompts for the password **first**. The frame appears around a
separate process, running as root, embedded through XEmbed. The unprivileged
state has its own marker -- `RootInfoWidget`, a framed label with **no colour**
saying "Changes in this module require root access." -- and Apply is *hidden*
rather than greyed while unprivileged.

That is a better idea than the one netcfgd implemented, and the reason is not
aesthetic. **The red frame is a statement about a credential boundary.** It
says: root is held, by something that is not this program, and it is on the
other side of that line. A border that reddens because a client set a bool
says nothing, because the client could set the bool at any time.

The second half is the same argument from the operator's side: **why should
anybody be able to edit a thing they do not hold the permission to commit?** An
editor that opens before authentication is a form that lies about what it can
do. Everything typed into it is provisional in a way nothing on screen admits.

## Decision

**The red frame means a privileged process exists. It is drawn only while one
does, and the editors open only when one does.**

Concretely:

1. `Administrator Mode...` starts **`ncfg control helper`** through whatever
   the desktop has -- `pkexec`, `kdesu`, `sudo -A`. Authentication happens
   here, before anything opens.
2. The helper prints `ready uid=N` and the client reddens **only for `uid=0`**.
3. The editors are enabled by the same event, and by nothing else.
4. Apply writes three typed principals down the pipe. No second prompt: root
   is already held.
5. Leaving the mode, or the client exiting, closes the pipe. The helper's
   protocol ends at end-of-file, so it cannot outlive the window that
   authenticated it.

### What crosses the boundary is not Qt

**0118's refusal of a root GUI stands, and this is why it had to be
re-examined rather than assumed.** TDE hands uid 0 to a TQt module with a theme
engine and a plugin loader; that was 2005, and polkit exists in large part
because of it. Qt6 also removed the XEmbed API TDE used, so a faithful copy
would be a separate root-owned *top-level window* rather than an inset one --
paying the whole cost and losing the visual property that made it worth paying.

So the privileged half is `ncfg control helper`: no toolkit, one verb, three
typed principals, parsed by the same `Principal::parse` and written by the same
`write_policy` the CLI uses. It takes no path, no config text and no shell --
the rule 0117 set for `wifi_add`, for the same reason, because a config file
may name a hook whose `run_as` defaults to root.

### The uid is checked, not assumed

`ready uid=N` exists because an elevator that silently did nothing would
otherwise leave a red frame around an unprivileged process, which is the one
thing this frame must never mean. The claim is verified against the process
that made it.

## What this costs

**A root process lives for as long as the mode is open**, which is a surface
that did not exist before. It is bounded three ways: it can only write a
control policy, it validates before writing, and it dies with the pipe. That is
narrower than a helper the desktop keeps warm, and much narrower than a root
GUI.

**Two prompts become one**, which is a gain, but the prompt now comes earlier
-- pressing `Administrator Mode` asks for a password before the operator has
decided anything. That is the correct order and it is worth naming, because the
old order felt cheaper.

## What this leaves open

- **The elevator is still unexercised.** `pkexec`, `kdesu` and `sudo -A` are
  chosen by `QStandardPaths::findExecutable`, and the headless probe fakes one
  through PATH. Which of them a real desktop picks, and whether its prompt
  behaves, wants a session.
- **Hiding Apply rather than greying it**, as TDE does. netcfgd's existing rule
  is that a refusal explains itself and a greyed-out button does not, so these
  two conventions disagree and the disagreement is not settled here.
