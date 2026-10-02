# 0263: a vendored frontend may be absent, and the build says so rather than stopping

Status: accepted
Date: 2026-10-02
Milestone: M9; the window can configure the machine. Confirms
[0173](0173-a-build-that-lost-a-feature-says-so.md)
against a global rule written the same day

## The conflict

`build-and-commit.md` carries a rule set by the copyright holder on
2026-09-07, *a vendored submodule is the build's to fetch, not the
reader's*, and it requires two things of a build that vendors a sibling:

> Fetch it, and *fail* when it cannot be fetched. A build that silently
> produces less is worse than one that stops, which is the same argument
> `evidence.md` makes about a gate over an empty file list.

`gui/Makefile` does the first and not the second. A clone whose `qtty`
submodule is absent and unfetchable builds the window, announces that it has
no terminal frontend, and succeeds.

0173 is the reason, and it predates the question: it was accepted on
2026-09-07, the same day, for the report *"netcfgd-tui is the same as
netcfgd-gui, and there is no --tui argument"*. What it decided was that the
loss be **announced** -- `gui.pro` says so at build time, and the binary
refuses `-tui` before `QApplication` naming `git submodule update --init` as
the remedy -- not that the build stop.

## Decided

**The project decision wins. 0173 stands.** Ruled by the copyright holder
2026-10-02, asked as a conflict between layers rather than resolved while
working, which is what `CLAUDE.md` asks for when the global guidelines and a
project's own decision disagree.

**It is not the failure the global rule is written against, and that is why
the two can both be right.** That rule's own argument is about *silence*: its
incident is raidcfgd resolving `libossa` through `pkg-config --exists ossa`,
building **no ossa backend at all** on a machine with nothing installed, and
saying nothing anywhere -- so the captured fixtures drifted from the library
they are a capture of before anybody noticed. Nothing here is silent. The
absence is stated in three places, at three moments: when the fetch cannot
happen, when `gui.pro` configures, and when a person types `netcfgd-tui`.

**A frontend is also not a backend.** An absent ossa backend means netcfgd
cannot see a class of hardware and does not say so; an absent qtty means a
window instead of a terminal, in a program whose other frontend is right
there and which says which command to use. The first is a hole in what
netcfgd can observe, the second is a choice of interface.

## What the global rule still governs here, unchanged

- **The build fetches it.** A person who has just cloned types `make` and
  gets the submodule; nobody is told to run `git submodule update --init`
  first.
- **The pin never moves.** `git submodule update --init -- qtty` checks out
  the commit the gitlink names and nothing else.
- **Fetching is visible.** It prints what it is fetching before it starts,
  because a clone is not a compile, and it is bounded by `timeout 600` with
  `GIT_TERMINAL_PROMPT=0` so it cannot sit waiting for a password nobody is
  there to type.
- **git is asked properly.** `git -C .. rev-parse --git-dir`, never
  `test -d .git`, which is false in a worktree and in a submodule checkout
  and is the spelling that cost raidcfgd its backend.

## The half that was not satisfied, and is now

The rule also asks that git's absence be reported **as its own condition
rather than as a repository that is not one**. The recipe collapsed three
causes into one sentence that guessed between them in parentheses: *"no
network, no key, or a source tree without git"*. They have different
remedies -- install git, build from a release that carries qtty, or look at
the network -- so they are three messages now, with the program's presence
established before git is asked anything.

Proven with the recipe's own bytes against an empty `QTTY_DIR`: present
builds it; absent with git off `PATH` names git; absent in a directory that
is not a checkout names that; and every branch still ends with 0173's line
about `netcfgd-tui`.

**The fetch-failure branch is not demonstrated**, because exercising it means
taking the network away from the machine running the test. Its message is
narrowed to what it can now mean rather than listing three possibilities, and
that is the whole of the improvement there.
