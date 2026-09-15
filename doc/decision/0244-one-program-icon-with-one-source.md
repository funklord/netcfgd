# 0244: one program icon, with one source

Status: accepted
Date: 2026-09-15
Milestone: M9; the program icon

## What was there

Four `Icon=` lines across the desktop files this tree ships, and **none of them
named netcfgd**:

```text
adapter/netcfgd-tde/netcfgd.desktop                 Icon=network
adapter/netcfgd-tde/netcfgd-tde-tray.desktop        Icon=network
adapter/netcfgd-tde/netcfgd-tde-tray-autostart      Icon=network
gui/packaging/netcfgd-gui.desktop                   Icon=network-wireless
```

Three borrowed a generic icon from whatever theme happened to be installed and
the fourth borrowed a different one, so the Qt window and the TDE tray showed
different pictures for one program and both showed somebody else's.

**Nothing noticed, and nothing could have.** A themed icon that does not exist
falls back silently to something else; an icon name is never wrong, only
absent. That is why this ends in a gate rather than a test.

## The shape

`art/netcfgd-master.png` is the only thing anybody replaces. Every render comes
down from it into `art/icon/`, and **the renders are committed**.

That is `doc/schema`'s bargain applied to pictures: the generated artifact is in
the tree so that building and shipping need none of what produced it. A machine
building netcfgd needs no image tooling at all; only whoever replaces the master
does.

**A raster master rather than an SVG**, which is a choice and not a default.
Nothing in this tree can rasterise an SVG -- there is no `rsvg-convert` and no
`inkscape` here, and ImageMagick's own SVG renderer is not something to trust
with the thing people recognise the program by. The art is also likely to arrive
from an image generator, which produces rasters. If a real SVG is ever drawn it
belongs beside the master, and the renders still come from a PNG export of it.

`make icons` checks the master is square and at least as large as the biggest
render before doing anything, because scaling *up* is the one thing this
pipeline must never do quietly.

## Where they go

`hicolor`, under two prefixes: `/usr` for the Qt front end, `/opt/trinity` for
the TDE one. TDE looks in its own prefix first and hicolor is the one theme both
toolkits fall back to, so this is the same eight files under a second root
rather than a second icon.

The icon is named `netcfgd` -- the program's name, which is the freedesktop
convention, and the reason no front end has to know where the file is.

## The gate

`tool/icon_gate.py`, in `make check` beside the uninstall gate. Two checks:
every size `ICON_SIZES` names has been rendered, and every `Icon=` in a shipped
desktop file names `netcfgd`.

Capable of a negative in both directions, checked rather than assumed: removing
one render fails it, and putting `Icon=network` back in one desktop file fails
it.

**What it does not promise** is on the tool. It does not look at the pictures. A
master replaced with a blank square passes, and so does one that is unreadable
at 16 pixels. `art/README.md` states what a replacement has to be -- square, at
least 512, transparent, and legible at tray size -- and no gate can check the
last one.

## The placeholder

`art/netcfgd-master.png` is a plain blue rounded square with a ring and a stem,
drawn with ImageMagick primitives. It is deliberately dull: it exists so the
pipeline could be built and checked end to end before any art exists, and it
should be replaced.

Recording that it is a placeholder here rather than only in a comment, because
"temporary" artwork that nobody wrote down is how a placeholder ships.
