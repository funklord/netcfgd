# The program icon

**One icon, one source, every front end.** Before this there were four
`Icon=` lines across the desktop files and none of them named netcfgd: three
said `network` and one said `network-wireless`, so the Qt window and the TDE
tray showed different pictures for the same program, and both showed somebody
else's.

## What to replace

`art/netcfgd-master.png`, and nothing else. Everything below is generated
from it.

Requirements for a replacement:

- **square**, and at least 512x512. 1024x1024 is better; the renders come
  down from it and never up.
- **transparent background.** A white square looks fine on a light theme and
  like a sticker on a dark one, which is the panel this program mostly lives
  in.
- **legible at 16 pixels.** This is the whole constraint, and it is the one an
  image generator will ignore: at tray size an icon is about forty usable
  pixels across, so anything with fine lines, small text or a detailed scene
  becomes grey mush. Silhouette first, detail never.
- PNG. Not SVG: nothing in this tree can rasterise one -- there is no
  `rsvg-convert` or `inkscape` here, and ImageMagick's own SVG renderer is not
  good enough to trust with the thing people recognise the program by. If a
  real SVG is ever drawn, it belongs here beside the master and the renders
  still come from a PNG export of it.

## Regenerating

    make icons

Renders every size into `art/icon/` with ImageMagick and nothing else.

**The renders are committed.** The build installs them and never rasterises,
so a machine building netcfgd needs no image tooling at all -- only whoever
replaces the master does. That is the same bargain `doc/schema` makes: a
generated artifact is in the tree so that reading it, shipping it and building
it need none of what produced it.

`make icon-check` is what the gate runs: every size the desktop files need
exists, and every shipped `Icon=` names this icon.

## Where they end up

`hicolor`, which is the theme every toolkit falls back to -- under `/usr` for
the Qt front end and under `/opt/trinity` for the TDE one, since TDE looks in
its own prefix first and hicolor is the one theme both agree on.

The icon is named `netcfgd`, which is the program's name, which is the
freedesktop convention and the reason no front end has to know where the file
is.
