#!/usr/bin/env python3
"""One program icon, and every front end names it.

**There were four `Icon=` lines and none of them named netcfgd.** Three said
`network` and one said `network-wireless`, so the Qt window and the TDE tray
showed different pictures for one program and both showed a generic one from
whatever theme happened to be installed. Nothing noticed, because a themed icon
that does not exist falls back silently to something else -- an icon name is
never wrong, only absent, which is why this needs a gate rather than a test.

Two checks, and the second is the one with teeth:

  * every size `Makefile`'s `ICON_SIZES` names has been rendered into
    `art/icon/`, so `make install` cannot ship a size that is not there;
  * every `Icon=` in a desktop file this tree ships names `netcfgd`.

WHAT THIS DOES NOT PROMISE. It does not look at the pictures. A master replaced
with a blank square passes, and so does one that is unreadable at 16 pixels --
`art/README.md` says what a replacement has to be and no gate can check it.
What this stops is the state the tree was in: front ends disagreeing about
which icon is theirs, and a size silently missing from an install.
"""

import pathlib
import re
import sys

MAKEFILE = pathlib.Path("Makefile")
RENDERED = pathlib.Path("art/icon")
MASTER = pathlib.Path("art/netcfgd-master.png")
NAME = "netcfgd"

# Where a TDE installation keeps its icon themes. Checked in order, and the
# check below is skipped where none of them is there: TDE is not a build
# dependency of this tree and most machines running `make check` will not have
# it.
TDE_ICON_DIRS = [
	pathlib.Path("/opt/trinity/share/icons"),
	pathlib.Path("/opt/tde/share/icons"),
	pathlib.Path("/usr/share/icons"),
]

# The TDE front end's source, which is where themed names are asked for.
TDE_SOURCES = sorted(pathlib.Path("adapter/netcfgd-tde").glob("*.cpp"))

# How a themed name is spelled in that source. `glyph =` is here because the
# tray picks its state icon into a variable and passes the variable, so a
# pattern that read only the call would see none of the four names that matter.
THEMED = [
	re.compile(r'loadIcon\(\s*"([A-Za-z0-9_.-]+)"'),
	re.compile(r'SmallIconSet\(\s*"([A-Za-z0-9_.-]+)"'),
	re.compile(r'state_glyph\([^)]*"([A-Za-z0-9_.-]+)"\s*\)'),
	re.compile(r'glyph\s*=\s*"([A-Za-z0-9_.-]+)"'),
]


def sizes():
	"""The sizes the Makefile says to render, read from the Makefile."""
	for line in MAKEFILE.read_text().splitlines():
		if line.startswith("ICON_SIZES"):
			return [int(n) for n in re.findall(r"\d+", line.split("=", 1)[1])]
	return []


def desktop_files():
	"""Every desktop file in the tree, minus anything built or staged."""
	skip = ("target/", "build/", "debian/netcfgd", "dist/")
	return [
		path
		for path in sorted(pathlib.Path(".").rglob("*.desktop"))
		if not any(part in str(path) for part in skip)
	]


def themed_names():
	"""Every icon name the TDE front end asks a theme for."""
	names = set()
	for path in TDE_SOURCES:
		text = path.read_text()
		for pattern in THEMED:
			names.update(pattern.findall(text))
	return names


def themes_at(root):
	"""Every icon name any theme under `root` carries."""
	held = set()
	for path in root.rglob("*"):
		if path.suffix in (".png", ".svg", ".svgz", ".mng"):
			held.add(path.stem)
	return held


def check_themed_icons():
	"""Every name the TDE front end asks for is in some installed theme.

	**A themed icon name is never wrong, only absent.** The loader substitutes
	the generic `unknown` picture and says nothing, so a name from the wrong
	icon set looks like a working feature until somebody sees the question mark
	-- which is what `network-disconnect` did on the tray's no-daemon rung, a
	freedesktop name no TDE theme carries. A fallback is in the code now, and
	this says when a name is falling back rather than being found.

	Returns 0 when it passed or had nothing to check, 1 when a name is in no
	theme at all.
	"""
	wanted = themed_names()
	if len(wanted) < 6:
		print(f"icon: only {len(wanted)} themed name(s) read from the TDE front end")
		print("icon:   the extraction is broken, which looks exactly like a pass")
		return 1

	root = next((path for path in TDE_ICON_DIRS if path.is_dir()), None)
	if root is None:
		print("icon: no TDE icon themes installed, so themed names were not checked")
		return 0

	held = themes_at(root)
	# A directory with no icons in it is not a theme tree, and checking against
	# an empty set would report every name as missing.
	if len(held) < 100:
		print(f"icon: {root} holds {len(held)} icon(s), which is not a theme tree")
		return 0

	missing = sorted(name for name in wanted if name not in held)
	for name in missing:
		print(f"icon: no theme under {root} has `{name}`")
		print("icon:   a name no theme carries draws the generic `unknown` picture")
	if missing:
		return 1
	print(f"icon: {len(wanted)} themed name(s) asked for by the TDE front end, all present")
	return 0


def main():
	if not MASTER.is_file():
		print(f"icon: {MASTER} is missing; there is no icon to ship")
		return 1

	wanted = sizes()
	# A run that read no sizes would find nothing missing and say so in the
	# same words as a real pass.
	if len(wanted) < 4:
		print(f"icon: only {len(wanted)} size(s) read from {MAKEFILE}; the extraction is broken")
		return 1

	fail = 0
	for size in wanted:
		rendered = RENDERED / f"{NAME}-{size}.png"
		if not rendered.is_file():
			print(f"icon: {rendered} is missing -- run `make icons` and commit it")
			fail = 1

	found = desktop_files()
	if not found:
		print("icon: no desktop files found; the extraction is broken")
		return 1

	named = 0
	for path in found:
		for number, line in enumerate(path.read_text().splitlines(), 1):
			if not line.startswith("Icon="):
				continue
			named += 1
			icon = line.split("=", 1)[1].strip()
			if icon != NAME:
				print(f"icon: {path}:{number}: `Icon={icon}` is not this program's icon")
				print(f"icon:   every front end names `{NAME}`, which is what art/ installs")
				fail = 1
	if not named:
		print("icon: no `Icon=` line in any desktop file; the extraction is broken")
		return 1

	fail |= check_themed_icons()

	if not fail:
		print(
			f"icon: {len(wanted)} size(s) rendered, "
			f"{named} `Icon=` line(s) across {len(found)} desktop file(s), all `{NAME}`"
		)
	return fail


if __name__ == "__main__":
	sys.exit(main())
