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

	if not fail:
		print(
			f"icon: {len(wanted)} size(s) rendered, "
			f"{named} `Icon=` line(s) across {len(found)} desktop file(s), all `{NAME}`"
		)
	return fail


if __name__ == "__main__":
	sys.exit(main())
