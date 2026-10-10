#!/usr/bin/env python3
"""Every named block the renderer can open is one `profile save` can override.

**What a missing kind does.** `ncfg profile save` renders the running document
into `profile/<name>/00-saved.conf` beside the base configuration, so every
block the base already defines has to be restated as `override`. Which blocks
those are is not something the renderer can guess -- an `override` on a block
nothing defines is a compile error and its absence on one that is defined is a
different one -- so `collect_overrides` in `host/profile_save.c` names them,
and `ncfg_render_opening` consults the set it builds.

A kind the renderer learned to write and that function was never told about is
therefore written bare. The base defines it, the snapshot redefines it, the
proof compile refuses, and the whole save rolls back with *"that would stop the
configuration compiling ... `rule profile-probe` is already defined"* -- about
a snapshot that is a faithful rendering of the machine. The verb is unusable on
any machine whose configuration has one of those blocks in it.

**This is a gate because the omission has happened three times.** `device` was
counted when it should not have been (an invented one is not a defined one),
`bluetooth` was missed when the renderer learned it, and `rule`, `access_point`
and `linkset` were missed for as long as the renderer could write them. Each
was found by a live script rather than by anything in the build, and each time
the renderer had moved and the list had not. There is nothing for a round trip
to catch here: it renders a document on its own, with no base to collide with.

Both directions, like the other gates here: a kind the renderer opens and the
list does not name fails, and a kind the list names and the renderer cannot
open fails too -- the second being how a block that was removed leaves a stale
entry behind.
"""

import pathlib
import re
import sys

RENDERER = [
	pathlib.Path("c/src/compile/render.c"),
	pathlib.Path("c/src/compile/render_link.c"),
	pathlib.Path("c/src/compile/render_device.c"),
]
SAVER = pathlib.Path("c/src/host/profile_save.c")


def without_comments(text):
	text = re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group(0)), text, flags=re.S)
	return re.sub(r"//[^\n]*", "", text)


def opened_kinds():
	"""Each kind `ncfg_render_opening` is called with, and where."""
	kinds = {}
	for path in RENDERER:
		if not path.exists():
			sys.exit(f"{path}: missing, so this gate would check nothing")
		source = without_comments(path.read_text(encoding="utf-8"))
		for match in re.finditer(
			r"ncfg_render_opening\s*\(\s*text\s*,\s*\"([a-z_]+)\"", source
		):
			kinds.setdefault(match.group(1), path.name)
	return kinds


def overridable_kinds():
	"""Each kind `collect_overrides` records.

	Read from that function alone rather than from the file: `ncfg_overrides_add`
	is a public call and another function here recording one for a different
	purpose would otherwise read as coverage.
	"""
	if not SAVER.exists():
		sys.exit(f"{SAVER}: missing, so this gate would check nothing")
	source = without_comments(SAVER.read_text(encoding="utf-8"))
	start = source.find("static int collect_overrides(")
	if start < 0:
		sys.exit(f"{SAVER}: no `collect_overrides`, so this gate cannot find the list")
	end = source.find("\n}", start)
	if end < 0:
		sys.exit(f"{SAVER}: `collect_overrides` does not end, so the list cannot be read")
	body = source[start:end]
	return set(re.findall(r"ncfg_overrides_add\s*\([^,]+,\s*\"([a-z_]+)\"", body))


def main():
	opened = opened_kinds()
	named = overridable_kinds()
	if not opened or not named:
		sys.exit("override_coverage_gate: read no kinds, so checked nothing")

	faults = []
	for kind in sorted(opened):
		if kind not in named:
			faults.append(
				f"{kind}: {opened[kind]} opens it and `collect_overrides` does not"
				f" name it, so `ncfg profile save` writes it bare and the save is"
				f" refused for a redefinition"
			)
	for kind in sorted(named):
		if kind not in opened:
			faults.append(
				f"{kind}: `collect_overrides` names it and no renderer opens it"
				f" -- drop it, or the list describes a block that is gone"
			)

	if faults:
		print("override_coverage_gate: FAILED")
		for fault in faults:
			print(f"  {fault}")
		return 1

	print(
		f"override_coverage_gate: {len(opened)} named block kind(s) the renderer"
		f" opens, each one `profile save` can override"
	)
	return 0


if __name__ == "__main__":
	sys.exit(main())
