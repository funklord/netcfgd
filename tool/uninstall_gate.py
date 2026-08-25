#!/usr/bin/env python3
"""Every file an install target places must be named by `uninstall`.

This exists because it drifted, twice over and in opposite directions.

`install-gui` and `install-modem-mbim` both placed files that `uninstall` had
never heard of, so removing netcfgd left root-owned binaries behind with
nothing accounting for them. And `uninstall` removed
`$(SYSCONFDIR)/netcfgd/netcfgd.conf`, which no install target has ever written
-- netcfgd ships no default configuration, so that line could only delete
something a person wrote by hand. Both directions are the same defect: the two
lists were maintained by memory.

So this compares them mechanically. It reads the Makefile, collects every
destination an `install`/`install-*` recipe writes, and requires each to appear
in the `uninstall` recipe. It also refuses the reverse -- a path `uninstall`
removes that nothing installs -- which is what the configuration bug looked
like.

Static on purpose: it needs no build, no root and no staging tree, so it runs
in `make check` on any machine rather than only where a full install works.
"""

import re
import sys

MAKEFILE = "Makefile"

# `install -m MODE src DEST` and `ln -sf target DEST`. The destination is the
# last word, and it is the only word that matters here.
PLACES = re.compile(r"^\s+(?:install\s+-m\s+\S+|ln\s+-sf)\s+.*?(\$\(DESTDIR\)\S+)\s*$")
REMOVES = re.compile(r"^\s+rm\s+-f\s+(\$\(DESTDIR\)\S+)\s*$")


def recipes(text):
	"""Map target name to its recipe lines."""
	out, current = {}, None
	for line in text.splitlines():
		if line and not line[0].isspace() and ":" in line and not line.startswith("\t"):
			name = line.split(":", 1)[0].strip()
			current = name if re.fullmatch(r"[A-Za-z0-9_.-]+", name) else None
			if current:
				out.setdefault(current, [])
		elif current and (line.startswith("\t") or not line.strip()):
			if line.strip():
				out[current].append(line)
		elif line.strip() and not line.startswith("\t"):
			current = None
	return out


def main():
	text = open(MAKEFILE, encoding="utf-8").read()
	found = recipes(text)

	installed, by_target = set(), {}
	for target, lines in found.items():
		if target != "install" and not target.startswith("install-"):
			continue
		for line in lines:
			match = PLACES.match(line.replace("\\", "").rstrip())
			if match:
				installed.add(match.group(1))
				by_target[match.group(1)] = target

	# A continuation line splits `install -m 0644 src \` from its destination,
	# so join them before matching or half the list is silently missed -- which
	# would make this gate pass by seeing nothing.
	joined = re.sub(r"\\\n\s*", " ", text)
	for target, lines in recipes(joined).items():
		if target != "install" and not target.startswith("install-"):
			continue
		for line in lines:
			match = PLACES.match(line.rstrip())
			if match:
				installed.add(match.group(1))
				by_target.setdefault(match.group(1), target)

	removed = set()
	for line in recipes(joined).get("uninstall", []):
		match = REMOVES.match(line.rstrip())
		if match:
			removed.add(match.group(1))

	if not installed:
		print("uninstall-gate: found no installed paths at all -- this gate is "
		      "checking nothing, which is worse than a failure")
		return 1
	if not removed:
		print("uninstall-gate: `uninstall` removes nothing -- refusing to pass")
		return 1

	fail = 0
	for path in sorted(installed - removed):
		print(f"uninstall-gate: {by_target[path]} installs {path}, "
		      f"and `uninstall` does not remove it")
		fail = 1
	for path in sorted(removed - installed):
		print(f"uninstall-gate: `uninstall` removes {path}, which no install "
		      f"target writes -- if that is somebody's own file, it is not "
		      f"ours to delete")
		fail = 1

	if not fail:
		print(f"uninstall-gate: {len(installed)} installed paths, all removed")
	return fail


if __name__ == "__main__":
	sys.exit(main())
