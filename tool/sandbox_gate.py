#!/usr/bin/env python3
"""Every /etc path netcfgd writes must be writable under its own systemd unit.

The two lists are kept in step by memory otherwise, which is the failure this
tree keeps finding -- `install` against `uninstall`, the shim's interfaces
against its bus policy, five documents against a field that never existed.
This is the same shape and it has already cost the worst outcome of the three.

**What it costs when they disagree.** `ProtectSystem=full` mounts /etc
read-only for the service, so a path netcfgd writes and the unit does not
allow-list fails with EROFS -- at run time, on a packaged install, and never in
a test, because every test writes into a temp directory. It happened: the unit
carried `ReadOnlyPaths=/etc/netcfgd` with a comment saying "netcfgd never
writes to it", which decision 0127 reversed by making netcfgd the *only*
writer of its own configuration. Every client write the socket exists to carry
was refused by netcfgd's own sandbox, on every systemd machine, and it surfaced
as a desktop client relaying a message about a file it had never touched.

The same unit had a second copy of the mistake in the other direction: its
comment chose `ProtectSystem=full` to *avoid* /etc being read-only, which is
what `full` does. So the DNS backends -- the reason the comment gave -- could
not write /etc/resolv.conf either.

**A granted file is not a granted directory, and this gate could not see the
difference until it had cost something.** netcfgd replaces a config file by
staging a dotfile beside it and renaming -- which needs write permission on the
*parent*, not on the target. `ReadWritePaths=-/etc/resolv.conf` grants the
file, so this gate said "allowed" and the write failed with EROFS anyway. It
asked whether the path was permitted when the code's requirement was whether
its directory was. Decision 0161; the writers fall back to an in-place write
now, so a file-granted path works and is no longer atomic. That is a real
property and it is reported rather than buried.

**What this does not check.** Whether a path is writable in fact: that needs
the unit running as root under systemd, which is not a thing a static gate can
do. `tests/live/sandbox_writes.sh` gets closer by making the same mounts in a
namespace. What this checks is that the two lists name the same paths, and now
also how each one will be written.

Static: it reads the sources and one unit file, so it runs anywhere.
"""

import pathlib
import re
import sys

UNIT = pathlib.Path("packaging/systemd/netcfgd.service")
SOURCES = [pathlib.Path("crates"), pathlib.Path("backend")]

# Paths under /etc that netcfgd reads and never writes. Naming them is the
# point of the list: an unclassified /etc path is a new one, and a new one is
# either a write the unit has to allow or a read somebody should say is a read.
READ_ONLY = {
	"/etc/passwd",  # resolving a hook's `run_as`
	"/etc/group",   # the same, for a group
	# Certificates an operator names in their own configuration. netcfgd opens
	# these to read, and for the supplicant's three it does not open them at
	# all -- it passes the path and wpa_supplicant opens it, in its own
	# namespace, which this unit does not bound.
	"/etc/ssl",
	"/etc/cert",
	# The operator's dhcpcd configuration. netcfgd never opens it: it creates a
	# symlink under its own run directory pointing here and passes that path to
	# dhcpcd with `-f`, so that a running client can be asked later which
	# config it was started with (0143). dhcpcd is what opens the target, in
	# its own privilege-separated sandbox, which this unit does not bound --
	# the same shape as the supplicant's certificates above. A dangling symlink
	# is not an error: dhcpcd logs and applies its defaults, measured, which is
	# exactly what it already does on a machine with no such file.
	"/etc/dhcpcd.conf",
}


def unit_allows(text):
	"""The paths the unit marks writable, with any `-` prefix stripped."""
	allowed = set()
	for line in text.splitlines():
		line = line.strip()
		if line.startswith("ReadWritePaths="):
			for path in line.split("=", 1)[1].split():
				allowed.add(path.lstrip("-"))
	return allowed


def covers(allowed, path):
	"""Whether an allow-listed path permits writing `path`.

	Prefix matching, because that is what a bind mount does:
	`ReadWritePaths=/etc/dnsmasq.d` makes everything under it writable, so
	naming the directory is enough and naming the file would be a promise
	about a filename the backend is free to change. Compared component-wise
	rather than by string prefix, so `/etc/netcfgd` does not appear to cover
	`/etc/netcfgd-other`.
	"""
	a = [p for p in allowed.split("/") if p]
	b = [p for p in path.split("/") if p]
	return b[: len(a)] == a


def strip_comments(text):
	"""Rust source with line comments removed.

	Doc comments carry example paths -- `wpa_supplicant`'s README shows
	`private_key="/etc/cert/user.prv"` -- and a gate that read those would
	report a path nothing opens. That is the noise that gets a gate ignored,
	and this tree has already decided once that the answer is to ask a
	narrower question rather than to keep an ignore list.
	"""
	out = []
	for line in text.splitlines():
		at = line.find("//")
		out.append(line if at == -1 else line[:at])
	return "\n".join(out)


def etc_paths_in_sources():
	"""Every `/etc/...` literal in non-test, non-comment source."""
	found = {}
	for root in SOURCES:
		# A source root that is not there reads as zero paths, and this gate
		# turns zero paths into "the unit allows something no code needs" --
		# three false findings, not a quiet pass. Either way it is a gate
		# reporting on a tree it never read, so it refuses instead. Found when
		# `backends/` was renamed to `backend/` and the gate blamed the unit.
		if not root.is_dir():
			raise SystemExit(
			    f"sandbox: {root} is not a directory, so this gate would read "
			    f"no source and blame the unit for every path it allows"
			)
		for path in root.rglob("*.rs"):
			if "/tests/" in str(path):
				continue
			text = path.read_text(encoding="utf-8", errors="replace")
			# Drop test modules: their paths are fixtures, not what runs.
			at = text.find("\nmod tests {")
			if at == -1:
				at = text.find("\n#[cfg(test)]")
			if at != -1:
				text = text[:at]
			for literal in re.findall(r'"(/etc/[A-Za-z0-9._/-]*)"', strip_comments(text)):
				found.setdefault(literal, set()).add(str(path))
	return found


def main():
	if not UNIT.exists():
		print(f"sandbox: {UNIT} is missing, so this gate is checking nothing")
		return 1

	text = UNIT.read_text(encoding="utf-8")
	if "ProtectSystem=full" not in text and "ProtectSystem=strict" not in text:
		# Without one of these /etc is writable and the allow-list is moot --
		# but so is the hardening, which is a decision rather than a default.
		print("sandbox: the unit no longer makes /etc read-only; was that meant?")
		return 1

	allowed = unit_allows(text)
	if not allowed:
		print("sandbox: the unit allow-lists nothing, so the extraction below "
		      "cannot fail -- and netcfgd cannot write /etc at all")
		return 1

	found = etc_paths_in_sources()
	if not found:
		print("sandbox: no /etc paths found in the sources, so this gate is "
		      "checking nothing")
		return 1

	failures = 0
	in_place = []
	for path in sorted(found):
		if any(covers(known, path) for known in READ_ONLY):
			continue
		if any(covers(known, path) for known in allowed):
			# **Granted, and now: granted how?** A stage-and-rename needs the
			# parent writable. Where only the file itself is granted the write
			# still lands -- 0161 -- but in place, so a reader can catch it
			# half-done. Not a failure, and not something to leave unsaid
			# either: it is a durability property of a config file, decided by
			# a line in a unit rather than by any code.
			parent = str(pathlib.PurePosixPath(path).parent)
			if any(covers(known, parent) for known in allowed):
				continue
			# A path with a descendant in this set is a directory netcfgd
			# writes *into*, so its children stage inside it and the parent
			# grant is irrelevant -- `/etc/netcfgd` against
			# `/etc/netcfgd/secrets`. One with no descendant is written as a
			# file. The discriminator is derived from the set rather than
			# guessed from the name, and where it is wrong it over-reports: a
			# granted directory that nothing else in the sources names would
			# be listed. This prints rather than fails, so that is the right
			# way to be wrong.
			if any(other != path and covers(path, other) for other in found):
				continue
			in_place.append(path)
			continue
		where = ", ".join(sorted(found[path])[:3])
		print(f"sandbox: {path} appears in the sources and the unit neither "
		      f"allows it nor is it classified read-only ({where})")
		failures += 1

	# The other direction: an allow-list entry nothing uses is usually the
	# residue of a backend that was removed, and it widens the sandbox for
	# nothing.
	for path in sorted(allowed):
		if not any(covers(path, seen) for seen in found):
			print(f"sandbox: the unit makes {path} writable and no source "
			      f"names it -- residue, or a path spelled differently?")
			failures += 1

	if failures:
		print(f"sandbox: {failures} disagreement(s) between the unit and the code")
		return 1
	for path in in_place:
		print(f"sandbox: {path} is granted as a file and not through its "
		      f"directory, so netcfgd writes it in place rather than "
		      f"atomically (0161)")
	print(f"sandbox: {len(found)} /etc path(s) in the code, all allowed or "
	      f"classified read-only; {len(in_place)} written in place")
	return 0


if __name__ == "__main__":
	sys.exit(main())
