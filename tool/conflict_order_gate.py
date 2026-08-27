#!/usr/bin/env python3
"""Every unit the exclusive drop-in conflicts with must also be ordered after.

`Conflicts=` stops the other unit. It does **not** say when. `systemd.unit(5)`:

    Note that this setting does not imply an ordering dependency, similarly
    to the Wants= and Requires= dependencies described above. This means
    that to ensure that the conflicting unit is stopped before the other
    unit is started, an After= or Before= dependency must be declared.

**What it costs when they disagree**, measured rather than imagined. netcfgd
declines an interface another daemon still claims, which is right, and it reads
that claim at startup. Unordered, it can read it while NetworkManager is still
shutting down: NM is genuinely alive, genuinely still claims the radio, and
netcfgd correctly declines it -- on behalf of a daemon one second from gone.
The drop-in has meanwhile stopped `wpa_supplicant.service` too, so the machine
ends with no network manager at all.

It is a race, so it fails intermittently, which is worse than failing. The
machine that found it reported both "keeps disconnecting now" and "now it
didn't go down" about one fault, and the time went on what else had changed.
Decision 0145.

**Why a gate and not a comment.** The drop-in gained `wpa_supplicant.service`
long after it was written, because stopping NetworkManager alone left a
supplicant answering on the radio. The next unit added to it will be added the
same way -- to the `Conflicts=` list, by somebody solving the problem in front
of them -- and the ordering is the half nobody thinks of. A comment saying
"keep these in step" is what this tree keeps finding already broken.

**What this does not check.** That the ordering works: that needs systemd, root
and the other daemons installed, which is not a thing a static gate can do. It
checks that the two lists name the same units, which is the half that goes
stale.

Static: it reads one file, so it runs anywhere.
"""

import pathlib
import re
import sys

DROPIN = pathlib.Path("packaging/systemd/netcfgd-exclusive.conf")


def directives(text, name):
	"""Every unit named by a directive, which may be repeated or space-separated.

	systemd accepts both spellings and treats them identically, so a gate that
	understood only one would pass a file it had not read.
	"""
	found = []
	for line in text.splitlines():
		line = line.strip()
		if line.startswith("#") or "=" not in line:
			continue
		key, _, value = line.partition("=")
		if key.strip() == name:
			found.extend(value.split())
	return found


def main():
	if not DROPIN.exists():
		print(f"conflict-order: {DROPIN} is missing")
		return 1
	text = DROPIN.read_text(encoding="utf-8")

	conflicts = directives(text, "Conflicts")
	after = set(directives(text, "After")) | set(directives(text, "Before"))

	if not conflicts:
		print("conflict-order: the drop-in declares no Conflicts= at all, "
		      "which is not what this file is for")
		return 1

	failures = 0
	for unit in conflicts:
		if unit not in after:
			print(f"conflict-order: {unit} is stopped by Conflicts= and "
			      f"nothing orders against it -- netcfgd can read its claim "
			      f"while it is still shutting down")
			failures += 1

	# The other direction is not a fault. Ordering against a unit without
	# conflicting with it is a normal thing to want, and saying so here would
	# be a gate inventing a rule rather than checking one.

	if failures:
		print(f"conflict-order: {failures} unit(s) conflicted with and not ordered")
		return 1
	print(f"conflict-order: {len(conflicts)} conflicted unit(s), each ordered after")
	return 0


if __name__ == "__main__":
	sys.exit(main())
