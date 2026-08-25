#!/usr/bin/env python3
"""netcfgd's kernel tag must have exactly one producer per object kind.

WHY THIS GATE EXISTS
    `netcfgd-observe`'s `tagged_origin` infers `Origin::Static` from the
    presence of netcfgd's protocol tag, which is what lets a restarted daemon
    reconcile after `/run` was cleared. That inference is sound only because
    the tag has a single producer: `Op::AddrAdd` is the only caller of
    `add_address`, `Op::RouteAdd` the only caller of `add_route`, and both
    record `Origin::Static`.

    A second producer -- an address installed from a delegated prefix, say,
    or a route a future backend path adds -- would wear the same tag and be
    read back as static, and the planner would then remove somebody's lease
    to satisfy a config that never asked for it. Nothing in `tagged_origin`
    would look wrong; the function would simply have stopped being true.

    So the property is asserted here rather than trusted, because it is a
    property of the tree and not of the function that depends on it.

WHAT IT CHECKS
    One call site each for `add_address` and `add_route` outside their own
    definitions and outside tests, and each of those call sites recording
    `Origin::Static`.
"""

import pathlib
import re
import sys

ROOTS = [pathlib.Path("crates"), pathlib.Path("backend")]

# (what installs it, the origin its call site must record)
PRODUCERS = [("add_address", "Origin::Static"), ("add_route", "Origin::Static")]

# How far after the call to look for the recorded origin. The two call sites
# record it within a dozen lines; the window is deliberately small, so that
# moving the recording far from the call fails here rather than silently.
WINDOW = 20


def sources():
	"""Every non-test Rust file under the roots.

	A missing root is an error rather than an empty list: a gate that reads
	nothing reports success exactly as loudly as one that read everything.
	"""
	for root in ROOTS:
		if not root.is_dir():
			sys.exit(f"tag-producer: {root} is not a directory, so this gate would read nothing")
		for path in sorted(root.rglob("*.rs")):
			if "/tests/" in str(path) or path.name.startswith("test"):
				continue
			yield path


def main():
	failures = []
	for call, origin in PRODUCERS:
		sites = []
		for path in sources():
			lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
			# Drop the file's test module: fixtures may call anything.
			text = "\n".join(lines)
			at = text.find("\nmod tests {")
			if at != -1:
				lines = text[:at].splitlines()
			for number, line in enumerate(lines):
				if re.search(rf"\.{call}\(", line) and f"fn {call}" not in line:
					following = "\n".join(lines[number : number + WINDOW])
					sites.append((path, number + 1, origin in following))
		if len(sites) != 1:
			where = ", ".join(f"{p}:{n}" for p, n, _ in sites) or "nowhere"
			failures.append(
			    f"{call} has {len(sites)} call sites ({where}); `tagged_origin` in "
			    f"netcfgd-observe infers {origin} from the tag and is only sound "
			    f"with one"
			)
			continue
		path, number, records = sites[0]
		if not records:
			failures.append(
			    f"{path}:{number} calls {call} but does not record {origin} within "
			    f"{WINDOW} lines; the tag would then imply an origin the code does "
			    f"not record"
			)

	if failures:
		for failure in failures:
			print(f"tag-producer: {failure}")
		sys.exit(1)
	print(f"tag-producer: {len(PRODUCERS)} tagged object kinds, one producer each")


if __name__ == "__main__":
	main()
