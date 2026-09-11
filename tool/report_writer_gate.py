#!/usr/bin/env python3
"""Only a declared writer takes `/run/netcfgd/reported/<interface>`.

`doc/interface-report.md` gives that file to one writer -- "the thing writing
it is the thing that brought the interface up" -- and provides
`reported.d/<interface>/<source>` for anything else with something to say about
the same link. The two are not equivalent: a writer renames over the single
file, so a second one replaces the first rather than joining it.

**The rule was broken by somebody who had just read it.** `netcfgd-modem-at`
took the single file to report which SIM the module was reading. On an ECM
module the DHCP client owns it, and the two alternated -- a lease renewal
erased the card, and an attach erased the lease's nameservers. A cellular link
with an address, a route and no resolver at all, from one line of path.

So a shipped shell writer that targets the single file has to be named in
`tool/report-single-writers.txt` with the reason it is the one that brought the
interface up. Writing that reason is the check: for the AT helper there is no
such sentence, because its own header says the DHCP client does it.

WHAT THIS DOES NOT SEE

Only the shell writers under `helper/` and `packaging/`. netcfgd generates two
more itself -- the script it hands `udhcpc -s` and openvpn's `--route-up` --
and those are Rust string literals this does not parse. They are netcfgd's own
and are started by netcfgd on an interface the document named, which is the
second of the contract's two claims; a new one there is a change to netcfgd's
code rather than a file somebody drops in, which is the case this is for.

Said out loud because a gate trusted for more than it does is worse than none.
"""

import pathlib
import re
import sys

LIST = "tool/report-single-writers.txt"
ROOTS = ["helper", "packaging"]

# **The path *segment*, not the literal `reported/`.** Shell assembles paths
# from variables, so a writer taking the single file may never spell a slash
# after it: `directory="$run_dir/reported"` and a `$directory/$interface` three
# lines later is the same defect and matched nothing. That exact mutation
# passed this gate on its first run, which is why the pattern is anchored on
# the slash *before* the segment and excludes the fragment tree by its suffix.
SINGLE = re.compile(r"/reported(?!\.d)")
FRAGMENT = re.compile(r"/reported\.d\b")


def declared():
	"""The paths named in the list, with the reason each gives."""
	out = {}
	for number, line in enumerate(pathlib.Path(LIST).read_text(encoding="utf-8").splitlines(), 1):
		line = line.strip()
		if not line or line.startswith("#"):
			continue
		path, separator, reason = line.partition(" -- ")
		if not separator or not reason.strip():
			sys.exit(f"report-writer: {LIST}:{number}: needs `path -- reason`")
		out[path.strip()] = reason.strip()
	return out


def writers():
	"""Every shipped shell file that writes the single report file."""
	found = []
	for root in ROOTS:
		for path in sorted(pathlib.Path(root).rglob("*")):
			if not path.is_file() or path.is_symlink():
				continue
			try:
				text = path.read_text(encoding="utf-8")
			except (UnicodeDecodeError, OSError):
				continue
			# **Only things that can write.** A systemd unit naming the
			# directory in `ReadWritePaths=` is a grant rather than a writer,
			# and flagging it sent this gate after the sandbox line instead of
			# the script -- which did find a real fault, the grant having been
			# left pointing at the old path, and was still the wrong subject.
			if not text.startswith("#!"):
				continue
			# A write, not a mention: the path has to be assigned or renamed
			# onto. Comments explaining the rule are exactly what this file is
			# full of, and matching those would fail the tree for its own
			# documentation -- the shape this project keeps meeting.
			code = "\n".join(
				line for line in text.splitlines() if not line.lstrip().startswith("#")
			)
			if SINGLE.search(code):
				found.append(str(path))
	return found


def main():
	listed = declared()
	found = writers()

	# **A gate over an empty list reports success exactly as loudly as a real
	# pass.** The tree has three of these today; none is not a tidier tree.
	if not found:
		print(
			"report-writer: no shipped writer targets reported/<interface>, "
			"which cannot be right -- has the layout changed?",
			file=sys.stderr,
		)
		return 1

	failures = []
	for path in found:
		if path not in listed:
			failures.append(
				f"{path} writes reported/<interface>, which belongs to whatever "
				f"brought the interface up. If that is not this, write "
				f"reported.d/<interface>/<source> instead; if it is, add it to "
				f"{LIST} with the reason"
			)
	for path in listed:
		if path not in found:
			failures.append(
				f"{LIST} names {path}, which no longer writes "
				"reported/<interface> -- drop the line"
			)

	for failure in failures:
		print(f"report-writer: {failure}", file=sys.stderr)
	if failures:
		return 1

	# The control from the other side: the fragment form is in use somewhere,
	# so "nothing writes a fragment" cannot pass as "everything is declared".
	fragments = [
		path
		for root in ROOTS
		for path in sorted(pathlib.Path(root).rglob("*"))
		if path.is_file() and not path.is_symlink()
		for text in [path.read_text(encoding="utf-8", errors="ignore")]
		if FRAGMENT.search(text)
	]
	if not fragments:
		print(
			"report-writer: nothing writes reported.d/, so the alternative this "
			"gate points writers at may not exist",
			file=sys.stderr,
		)
		return 1

	print(
		f"report-writer: {len(found)} writer(s) of reported/<interface>, all declared; "
		f"{len(fragments)} file(s) use the fragment form"
	)
	return 0


if __name__ == "__main__":
	sys.exit(main())
