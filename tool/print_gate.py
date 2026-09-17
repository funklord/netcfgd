#!/usr/bin/env python3
"""The two programs print through `say!`, which survives a closed pipe.

`ncfg status | head -1` aborted with a Rust panic -- exit 134, and four lines
about `library/std/src/io/stdio.rs` at somebody who had done nothing wrong.
`println!` unwraps its write; Rust ignores `SIGPIPE`, so a reader that has gone
comes back as `EPIPE` rather than as a signal, and the unwrap turns that into a
panic. Every ordinary shape did it: `| head`, `| less` quit early,
`ncfg show | jq .interfaces[0]`.

`netcfgd_sys::say!` and `sayln!` write the same bytes and end the process the
way a tool in a pipeline ends -- quietly, at 141. The behaviour has a test.
What it cannot have is a test per print site, and a `println!` added next year
would be a panic that nothing notices until it is in somebody's terminal: a
print site is never *wrong*, only absent from the one path a test drives, which
is the same reason the icon names need a gate rather than a test.

WHAT THIS DOES NOT SEE

The backends and adapters, which print little and are run by the daemon rather
than typed into a pipeline, and the GUI, which prints nothing. `eprintln!` is
left alone deliberately: stderr is not usually the pipe that closes, and where
the daemon's own messages go -- `netcfgd_sys::log::emit` -- the write error has
always been ignored rather than unwrapped.
"""

import pathlib
import re
import sys

# The two programs somebody types, which are one binary with two names.
WATCHED = [
	pathlib.Path("crates/netcfgd-cli/src"),
	pathlib.Path("crates/netcfgd-daemon/src"),
]

FORBIDDEN = re.compile(r"\b(println!|print!)\s*\(")


def main():
	files = sorted(path for directory in WATCHED for path in directory.rglob("*.rs"))
	# A gate over no files reports success exactly as loudly as a real pass,
	# and a crate that moved is how that happens.
	if len(files) < 5:
		print(f"print-gate: only {len(files)} source file(s) found; the paths are wrong")
		return 1

	found = 0
	for path in files:
		for number, line in enumerate(path.read_text().splitlines(), 1):
			match = FORBIDDEN.search(line)
			if not match:
				continue
			found += 1
			print(f"print-gate: {path}:{number}: {match.group(1)} panics on a closed pipe")
			print(f"print-gate:   write it with `say!` or `sayln!` from netcfgd_sys")
	if found:
		return 1

	print(f"print-gate: {len(files)} source file(s) in the two programs print through `say!`")
	return 0


if __name__ == "__main__":
	sys.exit(main())
