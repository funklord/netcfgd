#!/usr/bin/env python3
"""A comment inside an unquoted heredoc is a command line, not a comment.

`hwsim.sh` wrote a netcfgd document with `cat > "$f" <<CONF`, and one line of
the config it generated read:

	# So there is an `-m` for netcfgd to pass and to record.

An unquoted heredoc delimiter means the body is expanded, so those backticks
are a command substitution. The guest console carried
`tests/live/hwsim.sh: 1: -m: not found` -- line *1*, because a substitution
numbers its own text -- and the generated file got `# So there is an  for
netcfgd to pass`, the word silently gone from the comment it existed to carry.
`tunnel.sh` had the same shape with `route.add 10.9.0.0/24 via 10.8.0.2`
inside an `.ovpn` comment, arguments and all.

Three things make it worth a gate rather than two fixes:

  - `sh -n` cannot see it. The construct is valid, which is why `make shell`
    passed over both sites for as long as they existed, honestly reporting
    that the scripts parse.
  - The script's exit status is unaffected. A missing command prints to stderr
    and the heredoc still gets written, so nothing fails and the only symptom
    is a line of noise in a log nobody reads twice.
  - It is live-script prose that does it. These files explain themselves in
    markdown, where a backtick is how you name a flag -- so the habit that
    makes them readable is the habit that arms this, and it will recur.

Today both words happened to name nothing. The hazard is that these scripts
run under `unshare -rn` as root and write config files, so a comment naming a
command in backticks runs that command with its arguments.

WHAT THIS DOES NOT SEE

Command substitution in a heredoc body that is NOT a comment, which is the
ordinary reason to leave a delimiter unquoted: `tunnel.sh` interpolates
`$(fingerprint ...)` into an openvpn option and `wireguard.sh` writes
`$(wg genpsk)`. Both are deliberate and both must keep working, so the gate
asks only about lines the generated file will carry as comments.

Nor does it see a variable expansion -- `$work` in a generated comment is
usually the point. Only command substitution, which is never what a comment
wants.
"""

import pathlib
import re
import sys

# The files come from the caller -- `make shell` passes `SHELL_SCRIPTS`, the
# same list it parses with `sh -n`. A copy of that list here would be a second
# thing to be wrong, and the way it would be wrong is this half reporting a
# clean pass over a directory the parse half had already grown.

# `<<WORD` and `<<-WORD`, unquoted. A quoted delimiter -- <<'WORD' or <<"WORD"
# -- expands nothing and is the safe form, so it deliberately does not match.
OPENER = re.compile(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:$|[);|&])")

# A command substitution. `\`` and `\$(` are escaped and therefore literal, so
# they are removed before asking.
SUBSTITUTION = re.compile(r"`|\$\(")


def comments_that_expand(text):
	"""Yield (line number, line) for each expanding comment in a heredoc."""
	lines = text.split("\n")
	index = 0
	while index < len(lines):
		opener = OPENER.search(lines[index])
		if not opener:
			index += 1
			continue
		delimiter = opener.group(1)
		index += 1
		while index < len(lines) and lines[index].strip() != delimiter:
			line = lines[index]
			# What the generated file will carry as a comment. The leading
			# whitespace is `<<-`'s to strip, so it is not part of the test.
			if line.lstrip().startswith("#"):
				literal = line.replace("\\`", "").replace("\\$", "")
				if SUBSTITUTION.search(literal):
					yield index + 1, line
			index += 1


def main():
	files = sorted(path for path in map(pathlib.Path, sys.argv[1:]) if path.is_file())
	# A gate over no files reports success exactly as loudly as a real pass,
	# and an unexpanded glob is how that happens: `make` hands this the words
	# the shell produced, so a directory that moved arrives as a literal
	# `tool/vm/*.sh` that `is_file` drops, silently, leaving a shorter list
	# and the same green line.
	if len(files) < 40:
		print(f"heredoc-gate: only {len(files)} script(s) given; the caller's list is wrong")
		return 1

	found = 0
	for path in files:
		text = path.read_text(encoding="utf-8", errors="replace")
		for number, line in comments_that_expand(text):
			found += 1
			print(f"heredoc-gate: {path}:{number}: a heredoc comment runs a command")
			print(f"heredoc-gate:   {line.strip()}")
			print("heredoc-gate:   quote the delimiter, or drop the backticks")
	if found:
		return 1

	print(f"heredoc-gate: {len(files)} script(s) write no heredoc comment that expands")
	return 0


if __name__ == "__main__":
	sys.exit(main())
