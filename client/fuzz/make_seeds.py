#!/usr/bin/env python3
"""Seeds for the `replies` target, out of the socket schema.

WHY A GENERATOR AND NOT HAND-WRITTEN BYTES
    An input to this target is a selector byte and then a reply line, and the
    reply lines that matter are real ones. `doc/schema/socket.json` already
    holds every request and response this protocol has, one JSON object per
    line, and `client/tests/client_test` validates the library against it --
    so it is the authoritative set rather than a second copy of one.

    This maps each response to the reader that would be waiting for it and
    writes one seed per pair. A reply handed to the wrong reader is a useful
    input too, and the fuzzer reaches those by flipping the first byte; what a
    seed should be is the case that gets furthest, which is the matching one.

    Re-run it when the schema grows:

        python3 client/fuzz/make_seeds.py

TERMINATION
    One pass over the schema's lines. Writes only into the corpus directory
    named below, one file per response kind.
"""

import json
import pathlib
import sys

# The switch in `replies.c`, by index. A response this does not name is still
# written, against reader 0, because the framing and the JSON run whatever the
# typed walk makes of it.
READERS = {
	"hello": 0,
	"status": 1,
	"plan": 5,
	"configs": 10,
	"hooks": 12,
	"modems": 14,
	"profiles": 15,
	"probes": 16,
	"radios": 17,
	"wifi_scan": 18,
	"secrets": 9,
	"document": 11,
	"explanation": 3,
	"journal": 4,
	"event": 4,
	"ap_stations": 18,
	"wifi_status": 18,
	"ok": 0,
	"error": 8,
}

# A response several readers consume needs a seed per reader, and the extra
# pairs are here rather than inferred. `ncfg_client_saved_networks` sends
# `{"request":"show"}` and walks `networks[]` out of the document it gets back
# -- so the document response feeds reader 19 as well as 11, and the seed that
# actually reaches `read_routes` is a document whose networks have routes in
# them. `seed-document-saved-networks.bin` is that, made with
#
#     ncfg show --json   on a config with a network carrying
#                        `config`, `routes` and a `dns` block
#
# and kept rather than regenerated here, because this script reads the schema
# and the schema has no such document in it. **Measured 2026-10-21: without it
# the corpus never reached `read_routes` at all** -- a sabotage of that
# function went unnoticed for 971,215 executions, which is how the gap was
# found.
EXTRA = ()

def monitor_seeds(lines, into):
	"""The event stream, for the `monitor` target.

	**Both shapes, and the first version of this took only one.** A monitor
	delivers a bare `{"event": ...}` line; a request's answer carries
	`{"response": "event", "event": ...}`. The schema has one of the second
	and one of each of the five firsts, and a filter for the wrapped form
	alone saw one event kind where there are five -- which is how this target
	was seeded with a fifth of what the reader can meet (project.md 10.514).

	Three files: every event there is, as the stream a busy minute looks like;
	the same again four times over, for the repeated-call path a single line
	cannot reach; and half a line, for the end of stream arriving mid-event.
	"""
	events = []
	for line in lines:
		try:
			message = json.loads(line)
		except json.JSONDecodeError:
			continue
		if isinstance(message.get("event"), str):
			events.append(line)
	if not events:
		return 0
	into.mkdir(parents=True, exist_ok=True)
	(into / "seed-every-event.txt").write_text("\n".join(events) + "\n")
	(into / "seed-many.txt").write_text(("\n".join(events) + "\n") * 4)
	(into / "seed-half-a-line.txt").write_text(events[0][: len(events[0]) // 2])
	return 3


def main():
	root = pathlib.Path(__file__).resolve().parents[2]
	schema = root / "doc/schema/socket.json"
	into = pathlib.Path(__file__).resolve().parent / "corpus/replies"
	into.mkdir(parents=True, exist_ok=True)
	written = 0
	seen = {}
	for line in schema.read_text().splitlines():
		line = line.strip()
		if not line:
			continue
		try:
			kind = json.loads(line).get("response")
		except json.JSONDecodeError:
			print(f"make_seeds: {schema} has a line that is not JSON", file=sys.stderr)
			return 1
		if not kind:
			continue
		seen[kind] = seen.get(kind, 0) + 1
		name = f"seed-{kind}{'' if seen[kind] == 1 else '-' + str(seen[kind])}.bin"
		(into / name).write_bytes(bytes([READERS.get(kind, 0)]) + line.encode())
		written += 1
	if not written:
		print(f"make_seeds: no responses found in {schema}", file=sys.stderr)
		return 1
	stream = monitor_seeds(schema.read_text().splitlines(),
	    pathlib.Path(__file__).resolve().parent / "corpus/monitor")
	if not stream:
		print(f"make_seeds: no events found in {schema}, so the monitor target",
		    file=sys.stderr)
		print("make_seeds:   would be seeded with nothing", file=sys.stderr)
		return 1
	print(f"make_seeds: {written} reply seed(s) and {stream} stream seed(s)")
	return 0

if __name__ == "__main__":
	sys.exit(main())
