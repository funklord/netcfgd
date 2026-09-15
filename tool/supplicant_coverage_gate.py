#!/usr/bin/env python3
"""Every setting netcfgd sends a supplicant must be answered by a real one.

**This gate exists because the measurements kept being made and thrown away.**
Over the wifi audit of M9, each round that added a setting -- `sae_pwe`, `okc`,
`rand_addr_lifetime`, `preassoc_mac_addr` -- measured it against a real
`wpa_supplicant` on the `none` driver by hand, wrote the transcript into a
decision record as prose, and deleted the script. The next round had no way to
know it had been done, so it measured again. Meanwhile
`backend/netcfgd-supplicant/tests/live.rs` had been driving a real supplicant
and asserting read-back since M6, and none of the four was in it.

So this ties two things together:

  * the settings netcfgd sends, read out of the two places that send them --
    `SET <key>` globals in `kernel.rs` and `Setting::plain("key", ...)`
    per-network keys in `network.rs`;
  * what the real-supplicant suite drives, read out of the control-socket
    strings in `live.rs` plus explicit `// covers:` annotations for the
    settings a test exercises through `add_network` rather than by name.

A setting in neither fails the build, unless it is named in
`tool/supplicant-unexercised.txt` with a reason.

WHAT THIS DOES NOT PROMISE. It proves every setting is *driven* against a real
supplicant. It does not prove the value is right -- `SET okc 7` also answers
OK, as 10.122 records, so acceptance establishes that the key exists and not
that the value was understood. Nor does it read the suite's assertions: a test
that sends a key and checks nothing counts here. What it stops is a setting
shipping with no real supplicant ever having seen it, which is the specific
thing that kept happening.
"""

import re
import sys
import pathlib

KERNEL = pathlib.Path("crates/netcfgd-apply/src/kernel.rs")
NETWORK = pathlib.Path("backend/netcfgd-supplicant/src/network.rs")
LIVE = pathlib.Path("backend/netcfgd-supplicant/tests/live.rs")
UNEXERCISED = pathlib.Path("tool/supplicant-unexercised.txt")

# Globals netcfgd sends that are not settings of the supplicant's own: the
# handshake and the protocol, rather than anything a network is configured
# with. Named here rather than filtered by a pattern, because the whole point
# of the extraction is that a new key cannot arrive unnoticed.
NOT_A_SETTING = {"update_config", "not_a_real_global"}


def blanked(path):
	"""The file's lines with comments blanked, keeping the numbering.

	`privilege_gate.py` learned this the hard way: a comment quoting the text
	the scanner keys on ends a block early and silently drops what follows.
	Here a comment naming a setting would count as sending it.
	"""
	return [
		"" if line.lstrip().startswith("//") else line
		for line in path.read_text().splitlines()
	]


def sent():
	"""Settings netcfgd hands a supplicant, from the two places that hand them."""
	out = set()
	for line in blanked(KERNEL):
		for key in re.findall(r'"SET ([a-z0-9_]+)', line):
			out.add(key)
		# The formatted kind: `format!("SET {} {}", key, value)` is not one of
		# these, deliberately -- a key that is not a literal here cannot be
		# checked, and there are none. If one appears, this gate goes quiet
		# about it, so the count guard below is what catches the change.
		for key in re.findall(r'format!\("SET ([a-z0-9_]+) ', line):
			out.add(key)
	for line in blanked(NETWORK):
		for key in re.findall(r'Setting::(?:plain|secret)\(\s*"([a-z0-9_]+)"', line):
			out.add(key)
	return out - NOT_A_SETTING


def exercised():
	"""Settings the real-supplicant suite drives, by name or by annotation."""
	out = set()
	text = LIVE.read_text()
	# Driven by name: what the test actually puts on the control socket.
	for key in re.findall(r'(?:SET_NETWORK|GET_NETWORK) \{id\} ([a-z0-9_]+)', text):
		out.add(key)
	for key in re.findall(r'"(?:SET|GET) ([a-z0-9_]+)', text):
		out.add(key)
	# Driven through `add_network`, which renders a whole network: the test
	# never names these, so the test says which it covers. Beside the test
	# rather than in a file, so the claim and the evidence move together.
	for listed in re.findall(r'//\s*covers:\s*(.+)', text):
		out.update(re.findall(r'[a-z0-9_]+', listed))
	return out


def unexercised():
	"""Settings acknowledged as not driven, with a reason, by name."""
	if not UNEXERCISED.is_file():
		return set()
	out = set()
	for line in UNEXERCISED.read_text().splitlines():
		line = line.split("#", 1)[0].strip()
		if line:
			out.add(line)
	return out


def main():
	for path in (KERNEL, NETWORK, LIVE):
		if not path.is_file():
			print(f"supplicant-coverage: {path} is missing; the extraction is broken")
			return 1

	keys = sent()
	# A run that extracted nothing would find nothing uncovered and report
	# success in the same words as a real pass. `evidence.md`'s rule: a gate
	# over an empty list is not a pass.
	if len(keys) < 15:
		print(f"supplicant-coverage: only {len(keys)} settings found; the extraction is broken")
		print(f"supplicant-coverage:   looked in {KERNEL} and {NETWORK}")
		return 1

	drives = exercised()
	if not drives:
		print(f"supplicant-coverage: {LIVE} drives nothing; the extraction is broken")
		return 1

	acknowledged = unexercised()
	missing = sorted(keys - drives - acknowledged)
	stale = sorted(acknowledged - keys)
	claimed = sorted(acknowledged & drives)

	fail = 0
	for key in missing:
		print(f"supplicant-coverage: netcfgd sends `{key}` and no real supplicant is asked about it")
		fail = 1
	if missing:
		print(f"supplicant-coverage:   add a test to {LIVE}, or a `// covers:` line to the")
		print("supplicant-coverage:   test that drives it through add_network, or name it in")
		print(f"supplicant-coverage:   {UNEXERCISED} with the reason it cannot be")
	for key in stale:
		print(f"supplicant-coverage: `{key}` is excused in {UNEXERCISED} and nothing sends it")
		fail = 1
	for key in claimed:
		print(f"supplicant-coverage: `{key}` is excused in {UNEXERCISED} and the suite drives it")
		print("supplicant-coverage:   remove the excuse rather than leaving both")
		fail = 1

	if not fail:
		print(
			f"supplicant-coverage: {len(keys)} setting(s) netcfgd sends, "
			f"{len(keys & drives)} driven against a real supplicant, "
			f"{len(acknowledged)} excused by name"
		)
	return fail


if __name__ == "__main__":
	sys.exit(main())
