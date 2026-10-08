"""Every path in the scope and kind tables is a key the language actually has.

WHAT THIS ENFORCES
  `c/src/compile/scope.c` names configuration keys as paths -- `mtu`,
  `advertise.prefix`, `wifi.roam.signal` -- and gives the travelling ones a
  wire number. Those names are written by hand and nothing in C connects them
  to the lowering, so a row can name a key that does not exist, or a VALUE
  mistaken for a key, and every test over the table still passes: the lookup
  returns the row, and no fixture asks whether the key is real.

  That is not hypothetical. The first version of the kind registry carried six
  such rows -- `address`, which is not a key at all, and `radvd`, `odhcpd` and
  `auto`, which are values of `advertise.backend` -- alongside twelve keys
  registered a level too shallow. project.md 10.326.

  So this reads the same `strcmp` chains the lowering recognises keys by, and
  refuses a registered path whose leaf is not among the ones reachable from
  that block. The block matters: `address` IS a key spelling in this language
  -- a bluetooth device's -- so a pooled list of every spelling accepts
  `interface.address` and would have missed the fault that prompted this. The
  control below is that exact row.

WHAT IT DOES NOT CATCH, WHICH IS HALF THE QUESTION
  **Completeness.** Nothing enumerates the language's keys, so no check here
  can say a travelling key is missing from the registry. That gap is why
  `NCFG_KIND_NONE` is zero: an unregistered key cannot be written wrongly,
  only not at all.

  **Nesting, within a block.** Attribution is per FILE, so this sees the leaf
  and the sub-block names separately rather than that a given leaf belongs
  under a given sub-block. `interface.advertise.mtu` would pass: `advertise`
  is a head and `mtu` is an interface key, just not that sub-block's. Getting
  further needs the lowering to consult the registry rather than the other way
  round, which is a real change to `compile/` and is not started.

  **A wrong row in OWNERS below.** The attribution is hand-written. It fails
  loudly rather than quietly -- too narrow and the gate rejects real keys,
  which is the first thing anybody would notice -- but nothing here proves it
  right.

  **Whether a scope judgement is right.** It checks that a key exists, never
  that it belongs where the table puts it.

WHAT A FAILURE LOOKS LIKE
  The block, the path, and which component was not found, so the answer is
  either "fix the path" or "that is a value, not a key".
"""

import pathlib
import re
import sys

COMPILE = pathlib.Path("c/src/compile")
TABLE = COMPILE / "scope.c"

# Which blocks each lowering file can supply keys for.
#
# **Written out rather than derived, because the relation is many-to-many and
# the code says so only through call sites.** `lower_network.c` holds the
# shared security lowering, which an interface's `dot1x` and an access point's
# `wifi` both call; `lower_device.c` holds `ethtool` and `qdisc`, which an
# interface block also takes; `lower_kind.c` is reached from an interface's
# `kind`. A file absent from a block's row cannot supply that block a key,
# which is the whole point: `address` lives in `lower_rule.c` under
# `bluetooth` and must not satisfy `interface.address`.
OWNERS = {
	# `ncfg_lower_dns_key` lives here and is called from an interface's and a
	# network's `dns` block as well as from `global`'s.
	"lower_global.c": {"NCFG_BLOCK_GLOBAL", "NCFG_BLOCK_INTERFACE", "NCFG_BLOCK_NETWORK"},
	"lower_interface.c": {"NCFG_BLOCK_INTERFACE"},
	"lower_device.c": {"NCFG_BLOCK_DEVICE", "NCFG_BLOCK_INTERFACE"},
	"lower_kind.c": {"NCFG_BLOCK_DEVICE", "NCFG_BLOCK_INTERFACE"},
	"lower_network.c": {"NCFG_BLOCK_NETWORK", "NCFG_BLOCK_ACCESS_POINT",
	    "NCFG_BLOCK_INTERFACE"},
	"lower_rule.c": {"NCFG_BLOCK_RULE", "NCFG_BLOCK_LINKSET", "NCFG_BLOCK_BLUETOOTH"},
	# The value grammar -- addressing words, route words. It defines no keys,
	# and is listed so that an unlisted file is a gate failure rather than a
	# silent nothing.
	"lower_address.c": set(),
	"lower.c": set(),
	"lower_value.c": set(),
}

LOWERING = sorted(COMPILE.glob("lower*.c"))

# `strcmp(<something>, "literal")`, keeping the variable so a key can be told
# from a value. The lowering compares an assignment's key against a variable
# whose name says so -- `key`, `assignment->key` -- a block head against one
# named `head`, and an enumerated VALUE against neither: `name`, `word`,
# `text`. That third bucket is the one the registry must never name, and it is
# recognised by being in neither of the first two rather than by a list.
COMPARE = re.compile(r'strcmp\(\s*([A-Za-z_][\w.\->\[\]]*)\s*,\s*"([a-z_0-9]+)"')

# A row of any of the three tables: a block, a quoted path, then the rest.
ROW = re.compile(r'\{\s*(NCFG_BLOCK_[A-Z_]+)\s*,\s*"([a-z_0-9.]+)"')

# Enough of each to say the instrument is alive. A regex that stops matching
# reports a clean tree in exactly the words a clean tree uses.
KEY_FLOOR = 100
PATH_FLOOR = 60

# Names the grammar carries as their own item rather than as an assignment, so
# they are real and are not among the key literals. Declared here with the
# reason, because an undeclared exemption is an ignore list.
NOT_ASSIGNMENTS = {
	"hooks": "its own AST item -- `hook <phase> { }` -- not a `key = value`",
}


def literals():
	"""Key spellings and block heads, per block, as the lowering compares them."""
	keys = {}
	heads = {}
	unlisted = []
	for path in LOWERING:
		blocks = OWNERS.get(path.name)
		if blocks is None:
			unlisted.append(path.name)
			continue
		for variable, literal in COMPARE.findall(path.read_text()):
			if "key" in variable:
				where = keys
			elif "head" in variable:
				where = heads
			else:
				continue
			for block in blocks:
				where.setdefault(block, set()).add(literal)
	return keys, heads, unlisted


def rows(text):
	"""Every (block, path) the tables name, in file order."""
	return [(block, path) for block, path in ROW.findall(text)]


def bad_components(block, path, keys, heads):
	"""Which components of a path this block cannot supply, leaf last."""
	parts = path.split(".")
	mine = keys.get(block, set())
	subs = heads.get(block, set())
	missing = []
	for part in parts[:-1]:
		if part not in subs:
			missing.append((part, "sub-block"))
	# The leaf may be a sub-block head: a scope exception covering everything
	# under it is the inheritance the table is built on. A kind may not, and
	# that is checked in C rather than here -- a number belongs to one key.
	leaf = parts[-1]
	if leaf not in mine and leaf not in subs and leaf not in NOT_ASSIGNMENTS:
		missing.append((leaf, "key or sub-block"))
	return missing


# Three cases that must separate, and each fails the way a real fault does.
# A control that only passes is a constant; one that fails for an unrelated
# reason is a second instrument with the same blind spot.
CONTROL = (
	("NCFG_BLOCK_INTERFACE", "advertise.prefix", True, "a real path"),
	# A VALUE of `advertise.backend`, which is how three of the six rows in
	# 10.357 got written.
	("NCFG_BLOCK_INTERFACE", "advertise.radvd", False, "a value, not a key"),
	# A real key OF ANOTHER BLOCK -- bluetooth's. This is the row that
	# prompted the gate, and a pooled key list accepts it.
	("NCFG_BLOCK_INTERFACE", "address", False, "another block's key"),
	# And the same spelling where it IS the block's, so the rejection above
	# is about the block rather than about the word.
	("NCFG_BLOCK_BLUETOOTH", "address", True, "the same key where it lives"),
)


def control(keys, heads):
	"""Prove the check can speak before believing its silence."""
	for block, path, should_pass, what in CONTROL:
		missing = bad_components(block, path, keys, heads)
		if should_pass and missing:
			return f"{what} was rejected: {block} {path} -> {missing}"
		if not should_pass and not missing:
			return f"{what} was accepted: {block} {path}"
	return None


def main():
	keys, heads, unlisted = literals()
	if unlisted:
		print(f"registry-gate: no block attribution for {', '.join(unlisted)}")
		print("registry-gate: add a row to OWNERS rather than letting a file go unread")
		return 2
	broken = control(keys, heads)
	if broken:
		print(f"registry-gate: THE CONTROL FAILED -- {broken}")
		print("registry-gate: no result below means anything; fix the probe first")
		return 2
	spellings = set().union(*keys.values()) if keys else set()
	if len(spellings) < KEY_FLOOR:
		print(f"registry-gate: only {len(spellings)} key spelling(s) found in "
		    f"{len(LOWERING)} lowering file(s), under the floor of {KEY_FLOOR}")
		print("registry-gate: the extraction has stopped matching; this is not a pass")
		return 2

	registered = rows(TABLE.read_text())
	if len(registered) < PATH_FLOOR:
		print(f"registry-gate: only {len(registered)} table row(s) read, under the "
		    f"floor of {PATH_FLOOR}")
		return 2

	faults = []
	for block, path in registered:
		for part, what in bad_components(block, path, keys, heads):
			faults.append((block, path, part, what))

	if faults:
		print("registry-gate: a table names something the lowering does not have:")
		for block, path, part, what in faults:
			print(f"registry-gate:   {block} {path} -- `{part}` is no {what} that "
			    f"block can reach in compile/lower_*.c")
		print("registry-gate: either the path is wrong, it names a value rather than "
		    "a key, or it belongs to another block")
		return 1

	exempt = sum(1 for _, path in registered if path.split(".")[-1] in NOT_ASSIGNMENTS)
	heads_seen = set().union(*heads.values()) if heads else set()
	print(f"registry-gate: {len(registered)} registered path(s) all name keys their own "
	    f"block has, over {len(spellings)} key spelling(s) and {len(heads_seen)} block "
	    f"head(s) in {len(LOWERING)} file(s)")
	print(f"registry-gate: {exempt} exempt as non-assignment grammar; completeness and "
	    "nesting are out of reach and stay so -- see this file's header")
	return 0


if __name__ == "__main__":
	sys.exit(main())
