"""The C port's module order, checked against what its sources include.

WHAT THIS ENFORCES
  Decision 0263 numbers the port's modules and says dependencies come first:
  base, then json, then model, then compile, then sys, and then a sixth group
  holding proto, host, plan, apply, daemon and cli -- to which backend and
  observe were added later. A module in the first five may not include a
  header owned by a later one.

  The order is 0263's and is not restated here. What this file adds is the
  mapping from a header to the module that owns it, and that is *derived*
  rather than listed: a header's owner is the module whose sources define the
  functions it declares. A list would be a second thing to keep true, and the
  one place it went wrong would be the module somebody had just moved.

WHY THE SIXTH GROUP IS NOT ORDERED HERE
  Because 0263 does not order it. Writing an order for those six would be
  inventing a decision inside a gate, which is the worst place to keep one --
  quiet, and enforced. project.md 10.256 has the case for deciding one and
  says whose decision it is.

WHAT THIS CATCHES AND WHAT IT DOES NOT
  It catches a rule in the wrong layer being *reached for*: a compiler that
  includes a backend header to get a model rule compiles perfectly and nothing
  else complains.

  It does not catch the same rule being *copied*, which is the form both of
  the cases that prompted it actually took -- and the two are alternatives, so
  this closes the silent one and leaves the one a reader of the file can see.
  `c/src/model/device.c` has that history.

WHAT A FAILURE LOOKS LIKE
  The file, the header, and which module owns it, so that the answer is either
  "move the rule down" or "record a divergence", rather than a guess.
"""

import collections
import pathlib
import re
import sys

ROOT = pathlib.Path("c")
SRC = ROOT / "src"
HEADERS = ROOT / "include" / "ncfg"

# 0263's numbering. Anything not named here is in its sixth group, which that
# decision leaves unordered.
ORDER = {"base": 1, "json": 2, "model": 3, "compile": 4, "sys": 5}
LATER = 6

# A definition at column zero: a return type, then the name, then an open
# paren. `static` is included deliberately -- a static definition still tells
# you which module the name lives in, and a header never declares one.
DEFINITION = re.compile(r"^[A-Za-z_][A-Za-z0-9_ \t*]*?\b(ncfg_[a-z0-9_]+)\s*\(", re.M)
DECLARATION = re.compile(r"\b(ncfg_[a-z0-9_]+)\s*\(")
INCLUDE = re.compile(r'#include "ncfg/([a-z_0-9]+\.h)"')

FLOOR = 40


def tier(module):
	return ORDER.get(module, LATER)


def module_of(path):
	return path.relative_to(SRC).parts[0]


def main():
	if not SRC.is_dir() or not HEADERS.is_dir():
		print("module-order-gate: the C port is not here, so this checked nothing")
		return 1

	sources = sorted(SRC.glob("**/*.c")) + sorted(SRC.glob("**/*.h"))
	definer = {}
	for path in sources:
		module = module_of(path)
		for found in DEFINITION.finditer(path.read_text()):
			definer.setdefault(found.group(1), module)

	owner = {}
	for header in sorted(HEADERS.glob("*.h")):
		named = set(DECLARATION.findall(header.read_text()))
		seen = collections.Counter(definer[one] for one in named if one in definer)
		if seen:
			owner[header.name] = seen.most_common(1)[0][0]

	if len(owner) < FLOOR:
		print(f"module-order-gate: only {len(owner)} header(s) could be attributed to a "
		    f"module, which is fewer than the {FLOOR} this tree has -- the mapping is "
		    "broken, so nothing below means anything")
		return 1

	checked = 0
	bad = []
	for path in sources:
		module = module_of(path)
		if tier(module) >= LATER:
			continue
		checked += 1
		for found in INCLUDE.finditer(path.read_text()):
			header = found.group(1)
			if header in owner and tier(owner[header]) > tier(module):
				bad.append((path, header, module, owner[header]))

	if bad:
		print("module-order-gate: a module includes a header a later module owns:")
		for path, header, module, held in bad:
			print(f"module-order-gate:   {path} -- {module} ({tier(module)}) includes "
			    f"ncfg/{header}, which {held} owns")
		print("module-order-gate: decision 0263 orders these; either the rule belongs in "
		    "an earlier module or the divergence belongs in project.md")
		return 1

	print(f"module-order-gate: {checked} source(s) in the five ordered modules include "
	    f"nothing a later one owns, over {len(owner)} attributed header(s)")
	return 0


if __name__ == "__main__":
	sys.exit(main())
