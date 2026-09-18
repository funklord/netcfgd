"""Every public header of the C port, included together, in one file.

WHAT THIS CATCHES, AND WHY NOTHING ELSE DID
  `tun.h` declared its own `ncfg_tun_mode_t` with the same two enumerators as
  `document.h`. C makes a repeated enumerator a *redeclaration*, so any
  translation unit including both failed to compile -- and none ever did.
  `tun.c` and `tun_test.c` take `tun.h` alone, so the module built, its tests
  passed, and `c_tests_gate.py` was satisfied that the header was reached by a
  test. It was. It just could not be reached at the same time as its neighbour.

  That is a latent build break that appears the day somebody writes the first
  caller needing both -- which is exactly when they are trying to do something
  else, and the error names a line neither of them wrote.

WHY A WHOLE-TREE INCLUDE RATHER THAN EVERY PAIR
  Pairs are O(n^2) compiles for a property that is nearly always transitive: a
  name clash between two headers shows up as readily with all of them present
  as with just those two. What one file cannot catch is a header that fails to
  compile *alone* -- one that depends on something a neighbour happens to
  include first. `c_tests_gate.py` covers that from the other side, since a
  test includes what it needs and little else.

  So this is the cheaper half of a two-sided property, and it is the half that
  was missing.

WHAT A FAILURE LOOKS LIKE
  The compiler's own message, unedited. It names the header, the line and the
  clashing name, which is more than this file could say about it.
"""

import pathlib
import subprocess
import sys
import tempfile

HEADERS = pathlib.Path("c/include/ncfg")
INCLUDE = pathlib.Path("c/include")
CLIENT = pathlib.Path("client")
FLOOR = 20


def main():
	if not HEADERS.is_dir():
		print(f"headers-gate: {HEADERS} is missing, so this would check nothing")
		return 1
	names = sorted(path.name for path in HEADERS.glob("*.h"))
	# A gate over an empty list passes as loudly as a real one.
	if len(names) < FLOOR:
		print(f"headers-gate: found {len(names)} header(s) under {HEADERS}, fewer than")
		print(f"headers-gate:   the {FLOOR} this tree has had for months -- the listing is broken")
		return 1

	body = "".join(f'#include "ncfg/{name}"\n' for name in names)
	body += "int main(void) { return 0; }\n"
	with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as handle:
		handle.write(body)
		source = handle.name
	try:
		done = subprocess.run(
			["gcc", "-std=c11", f"-I{INCLUDE}", f"-I{CLIENT}", "-fsyntax-only", source],
			capture_output=True, text=True, timeout=120,
		)
	except (OSError, subprocess.SubprocessError) as error:
		print(f"headers-gate: could not run the compiler: {error}")
		return 1
	finally:
		pathlib.Path(source).unlink(missing_ok=True)

	if done.returncode != 0:
		print(f"headers-gate: the {len(names)} public headers do not compose:")
		for line in done.stderr.splitlines()[:12]:
			print(f"headers-gate:   {line.replace(source, 'all-headers.c')}")
		print("headers-gate:   two headers declaring one name is a build that breaks for")
		print("headers-gate:   whoever first needs both, in a file neither of them is in")
		return 1
	print(f"headers-gate: {len(names)} public header(s), all of them in one file")
	return 0


if __name__ == "__main__":
	sys.exit(main())
