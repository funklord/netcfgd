#!/usr/bin/env python3
"""Every module of the C port has a test that includes its header.

Decision 0263 says what a module owes: its header, its sources, and **its
tests in the same wave** -- not afterwards. A module whose tests are "to
follow" is a module that has not been ported, and the Rust being replaced
carries its tests beside it, most of them naming a defect that shipped.

That sentence is worth nothing unless something checks it, because the way it
fails is silent: a header lands, the library builds, `make -C c test` passes
over the modules that *do* have tests, and the count goes up. A pass over a
smaller set reports success exactly as loudly as a real one.

WHAT THIS CHECKS

Every header under `c/include/ncfg/` is `#include`d by at least one test under
`c/tests/`. Not that the tests are good -- nothing can check that -- but that
the module is reached by one at all.

WHAT THIS DOES NOT SEE

Whether a source file under `c/src/` is exercised. A module is its header
here: that is what other modules call, and a `.c` with no header is either
private to its module or something this gate should be told about.
"""

import pathlib
import re
import sys

HEADERS = pathlib.Path("c/include/ncfg")
TESTS = pathlib.Path("c/tests")


def main():
	if not HEADERS.is_dir():
		print("c-tests-gate: no C port in this tree, so there is nothing to check")
		return 0

	headers = sorted(path.name for path in HEADERS.glob("*.h"))
	tests = sorted(TESTS.glob("*_test.c"))
	if not headers or not tests:
		print(f"c-tests-gate: {len(headers)} header(s) and {len(tests)} test(s) found;")
		print("c-tests-gate:   the extraction is broken, which looks exactly like a pass")
		return 1

	included = set()
	for path in tests:
		for match in re.finditer(r'#include\s+"ncfg/([A-Za-z0-9_]+\.h)"', path.read_text()):
			included.add(match.group(1))

	missing = [header for header in headers if header not in included]
	for header in missing:
		print(f"c-tests-gate: ncfg/{header} is included by no test under {TESTS}")
		print("c-tests-gate:   0263: a module whose tests are to follow has not been ported")
	if missing:
		return 1

	print(f"c-tests-gate: {len(headers)} header(s), each reached by a test in {len(tests)} file(s)")
	return 0


if __name__ == "__main__":
	sys.exit(main())
