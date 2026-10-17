#!/usr/bin/env python3
"""Every decision record has a number of its own, and its title agrees with it.

**What a duplicate number costs.** The records are cited by number from source
and from `project.md` -- 325 citations of three numbers alone when this was
written -- and a number is worth citing only because it names one decision.
Three records had been written with numbers already taken, so `0263`, `0264`
and `0265` each named two: every citation of them became ambiguous, and
`settings.c` carried one that resolved to neither. Fixing it meant renumbering
three records and re-pointing their citations by reading context, which is the
sort of work nobody should have to do twice.

**Why it happened is worth more than the fix.** The number of a new record is
the highest existing one plus one, and nothing told anybody what the highest
was. A `ls | tail` on a directory of 275 files is easy to misread, and the
three collisions are dated within five days of each other -- so this is not
one slip but the predictable result of asking a person to compute a maximum.

The title is checked against the filename for the other half of the same
hazard: a renumber that moves the file and leaves `# 0264:` at the top of it
produces a record that disagrees with its own name, and a reader who greps for
one finds the other.
"""

import pathlib
import re
import sys

RECORDS = pathlib.Path("doc/decision")


def main() -> int:
    if not RECORDS.is_dir():
        print("decision-gate: no doc/decision, nothing to check")
        return 0
    seen: dict[str, list[str]] = {}
    mismatched: list[str] = []
    for path in sorted(RECORDS.glob("*.md")):
        match = re.match(r"^(\d{4})-", path.name)
        if not match:
            print(f"decision-gate: {path.name} does not open with a four-digit number")
            return 1
        number = match.group(1)
        seen.setdefault(number, []).append(path.name)
        head = path.read_text(encoding="utf-8").split("\n", 1)[0]
        title = re.match(r"^#\s*(\d{4})\s*:", head)
        if not title:
            mismatched.append(f"{path.name}: first line is not `# {number}: ...`")
        elif title.group(1) != number:
            mismatched.append(
                f"{path.name}: titled {title.group(1)} and filed as {number}"
            )
    duplicates = {n: f for n, f in seen.items() if len(f) > 1}
    for number, files in sorted(duplicates.items()):
        print(f"decision-gate: {number} names {len(files)} records:")
        for name in files:
            print(f"    {name}")
    for problem in mismatched:
        print(f"decision-gate: {problem}")
    if duplicates or mismatched:
        print(
            "decision-gate: a citation by number must name one decision. The next "
            f"free number is {max(int(n) for n in seen) + 1:04d}."
        )
        return 1
    print(
        f"decision-gate: {len(seen)} records, each with a number of its own and a "
        f"title that agrees with it; the next free number is "
        f"{max(int(n) for n in seen) + 1:04d}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
