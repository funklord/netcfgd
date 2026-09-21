The configuration and the document it must compile to, on every architecture.

`netcfgd.conf` is deliberately awkward: a list, a nested block, a non-ASCII
SSID, an integer, a bool, and two interfaces of different kinds -- the shapes
where a byte-order or a hash-ordering difference would show. `expected.json` is
what `ncfg show --json` produces from it.

Checked with `sh tests/determinism.sh`, which cross-builds and runs under
emulation. The recorded result for the **earlier** fixture: byte-identical on
x86_64, aarch64 and s390x, md5 `dccacd09181d5903e5eda91db2183207`. s390x is the
one that matters most -- it is big-endian, so it is the only one of the three
that would catch a native-endian assumption in the compiler or the hash.

**That run has not been repeated since**, and the md5 above is of the document
this fixture no longer produces: `mtu`, `qdisc` and `bridge` moved from
`interface` to `device` in the language, and this file went on stating them
where they used to go. It therefore stopped compiling at all -- which
`determinism.sh` would have reported as three failures on a machine with
docker, and reported as a skip on every machine without one. Fixed by moving
the three blocks and regenerating `expected.json`; somebody with docker and the
qemu handlers should run the script again and record what it says here.

The same two files are in `tool/agree_gate.py`'s corpus, which is what noticed:
that gate compiles this directory with both `ncfg` programs and compares the
documents, so a fixture that compiles with neither is a fixture it refuses.
