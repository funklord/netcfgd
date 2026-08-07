The configuration and the document it must compile to, on every architecture.

`netcfgd.conf` is deliberately awkward: a list, a nested block, a non-ASCII
SSID, an integer, a bool, and two interfaces of different kinds -- the shapes
where a byte-order or a hash-ordering difference would show. `expected.json` is
what `ncfg show --json` produces from it.

Checked with `sh tests/determinism.sh`, which cross-builds and runs under
emulation. The recorded result: **byte-identical on x86_64, aarch64 and
s390x**, md5 `dccacd09181d5903e5eda91db2183207`. s390x is the one that matters
most -- it is big-endian, so it is the only one of the three that would catch a
native-endian assumption in the compiler or the hash.
