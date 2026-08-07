#!/bin/sh
# The same configuration must compile to the same bytes on every architecture.
#
#     sh tests/determinism.sh
#
# Section 6 claims "same config compiles to byte-identical document across runs
# and platforms". The runs half was gated; the *platforms* half had never been
# checked against a second platform at all, because there was no way to build
# for one and no way to run one.
#
# There is now. `rust:1-slim-trixie` carries a rustup that can add a target,
# and qemu-user through binfmt lets the result execute, so this cross-builds
# `ncfg` and runs `ncfg show --json` on each architecture against the same
# fixture.
#
# **s390x is the point.** aarch64 and x86_64 are both little-endian, so they
# agree for reasons that say nothing about byte order. s390x is big-endian and
# is the only one of the three that would catch a native-endian assumption in
# the compiler, the canonicaliser or the hash.
#
# Emulated, and that limit is real: this proves the *pure* path -- text in,
# canonical document out -- and proves nothing about drivers, netlink or
# timing on real hardware. It is the half that does not need the hardware.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture="$repo/tests/determinism"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "determinism.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "determinism.sh: skipping: $1"
	exit 0
}

command -v docker >/dev/null 2>&1 || skip "no docker"
docker info >/dev/null 2>&1 || skip "docker is installed but not usable"
[ -e /proc/sys/fs/binfmt_misc/qemu-aarch64 ] || skip "no qemu-aarch64 binfmt handler"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-det.XXXXXX")
cleanup() {
	# The container writes as root, so a plain rm cannot finish the job.
	docker run --rm -v "$work":/w debian:trixie rm -rf /w/out /w/bin >/dev/null 2>&1 || true
	rm -rf "$work" 2>/dev/null || true
	return 0
}
trap cleanup EXIT INT TERM

mkdir -p "$work/bin" "$work/etc"
cp "$fixture/netcfgd.conf" "$work/etc/netcfgd.conf"

# rust-triple : dpkg-architecture : gnu-triple
#
# The gnu triple is the last field because both names derive from it and they
# are not the same string: Debian ships the package `gcc-aarch64-linux-gnu`
# containing the binary `aarch64-linux-gnu-gcc`. Naming the package and using
# it as the linker gets "linker not found", which is the same mistake the
# Makefile's CROSS_GNU table exists to avoid. An empty field means the host.
targets="x86_64-unknown-linux-gnu:amd64: \
         aarch64-unknown-linux-gnu:arm64:aarch64-linux-gnu \
         s390x-unknown-linux-gnu:s390x:s390x-linux-gnu"

echo "determinism.sh: cross-building, which takes a few minutes"
cat > "$work/build.sh" <<'BUILD'
set -e
for spec in $TARGETS; do
	triple=${spec%%:*}; rest=${spec#*:}; arch=${rest%%:*}; cc=${rest#*:}
	# `if`, not `&&`: under `set -e` a false test is the last command in the
	# list, so `[ -n "$cc" ] && ...` exits the script on the entry whose
	# linker is empty -- which is the host one, the first in the list.
	if [ -n "$cc" ]; then dpkg --add-architecture "$arch"; fi
done
apt-get -qq update >/dev/null 2>&1
# The host needs ncurses too, and its entry carries no cross-linker -- so it
# fell through the per-architecture install below and failed at link time on
# `-lncursesw`, which reads like a cross-compilation problem and is not one.
apt-get -qq install -y libncurses-dev >/dev/null 2>&1
for spec in $TARGETS; do
	triple=${spec%%:*}; rest=${spec#*:}; arch=${rest%%:*}; cc=${rest#*:}
	if [ -n "$cc" ]; then
		apt-get -qq install -y "gcc-$cc" "libncurses-dev:$arch" >/dev/null 2>&1
	fi
	rustup target add "$triple" >/dev/null 2>&1
done
cp -a /src /work && cd /work
export CARGO_TARGET_DIR=/out
for spec in $TARGETS; do
	triple=${spec%%:*}; rest=${spec#*:}; arch=${rest%%:*}; cc=${rest#*:}
	if [ -n "$cc" ]; then
		export "CARGO_TARGET_$(echo "$triple" | tr 'a-z-' 'A-Z_')_LINKER=$cc-gcc"
	fi
	if ! cargo build --release --target "$triple" -p netcfgd-bin >/tmp/build.log 2>&1; then
		echo "build failed for $triple:"
		grep -E "^error" -A5 /tmp/build.log | head -12
		exit 1
	fi
	mkdir -p "/bin_out/$arch"
	cp "/out/$triple/release/netcfgd" "/bin_out/$arch/netcfgd"
	ln -sf netcfgd "/bin_out/$arch/ncfg"
done
chown -R "$OWNER" /bin_out
BUILD

docker run --rm -v "$repo":/src:ro -v "$work/bin":/bin_out -v "$work":/w \
	-e TARGETS="$targets" -e OWNER="$(id -u):$(id -g)" \
	rust:1-slim-trixie sh /w/build.sh

first=""
failures=0
for spec in $targets; do
	rest=${spec#*:}
	arch=${rest%%:*}
	# The binary is a multi-call one and picks its program from argv[0], so it
	# has to be invoked as `ncfg` and not as a path ending in anything else.
	docker run --rm --platform "linux/$arch" -v "$work":/w debian:trixie sh -c \
		'apt-get -qq update >/dev/null 2>&1
		 apt-get -qq install -y libncursesw6 >/dev/null 2>&1
		 /w/bin/'"$arch"'/ncfg show --json --config-dir /w/etc' \
		> "$work/out.$arch" 2>"$work/err.$arch" || {
		echo "FAIL $arch: ncfg did not run"
		sed 's/^/       /' "$work/err.$arch" | tail -3
		failures=$((failures + 1))
		continue
	}
	if [ -z "$first" ]; then
		first=$arch
		if cmp -s "$work/out.$arch" "$fixture/expected.json"; then
			echo "ok   $arch matches tests/determinism/expected.json"
		else
			echo "FAIL $arch does not match the committed document"
			diff "$fixture/expected.json" "$work/out.$arch" | head -6
			failures=$((failures + 1))
		fi
		continue
	fi
	if cmp -s "$work/out.$arch" "$work/out.$first"; then
		echo "ok   $arch is byte-identical to $first"
	else
		echo "FAIL $arch differs from $first"
		diff "$work/out.$first" "$work/out.$arch" | head -6
		failures=$((failures + 1))
	fi
done

if [ "$failures" -ne 0 ]; then
	echo "determinism.sh: $failures failed" >&2
	exit 1
fi
echo "determinism.sh: ok -- little-endian and big-endian agree byte for byte"
