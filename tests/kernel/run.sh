#!/bin/sh
# Three kernels that differ only in whether they can do NAT, and netcfgd
# against each of them.
#
#     sh tests/kernel/run.sh <linux-source-dir> [out-dir]
#     make kernel-natcap KERNEL_SRC=<linux-source-dir>
#
# WHY A KERNEL IS BUILT AT ALL, GIVEN `tests/hull/natcap/` EXISTS
#   That rig measures the same states on the host's kernel by blocking module
#   autoload, which makes a construct unreachable by the same lookup that
#   fails when it was never compiled -- `nf_tables` asks for the chain type,
#   asks the module loader, asks again, and returns its own error without
#   regard for why the module never appeared. That is an argument, and this is
#   the experiment it predicts: **CONFIG_MODULES is off in all three kernels
#   here**, so there is no loader at all and "absent" cannot be confused with
#   "blocked".
#
#   Measured 2026-10-24 on 6.12.113, the two agreeing exactly: `ENOENT` with
#   `NFT_MSG_NEWCHAIN` refused where the chain type is missing, `ENOENT` with
#   `NFT_MSG_NEWRULE` where the masquerade is, and `EOPNOTSUPP` nowhere.
#
#   It also earned its keep on the way: there is no `CONFIG_NFT_CHAIN_NAT`.
#   `net/netfilter/Makefile` builds `nft_chain_nat.o` from `CONFIG_NFT_NAT`,
#   so netcfgd's capability sentence names both spellings -- found by this
#   script's own config check refusing a kernel configured with the symbol
#   that does not exist.
#
# THE CONTROL IS k0 AND IT IS NOT OPTIONAL
#   A kernel this small refusing NAT proves nothing by itself: it could be
#   refusing for any of the hundred things `x86_64_defconfig` minus modules
#   leaves out. k0 is the same kernel with the two constructs built in, and it
#   applies NAT. Without that line the other two measure a stripped kernel
#   rather than a missing construct.
#
# WHY NOT UNDER hull, WHICH IS WHERE THE REST OF THIS LIVES
#   hull's spec declares `(kernel "path:./bzImage")` and the qemu engine has
#   not built it -- it boots `/boot/vmlinuz-<release>`, the host's own
#   (hull's project.md section 1188 says so, and this was signalled to hull's
#   inbox on 2026-10-24). So this tier drives qemu directly, with an
#   initramfs built by the kernel's own `gen_init_cpio`, and moves under hull
#   the day that key works.
#
# WHAT IT COSTS AND HOW IT STOPS
#   A 1.6 GB source tree the caller supplies, three kernel builds of a few
#   minutes each, and three boots of a couple of seconds. Each qemu is bounded
#   by `timeout` and by `-no-reboot`, which is the right bound here and would
#   not be for a container: a vm is a child of this shell, so a signal reaches
#   it -- `running-code.md` has the container case.
set -eu

src=${1:-}
out=${2:-dist/kernel}
rootfs=${NATCAP_ROOTFS:-}
build=${NCFG_BUILD:-c}
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
jobs=${KERNEL_JOBS:-$(nproc 2>/dev/null || echo 4)}
boot_seconds=${KERNEL_BOOT_SECONDS:-300}

if [ -z "$src" ] || [ ! -f "$src/Makefile" ]; then
	cat >&2 <<USAGE
run.sh: needs an unpacked linux source tree, and this tree does not ship one.
run.sh:   On Debian:
run.sh:     apt-get download linux-source-6.12
run.sh:     dpkg-deb -x linux-source-6.12_*_all.deb x
run.sh:     tar -xf x/usr/src/linux-source-6.12.tar.xz
run.sh:     sh tests/kernel/run.sh linux-source-6.12
USAGE
	exit 1
fi
command -v qemu-system-x86_64 >/dev/null 2>&1 || {
	echo "run.sh: qemu-system-x86_64 is what boots these" >&2
	exit 1
}
# **The userland comes from the natcap image, materialized.** It was a
# `docker export` directory under `dist/` until 2026-10-25, when the rigs moved
# to `hull build` images (project.md 10.558) and that directory stopped
# existing. A stored ref is not a directory, and this tier needs one to pack
# into a cpio -- so materialize it, which is also the faithful direction:
# `hull materialize` keeps the modes a `tar -x` as a user would have dropped.
mkdir -p "$out"
if [ -z "$rootfs" ]; then
	rootfs=$out/natcap-rootfs
	if [ ! -d "$rootfs" ]; then
		hull=${HULL:-$HOME/src/hull/build/hull}
		command -v "$hull" >/dev/null 2>&1 || {
			echo "run.sh: need \`hull\` to materialize the image; set HULL=<path>" >&2
			exit 1
		}
		"$hull" images 2>/dev/null | grep -q '^netcfgd/natcap[[:space:]]' || {
			echo "run.sh: netcfgd/natcap is not in the store; \`make hull-image\`" >&2
			echo "run.sh:   builds it, or set NATCAP_ROOTFS to a directory instead" >&2
			exit 1
		}
		echo "run.sh: materializing netcfgd/natcap into $rootfs"
		"$hull" materialize netcfgd/natcap "$rootfs"
	fi
fi
[ -d "$rootfs" ] || {
	echo "run.sh: $rootfs is not there, and nothing could make it" >&2
	exit 1
}
for program in netcfgd ncfg; do
	[ -x "$build/$program" ] || {
		echo "run.sh: $build/$program is not built; \`make -C c\` first" >&2
		exit 1
	}
done
# **KVM or not is reported rather than required.** Without it these boot under
# TCG, slower and just as valid; silence about it is what makes a timing
# surprise look like a hang.
accel=tcg
[ -r /dev/kvm ] && [ -w /dev/kvm ] && accel=kvm
echo "run.sh: $jobs job(s), acceleration $accel, source $src"

# The initramfs is built once and carries no kernel: the same userland meets
# all three, which is what makes the three results comparable.
python3 "$here/make-initramfs.py" "$rootfs" "$here/kinit.sh" \
	"$build/netcfgd,$build/ncfg" "$out/initramfs.spec"
"$src/usr/gen_init_cpio" "$out/initramfs.spec" 2>/dev/null > "$out/initramfs.cpio" || {
	# The kernel tree builds `gen_init_cpio` as part of its own initramfs
	# machinery; compile it directly rather than asking for a full build.
	cc -O2 -o "$out/gen_init_cpio" "$src/usr/gen_init_cpio.c"
	"$out/gen_init_cpio" "$out/initramfs.spec" > "$out/initramfs.cpio"
}
gzip -1 -c "$out/initramfs.cpio" > "$out/initramfs.cpio.gz"
rm -f "$out/initramfs.cpio"
printf 'run.sh: initramfs %s\n' "$(du -h "$out/initramfs.cpio.gz" | cut -f1)"

failures=0
for state in k0 k1 k2; do
	echo
	echo "########## $state"
	sh "$here/config-kernel.sh" "$src" "$state"
	( cd "$src" && nice -n 10 make -j"$jobs" bzImage ) > "$out/build-$state.log" 2>&1 || {
		echo "run.sh: $state did not build; see $out/build-$state.log" >&2
		failures=$((failures + 1))
		continue
	}
	cp "$src/arch/x86/boot/bzImage" "$out/bzImage-$state"
	timeout -k 10 "$boot_seconds" qemu-system-x86_64 \
		-accel "$accel" -cpu host -smp 2 -m 2G -nographic -no-reboot \
		-kernel "$out/bzImage-$state" -initrd "$out/initramfs.cpio.gz" \
		-append "console=ttyS0 panic=5 loglevel=4" > "$out/run-$state.log" 2>&1 || true
	sed -n '/^=== /,/^natcap-kernel:/p' "$out/run-$state.log"
	# **The verdict comes from the guest's own line, not from qemu's status.**
	# qemu exits 0 for a machine that powered off whatever happened inside it,
	# and a boot that never reached the payload leaves no line at all -- which
	# must be a failure here rather than a silence.
	if ! grep -q "^natcap-kernel: every check passed" "$out/run-$state.log"; then
		echo "run.sh: $state did not pass; see $out/run-$state.log" >&2
		failures=$((failures + 1))
	fi
done

echo
if [ "$failures" -gt 0 ]; then
	echo "run.sh: $failures state(s) failed"
	exit 1
fi
echo "run.sh: all three states behaved as the autoload-blocked rig predicts"
