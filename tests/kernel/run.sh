#!/bin/sh
# Three kernels that differ only in whether they can do NAT, and netcfgd
# against each of them, in machines hull boots.
#
#     sh tests/kernel/run.sh <linux-source-dir> [out-dir]
#     make kernel-natcap KERNEL_SRC=<linux-source-dir>
#
# WHY A KERNEL IS BUILT AT ALL, GIVEN `tests/hull/natcap/` EXISTS
#   That rig measures the same states on the host's kernel by blocking module
#   autoload, which makes a construct unreachable by the same lookup that
#   fails when it was never compiled. That is an argument, and this is the
#   experiment it predicts: **CONFIG_MODULES is off in all three kernels
#   here**, so there is no loader at all and "absent" cannot be confused with
#   "blocked".
#
#   Measured 2026-10-24 on 6.12.113, the two agreeing exactly: `ENOENT` with
#   `NFT_MSG_NEWCHAIN` refused where the chain type is missing, `ENOENT` with
#   `NFT_MSG_NEWRULE` where the masquerade is, and `EOPNOTSUPP` nowhere.
#
#   **k3 is a different question in the same shape**, added 2026-10-25: a
#   bridge the kernel can make and cannot filter. It exists because netcfgd
#   told an operator that a refused per-port vlan means the bridge lacks
#   `vlan_filtering = true` -- a configuration cause -- and nothing knew what
#   a kernel built without `CONFIG_BRIDGE_VLAN_FILTERING` would say. The
#   answer is that the vlan sentence never appears: the settings step is
#   refused first, and that refusal had no sentence at all.
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
# IT DRIVES hull, SINCE 2026-10-25
#   It drove qemu by hand until then, with an initramfs built by the kernel's
#   own `gen_init_cpio` -- because hull's spec declared `(kernel "path:FILE")`
#   and its engine had not built it. hull built it (`0a7b73d`), and this tier
#   lost about two hundred lines of plumbing: no initramfs to pack, no
#   `/dev/console` to declare, no `-append` to get right, and the userland is
#   the natcap image the sibling rig already builds rather than a cpio of a
#   materialized tree.
#
#   **What a hull guest needs, which a hand-driven one did not:** virtio-9p
#   for the root share, vsock for the agent, and `console=hvc0` on a virtio
#   console -- all built in, there being no modules. `config-kernel.sh` sets
#   them and checks them; without them the machine boots and hull reports only
#   "the guest agent never answered".
#
#   **A rebuilt hull needs its core restarted.** The engine runs in the `hull
#   core` daemon, one per user, and `hull run` dials one that is already
#   running -- so a core from an older build serves an older engine while a new
#   frontend plans the new vector. That cost a day here: the plan declared
#   `vm.kernel.path: native` and qemu was handed the host's kernel. hull's own
#   suite could not catch it, having tested with a copy of the host kernel,
#   where ignoring the path is indistinguishable from honouring it. A kernel
#   whose release differs from the host's is the discriminator, which is why
#   the payload prints `uname -sr` and reads `/proc/config.gz`.
#
# WHAT IT COSTS AND HOW IT STOPS
#   A 1.6 GB source tree the caller supplies, three kernel builds of a few
#   minutes each, and three machines of a few seconds. Each machine is bounded
#   by `timeout` around `hull run`, which is the right bound for a vm -- qemu
#   is a child of that process, so a signal reaches it. `running-code.md` has
#   the container case, which this is not.
set -eu

src=${1:-}
out=${2:-dist/kernel}
build=${NCFG_BUILD:-c}
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/../.." && pwd)
hull=${HULL:-$HOME/src/hull/build/hull}
jobs=${KERNEL_JOBS:-$(nproc 2>/dev/null || echo 4)}
boot_seconds=${KERNEL_BOOT_SECONDS:-400}
image=${NATCAP_IMAGE:-netcfgd/natcap}

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
command -v "$hull" >/dev/null 2>&1 || {
	echo "run.sh: $hull is not runnable. hull is a sibling project, not" >&2
	echo "run.sh:   vendored here -- build it there and set HULL=<path>." >&2
	exit 1
}
"$hull" images 2>/dev/null | grep -q "^$(echo "$image" | sed 's/[]\/$*.^|[]/\\&/g')[[:space:]]" || {
	echo "run.sh: $image is not in the store, and it is this tier's userland;" >&2
	echo "run.sh:   \`make hull-image\` builds it." >&2
	exit 1
}
for program in netcfgd ncfg; do
	[ -x "$build/$program" ] || {
		echo "run.sh: $build/$program is not built; \`make -C c\` first" >&2
		exit 1
	}
done
printf 'run.sh: %s, %s, %s job(s), image %s\n' \
	"$("$hull" --version 2>/dev/null | head -1)" \
	"$("$hull" --version 2>/dev/null | sed -n 's/^commit //p' | head -1)" \
	"$jobs" "$image"

mkdir -p "$out"
failures=0
for state in k0 k1 k2 k3; do
	echo
	echo "########## $state"
	sh "$here/config-kernel.sh" "$src" "$state"
	( cd "$src" && nice -n 10 make -j"$jobs" bzImage ) > "$out/build-$state.log" 2>&1 || {
		echo "run.sh: $state did not build; see $out/build-$state.log" >&2
		failures=$((failures + 1))
		continue
	}
	cp "$src/arch/x86/boot/bzImage" "$out/bzImage-$state"

	# The spec is written per state because a `hull.conf` takes no variables
	# and the kernel is what varies. Absolute paths throughout, so it does not
	# matter where hull resolves them from.
	cat > "$out/$state.conf" <<SPEC
; Generated by tests/kernel/run.sh -- the $state kernel in a hull machine.
(machine
  (source "$image")
  (mutable overlay)
  (backend vm)
  (memory "2G")
  (cpus 2)
  (tuning (vm (kernel "path:$(cd "$out" && pwd)/bzImage-$state")))
  (volumes
    (volume (host "$repo") (guest "/repo") (mode ro))
    (volume (host "$here") (guest "/payload") (mode ro)))
  (command "sh" "/payload/payload.sh"))
SPEC
	timeout -k 10 "$boot_seconds" "$hull" run -f "$out/$state.conf" \
		> "$out/run-$state.log" 2>&1 || true
	sed -n '/^=== /,$p' "$out/run-$state.log"
	# **The verdict comes from the guest's own line.** hull exits 0 for a
	# machine that ran its command whatever the command concluded, and a boot
	# that never reached the payload leaves no line at all -- which must be a
	# failure here rather than a silence.
	if ! grep -q "^VERDICT ok" "$out/run-$state.log"; then
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
