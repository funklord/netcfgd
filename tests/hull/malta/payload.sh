#!/bin/sh
# Builds netcfgd with OpenWrt's toolchain and boots OpenWrt's malta-be kernel with
# it, running the router test there (project.md 10.742).
#
# `vmlinux.elf` carries the stock rootfs as its initramfs, and an `-initrd` is
# unpacked on top of it, so the test's files arrive with nothing of OpenWrt's
# changed but `/etc/rc.local`, which runs when the boot is done.
#
# Always exits 0 and reports through /verdict/malta.
#
# HOW IT STOPS: the build runs under `timeout` and qemu under another, the guest
# reboots itself when its payload ends and `-no-reboot` turns that into an exit,
# and a run that never prints the end marker reads as bad.
out=/verdict/malta
: > "$out"
say() { echo "$*" >> "$out"; echo "malta: $*"; }

toolchain=$(echo /malta/toolchain/toolchain-*)
export STAGING_DIR=/malta/toolchain
mkdir -p /tools
for tool in ar nm ranlib size strip objdump; do
	ln -sf "$toolchain/bin/mips-openwrt-linux-musl-$tool" "/tools/$tool"
done
export PATH=/tools:$toolchain/bin:$PATH

mkdir -p /work
(cd /repo && tar -cf - --exclude='*.o' --exclude='*.a' --exclude='*.d' \
	--exclude=fuzznet-build --exclude='fuzznet/build*' --exclude=.git \
	--exclude=fuzznet/qtty --exclude=.build-flags --exclude=c/netcfgd \
	--exclude=c/netcfgd-static c client fuzznet VERSION) | tar -xf - -C /work
cd /work/c || { say "VERDICT bad: the tree did not copy"; exit 0; }
timeout 1500 make -j4 CC=mips-openwrt-linux-musl-gcc netcfgd-static > /verdict/build.log 2>&1
built=$?
say "built: exit $built, $(file netcfgd-static 2>/dev/null | cut -d: -f2 | cut -d, -f1-3)"
file netcfgd-static 2>/dev/null | grep -q 'MSB.*MIPS' ||
	{ tail -20 /verdict/build.log >> "$out"; say "VERDICT bad: that is not a MIPS program"; exit 0; }
say "segments: $(size netcfgd-static | awk 'NR==2 { print "text", $1, "bss", $3 }')"

# What the guest gets, laid over the stock rootfs.
top=/overlay
mkdir -p $top/payload $top/repo/packaging/procd $top/verdict $top/etc
cp netcfgd-static $top/payload/netcfgd
"$toolchain/bin/mips-openwrt-linux-musl-strip" $top/payload/netcfgd
cp /malta/module/lib/modules/*/dummy.ko $top/payload/dummy.ko
cp /payload/guest.sh /payload/wider.conf $top/payload/
cp /repo/tests/hull/openwrt/payload.sh $top/payload/payload.sh
cp /repo/packaging/procd/netcfgd $top/repo/packaging/procd/netcfgd
: > $top/payload/kernel-has-netfilter
printf '%s\n' '#!/bin/sh' 'sh /payload/guest.sh > /dev/console 2>&1 &' 'exit 0' > $top/etc/rc.local
(cd $top && find . | cpio -o -H newc --quiet > /malta/overlay.cpio)

say "booting"
timeout -k 10 900 qemu-system-mips -M malta -cpu 24Kc -m 128 -display none -monitor none \
	-no-reboot -nic none -vga none -serial file:/verdict/console -kernel /malta/vmlinux.elf \
	-initrd /malta/overlay.cpio -append 'console=ttyS0,115200'
ran=$?
say "qemu left with $ran"
grep -q 'GUEST-END' /verdict/console 2>/dev/null ||
	{ tail -30 /verdict/console >> "$out"; say "VERDICT bad: the guest never finished"; exit 0; }
sed -n '/GUEST-BEGIN/,/GUEST-END/p' /verdict/console | tr -d '\r' | grep -v 'GUEST-' >> "$out"
if grep -q "^VERDICT bad" "$out" || [ "$(grep -c "^VERDICT ok" "$out")" -ne 2 ]; then
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
