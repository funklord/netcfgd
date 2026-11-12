#!/bin/sh
# Builds netcfgd with OpenWrt's arm64 toolchain and boots OpenWrt's armsr-armv8
# kernel with it, running the router test there (project.md 10.814): malta's
# payload.sh with arm64's names, and malta's guest.sh and wider.conf, so the two
# tiers run one test on two machines.
#
# The initramfs kernel carries the stock rootfs, and an `-initrd` is unpacked on
# top of it, so the test's files arrive with nothing of OpenWrt's changed but
# `/etc/rc.local`, which runs when the boot is done.
#
# Always exits 0 and reports through /verdict/armsr.
#
# HOW IT STOPS: the build runs under `timeout` and qemu under another, the guest
# reboots itself when its payload ends and `-no-reboot` turns that into an exit,
# and a run that never prints the end marker reads as bad.
out=/verdict/armsr
: > "$out"
say() { echo "$*" >> "$out"; echo "armsr: $*"; }

toolchain=$(echo /armsr/toolchain/toolchain-*)
export STAGING_DIR=/armsr/toolchain
mkdir -p /tools
for tool in ar nm ranlib size strip objdump; do
	ln -sf "$toolchain/bin/aarch64-openwrt-linux-musl-$tool" "/tools/$tool"
done
export PATH=/tools:$toolchain/bin:$PATH

mkdir -p /work
(cd /repo && tar -cf - --exclude='*.o' --exclude='*.a' --exclude='*.d' \
	--exclude=fuzznet-build --exclude='fuzznet/build*' --exclude=.git \
	--exclude=fuzznet/qtty --exclude=.build-flags --exclude=c/netcfgd \
	--exclude=c/netcfgd-static c client fuzznet VERSION) | tar -xf - -C /work
cd /work/c || { say "VERDICT bad: the tree did not copy"; exit 0; }
timeout 1500 make -j4 CC=aarch64-openwrt-linux-musl-gcc netcfgd-static > /verdict/build.log 2>&1
built=$?
say "built: exit $built, $(file netcfgd-static 2>/dev/null | cut -d: -f2 | cut -d, -f1-3)"
file netcfgd-static 2>/dev/null | grep -q 'LSB.*aarch64' ||
	{ tail -20 /verdict/build.log >> "$out"; say "VERDICT bad: that is not an arm64 program"; exit 0; }
say "segments: $(size netcfgd-static | awk 'NR==2 { print "text", $1, "bss", $3 }')"

# What the guest gets, laid over the stock rootfs.
top=/overlay
mkdir -p $top/payload $top/repo/packaging/procd $top/verdict $top/etc
cp netcfgd-static $top/payload/netcfgd
"$toolchain/bin/aarch64-openwrt-linux-musl-strip" $top/payload/netcfgd
# The apk-v3 package of 25.12 (10.813), made by the apk-tools the image built.
(cd /work && mkdir -p tool packaging/procd && cp /repo/tool/openwrt_apk.sh tool/openwrt_apk.sh &&
	cp /repo/packaging/procd/netcfgd packaging/procd/netcfgd &&
	APK=/armsr/apk-tools/build/src/apk sh tool/openwrt_apk.sh $top/payload/netcfgd aarch64_generic \
		$top/payload/netcfgd.apk)
say "package: $(wc -c < $top/payload/netcfgd.apk 2>/dev/null) bytes"
cp /armsr/module/lib/modules/*/dummy.ko $top/payload/dummy.ko
cp /armsr/veth/lib/modules/*/veth.ko $top/payload/veth.ko
cp /repo/tests/hull/malta/guest.sh /repo/tests/hull/malta/wider.conf $top/payload/
# armsr's image carries no wireless stack, so guest.sh says the radio half was not
# run and why, rather than failing it or passing over it.
echo "armsr's image has no cfg80211, wpad or iw (hull-malta runs it)" > $top/payload/no-radio
cp /repo/tests/hull/openwrt/payload.sh $top/payload/payload.sh
cp /repo/packaging/procd/netcfgd $top/repo/packaging/procd/netcfgd
: > $top/payload/kernel-has-netfilter
# The root here is the initramfs, in RAM (see tests/hull/openwrt/payload.sh), and
# guest.sh goes on with the package after the shared payload (10.813).
: > $top/payload/ramdisk-root
: > $top/payload/keep-installed
printf '%s\n' '#!/bin/sh' 'sh /payload/guest.sh > /dev/console 2>&1 &' 'exit 0' > $top/etc/rc.local
(cd $top && find . | cpio -o -H newc --quiet > /armsr/overlay.cpio)

say "booting"
# 256 MB, a small Filogic router's; `virt`'s console is its PL011.
timeout -k 10 1200 qemu-system-aarch64 -M virt -cpu cortex-a53 -smp 2 -m 256 -display none \
	-monitor none -no-reboot -nic none -serial file:/verdict/console -kernel /armsr/Image \
	-initrd /armsr/overlay.cpio -append 'console=ttyAMA0,115200'
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
