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
cp /repo/tests/hull/malta/guest.sh /repo/tests/hull/malta/prefix.sh /repo/tests/hull/malta/pppoe.sh \
	/repo/tests/hull/malta/lan.sh /repo/tests/hull/malta/wider.conf $top/payload/
# armsr's image carries no wireless stack, so guest.sh says the radio half was not
# run and why, rather than failing it or passing over it.
echo "armsr's image has no cfg80211, wpad or iw (hull-malta runs it)" > $top/payload/no-radio
cp /repo/tests/hull/openwrt/payload.sh $top/payload/payload.sh
cp /repo/packaging/procd/netcfgd $top/repo/packaging/procd/netcfgd
: > $top/payload/kernel-has-netfilter
# And an ISP behind each of the guest's two NICs: DHCPv6 for prefix.sh (10.815),
# PPPoE for pppoe.sh (10.816); and uradvd, for prefix.sh to advertise with (10.817).
cp /armsr/uradvd.apk $top/payload/uradvd.apk
: > $top/payload/isp6
: > $top/payload/pppoe
# The root here is the initramfs, in RAM (see tests/hull/openwrt/payload.sh), and
# guest.sh goes on with the package after the shared payload (10.813).
: > $top/payload/ramdisk-root
: > $top/payload/keep-installed
printf '%s\n' '#!/bin/sh' 'sh /payload/guest.sh > /dev/console 2>&1 &' 'exit 0' > $top/etc/rc.local
(cd $top && find . | cpio -o -H newc --quiet > /armsr/overlay.cpio)

# **The ISP: kea-dhcp6 on a tap the guest's virtio NIC is**, configured as
# `tests/hull/delegation/isp.sh` configures it, so the two tiers delegate the same.
# kea binds only an interface with a usable link-local, and a tap has carrier, and
# so a link-local, only once qemu holds it -- so qemu starts first, in the
# background, and kea once the address has settled. The guest asks for a prefix
# well after its boot, so kea is there first.
# The tap driver is a module of the host's kernel, which this machine runs
# (hull.conf), so it is loaded here, and the node made where the image has none.
modprobe tun 2>> "$out"
if [ ! -e /dev/net/tun ]; then
	mkdir -p /dev/net
	mknod /dev/net/tun c 10 200 2>> "$out"
fi
ip tuntap add dev tap0 mode tap 2>> "$out" || {
	say "note: no tap, so prefix.sh will find no ISP"
	say "  kernel $(uname -r); modules: $(ls /lib/modules 2>&1 | tr '\n' ' ')"
	say "  /dev/net/tun: $(ls -l /dev/net/tun 2>&1); tun loaded: $(grep -c '^tun ' /proc/modules)"
	say "  modprobe: $(modprobe -v tun 2>&1 | tr '\n' ' ' | cut -c1-160)"
}
ip tuntap add dev tap1 mode tap 2>> "$out" || say "note: no second tap, so pppoe.sh will find no server"
ip link set tap1 up 2>/dev/null
# **And the access concentrator on the second**, as `tests/live/pppoe-session.sh`
# runs it, with the plugin path given for the reason that file gives: Debian's is
# not where pppoe-server looks by default.
cat > /run/ac.options <<'OPTIONS'
noauth
lcp-echo-interval 10
lcp-echo-failure 2
ms-dns 192.0.2.53
logfile /run/ac-pppd.log
OPTIONS
# The concentrator's own pppd needs ppp in this machine's kernel, the host's,
# where it is modules (hull.conf).
modprobe -a ppp_generic pppoe 2>> "$out"
plugin=$(ls /usr/lib/pppd/*/rp-pppoe.so 2>/dev/null | head -1)
sysctl -q -w net.ipv6.conf.tap0.accept_dad=0 2>/dev/null
ip link set tap0 up 2>/dev/null
ip -6 addr add 2001:db8:aaaa::1/64 dev tap0 nodad 2>/dev/null
# kea writes a DUID on its first start, and the slim image has no directory for
# it -- what `tests/hull/delegation/hull.conf` met first.
mkdir -p /run/kea /var/lib/kea
cat > /run/kea/kea.json <<'JSON'
{ "Dhcp6": {
  "interfaces-config": { "interfaces": [ "tap0" ] },
  "lease-database": { "type": "memfile", "persist": false },
  "valid-lifetime": 600,
  "preferred-lifetime": 300,
  "subnet6": [ {
      "id": 1,
      "subnet": "2001:db8:aaaa::/48",
      "pools": [ { "pool": "2001:db8:aaaa::100 - 2001:db8:aaaa::200" } ],
      "pd-pools": [ { "prefix": "2001:db8:1234::", "prefix-len": 48, "delegated-len": 56 } ],
      "interface": "tap0"
  } ]
} }
JSON

# **The console from a run before this one is not this run's.** The verdict
# volume outlives a run, and a qemu that never started -- the tap it was given
# missing, as `hull-armsr` once was -- left the last run's GUEST-END in place
# and the old guest's two VERDICT ok read as this one's (10.815). So it is
# emptied first, and a qemu that did not leave cleanly is a bad run whatever
# the console holds.
: > /verdict/console
say "booting"
# 256 MB, a small Filogic router's; `virt`'s console is its PL011.
timeout -k 10 1200 qemu-system-aarch64 -M virt -cpu cortex-a53 -smp 2 -m 256 -display none \
	-monitor none -no-reboot -serial file:/verdict/console -kernel /armsr/Image \
	-netdev tap,id=wan,ifname=tap0,script=no,downscript=no \
	-device virtio-net-pci,netdev=wan,mac=52:54:00:12:34:56,romfile= \
	-netdev tap,id=dsl,ifname=tap1,script=no,downscript=no \
	-device virtio-net-pci,netdev=dsl,mac=52:54:00:12:34:57,romfile= \
	-initrd /armsr/overlay.cpio -append 'console=ttyAMA0,115200' &
qemu=$!
n=0
until ip -o -6 addr show dev tap0 scope link 2>/dev/null | grep -v tentative | grep -q fe80 ||
	[ $n -gt 100 ]; do
	sleep 0.2
	n=$((n + 1))
done
kea-dhcp6 -c /run/kea/kea.json > /run/kea/kea.log 2>&1 &
kea=$!
# Every DHCPv6 packet on the ISP's wire, decoded, for while it fails: what kea sent
# is the question when a client keeps soliciting (10.815). Ends with qemu.
timeout 1300 tcpdump -i tap0 -n -l -vv -s0 udp port 546 or udp port 547 > /run/dhcp6.txt 2>/dev/null &
capture=$!
say "kea $(dpkg-query -W -f='${Version}' kea-dhcp6-server 2>/dev/null) on tap0 after $((n / 5)) s"
pppoe-server -I tap1 -L 10.64.0.1 -R 10.64.0.100 -N 1 -O /run/ac.options -g "$plugin" -k \
	> /run/ac.log 2>&1 &
ac=$!
say "pppoe-server $(dpkg-query -W -f='${Version}' pppoe 2>/dev/null) on tap1, plugin ${plugin:-none}"
# The taps' state through the run, a line a minute while qemu lives: what the
# guest's NIC reads as carrier is this end's doing (10.815).
(
	while [ -d /proc/$qemu ]; do
		echo "$(date +%T) $(ip -br link show tap0 2>&1) / $(ip -br -6 addr show tap0 2>&1 | cut -c1-80)"
		sleep 60
	done
) > /run/taps.log 2>&1 &
wait $qemu
ran=$?
kill $kea $ac $capture 2>/dev/null
wait $kea 2>/dev/null
wait $ac 2>/dev/null
pkill -f '^pppd .*rp-pppoe' 2>/dev/null
say "qemu left with $ran"
[ "$ran" -eq 0 ] || say "VERDICT bad: qemu did not leave cleanly"
grep -iE 'error|fail|DHCP6_LEASE_PD|ADVERTISE_PD|leases' /run/kea/kea.log 2>/dev/null | head -6 |
	sed 's/^[^]]*] //' | cut -c1-400 | sed 's/^/  kea: /' >> "$out"
tail -8 /run/ac.log /run/ac-pppd.log 2>/dev/null | cut -c1-200 | sed 's/^/  concentrator: /' >> "$out"
sed 's/^/  tap: /' /run/taps.log >> "$out" 2>/dev/null
if grep -q 'delegated on isp6 after .*: nothing' /verdict/console 2>/dev/null; then
	grep -m 8 -E 'solicit|advertise|request|reply' /run/dhcp6.txt 2>/dev/null | cut -c1-700 |
		sed 's/^/  wire: /' >> "$out"
fi
grep -q 'GUEST-END' /verdict/console 2>/dev/null ||
	{ tail -30 /verdict/console >> "$out"; say "VERDICT bad: the guest never finished"; exit 0; }
sed -n '/GUEST-BEGIN/,/GUEST-END/p' /verdict/console | tr -d '\r' | grep -v 'GUEST-' >> "$out"
if grep -q "^VERDICT bad" "$out" || [ "$(grep -c "^VERDICT ok" "$out")" -ne 2 ]; then
	say "VERDICT bad"
else
	say "VERDICT ok"
fi
exit 0
