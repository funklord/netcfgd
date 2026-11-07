#!/bin/sh
# Inside OpenWrt: the router test, then what only a real kernel can answer, then
# the verdict on the console and a reboot, which ends qemu.
#
# HOW IT STOPS: the router test bounds its own waits, the observation below is one
# bounded command, and `reboot -f` is unconditional.
sh /payload/payload.sh
echo GUEST-BEGIN
uname -srm
grep -E 'MemTotal|MemAvailable' /proc/meminfo
cat /verdict/openwrt
echo GUEST-END
sleep 1
reboot -f
