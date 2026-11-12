#!/bin/sh
# The suspend rig's guest half: run tests/live/suspend.sh off the repo image,
# with the host's binaries, and leave a verdict on the verdict image the host
# reads back whatever the guest's console does across the sleep (10.790,
# 10.809). Synced, since the host reads the image after the machine stops.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:$PATH
export PATH
mount -t tmpfs -o size=1g tmpfs /tmp 2>/dev/null || true
echo "=== guest: kernel $(uname -r), sleep states: $(cat /sys/power/state)"
echo "=== mem_sleep: $(cat /sys/power/mem_sleep 2>/dev/null)"
# A pm_test level from the host, for a rig check on a hull that cannot wake a
# guest yet: `make hull-suspend SUSPEND_TEST=freezer`.
level=
[ -s /repo/pm_test ] && level=$(cat /repo/pm_test)
control=
[ -s /repo/control ] && control=1
# `make hull-suspend SUSPEND_STATE=disk` for hibernation, which hull resumes
# in a new qemu on the same disks; `mem` otherwise.
state=mem
[ -s /repo/state ] && state=$(cat /repo/state)
# `SUSPEND_AUTHORITATIVE=1`: the dock's dnsmasq answers as OpenWrt's does.
authoritative=
[ -s /repo/authoritative ] && authoritative=1
# Bounded, so a verdict is written whatever the test does (10.809).
NCFG_SUSPEND_TEST=$level NCFG_SUSPEND_CONTROL=$control NCFG_SUSPEND_STATE=$state NCFG_SUSPEND_AUTHORITATIVE=$authoritative NCFG_LIVE=1 NCFG_LIVE_BUILD=/repo/c \
	timeout -k 10 1200 sh /repo/tests/live/suspend.sh > /verdict/log 2>&1
rc=$?
sync
cat /verdict/log
if [ "$rc" -eq 0 ]; then
	echo "VERDICT ok" > /verdict/suspend
else
	echo "VERDICT bad rc=$rc" > /verdict/suspend
fi
sync
