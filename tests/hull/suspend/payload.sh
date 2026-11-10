#!/bin/sh
# The suspend rig's guest half: run tests/live/suspend.sh off the share, with
# the host's binaries, and leave a verdict the host can read whatever the
# guest's console does across the sleep (10.790).
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:$PATH
export PATH
mount -t tmpfs -o size=1g tmpfs /tmp 2>/dev/null || true
echo "=== guest: kernel $(uname -r), sleep states: $(cat /sys/power/state)"
echo "=== mem_sleep: $(cat /sys/power/mem_sleep 2>/dev/null)"
# A pm_test level from the host, for a rig check on a hull that cannot wake a
# guest yet: `make hull-suspend SUSPEND_TEST=freezer`.
level=
[ -s /verdict/pm_test ] && level=$(cat /verdict/pm_test)
NCFG_SUSPEND_TEST=$level NCFG_LIVE=1 NCFG_LIVE_BUILD=/repo/c \
	sh /repo/tests/live/suspend.sh > /verdict/log 2>&1
rc=$?
cat /verdict/log
if [ "$rc" -eq 0 ]; then
	echo "VERDICT ok" > /verdict/suspend
else
	echo "VERDICT bad rc=$rc" > /verdict/suspend
fi
