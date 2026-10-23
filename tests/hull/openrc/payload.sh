#!/bin/sh
# netcfgd's init payload, in a guest that OpenRC booted.
#
# **This runs `tool/vm/payload/init.sh` unchanged**, the same file
# `make vm-init` runs on this tree's own VM tier -- and the reason for being
# here is in that payload's own header: on a systemd guest the openrc half
# cannot run at all, because `openrc` depends on `insserv` and `systemd-sysv`
# conflicts with it. The header names the remedy and calls it a second image
# and the holder's call. This is that image, as a bake and a spec.
#
# The machine boots `/sbin/openrc-init`, not `/sbin/init`, and that is the
# whole difference: openrc refuses to manage services on a system it did not
# boot, so merely installing it leaves `start` answering " * WARNING: netcfgd
# is already starting" and doing nothing. The payload now checks for
# `/run/openrc/softlevel` before counting anything, which is that measurement
# written down.
set -u
printf 'pid 1: %s\n' "$(cat /proc/1/comm 2>/dev/null || echo unknown)"
waited=0
while [ ! -f /run/openrc/softlevel ] && [ "$waited" -lt 300 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
if [ ! -f /run/openrc/softlevel ]; then
	echo "payload: openrc never recorded a softlevel, so it did not boot this" >&2
	echo "payload:   guest; pid 1 is $(cat /proc/1/comm 2>/dev/null)" >&2
	exit 1
fi
printf 'openrc up after %s ms, softlevel %s\n' "$((waited * 100))" "$(cat /run/openrc/softlevel)"
# The LSB script's own path wants `lsb-base`, which the image carries, so the
# payload's apt step has nothing to fetch and this guest needs no network.
exec sh /mnt/repo/tool/vm/payload/init.sh
