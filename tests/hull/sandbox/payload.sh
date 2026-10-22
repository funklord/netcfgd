#!/bin/sh
# netcfgd's own systemd payload, in a hull vm with the image's init as PID 1.
#
# **This runs `tool/vm/payload/sandbox_writes.sh` unchanged**, which is the
# point: that payload is what `make vm-sandbox` runs on this tree's own VM
# tier, and running the same file here is what makes the two comparable. It
# expects the repository at `/mnt/repo`, so the machine shares it there.
#
# **The wait is hull's instruction and not caution.** The workload starts when
# the machine does, not when the init is up, so `systemctl` run too early says
# systemd is not PID 1 -- which `sandbox_writes.sh` would read as a machine
# with no systemd and, under NCFG_LIVE, fail for. `/run/systemd/private`
# appearing is the signal hull names; `is-system-running --wait` is the rest.
#
# A degraded boot is reported and not fatal: what this exists to run is the
# script's own last block, and a getty that could not start is not a systemd
# that cannot impose a sandbox.
set -u
printf 'pid 1: %s\n' "$(cat /proc/1/comm 2>/dev/null || echo unknown)"
waited=0
while [ ! -S /run/systemd/private ] && [ "$waited" -lt 200 ]; do
	waited=$((waited + 1))
	sleep 0.1
done
if [ ! -S /run/systemd/private ]; then
	echo "payload: /run/systemd/private never appeared, so systemd is not up" >&2
	echo "payload:   pid 1 is $(cat /proc/1/comm 2>/dev/null), which is what to read first" >&2
	exit 1
fi
printf 'systemd up after %s ms; state: ' "$((waited * 100))"
timeout 120 systemctl is-system-running --wait || true
exec sh /mnt/repo/tool/vm/payload/sandbox_writes.sh
