#!/bin/sh
# What each machine on the wire reports: that it booted, that it has the
# segment NIC, and that an address it sets itself comes up on it.
#
#     sh payload.sh <my-name> <my-address> <sibling-name>
#
# **It always exits 0, and the verdict file carries the pass or the fail.**
# `hull run` over a `(machines ...)` file plans them together and the first
# failure stops the rest, so a payload that exits non-zero takes its siblings
# with it -- measured on this rig's first run, where `isp` failed and `cpe`
# never started, and the collector then reported `cpe` as the machine that
# never reached its payload. That reading was true and useless: the cause was
# the other machine. A verdict in a file lets every machine run and be judged
# on its own.
#
# **`eth1` is the segment, not `eth0`.** hull gives a machine passt's user-net
# NIC first and the segment's after it, with no address on the segment --
# Appendix D's "as a test of network software sets its own", which for netcfgd
# is the point rather than an inconvenience. The first run of this rig read
# `eth0`'s 10.0.2.15 as its address and concluded it was on a wire it was not
# on.
#
# **Frames across the segment are hull's own tested property**, asserted in its
# `test/qemu_test.sh` by two vms hearing each other's raw frames with a third
# on another segment hearing nothing. This rig does not re-prove it; what it
# proves is the collector -- a verdict per machine, and an absent one failing
# the run -- which is what 10.570 names as the hard part of the delegation rig.
set -u
me=${1:?usage: payload.sh <my-name> <my-address> <sibling-name>}
mine=${2:?usage: payload.sh <my-name> <my-address> <sibling-name>}
peer=${3:?usage: payload.sh <my-name> <my-address> <sibling-name>}
out=/verdict/$me
say() { printf '%s\n' "$*" >> "$out"; }

: > "$out"
say "machine $me, kernel $(uname -r)"
say "interfaces: $(ip -o link show | awk -F': ' '{printf "%s ", $2}')"

if [ ! -d /sys/class/net/eth1 ]; then
	say "VERDICT bad: no eth1, so this machine has no segment NIC"
	exit 0
fi
say "eth1 mac: $(cat /sys/class/net/eth1/address 2>/dev/null)"

ip link set eth1 up 2>&1 | sed 's/^/  ip: /' >> "$out"
ip addr add "$mine" dev eth1 2>&1 | sed 's/^/  ip: /' >> "$out"
# **Read it back rather than testing the command's status**, which is both the
# stronger check and the only one that works here: `if ! ip addr add ... | sed`
# tests SED's status, not `ip`'s, so a branch written that way can never fire.
# This rig had one, and what caught the refusal was this read-back -- the same
# instrument fault that cost a probe earlier in this tree (10.551's three
# instrument faults). An address that did not take is what the delegation rig
# will care about most, so assert the state rather than the call.
if ! ip -o -4 addr show dev eth1 | grep -q "${mine%%/*}"; then
	say "VERDICT bad: $mine is not on eth1 after setting it"
	exit 0
fi
say "eth1 carries: $(ip -o -4 addr show dev eth1 | awk '{print $4}')"
say "peer is $peer, whose address this rig does not assert -- hull's own suite"
say "  proves frames cross a segment; this one proves the collector"
say "VERDICT ok: segment NIC up and carrying the address it set itself"
