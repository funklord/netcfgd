# Several guests on one wire, which is what the tier was asked for.
#
# The segment is a qemu multicast socket, so this is real layer 2 between real
# kernels -- not veth in one kernel, which `unshare -rn` already gives and
# `delegation.sh` already uses. What it buys over that is the thing above it:
# each of these is a separate kernel with its own modules and its own init.
#
# Run by tool/vm/run.sh, which sets VM_INDEX and VM_COUNT from the command
# line. Addresses are 10.42.0.<index>, so every guest knows every other's
# without being told.
set -u
wire=eth1
ip link set "$wire" up
ip addr add "10.42.0.$VM_INDEX/24" dev "$wire"
# **No iproute2-only flags.** The guest's `ip` is busybox's: `ip -4 -br addr
# show` prints a usage message and returns nothing, which inside a command
# substitution reads as an empty address rather than as an error. The first run
# of this reported `guest 3 of 3 on ` and looked like a configuration fault.
echo "guest $VM_INDEX of $VM_COUNT at $(ip addr show "$wire" |
	sed -n 's/.*inet \([0-9.\/]*\).*/\1/p')"

# **Waited for rather than slept at.** The other guests boot at their own pace
# and a fixed sleep is either too short on a loaded machine or wasted on an
# idle one. The bound is what makes this terminate: 60 tries, a second apart.
peer_ok=0
peer_total=0
other=1
while [ "$other" -le "$VM_COUNT" ]; do
	if [ "$other" -ne "$VM_INDEX" ]; then
		peer_total=$((peer_total + 1))
		tries=0
		while [ "$tries" -lt 60 ]; do
			if ping -c1 -W1 "10.42.0.$other" >/dev/null 2>&1; then
				echo "peer $other: reachable after ${tries}s"
				peer_ok=$((peer_ok + 1))
				break
			fi
			tries=$((tries + 1))
			sleep 1
		done
		[ "$tries" -lt 60 ] || echo "peer $other: UNREACHABLE after 60s"
	fi
	other=$((other + 1))
done

echo "peers:  $peer_ok of $peer_total reachable"
[ "$peer_ok" -eq "$peer_total" ]
