# Does the wire between guests carry frames? Diagnostic rather than assertion.
#
# **It reports and does not fail**, deliberately -- and that means `run.sh`
# prints "ok" for a run in which the wire was completely dead, as it did while
# the `localaddr` control was being taken. Read the packet counts, not the
# exit status. `cluster.sh` is the one that asserts.
#
# **The guest's `ip` is busybox's, not iproute2's.** `ip -4 -br addr show`
# prints a usage message and nothing else, which inside a command substitution
# reads as an empty address rather than as an error -- the first cluster run
# reported `guest 3 of 3 on ` and looked like a configuration problem. So
# nothing here uses a flag iproute2 added.
set -u
echo "index:  $VM_INDEX of $VM_COUNT"
echo "links:  $(ls /sys/class/net | tr '\n' ' ')"
for nic in $(ls /sys/class/net); do
	[ "$nic" = lo ] && continue
	echo "  $nic mac=$(cat /sys/class/net/$nic/address) carrier=$(cat /sys/class/net/$nic/carrier 2>/dev/null || echo -)"
done
wire=eth1
ip link set "$wire" up
ip addr add "10.42.0.$VM_INDEX/24" dev "$wire" 2>&1
echo "addr:   $(ip addr show "$wire" | sed -n 's/.*inet \([0-9.\/]*\).*/\1/p')"
# Every guest is given time to come up, then what ARRIVED is reported rather
# than whether a ping succeeded: the packet counters and the neighbour table
# say whether layer 2 works at all, which a failed ping does not.
sleep 20
other=1
[ "$VM_INDEX" -eq 1 ] && other=2
ping -c3 -W2 "10.42.0.$other" 2>&1 | tail -3
echo "neigh:  $(ip neigh show 2>/dev/null | tr '\n' ';')"
echo "rx:     $(cat /sys/class/net/$wire/statistics/rx_packets) packets"
echo "tx:     $(cat /sys/class/net/$wire/statistics/tx_packets) packets"
