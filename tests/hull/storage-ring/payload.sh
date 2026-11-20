#!/bin/sh
# One box of the storage ring (hull.conf, project.md 10.887).
# $1 its name, $2 its storage address, $3 the other two's.
#
# netcfgd, run as `ncfg apply`, puts eth0 and eth1 in br-storage with STP on
# and MTU 9000, and the address on the bridge. Then, once all three have
# said they are up and spanning tree has had time to settle: a full jumbo
# frame that may not fragment (8972 bytes of ICMP) to each of the others,
# a second plan with nothing to do, and the ports' STP states written for
# the target to count -- across the ring exactly one port must block. Then
# a forwarding cable is cut and the ring must heal around it.
#
# Always exits 0 and reports through /verdict/NAME.
#
# HOW IT STOPS: every wait and loop is bounded (180 s at most), and the machine
# ends with this.
set -u
PATH=/usr/sbin:/sbin:/usr/bin:/bin
name=$1 address=$2 others=$3
v=/verdict
out=$v/$name
: > "$out"
failed=0
say() { echo "$*" >> "$out"; echo "$name: $*"; }
check() { if [ "$2" = "$3" ]; then say "ok   $1"; else say "FAIL $1 -- expected '$3', got '$2'"; failed=1; fi; }
waitfor() { n=0; while ! eval "$1" >/dev/null 2>&1 && [ "$n" -lt "$(($2 * 2))" ]; do sleep 0.5; n=$((n + 1)); done; eval "$1" >/dev/null 2>&1; }

mount -t tmpfs -o size=16m tmpfs /tmp 2>/dev/null
work=/tmp/ring
mkdir -p "$work/etc" "$work/run"
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
ncfg=/repo/c/ncfg
ip link set lo up
cat > "$work/etc/netcfgd.conf" <<CONF
device eth0 { mtu = 9000 }
device eth1 { mtu = 9000 }
device br-storage {
	mtu = 9000
	bridge {
		members       = ["eth0", "eth1"]
		stp           = true
		forward_delay = 4
		max_age       = 6
	}
}
interface eth0 { config = "null" }
interface eth1 { config = "null" }
interface br-storage { config = "$address/24" }
CONF
# -01, the NAS, is the root, so both its links forward and the port that
# blocks is on the ml350 -- -03 cable, which carries neither box's NAS
# traffic.
if [ "$name" = dl180g6-01 ]; then
	sed -i 's/^\t\tstp           = true$/&\n\t\tpriority      = 4096/' "$work/etc/netcfgd.conf"
fi
timeout 60 "$ncfg" apply > "$work/apply.log" 2>&1
say "     apply exited $?"
grep -v '^netcfgd: \[observe\]' "$work/apply.log" | sed 's/^/     apply: /' >> "$out"
check "the bridge is up with the address" "$(ip -4 -br addr show br-storage | grep -o "$address/24")" "$address/24"
check "the bridge carries MTU 9000" "$(cat /sys/class/net/br-storage/mtu 2>&1)" "9000"
check "spanning tree is on" "$(cat /sys/class/net/br-storage/bridge/stp_state 2>&1)" "1"
check "both ports are in it" "$(ls /sys/class/net/br-storage/brif 2>/dev/null | tr '\n' ' ')" "eth0 eth1 "
[ "$name" = dl180g6-01 ] && check "the NAS bridge has priority 4096" \
	"$(cat /sys/class/net/br-storage/bridge/priority 2>&1)" "4096"
touch $v/up-$name
for box in ml350 dl180g6-01 dl180g6-03; do
	waitfor "[ -f $v/up-$box ]" 120 || say "     $box never came up"
done
# Spanning tree: listening and learning at forward_delay 4 s each, so a
# port forwards about 8 s after the topology settles. Wait for no port of
# this bridge to be in either state.
waitfor '! grep -qE "^(1|2)$" /sys/class/net/br-storage/brif/*/state' 60
for other in $others; do
	check "a jumbo frame reaches $other unfragmented" \
		"$(ping -c 2 -W 2 -M do -s 8972 "$other" >/dev/null 2>&1 && echo reached || echo lost)" "reached"
done
again=$(timeout 60 "$ncfg" plan 2>&1)
case "$again" in
*"nothing to do"*) say "ok   a second plan has nothing to do" ;;
*) say "FAIL a second plan wants: $(echo "$again" | grep -v '^netcfgd:' | head -3 | tr '\n' ' ')"; failed=1 ;;
esac
# 0 disabled, 1 listening, 2 learning, 3 forwarding, 4 blocking.
for port in eth0 eth1; do
	echo "$name $port $(cat /sys/class/net/br-storage/brif/$port/state 2>&1)" >> $v/states
done
touch $v/done-$name
for box in ml350 dl180g6-01 dl180g6-03; do
	waitfor "[ -f $v/done-$box ]" 120
done
# A cable cut: the segment's two ends both lose the link, as a pulled cable
# drops carrier at both. Cut the one segment the box holding the blocked
# port is not on -- the hard case: that box loses no link of its own, so
# classic spanning tree unblocks its port only once the root's information
# on it has aged out (`max_age`), then listens and learns. Every box must
# reach the other two again, and within 20 s: at the kernel's default
# `max_age` of 20 s this took 28 to 30 (10.889), and at 6 it is 6 + 2 x 4. hull.conf cables eth0 to the first segment
# named and eth1 to the second.
segment() {
	case "$1 $2" in
	"ml350 eth0" | "dl180g6-01 eth0") echo a ;;
	"dl180g6-01 eth1" | "dl180g6-03 eth0") echo b ;;
	"dl180g6-03 eth1" | "ml350 eth1") echo c ;;
	esac
}
blocked=$(awk '$3 == 4 { print $1, $2; exit }' $v/states)
blocker=${blocked%% *}
for cut in a b c; do
	[ "$(segment "$blocker" eth0)" != "$cut" ] && [ "$(segment "$blocker" eth1)" != "$cut" ] && break
done
for port in eth0 eth1; do
	if [ "$(segment "$name" "$port")" = "$cut" ]; then
		ip link set "$port" down
		say "     cut segment $cut here ($port down); $blocked was blocking"
	fi
done
touch $v/cut-$name
for box in ml350 dl180g6-01 dl180g6-03; do
	waitfor "[ -f $v/cut-$box ]" 120
done
# Reconvergence: from the cut, ping both others every half second until
# both answer, for 90 s at most.
start=$(date +%s)
healed=no
n=0
while [ "$n" -lt 180 ]; do
	reached=0
	for other in $others; do
		ping -c 1 -W 1 "$other" >/dev/null 2>&1 && reached=$((reached + 1))
	done
	if [ "$reached" -eq 2 ]; then healed=yes; break; fi
	sleep 0.5
	n=$((n + 1))
done
took=$(( $(date +%s) - start ))
say "     both others answered again $took s after the cut"
check "the ring heals around a cut cable" "$healed" "yes"
check "  within 20 s" "$([ "$took" -le 20 ] && echo yes || echo "no, $took s")" "yes"
for other in $others; do
	check "  and a jumbo frame reaches $other again" \
		"$(ping -c 2 -W 2 -M do -s 8972 "$other" >/dev/null 2>&1 && echo reached || echo lost)" "reached"
done
touch $v/healed-$name
for box in ml350 dl180g6-01 dl180g6-03; do
	waitfor "[ -f $v/healed-$box ]" 120
done
if [ "$failed" -eq 0 ]; then say "VERDICT ok"; else say "VERDICT bad"; fi
exit 0
