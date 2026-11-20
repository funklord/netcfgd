#!/bin/sh
# One box of the storage ring (hull.conf, project.md 10.887).
# $1 its name, $2 its storage address, $3 the other two's.
#
# netcfgd, run as `ncfg apply`, puts eth0 and eth1 in br-storage with STP on
# and MTU 9000, and the address on the bridge. Then, once all three have
# said they are up and spanning tree has had time to settle: a full jumbo
# frame that may not fragment (8972 bytes of ICMP) to each of the others,
# a second plan with nothing to do, and the ports' STP states written for
# the target to count -- across the ring exactly one port must block.
#
# Always exits 0 and reports through /verdict/NAME.
#
# HOW IT STOPS: every wait is bounded (120 s at most), and the machine
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
	}
}
interface eth0 { config = "null" }
interface eth1 { config = "null" }
interface br-storage { config = "$address/24" }
CONF
timeout 60 "$ncfg" apply > "$work/apply.log" 2>&1
say "     apply exited $?"
grep -v '^netcfgd: \[observe\]' "$work/apply.log" | sed 's/^/     apply: /' >> "$out"
check "the bridge is up with the address" "$(ip -4 -br addr show br-storage | grep -o "$address/24")" "$address/24"
check "the bridge carries MTU 9000" "$(cat /sys/class/net/br-storage/mtu 2>&1)" "9000"
check "spanning tree is on" "$(cat /sys/class/net/br-storage/bridge/stp_state 2>&1)" "1"
check "both ports are in it" "$(ls /sys/class/net/br-storage/brif 2>/dev/null | tr '\n' ' ')" "eth0 eth1 "
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
if [ "$failed" -eq 0 ]; then say "VERDICT ok"; else say "VERDICT bad"; fi
exit 0
