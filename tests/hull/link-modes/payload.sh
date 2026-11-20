#!/bin/sh
# netcfgd forcing virtio-net's link modes, read back through sysfs (10.877).
#
# Asserted:
#   - the NIC under test is virtio-net, so the result says something about a
#     driver rather than about whatever answered;
#   - `autoneg off, speed 100, duplex full` is applied, and the kernel's own
#     /sys/class/net/eth1/speed and duplex say 100 and full -- sysfs, not
#     netcfgd's reading of netlink, so the encoder is not checking itself;
#   - a second plan has nothing to do (it converges);
#   - netcfgd left its record of what it forced;
#   - changed to 1000, the next apply moves it and sysfs says 1000;
#   - asked to negotiate, virtio refuses, the plan says why, and the
#     interface's address is applied anyway: the op is optional;
#   - the rings (10.881): shrunk to 128 each, read back by ethtool -g -- a
#     reader that is not netcfgd's -- and a second plan has nothing to do.
#
# Always exits 0 and reports through /verdict/link-modes.
#
# HOW IT STOPS: no waits and no loops beyond the fixed steps; each ncfg call
# is under `timeout 60`, and the machine takes everything with it when it ends.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/link-modes
: > "$out"
say() { echo "$*" >> "$out"; echo "link-modes: $*"; }
failed=0
check() { # $1 what, $2 actual, $3 expected
	if [ "$2" = "$3" ]; then
		say "ok   $1"
	else
		say "FAIL $1 -- expected '$3', got '$2'"
		failed=1
	fi
}
contains() { # $1 what, $2 text, $3 fragment
	case "$2" in
	*"$3"*) say "ok   $1" ;;
	*) say "FAIL $1 -- '$3' not in: $(echo "$2" | tr '\n' ' ' | cut -c1-300)"; failed=1 ;;
	esac
}
mount -t tmpfs -o size=16m tmpfs /tmp 2>/dev/null
work=/tmp/link-modes
mkdir -p "$work/etc" "$work/run"
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
ncfg=/repo/c/ncfg
if [ ! -x "$ncfg" ]; then
	say "VERDICT bad: $ncfg is not built on the host"
	exit 0
fi
dev=eth1
if [ ! -e /sys/class/net/$dev ]; then
	say "VERDICT bad: no $dev, so the segment's NIC is missing: $(ls /sys/class/net | tr '\n' ' ')"
	exit 0
fi
driver=$(basename "$(readlink /sys/class/net/$dev/device/driver 2>/dev/null)")
check "$dev is virtio-net" "$driver" "virtio_net"
say "     before: speed $(cat /sys/class/net/$dev/speed 2>&1) duplex $(cat /sys/class/net/$dev/duplex 2>&1)"

write_doc() { # $1 the ethtool body
	cat > "$work/etc/netcfgd.conf" <<CONF
device $dev {
	ethtool {
$1
	}
}
interface $dev { config = "10.77.0.2/24" }
CONF
}

write_doc '		autoneg = "off"
		speed   = 100
		duplex  = "full"'
plan=$(timeout 60 "$ncfg" plan 2>&1)
contains "the plan forces 100/full" "$plan" "link.set_link_modes $dev"
applied=$(timeout 60 "$ncfg" apply 2>&1)
say "     apply: $(echo "$applied" | grep -c set_link_modes) link-modes line(s)"
check "sysfs says 100" "$(cat /sys/class/net/$dev/speed 2>&1)" "100"
check "sysfs says full" "$(cat /sys/class/net/$dev/duplex 2>&1)" "full"
again=$(timeout 60 "$ncfg" plan 2>&1)
case "$again" in
*set_link_modes*) say "FAIL a second plan sets the link modes again: $again"; failed=1 ;;
*) say "ok   a second plan has nothing to set" ;;
esac
check "netcfgd recorded what it forced" "$(tr '\n' ' ' < "$work/run/link_modes/$dev" 2>&1)" "speed 100 duplex full "

write_doc '		autoneg = "off"
		speed   = 1000
		duplex  = "full"'
timeout 60 "$ncfg" apply > "$work/apply2.log" 2>&1
check "moved to 1000" "$(cat /sys/class/net/$dev/speed 2>&1)" "1000"

write_doc '		autoneg = "on"'
negotiate=$(timeout 60 "$ncfg" apply 2>&1)
contains "asked to negotiate, virtio refuses and the plan says why" "$negotiate" "the driver refused the mode"
contains "and the address is applied anyway" "$(ip -4 -br addr show $dev)" "10.77.0.2/24"
check "the forced speed is left as it was" "$(cat /sys/class/net/$dev/speed 2>&1)" "1000"

# The rings. virtio's maximum is its queue size, so the test shrinks them.
write_doc '		autoneg = "off"
		speed   = 1000
		duplex  = "full"
		rx_ring = 128
		tx_ring = 128'
rings_plan=$(timeout 60 "$ncfg" plan 2>&1)
contains "the plan sizes the rings" "$rings_plan" "link.set_rings $dev"
timeout 60 "$ncfg" apply > "$work/apply-rings.log" 2>&1
if command -v ethtool >/dev/null 2>&1; then
	current=$(ethtool -g $dev 2>&1 | sed -n '/^Current/,$p')
	check "ethtool says rx 128" "$(echo "$current" | awk '/^RX:/ { print $2; exit }')" "128"
	check "ethtool says tx 128" "$(echo "$current" | awk '/^TX:/ { print $2; exit }')" "128"
	if [ "$failed" -ne 0 ]; then
		say "     the apply said: $(grep -v '^netcfgd: \[observe\]' "$work/apply-rings.log" | tr '\n' ' ' | cut -c1-600)"
		say "     ethtool -g: $(ethtool -g $dev 2>&1 | tr '\n' ' ')"
		say "     transport: $(readlink -f /sys/class/net/$dev/device/.. 2>&1); features $(cat /sys/class/net/$dev/device/features 2>&1)"
	fi
else
	say "FAIL no ethtool in the image to read the rings back with: make hull-image"
	failed=1
fi
rings_again=$(timeout 60 "$ncfg" plan 2>&1)
case "$rings_again" in
*set_rings*) say "FAIL a second plan sizes the rings again: $(cat "$work/apply-rings.log")"; failed=1 ;;
*) say "ok   a second plan has no ring to size" ;;
esac

if [ "$failed" -eq 0 ]; then
	say "VERDICT ok"
else
	say "VERDICT bad"
fi
exit 0
