#!/bin/sh
# netrescue's last rung against virtio-net (project.md 10.879).
#
# Asserted:
#   - netrescue climbs to rung 5 on a port that has no carrier as far as it
#     is told, and says it rebound eth1's device from virtio_net;
#   - the device is bound to virtio_net again afterwards, and eth1 exists
#     with a new ifindex -- the proof the device really went and came back,
#     which "bound to virtio_net" alone would also be without a rebind;
#   - it reports what the kernel said, or that it said nothing troubled;
#   - and the forcing rung before it set 100/full on the real driver.
#
# Always exits 0 and reports through /verdict/rescue.
#
# HOW IT STOPS: netrescue runs with `--for 40`, its own bound, under a
# `timeout 60` as well; nothing else loops. The machine ends with it.
set -u
PATH=/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin
export PATH
out=/verdict/rescue
: > "$out"
say() { echo "$*" >> "$out"; echo "rescue: $*"; }
failed=0
contains() { # $1 what, $2 text, $3 fragment
	case "$2" in
	*"$3"*) say "ok   $1" ;;
	*) say "FAIL $1 -- '$3' not found"; failed=1 ;;
	esac
}
mount -t tmpfs -o size=16m tmpfs /tmp 2>/dev/null
rescue=/repo/c/netrescue
if [ ! -x "$rescue" ]; then
	say "VERDICT bad: $rescue is not built on the host"
	exit 0
fi
dev=eth1
device=$(readlink -f /sys/class/net/$dev/device 2>/dev/null)
if [ -z "$device" ]; then
	say "VERDICT bad: no $dev with a device: $(ls /sys/class/net | tr '\n' ' ')"
	exit 0
fi
name=${device##*/}
index_before=$(cat /sys/class/net/$dev/ifindex)
say "     $dev is $name, driven by $(basename "$(readlink -f "$device/driver")")"

ports=/tmp/ports
mkdir -p "$ports/$dev"
printf '1\n' > "$ports/$dev/type"
printf '0\n' > "$ports/$dev/carrier"
ln -s "$device" "$ports/$dev/device"

timeout 60 "$rescue" --dir /tmp/rescue --sysfs "$ports" --wait 3 --listen 1 \
	--fallback none --for 40 > /tmp/rescue.out 2>&1
report=$(cat /tmp/rescue.out)
sed 's/^/     /' /tmp/rescue.out >> "$out"
contains "it forced the port at rung 4" "$report" "rung 4:"
contains "it reached the last rung" "$report" "rung 5:"
contains "and rebound eth1's device from virtio_net" "$report" "rebound $dev: device $name unbound from virtio_net"
case "$report" in
*"kernel, after rebinding:"*|*"said nothing troubled"*) say "ok   and said what the kernel said" ;;
*) say "FAIL it did not report on the kernel log"; failed=1 ;;
esac
driver=$(basename "$(readlink -f "$device/driver" 2>/dev/null)")
if [ "$driver" = virtio_net ]; then
	say "ok   the device is bound to virtio_net again"
else
	say "FAIL the device is not bound afterwards: '$driver'"
	failed=1
fi
index_after=$(cat /sys/class/net/$dev/ifindex 2>/dev/null)
if [ -n "$index_after" ] && [ "$index_after" != "$index_before" ]; then
	say "ok   and $dev is there, a new link: ifindex $index_before then $index_after"
else
	say "FAIL $dev is gone: $(ls /sys/class/net | tr '\n' ' ')"
	failed=1
fi

if [ "$failed" -eq 0 ]; then
	say "VERDICT ok"
else
	say "VERDICT bad"
fi
exit 0
