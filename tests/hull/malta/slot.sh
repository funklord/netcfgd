# A firewall slot's members on OpenWrt (0340, project.md 10.915), sourced by
# guest.sh after restart.sh: `say`, `out`, `failed` and `miss` are its.
#
# What 10.915 changed and could only reason about: procd hands netcfgd
# NCFG_SLOT_DIR=/etc/netcfgd/slot, because /var is a link into /tmp; a member
# written live is recorded there; and when the table goes -- `fw4 flush`, which
# LuCI's every "Save & Apply" runs, is the case a router meets daily, and a
# reboot the case it meets rarely -- the apply that writes the table back writes
# the member back from the record. The kernel is OpenWrt's and big-endian, so
# the set's keys and its members' bytes are read by the kernel's own byte order.
#
# HOW IT STOPS: each wait counts its seconds; the steps are a fixed list.
member() { nft list set inet netcfgd slot-quarantine-4 2>/dev/null | grep -c '198\.51\.100\.66'; }

pid=$(pidof netcfgd)
dir=$(tr '\0' '\n' < /proc/${pid:-0}/environ 2>/dev/null | sed -n 's/^NCFG_SLOT_DIR=//p')
say "slot: procd gave netcfgd NCFG_SLOT_DIR=${dir:-nothing}"
[ "$dir" = /etc/netcfgd/slot ] || miss slot.sh "$LINENO"

said=$(/usr/bin/ncfg slot add quarantine 198.51.100.66 2>&1 | head -1)
n=0
until [ "$(member)" = 1 ] || [ $n -gt 10 ]; do sleep 1; n=$((n + 1)); done
say "slot: '$said'; the kernel's set holds it: $(member)"
[ "$(member)" = 1 ] || miss slot.sh "$LINENO"

recorded=$(cat /etc/netcfgd/slot/quarantine 2>/dev/null | tr '\n' ' ')
say "slot: recorded in /etc: ${recorded:-nothing}; under /var/lib: $(ls /var/lib/netcfgd/slot 2>/dev/null | wc -l) file(s)"
echo "$recorded" | grep -q '^198\.51\.100\.66 0 $' || miss slot.sh "$LINENO"

# The table emptied as a router's own firewall restart empties it; netcfgd
# writes it back, and the member with it, from the record.
/etc/init.d/firewall restart > /dev/null 2>&1
n=0
until [ "$(member)" = 1 ] || [ $n -gt 30 ]; do sleep 1; n=$((n + 1)); done
say "slot: after fw4's flush and netcfgd's apply, the set holds it: $(member) (after $n s)"
[ "$(member)" = 1 ] || miss slot.sh "$LINENO"

/usr/bin/ncfg slot remove quarantine 198.51.100.66 > /dev/null 2>&1
n=0
until [ ! -e /etc/netcfgd/slot/quarantine ] || [ $n -gt 10 ]; do sleep 1; n=$((n + 1)); done
say "slot: removed, the set holds it $(member) time(s) and the record is $([ -e /etc/netcfgd/slot/quarantine ] && echo still there || echo gone)"
[ "$(member)" = 0 ] && [ ! -e /etc/netcfgd/slot/quarantine ] || miss slot.sh "$LINENO"
