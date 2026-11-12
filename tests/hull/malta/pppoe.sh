# A PPPoE WAN, sourced by guest.sh: `say`, `out` and `failed` are its. Run where
# the payload put an access concentrator behind a second NIC and said so in
# /payload/pppoe -- `hull-armsr`, whose outer machine runs Debian's pppoe-server
# on the tap that NIC is (10.816).
#
# The other WAN most ISPs hand a router, and the one netcfgd drives through
# somebody else's pppd: here OpenWrt's own, 2.5 with its pppoe.so, where
# `tests/live/pppoe-session.sh` dials Debian's. Same document, same checks: the
# session comes up, IPCP's address is pppd's, and the nameservers the server
# pushed reach netcfgd's report.
#
# HOW IT STOPS: each wait counts its seconds.

say "dsl0: $(cat /sys/class/net/dsl0/address 2>/dev/null || echo missing), /dev/ppp $([ -e /dev/ppp ] && echo there || echo absent)"
mkdir -p /etc/netcfgd/secrets
printf '%s' 'dsl-password' > /etc/netcfgd/secrets/dsl
chmod 600 /etc/netcfgd/secrets/dsl
cat >> /etc/netcfgd/netcfgd.conf <<'CONF'
device ppp0 {
	pppoe {
		parent   = "dsl0"
		username = "alice@isp.example"
		password = "@secret:dsl"
	}
}
interface ppp0 {
	config = "null"
}
CONF
n=0
until ip -4 addr show dev ppp0 2>/dev/null | grep -q 'inet 10.64.0.100' || [ $n -gt 60 ]; do
	sleep 1
	n=$((n + 1))
done
addr=$(ip -4 -o addr show dev ppp0 2>/dev/null | awk '{print $4}')
say "ppp0 after $n s: ${addr:-nothing}, by $(pidof pppd | wc -w) pppd"
report=/run/netcfgd/reported/ppp0
n=0
until grep -q '^dns=' "$report" 2>/dev/null || [ $n -gt 10 ]; do
	sleep 1
	n=$((n + 1))
done
say "the report: $(grep -E '^(dns|address)=' "$report" 2>/dev/null | tr '\n' ' ')"
dialled=no
# BusyBox's `ip -o` gives a point-to-point address as `10.64.0.100 peer
# 10.64.0.1/32`, so the field carries no length; iproute2's carries one.
case "$addr" in
10.64.0.100 | 10.64.0.100/*)
	grep -q '^dns=192.0.2.53$' "$report" 2>/dev/null && ! grep -q '^address=' "$report" &&
		dialled=yes
	;;
esac
if [ "$dialled" = no ]; then
	failed=1
	ps w | grep '[p]ppd' | cut -c1-140 >> "$out"
	logread | grep -E 'pppd|pppoe' | tail -12 | cut -c1-140 >> "$out"
fi
# And IPv6 over the session, as a DSL ISP delivers it: IPv6CP gives ppp0 a
# link-local (pppd is told `+ipv6`), and DHCPv6 over it delegates a prefix
# (10.826). The concentrator's end runs a kea of its own for this.
say "ppp0's link-local: $(ip -6 -o addr show dev ppp0 scope link 2>/dev/null | awk '{print $4}' | head -1)"
sed -i '/^interface ppp0 {/,/^}/ s/config = "null"/config = "dhcp6 pd_length 56"/' \
	/etc/netcfgd/netcfgd.conf
n=0
until [ -s /run/netcfgd/prefixes/ppp0 ] || [ $n -gt 90 ]; do
	sleep 1
	n=$((n + 1))
done
over=$(head -1 /run/netcfgd/prefixes/ppp0 2>/dev/null)
say "delegated over the session after $n s: ${over:-nothing}"
case "$over" in
2001:db8:5678:*) ;;
*)
	failed=1
	ps w | grep '[o]dhcp6c' | cut -c1-140 >> "$out"
	;;
esac
# Hung up again, so the package half after this starts from a router with no session.
sed -i '/^device ppp0 {/,/^}/d' /etc/netcfgd/netcfgd.conf
n=0
until [ ! -e /sys/class/net/ppp0 ] || [ $n -gt 20 ]; do
	sleep 1
	n=$((n + 1))
done
say "after the device left the document: ppp0 $([ -e /sys/class/net/ppp0 ] && echo still there || echo gone), $(pidof pppd | wc -w) pppd"
[ ! -e /sys/class/net/ppp0 ] || failed=1
