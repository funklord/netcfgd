# A LAN served, sourced by guest.sh: `say`, `out` and `failed` are its.
#
# The other half of every router: addresses for the hosts behind it. netcfgd hands
# that to dnsmasq (decision 0297), and here the dnsmasq is OpenWrt's own -- the
# stock build, `no-DHCPv6`, whose DHCPv4 is all a LAN needs from it -- where
# `hull-dhcp-server` runs Debian's (10.819). The LAN is a veth pair netcfgd makes;
# `client4` is no interface of the document's, and BusyBox's udhcpc on it is the
# host asking.
#
# HOW IT STOPS: each wait counts its seconds, and udhcpc is told to quit after its
# tries (`-n -q -t`).
cat >> /etc/netcfgd/netcfgd.conf <<'CONF'
device lan4 {
	veth {
		peer = "client4"
	}
}
interface lan4 {
	config = "192.168.7.1/24"
	dhcp_server {
		dns = ["192.168.7.53"]
	}
}
CONF
n=0
until [ -s /run/netcfgd/dhcp-server/lan4.pid ] || [ $n -gt 30 ]; do
	sleep 1
	n=$((n + 1))
done
say "lan4's server after $n s: $(cat /run/netcfgd/dhcp-server/lan4.pid 2>/dev/null || echo none), $(pidof dnsmasq | wc -w) dnsmasq"
ip link set client4 up 2>/dev/null
# Told nothing to do with the lease (`-s /bin/true`): the host's own end is not the
# question, and a default route from it would be the router's own.
leased=$(udhcpc -i client4 -n -q -t 6 -T 2 -s /bin/true 2>&1 | sed -n 's/.*lease of \([0-9.]*\) obtained.*/\1/p' |
	tail -1)
say "client4 was offered ${leased:-nothing}; the server's leases: $(cut -d' ' -f3 /run/netcfgd/dhcp-server/lan4.leases 2>/dev/null | tr '\n' ' ')"
shown=$(/usr/bin/ncfg status 2>/dev/null | sed -n '/^DHCP leases/,$p' | grep -c "$leased")
say "and \`ncfg status\` shows it: $shown"
case "$leased" in
192.168.7.*)
	grep -q "$leased" /run/netcfgd/dhcp-server/lan4.leases 2>/dev/null && [ "$shown" -ge 1 ] ||
		failed=1
	;;
*)
	failed=1
	grep -vE '^#' /run/netcfgd/dhcp-server/lan4.conf 2>/dev/null | tr '\n' ' ' | cut -c1-300 |
		sed 's/^/  lan4.conf: /' >> "$out"
	echo >> "$out"
	tail -5 /run/netcfgd/dhcp-server/lan4.log 2>/dev/null | sed 's/^/  dnsmasq: /' >> "$out"
	logread | grep -E 'dnsmasq' | tail -5 | cut -c1-150 | sed 's/^/  syslog: /' >> "$out"
	;;
esac
