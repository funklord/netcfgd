# A WireGuard tunnel from the router, sourced by guest.sh: `say`, `out` and `failed`
# are its. Run where the payload brought OpenWrt's kmod-wireguard and a peer's key
# (/payload/wg/) -- `hull-armsr`, whose outer machine is the far peer across the
# ISP's link, and pings this end's tunnel address to say it came up (10.824).
#
# The VPN a router is most often asked for, and netcfgd's own -- no tool, only the
# kernel's generic netlink -- on OpenWrt's module. The module is not in the image:
# a person installs it from the kmods feed, as this does from the files.
#
# HOW IT STOPS: each wait counts its seconds.
force=
[ -e /payload/ramdisk-root ] && force=--force-non-repository
apk add --allow-untrusted --no-network $force /payload/wg/*.apk 2>&1 | grep -v WARNING | tail -1 |
	sed 's/^/  apk: /' >> "$out"
insmod wireguard 2>/dev/null
mkdir -p /etc/netcfgd/secrets
cp /payload/wg/guest.key /etc/netcfgd/secrets/wg0
chmod 600 /etc/netcfgd/secrets/wg0
cat >> /etc/netcfgd/netcfgd.conf <<CONF
device wg0 {
	wireguard {
		private_key = "@secret:wg0"
		listen_port = 51821
		peer isp {
			public_key  = "$(cat /payload/wg/peer.pub)"
			allowed_ips = "10.99.0.1/32"
			endpoint    = "192.0.2.1:51820"
		}
	}
}
interface wg0 {
	config = "10.99.0.2/24"
}
CONF
n=0
until ip -o -4 addr show dev wg0 2>/dev/null | grep -q '10.99.0.2/' || [ $n -gt 30 ]; do
	sleep 1
	n=$((n + 1))
done
say "wg0 after $n s: $(ip -o -4 addr show dev wg0 2>/dev/null | awk '{print $4}'), module $(grep -c '^wireguard ' /proc/modules)"
# The handshake, from this end: a ping the far end must answer through the tunnel.
n=0
until ping -c 1 -W 1 10.99.0.1 > /dev/null 2>&1 || [ $n -gt 30 ]; do
	sleep 1
	n=$((n + 1))
done
answered=$(ping -c 1 -W 1 10.99.0.1 > /dev/null 2>&1 && echo yes || echo no)
say "the far peer answered through the tunnel: $answered, after $n s"
[ "$answered" = yes ] || {
	failed=1
	/usr/bin/ncfg status 2>/dev/null | grep -iA6 '^wg0' | head -8 | sed 's/^/  status: /' >> "$out"
	logread | grep netcfgd | grep -iE 'wg0|wireguard' | tail -4 | cut -c1-160 | sed 's/^/  log: /' >> "$out"
}
