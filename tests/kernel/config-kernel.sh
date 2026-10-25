#!/bin/sh
# Configure a kernel that genuinely cannot do nftables NAT.
#
#     sh config-kernel.sh <source-dir> k0|k1|k2|k3
#
# k0: everything NAT needs, built in -- the control. Without it a refusal
#     could be an artifact of a stripped kernel rather than of the construct
#     that was left out, and every "refused" below would prove nothing.
# k1: nf_tables built in, no `nat` chain type and no masquerade.
# k2: the `nat` chain type built in, no masquerade.
# k3: a bridge with no VLAN filtering, which is a different question: netcfgd
#     tells an operator that a refused per-port vlan means the bridge lacks
#     `vlan_filtering = true`, and that sentence is a configuration cause. A
#     kernel built without `CONFIG_BRIDGE_VLAN_FILTERING` cannot do it at all,
#     and nothing here knew which errno that gives -- so this state exists to
#     find out whether the sentence is right in both cases or misleading in
#     one of them.
#
# **CONFIG_MODULES is off**, which is the whole point of doing this at all:
# with no module support there is no loader, no autoload, and nothing that
# could be said to be "blocked" rather than absent. `tests/hull/natcap/`
# measures the same states by blocking autoload in a guest on the host's
# kernel, and this is the control for the claim that the two are the same
# lookup failing.
set -eu
src=$1
state=$2
cd "$src"
make -s x86_64_defconfig >/dev/null
# Off: module support, and every nftables NAT construct netcfgd asks for.
scripts/config -d MODULES -d MODULE_UNLOAD \
	-d NFT_MASQ -d NFT_REDIR -d NFT_NAT -d NFT_CHAIN_NAT \
	-d NF_NAT -d NF_NAT_MASQUERADE \
	-d IP_NF_IPTABLES -d IP6_NF_IPTABLES -d NFT_COMPAT
# On: what netcfgd needs to get as far as asking for NAT, plus a serial
# console, an initramfs, and the sysrq that powers the machine off.
scripts/config -e NET -e INET -e IPV6 -e UNIX \
	-e NETFILTER -e NETFILTER_ADVANCED -e NETFILTER_NETLINK \
	-e NF_CONNTRACK -e NF_TABLES -e NF_TABLES_INET \
	-e DUMMY -e MAGIC_SYSRQ -e MAGIC_SYSRQ_DEFAULT_ENABLE \
	-e BLK_DEV_INITRD -e RD_GZIP -e DEVTMPFS -e DEVTMPFS_MOUNT \
	-e TMPFS -e PROC_FS -e SYSFS -e INOTIFY_USER -e EPOLL -e SIGNALFD \
	-e TIMERFD -e EVENTFD -e MULTIUSER -e SERIAL_8250 -e SERIAL_8250_CONSOLE \
	-e IKCONFIG -e IKCONFIG_PROC
# **What a hull guest needs built in**, added 2026-10-25 when hull gained
# `(kernel "path:FILE")` and these kernels would not come up under it: "the
# guest agent never answered". A hull vm reaches its guest over virtio -- a 9p
# root share, a vsock control channel and `console=hvc0` on a virtio console --
# and with `CONFIG_MODULES` off there is no module for any of it to load, which
# is the case hull says this form is for. A kernel for hand-driven qemu needed
# none of them: the rootfs was the initramfs and the console was ttyS0.
scripts/config -e VIRTIO -e VIRTIO_PCI -e VIRTIO_MENU -e VIRTIO_NET \
	-e VIRTIO_CONSOLE -e VIRTIO_BLK -e HVC_DRIVER \
	-e NET_9P -e NET_9P_VIRTIO -e 9P_FS -e 9P_FS_POSIX_ACL \
	-e VSOCKETS -e VIRTIO_VSOCKETS -e OVERLAY_FS
if [ "$state" = k0 ]; then
	# The control: the chain type and the masquerade both built in.
	scripts/config -e NF_NAT -e NF_NAT_MASQUERADE -e NFT_NAT -e NFT_MASQ
fi
if [ "$state" = k3 ]; then
	# A bridge that exists and cannot filter: everything NAT needs stays in,
	# so a refusal here is about the bridge and not about a stripped kernel.
	scripts/config -e NF_NAT -e NFT_NAT -e NFT_MASQ -e NF_NAT_MASQUERADE \
		-e BRIDGE -d BRIDGE_VLAN_FILTERING -e VLAN_8021Q
fi
if [ "$state" = k2 ]; then
	# The chain type present and the masquerade absent, which is the second
	# state the autoload-blocked rig measures.
	#
	# **`CONFIG_NFT_NAT`, because `CONFIG_NFT_CHAIN_NAT` does not exist.**
	# `net/netfilter/Makefile` builds `nft_chain_nat.o` from `CONFIG_NFT_NAT`,
	# so the module an operator loads and the symbol they would look for in a
	# config are spelled differently -- which is why netcfgd's own sentence
	# now names both.
	scripts/config -e NF_NAT -e NFT_NAT -d NFT_MASQ
fi
make -s olddefconfig >/dev/null
# **Read the config back rather than trusting the writes.** `scripts/config`
# cannot refuse an option whose dependencies are unmet, and `olddefconfig` may
# answer differently than asked; a kernel that quietly kept NAT would make
# every measurement below a measurement of nothing.
fail=0
# IKCONFIG_PROC so the guest can prove from inside which kernel it booted:
# `/proc/config.gz` is the instrument's own account of itself, and without it
# a run in the wrong machine looks exactly like a run in the right one.
want_y="CONFIG_NF_TABLES CONFIG_NF_TABLES_INET CONFIG_NETFILTER_NETLINK CONFIG_DUMMY CONFIG_IKCONFIG_PROC"
# The virtio set is checked too: with MODULES off a tristate that cannot be
# built in is simply dropped, and the symptom is a guest that boots and says
# nothing anybody can hear.
want_y="$want_y CONFIG_VIRTIO_PCI CONFIG_VIRTIO_NET CONFIG_VIRTIO_CONSOLE"
want_y="$want_y CONFIG_NET_9P_VIRTIO CONFIG_9P_FS CONFIG_VIRTIO_VSOCKETS"
want_n="CONFIG_MODULES"
case "$state" in
k1|k2) want_n="$want_n CONFIG_NFT_MASQ" ;;
esac
[ "$state" = k2 ] && want_y="$want_y CONFIG_NFT_NAT CONFIG_NF_NAT"
[ "$state" = k0 ] && want_y="$want_y CONFIG_NFT_NAT CONFIG_NF_NAT CONFIG_NFT_MASQ"
if [ "$state" = k3 ]; then
	want_y="$want_y CONFIG_BRIDGE CONFIG_NFT_MASQ"
	want_n="CONFIG_MODULES CONFIG_BRIDGE_VLAN_FILTERING"
fi
[ "$state" = k1 ] && want_n="$want_n CONFIG_NFT_CHAIN_NAT CONFIG_NF_NAT CONFIG_NFT_NAT"
for sym in $want_y; do
	if ! grep -qx "$sym=y" .config; then
		echo "config: $sym is not built in, and this measurement needs it" >&2
		fail=1
	fi
done
for sym in $want_n; do
	if grep -qx "$sym=[ym]" .config; then
		echo "config: $sym survived, so this kernel is not the one asked for" >&2
		fail=1
	fi
done
[ "$fail" -eq 0 ] || exit 1
printf 'config: %s ready -- ' "$state"
for sym in CONFIG_MODULES CONFIG_NF_TABLES CONFIG_NFT_NAT CONFIG_NFT_MASQ CONFIG_NF_NAT; do
	printf '%s=%s ' "${sym#CONFIG_}" "$(grep -x "$sym=.*" .config | cut -d= -f2 || echo n)"
done
echo
