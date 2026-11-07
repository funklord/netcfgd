#!/bin/sh
# ipk.sh -- an OpenWrt package of a program already built for the machine.
#
#     sh tool/ipk.sh PROGRAM ARCHITECTURE OUT.ipk
#
# PROGRAM is a static netcfgd for that machine, as `make -C c netcfgd-static` with
# OpenWrt's toolchain makes it, and ARCHITECTURE opkg's word for the machine, as
# `opkg print-architecture` gives it. An `.ipk` is a gzipped tar of three members,
# and nothing here needs OpenWrt's build system to make one.
#
# **Installing configures nothing and starts nothing**, as with the Debian and
# Alpine packages (project.md 10.750): the init script is left disabled, because
# netifd is holding the network and a daemon that took over on `opkg install`
# could take a router off it.
#
# HOW IT STOPS: straight through. It writes into a directory of mktemp's, and takes
# that away by the path it was given.
set -eu
program=$1
architecture=$2
out=$3
here=$(cd "$(dirname "$0")/.." && pwd)
version=$(cat "$here/VERSION")
size=$(wc -c < "$program")

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/data/usr/sbin" "$work/data/usr/bin" "$work/data/etc/init.d" \
	"$work/data/etc/netcfgd" "$work/data/lib/upgrade/keep.d" "$work/control"
cp "$program" "$work/data/usr/sbin/netcfgd"
chmod 755 "$work/data/usr/sbin/netcfgd"
ln -s ../sbin/netcfgd "$work/data/usr/bin/ncfg"
cp "$here/packaging/procd/netcfgd" "$work/data/etc/init.d/netcfgd"
chmod 755 "$work/data/etc/init.d/netcfgd"
# **What `sysupgrade` carries over, and the program is in it on purpose** (project.md
# 10.753). A firmware image holds no netcfgd and "keep settings" keeps only what is
# named, so a router whose port was handed to netcfgd came back with netifd no longer
# holding it and nothing else there to. The program is static, so it runs on whatever
# the new image brings; the store is this node's identity, which every paired device
# knows it by.
cat > "$work/data/lib/upgrade/keep.d/netcfgd" <<'KEEP'
/etc/netcfgd/
/root/.local/share/fuzznet/
/usr/sbin/netcfgd
/usr/bin/ncfg
/etc/init.d/netcfgd
/etc/rc.d/S21netcfgd
/etc/rc.d/K89netcfgd
KEEP

cat > "$work/control/control" <<CONTROL
Package: netcfgd
Version: $version
Architecture: $architecture
Installed-Size: $size
Section: net
Maintainer: Nabeel Sowan <nabeel@vibes.se>
Description: A network configuration daemon whose text file is the source of truth
CONTROL

echo 2.0 > "$work/debian-binary"
(cd "$work/data" && tar --owner=0 --group=0 -czf ../data.tar.gz .)
(cd "$work/control" && tar --owner=0 --group=0 -czf ../control.tar.gz .)
(cd "$work" && tar --owner=0 --group=0 -czf pack.ipk ./debian-binary ./data.tar.gz ./control.tar.gz)
cp "$work/pack.ipk" "$out"
