#!/bin/sh
# openwrt_apk.sh -- an OpenWrt 25.12 package of a program already built for the machine.
#
#     APK=path/to/apk sh tool/openwrt_apk.sh PROGRAM ARCHITECTURE OUT.apk
#
# OpenWrt 25.12 replaced opkg with apk-tools 3, so `tool/ipk.sh`'s package does
# not install there (project.md 10.812, 10.813). This makes the apk-v3 package
# of the same files: the static program, `ncfg` as a link to it, the procd
# script and the sysupgrade keep list. ARCHITECTURE is apk's word for the
# machine, as `apk --print-arch` on the router gives it.
#
# APK is an apk-tools 3 with `mkpkg`, which OpenWrt's own apk is built without;
# `make apk-tools` builds one from Alpine's source under $(BUILD_DIR).
#
# **Installing configures nothing and starts nothing**, as with every package
# of netcfgd's (10.750): no scripts, so the init script stays out of
# /etc/rc.d until a person enables it -- netifd is holding the network.
#
# **Root's files without root.** mkpkg records each file's owner by name, from
# the build directory, which is this user's; it runs under `unshare -r`, where
# this user is uid 0, so the package says root.
#
# The package is unsigned, so it installs with `apk add --allow-untrusted`.
#
# HOW IT STOPS: straight through. It writes into a directory of mktemp's, and
# takes that away by the path it was given.
set -eu
# A system's own modes for what it lays down (10.813): a builder's umask of
# 002 made what the package creates group-writable -- the keep list 0664, a
# new directory 0775. (apk leaves a directory the router already has alone:
# measured, /etc stayed 0755 under a package that carried it as 0775.)
umask 022
program=$1
architecture=$2
out=$3
here=$(cd "$(dirname "$0")/.." && pwd)
version=$(cat "$here/VERSION")
apk=${APK:-}

if [ -z "$apk" ] || [ ! -x "$apk" ]; then
	echo "openwrt_apk: APK names no apk-tools 3 to make the package with;" >&2
	echo "openwrt_apk:   \`make apk-tools\` builds one, and says where it is" >&2
	exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root/usr/sbin" "$work/root/usr/bin" "$work/root/etc/init.d" \
	"$work/root/etc/netcfgd" "$work/root/lib/upgrade/keep.d"
cp "$program" "$work/root/usr/sbin/netcfgd"
chmod 755 "$work/root/usr/sbin/netcfgd"
ln -s ../sbin/netcfgd "$work/root/usr/bin/ncfg"
cp "$here/packaging/procd/netcfgd" "$work/root/etc/init.d/netcfgd"
chmod 755 "$work/root/etc/init.d/netcfgd"
# The same list `tool/ipk.sh` writes, for its reason (10.753): a firmware image
# holds no netcfgd, and "keep settings" keeps only what is named.
cat > "$work/root/lib/upgrade/keep.d/netcfgd" <<'KEEP'
/etc/netcfgd/
/root/.local/share/fuzznet/
/usr/sbin/netcfgd
/usr/bin/ncfg
/etc/init.d/netcfgd
/etc/rc.d/S21netcfgd
/etc/rc.d/K89netcfgd
KEEP

unshare -r "$apk" mkpkg \
	--info "name:netcfgd" \
	--info "version:$version" \
	--info "arch:$architecture" \
	--info "description:A network configuration daemon whose text file is the source of truth" \
	--info "maintainer:Nabeel Sowan <nabeel@vibes.se>" \
	--files "$work/root" \
	--output "$work/pack.apk"
cp "$work/pack.apk" "$out"
