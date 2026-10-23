#!/bin/sh
# The guest `tool/vm/payload/init.sh` has never had: sysvinit as PID 1, with
# OpenRC installed beside it.
#
#     sh tests/hull/openrc/bake-rootfs.sh [DIR]
#
# WHY THIS IMAGE EXISTS AT ALL
#   That payload tests two init integrations netcfgd ships and nothing had
#   executed: `packaging/sysvinit/netcfgd` and `packaging/openrc/netcfgd`. On
#   the Debian guest of this tree's own VM tier only the first runs, and even
#   that one runs through systemd's `systemd-sysv-generator` rather than under
#   the init it is written for -- the payload's header says so at length. The
#   openrc half could not run at all: `openrc` depends on `insserv` and
#   `systemd-sysv` conflicts with it.
#
#   The payload's header names the remedy -- "a Debian guest with
#   `sysvinit-core` as pid 1 instead of `systemd-sysv`" -- and calls it a second
#   image and the holder's call. On hull a second image is a bake and a spec,
#   not a qcow2 in `~/vm`, so the call cost one afternoon. Measured first:
#   `sysvinit-core openrc lsb-base` install together in a `debian:trixie-slim`
#   with no systemd-sysv, giving `/sbin/init` (sysvinit) and `/sbin/openrc-run`.
#
# WHY THE IMAGE CARRIES A `localmount` SERVICE AND NETCFGD DOES NOT DROP THE
# DEPENDENCY
#   `packaging/openrc/netcfgd` says `need localmount`, and its second line says
#   who it is for: Gentoo and Alpine. Both of those ship `localmount`. Debian's
#   `openrc` does not -- it keeps sysvinit's `mountall.sh` instead, and nothing
#   in `/etc/init.d` provides the name -- so openrc refuses the service outright:
#
#       Service 'netcfgd' needs non existent service 'localmount'
#        * ERROR: netcfgd needs service(s) localmount
#
#   Measured here, and it cost three of this payload's checks on the first run.
#   The dependency is right for the audience the script names, so the **image**
#   supplies the name a stand-in distribution would have. The alternative --
#   editing `packaging/openrc/netcfgd` to suit the one distribution it is not
#   written for -- would weaken a correct dependency to make a rig pass, which
#   is the rig testing itself.
#
#   It is deliberately inert. What is under test is netcfgd's script, not
#   whether a mount ran: `start()` returning 0 is enough for `need` to be
#   satisfiable, and anything more would be this image pretending to be Gentoo.
#
# The setuid and setgid bits are put back from the image's own listing, for the
# reason `tests/hull/sandbox/bake-rootfs.sh` gives; `start-stop-daemon` and
# `su` are the ones that matter here.
set -eu
dir=${1:-dist/hull-openrc-rootfs}
name=netcfgd-openrc-rootfs-$$
command -v docker >/dev/null 2>&1 || {
	echo "bake-rootfs.sh: docker is what bakes this; see the header" >&2
	exit 1
}
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT INT TERM
docker run --name "$name" debian:trixie-slim sh -c '
	set -eu
	export DEBIAN_FRONTEND=noninteractive
	apt-get -qq update >/dev/null
	apt-get -qq install -y --no-install-recommends \
		sysvinit-core openrc lsb-base util-linux iproute2 >/dev/null 2>&1
	[ -x /sbin/init ] || { echo "no /sbin/init" >&2; exit 1; }
	[ -x /sbin/openrc-run ] || { echo "no openrc-run" >&2; exit 1; }
	# **systemd must not be the init here**, which is the whole point of the
	# image: if `systemd-sysv` is in, openrc is out and this is the guest the
	# tier already has.
	if dpkg -l systemd-sysv 2>/dev/null | grep -q "^ii"; then
		echo "systemd-sysv is installed, so this is not a sysvinit image" >&2
		exit 1
	fi
	# The `localmount` stand-in; see the header for why it is here and why it
	# does nothing. Named `provide localmount` as well as being called it, so a
	# reader of either half finds the other.
	cat > /etc/init.d/localmount <<"SERVICE"
#!/sbin/openrc-run
# Gentoo and Alpine ship this; Debian keeps sysvinit mountall.sh and has no
# service of this name. Baked in by tests/hull/openrc/bake-rootfs.sh so that
# netcfgd packaging/openrc/netcfgd -- which needs localmount, correctly, for
# the distributions it names -- can be started in this guest at all.
description="stand-in for the localmount of Gentoo and Alpine"
depend() {
	provide localmount
}
start() {
	return 0
}
stop() {
	return 0
}
SERVICE
	chmod 0755 /etc/init.d/localmount
	sh -n /etc/init.d/localmount || { echo "the localmount stand-in does not parse" >&2; exit 1; }
	echo "bake: sysvinit $(dpkg-query -W -f=\${Version} sysvinit-core), openrc $(dpkg-query -W -f=\${Version} openrc)"
	find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%m %p\n"
' > /tmp/ncfg-openrc-modes.$$
# **Read the file, do not tee into `head`.** `head -1` closes the pipe, `tee`
# takes SIGPIPE, and the modes below are never written -- which is how the
# first run of this reported "no setuid or setgid bit was put back" about an
# image that had twelve.
head -1 /tmp/ncfg-openrc-modes.$$
rm -rf "$dir"
mkdir -p "$dir"
docker export "$name" | tar -C "$dir" -xf -
put=0
while read -r mode path; do
	case "$mode" in
	[0-9]*) ;;
	*) continue ;;
	esac
	if [ -f "$dir$path" ]; then
		chmod "$mode" "$dir$path"
		put=$((put + 1))
	fi
done < /tmp/ncfg-openrc-modes.$$
rm -f /tmp/ncfg-openrc-modes.$$
[ "$put" -gt 0 ] || { echo "bake-rootfs.sh: no setuid or setgid bit was put back" >&2; exit 1; }
printf 'bake-rootfs.sh: %s, %s, %d setuid or setgid file(s) restored\n' \
	"$dir" "$(du -sh "$dir" | cut -f1)" "$put"
