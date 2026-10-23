#!/bin/sh
# The guest image `sandbox_writes.sh` needs: a real systemd, as PID 1.
#
#     sh tests/hull/sandbox/bake-rootfs.sh [DIR]
#
# `tests/hull/hwsim/bake-rootfs.sh` carries the argument for baking with docker
# rather than with `hull build`, and it holds here unchanged: a build step maps
# one uid, so a maintainer script that gives a file to its own system user
# cannot, and `systemd-sysv` has several. hull `1b12294` fixed that for an
# overlay chroot MACHINE and not for a build step, and a machine's overlay is a
# tmpfs that goes with it, so there is still nowhere to keep the result.
#
# **The setuid and setgid bits are put back, which the hwsim image does not
# need and this one does.** `docker export` through `tar` as an ordinary user
# drops them; systemd's mount units and `su` want them, and hull since
# `bfeb65f` runs qemu in a user namespace where the user is root, so a file
# this script owns shows the guest as root's -- which makes a restored setuid
# bit a real setuid-root program again. The list is read out of the image
# rather than written here: a hard-coded list is a claim about a base that
# changes.
#
# **`udev`, because systemd waits for it.** A Debian image carries none, and
# `serial-getty@hvc0` then waits on a device nothing announces, so the boot
# never reaches `running` -- measured by hull, 2026-10-22, and the cheapest fix
# is the package rather than masking the unit.
set -eu
dir=${1:-dist/hull-sandbox-rootfs}
name=netcfgd-sandbox-rootfs-$$
command -v docker >/dev/null 2>&1 || {
	echo "bake-rootfs.sh: docker is what bakes this; see the header" >&2
	exit 1
}
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT INT TERM
docker run --name "$name" debian:trixie-slim sh -c '
	set -eu
	apt-get -qq update >/dev/null
	apt-get -qq install -y --no-install-recommends \
		systemd systemd-sysv udev dbus util-linux iproute2 >/dev/null 2>&1
	for t in systemctl systemd-run setpriv unshare timeout; do
		command -v "$t" >/dev/null || { echo "missing: $t" >&2; exit 1; }
	done
	[ -x /sbin/init ] || { echo "no /sbin/init" >&2; exit 1; }
	echo "bake: systemd $(systemctl --version | head -1 | cut -d" " -f2), every tool in"
	# The modes this image carries, for the extraction to put back.
	find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%m %p\n"
' > /tmp/ncfg-sandbox-modes.$$
# The file in full, then the line worth showing. `tail -1` read the whole
# stream and so worked, but printed a mode line where the interesting one is
# the first; piping into `head` instead would have truncated the file, which
# the openrc script's comment records paying for.
head -1 /tmp/ncfg-sandbox-modes.$$
rm -rf "$dir"
mkdir -p "$dir"
docker export "$name" | tar -C "$dir" -xf -
# Back on, in the order the image reported them, and counted so that a silent
# zero cannot pass for success.
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
done < /tmp/ncfg-sandbox-modes.$$
rm -f /tmp/ncfg-sandbox-modes.$$
[ "$put" -gt 0 ] || { echo "bake-rootfs.sh: no setuid or setgid bit was put back" >&2; exit 1; }
printf 'bake-rootfs.sh: %s, %s, %d setuid or setgid file(s) restored\n' \
	"$dir" "$(du -sh "$dir" | cut -f1)" "$put"
