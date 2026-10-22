#!/bin/sh
# The guest image `hwsim.sh` needs, as a directory hull can run.
#
#     sh tests/hull/hwsim/bake-rootfs.sh [DIR]
#
# WHY DOCKER BAKES IT AND NOT HULL
#   hull's own section 12 says to put packages in an image with `hull build`,
#   and that is the right shape -- it is not what works today, measured
#   2026-10-22 against hull 4161c8a. Three roads and each has a snag: into a
#   `(mutable overlay)` vm the install truncates silently (it left a gcc whose
#   `cc1` was missing, which then read as a netcfgd fault two steps later);
#   with `(mutable direct)` the guest writes through 9p as the host user, so
#   dpkg's `chown` fails and apt dies; and `hull build`'s own step runs in a
#   chroot machine where, even with `-o APT::Sandbox::User=root`, `apt-get
#   install` reported four of seven packages as "unable to locate" after an
#   update that had just succeeded.
#
#   So the packages come from the one tool here that can already install them,
#   and hull gets what it is good at: a kernel of its own, real root, and the
#   radios. Replace this script with a `(build …)` form the day that path
#   works; the machine file does not change when it does.
#
# WHAT IT DOES NOT INSTALL
#   No compiler. `payload.sh` runs the binaries the host built, through the
#   read-only share, because the guest and the host are one architecture and
#   one libc and what is under test is the radio. gcc in a guest is also its
#   own open question -- the driver could not find `cc1` on an overlay over
#   the share, printing a bare name where it prints a path.
set -eu
dir=${1:-dist/hull-hwsim-rootfs}
name=netcfgd-hwsim-rootfs-$$
command -v docker >/dev/null 2>&1 || {
	echo "bake-rootfs.sh: docker is what bakes this; see the header" >&2
	exit 1
}
# Named with this shell's pid and removed on every path, so two runs cannot
# collide and a failure leaves no container behind.
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT INT TERM
docker run --name "$name" debian:trixie-slim sh -c '
	set -eu
	apt-get -qq update >/dev/null
	apt-get -qq install -y --no-install-recommends \
		kmod iw wpasupplicant iproute2 dnsmasq-base dhcpcd-base \
		iputils-ping >/dev/null 2>&1
	apt-get clean
	for t in modprobe iw wpa_supplicant ip dnsmasq dhcpcd ping; do
		command -v "$t" >/dev/null || { echo "missing: $t" >&2; exit 1; }
	done
	echo "bake: every tool the test asks for is in"
'
rm -rf "$dir"
mkdir -p "$dir"
docker export "$name" | tar -C "$dir" -xf -
printf 'bake-rootfs.sh: %s, %s\n' "$dir" "$(du -sh "$dir" | cut -f1)"
