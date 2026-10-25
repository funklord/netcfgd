#!/bin/sh
# The guest image for measuring what a kernel says when it cannot do NAT.
#
#     sh tests/hull/natcap/bake-rootfs.sh [DIR]
#
# WHY THIS RIG EXISTS
#   netcfgd translates a kernel refusal into a sentence an operator can act on
#   (`ncfg_kernel_hint`), and 0287 makes that sentence the text of a red row in
#   a rule list. Every such sentence is a claim about an errno, and **no claim
#   about a kernel refusal can be checked on a machine whose kernel does the
#   thing**: this host has `nft_chain_nat` and `nft_masq`, so the two states
#   the NAT sentence is about cannot occur here, and the arm was first written
#   keyed on two errnos because nobody could say which one arrived.
#
#   A vm can be that machine without a kernel being built. The guest boots with
#   an empty module table and its own `/proc/sys/kernel/modprobe`, so blocking
#   autoload leaves a construct unreachable exactly as a kernel compiled
#   without it would -- the lookup that fails is the same one, and it does not
#   care why the module never appeared. What that measured is in `nft.c` and in
#   project.md: `ENOENT` for both, `EOPNOTSUPP` for neither.
#
#   A container cannot do this and neither can a namespace: both share the
#   host's kernel, where the modules are loaded and registration is global.
#
# WHY DOCKER BAKES IT AND NOT HULL
#   The same reason `tests/hull/hwsim/bake-rootfs.sh` gives at length:
#   packages do not install into a `(mutable overlay)` guest, and
#   `(mutable direct)` writes through 9p as the host user so dpkg's chown
#   fails.
#
#   **The third reason it gave -- a build step trips over a maintainer script
#   wanting more than one uid -- is gone, measured 2026-10-25**: that header
#   has the run. So "replace this with a `(build ...)` form the day that path
#   works" is now a thing somebody can do, and it is a pass across all four
#   rigs rather than an edit to one; this script's own package set (`kmod`,
#   `iproute2`) is the least of what it would move.
#
# WHAT IT INSTALLS, AND WHAT IT DELIBERATELY DOES NOT
#   `kmod` for modprobe, `iproute2` for the control that proves autoload is
#   blocked. **No compiler**: the binaries come from the share, because what is
#   under test is the kernel's answer and netcfgd's sentence about it, not the
#   guest's toolchain -- `hwsim`'s rig builds in the guest and says why there.
#   That keeps this image around 110 MB where that one is 430.
#
#   The setuid and setgid bits are put back from the image's own listing, for
#   the reason `tests/hull/sandbox/bake-rootfs.sh` gives. Nothing here needs
#   one -- the payload is root in the guest and calls no setuid program -- so
#   this is for the next payload rather than for this one.
set -eu
dir=${1:-dist/hull/natcap-rootfs}
name=netcfgd-natcap-rootfs-$$
command -v docker >/dev/null 2>&1 || {
	echo "bake-rootfs.sh: docker is what bakes this; see the header" >&2
	exit 1
}
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT INT TERM
docker run --name "$name" debian:trixie-slim sh -c '
	set -eu
	export DEBIAN_FRONTEND=noninteractive
	apt-get -qq update >/dev/null
	apt-get -qq install -y --no-install-recommends kmod iproute2 >/dev/null 2>&1
	# **Both, named, because the payload is useless without either**: modprobe
	# is how a state is set up and `ip` is the control that proves the block.
	command -v modprobe >/dev/null || { echo "no modprobe in the image" >&2; exit 1; }
	command -v ip >/dev/null || { echo "no ip in the image" >&2; exit 1; }
	echo "bake: kmod $(dpkg-query -W -f=\${Version} kmod), iproute2 $(dpkg-query -W -f=\${Version} iproute2)"
	find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%m %p\n"
' > /tmp/ncfg-natcap-modes.$$
# Read the file rather than tee into `head`: the openrc rig's header has what
# that cost when `head` closed the pipe and the modes were never written.
head -1 /tmp/ncfg-natcap-modes.$$
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
done < /tmp/ncfg-natcap-modes.$$
rm -f /tmp/ncfg-natcap-modes.$$
[ "$put" -gt 0 ] || { echo "bake-rootfs.sh: no setuid or setgid bit was put back" >&2; exit 1; }
printf 'bake-rootfs.sh: %s, %s, %d setuid or setgid file(s) restored\n' \
	"$dir" "$(du -sh "$dir" | cut -f1)" "$put"
