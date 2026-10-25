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
#   dpkg's `chown` fails and apt dies; and in a `hull build` step the packages
#   resolve and install, and then `dnsmasq-base`'s postinst fails -- a build
#   step maps one uid, so a maintainer script giving a file to its own system
#   user cannot, which is hull's own "many uids" question.
#
#   **That third snag is gone, measured 2026-10-25 on hull `a5c1f58-dirty`.**
#   hull mapped many uids on its chroot engine from 2026-10-23, and this exact
#   package list -- `build-essential kmod iw wpasupplicant iproute2
#   dnsmasq-base dhcpcd-base iputils-ping` -- installs in a `(build ...)` step
#   with `(network true)`: exit 0, every binary the loop below checks present,
#   `dnsmasq-base`'s postinst among the ones that ran. The stored manifest
#   carries what this script cannot: eight files at mode 04755 and the non-root
#   owners (`uid 42`, `999`, `65534`), where a `docker export` through `tar -x`
#   as a user drops both and the chmod below puts only the modes back.
#
#   One warning came with it and was chased, because it turned out to be a
#   hull fault rather than apt's: the step tree's root was 0700, so no uid but
#   root could traverse it and apt's sandbox fell back to fetching as root.
#   hull fixed it at `b7126fe`; on a binary built from that commit the root is
#   0755, both apt runs report zero unsandboxed warnings, and `_apt` owns and
#   writes its own partial directories (10.556, 10.557).
#
#   **So this script stays for now by inertia rather than by argument**, and
#   moving the four rigs onto built images is a deliberate pass rather than a
#   change to make while editing one of them: every rig's source changes, the
#   bake scripts go, the Makefile's image targets change, and the ownership
#   half only pays off on a hull carrying `a1b6dd2` (hull's own report of
#   2026-10-25, not measured here). Raised with the holder on that date.
#
#   **A fourth snag was claimed here and was mine.** The step first reported
#   four of seven packages "unable to locate", which read as hull's. A build
#   step is offline unless it says `(network true)`, which that one did not,
#   and `apt-get update` exits 0 when it cannot fetch -- so the update
#   "succeeded" against nothing and only cached names resolved. hull's session
#   measured it and said so; the line above is what is left once the network
#   is declared.
#
#   So the packages come from the one tool here that can already install them,
#   and hull gets what it is good at: a kernel of its own, real root, and the
#   radios. Replace this script with a `(build ...)` form the day that path
#   works; the machine file does not change when it does.
#
# WHAT IT INSTALLS AND WHY A COMPILER IS AMONG IT
#   `build-essential`, so the payload builds netcfgd in the guest rather than
#   running what the host built: `build-and-commit.md`'s argument is that a
#   build in the runner's own image catches what a developer machine hides, and
#   a test running the host's binary tests the host's toolchain. It costs about
#   300 MB of image and a couple of minutes a run, which a by-hand test can
#   afford.
#
#   **A guest could not build anything before hull `7b47668`**: with no PATH
#   exported, gcc could not resolve its own argv[0] and printed a bare `cc1`
#   where it prints a path. That was one of this rig's five findings, and the
#   payload falls back to the share -- loudly -- on an image with no compiler.
# WHAT THIS IMAGE IS NOT, AND IT MATTERS BEYOND THIS TEST
#   `docker export` piped through `tar -x` as an ordinary user **drops every
#   setuid bit and every owner**. Measured 2026-10-22: the `debian:trixie-slim`
#   image has eight setuid-root programs -- `mount`, `umount`, `su`, `passwd`,
#   `newgrp`, `chsh`, `chfn`, `gpasswd` -- and this tree has none, every file
#   being `funk:users` mode 0755. `hull materialize` of the same image keeps
#   all eight, so hull's own path is the faithful one and this is a convenience
#   until it can install a package set.
#
#   `hwsim.sh` does not care: it runs as root in the guest and calls no setuid
#   program. A payload that needs one -- anything calling `sudo`, or `mount` as
#   a user -- must not use this image, and would want `hull materialize` plus a
#   package step instead.
#
#   **The hull bug this was once said to mask is not the one described, and
#   the correction is measured.** The sentence here used to say that 9p shows
#   a guest every file as the host user's, so a setuid-root program becomes
#   setuid-1000 and root running it is refused. Measured 2026-10-25 in a
#   `dir:`-sourced vm on hull `a5c1f58-dirty`, booting this family of images:
#   the guest sees owner **0**, group **65534**, and every mode bit intact --
#   `4755 /usr/bin/su`, `2755 /var/lib/apt`, eight setuid files. The host
#   user maps to root rather than to 1000, so that hazard does not arise in
#   this form; what does not map is the GROUP, and the rule is which gid
#   rather than which name: a machine maps the user's uid and primary gid,
#   `funk`'s primary gid is 1000, and `tar -x` leaves these files gid 100
#   (`users`), which is outside the map and so arrives as the overflow gid.
#
#   So the reason to keep this note is narrower and still real: the bits here
#   are restored by `chmod` from the image's own listing rather than carried,
#   and a payload that needs a file's OWNER or GROUP to be anything in
#   particular -- not just its mode -- is not served by a `docker export` at
#   all. hull reported on 2026-10-25 (its `f82403d`) that a *stored* tree now
#   gets its non-root owners back inside a vm as well as on chroot, by mapping
#   a subuid range and chowning the manifest's owners before boot -- uid and
#   gid both, by their account. These images are `dir:` sources with no
#   manifest, so that does not reach them; and hull reported next that `hull
#   run` of a stored image does not yet emit the owners list for that engine
#   half to act on, so `hull materialize` plus a package step -- what this
#   header has recommended from the start -- is for now blocked on the package
#   install AND on the store side of ownership, the second in flight.
set -eu
dir=${1:-dist/hull/hwsim-rootfs}
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
		build-essential kmod iw wpasupplicant iproute2 dnsmasq-base \
		dhcpcd-base iputils-ping >/dev/null 2>&1
	apt-get clean
	for t in cc make modprobe iw wpa_supplicant ip dnsmasq dhcpcd ping; do
		command -v "$t" >/dev/null || { echo "missing: $t" >&2; exit 1; }
	done
	echo "bake: every tool the test asks for is in"
'
rm -rf "$dir"
mkdir -p "$dir"
docker export "$name" | tar -C "$dir" -xf -
printf 'bake-rootfs.sh: %s, %s\n' "$dir" "$(du -sh "$dir" | cut -f1)"
