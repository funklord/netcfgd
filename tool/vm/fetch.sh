#!/bin/sh
# Fetch the guest images the VM tier boots, into a store outside the tree.
#
#     sh tool/vm/fetch.sh            # both guests, into $VM_DIR, default ~/vm
#     sh tool/vm/fetch.sh alpine     # just one
#     sh tool/vm/fetch.sh debian
#
# WHY A VM TIER EXISTS AT ALL
#   `make live` runs 61 scripts under `unshare -rn`, which gives real netlink
#   and real interfaces on the host's kernel. Eight of them name something a
#   namespace cannot provide -- real root, module loading, /dev/vhci, /dev/ppp
#   or systemd -- and four skipped on the machine this was written on. netcfgd
#   also ships three init integrations (packaging/systemd, packaging/openrc,
#   packaging/procd) and that machine runs sysvinit, so none of the three is
#   exercised anywhere. Every kernel measurement in doc/decision says
#   "measured on 6.12" because 6.12 is the only kernel there is.
#
#   So this tier is for exactly what a namespace cannot do: its own kernel,
#   its own modules, its own init. Several hosts on a wire is NOT one of those
#   -- `unshare -rn` plus veth already does that, and delegation.sh already
#   runs a real kea talking to a real odhcp6c that way.
#
# TWO GUESTS, AND WHAT EACH IS FOR
#   **Debian** matches the development machine's libc, so `target/debug/netcfgd`
#   runs in it straight off the read-only share with nothing cross-built and no
#   toolchain installed on the host. It also brings **systemd**, which is what
#   `sandbox_writes.sh` refuses for -- the one live script that ends `make live`
#   with a non-zero exit -- so the unit's real sandbox becomes checkable rather
#   than inspected.
#
#   **Alpine** is the cheap one: a ten-second boot, and OpenRC, which is a
#   second of the three init systems netcfgd ships and which nothing else here
#   runs. It cannot run the host's binary -- it is musl, and a glibc executable
#   reports `not found` because its interpreter is absent -- so it is for
#   kernel-and-module work rather than for netcfgd's own suite.
#
#   A musl Rust target was considered and dropped. Debian packages no Rust std
#   for musl, so it would have meant a second toolchain outside apt on the host
#   to serve a guest, which is backwards from the reason this tier exists.
#
# WHY THE NETBOOT FLAVOUR FOR ALPINE, AND WHY NO DISK IMAGE
#   It is three loose files -- a kernel, an initramfs and a modloop squashfs
#   holding the modules -- so the guest boots diskless with the command line as
#   an ARGUMENT. Nothing is written to a disk image: no qcow2, no overlay, and
#   nothing ever written over the network store this lives on, which matters
#   rather than being tidy, because a guest disk over NFS has locking and
#   coherency problems that present as guest corruption.
#
#   **The standard ISO was tried and dropped, and the reason is the command
#   line.** The ISO carries the same three files and boots them through
#   ISOLINUX, which has to be told the console and the overlay by typing at its
#   boot prompt over the serial port -- and ISOLINUX polls that port and loses
#   characters at both ends. One `printf` arrived truncated mid-word; a
#   character at a time with a pause arrived with its head eaten, the prompt
#   not yet existing when the typing began. Both boots then SUCCEEDED having
#   dropped the instruction, which is the worst shape of failure available, and
#   no amount of sleeping fixes it: the start needs the prompt to exist and the
#   end needs it to still be reading, and nothing outside the guest can see
#   either. Booting the kernel directly puts the command line somewhere it
#   cannot be misheard.
#
#   It also brings OpenRC as the guest's real init, which is one of the three
#   netcfgd ships and cannot otherwise be run.
#
# WHY THE `lts` FLAVOUR AND NOT `virt`
#   The tarball carries both, and `virt` is the obvious choice for a VM: a
#   20 MB modloop against 192 MB, and a smaller initramfs. It is the wrong one.
#   Read out of the shipped kernel configs, which are plain text in the same
#   tarball:
#
#       symbol                   lts   virt
#       MAC80211_HWSIM            m     no     real radios, hwsim.sh
#       BT_HCIVHCI                m     no     /dev/vhci, bluetooth.sh
#       PPPOE                     m     no     ppp.sh, pppoe-session.sh
#
#   Those three are exactly the capabilities this tier exists for, and `virt`
#   has none of them. Everything else the suite wants -- VRF, WireGuard, VXLAN,
#   macvlan, ifb, cake, bonding, geneve -- is a module in both. So the 172 MB
#   buys the whole reason for the tier and `virt` would buy a faster boot and
#   none of it.
#
#   The guest kernel is 6.12.1-3, against 6.12.107 on the machine this was
#   written on. That difference is a feature: every kernel measurement in
#   doc/decision says "measured on 6.12" because one kernel was all there was.
#
# WHY THE HASH IS PINNED HERE
#   A pin cannot tell you it has been superseded -- `evidence.md` is explicit
#   about that -- and it is still the right trade for a test guest: every run
#   should boot the same kernel, and moving to a new one is a commit somebody
#   reviews rather than whatever the mirror served today. The published
#   checksum was read from the mirror once, by hand, at the URL below.
set -eu

store=${VM_DIR:-$HOME/vm}
want=${1:-all}

for tool in curl sha256sum sha512sum tar; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "fetch: $tool is not installed" >&2
		exit 1
	}
done
mkdir -p "$store"

# A pin cannot say it has been superseded, which `evidence.md` is explicit
# about, and it is still right here: every run should boot the same kernel, and
# moving to a new one is a commit somebody reviews rather than whatever the
# mirror served today. Both checksums below were read once from the
# publisher's own file, by hand, at the URL beside them.

alpine() {
	version=3.21.0
	branch=v3.21
	arch=x86_64
	tarball="alpine-netboot-$version-$arch.tar.gz"
	# $base/$tarball.sha256
	sha256=41010d3fd043b0f781c82067cd3ffe7cc6a014c9579f7a186f5176bf2e78f3cc
	base="https://dl-cdn.alpinelinux.org/alpine/$branch/releases/$arch"
	dest="$store/alpine-$version-$arch"

	# Already here and intact is a no-op, so this is safe to call from a make
	# target. The three files the boot needs are checked by name and the
	# tarball's recorded hash by content, the extracted files carrying none of
	# their own.
	if [ -f "$dest/boot/vmlinuz-lts" ] && [ -f "$dest/boot/initramfs-lts" ] &&
		[ -f "$dest/boot/modloop-lts" ] && [ -f "$dest/.verified" ] &&
		[ "$(cut -d' ' -f1 < "$dest/.verified")" = "$sha256" ]; then
		echo "fetch: $dest is present and verified"
		return 0
	fi

	work=$(mktemp -d "$store/fetch.XXXXXX")
	echo "fetch: $base/$tarball"
	if ! curl -fsSL --max-time 900 -o "$work/$tarball" "$base/$tarball"; then
		rm -rf "$work"
		echo "fetch: could not download $tarball" >&2
		return 1
	fi

	# Checked before anything is extracted, so a bad download never becomes
	# files on disk that a later run would find and boot.
	if ! printf '%s  %s\n' "$sha256" "$work/$tarball" | sha256sum -c - >/dev/null 2>&1; then
		got=$(sha256sum "$work/$tarball" | cut -d' ' -f1)
		rm -rf "$work"
		echo "fetch: $tarball does not match the pinned checksum" >&2
		echo "fetch:   expected $sha256" >&2
		echo "fetch:   got      $got" >&2
		echo "fetch: either the mirror served something else or the pin is stale;" >&2
		echo "fetch:   check $base/$tarball.sha256 and move the pin deliberately" >&2
		return 1
	fi

	rm -rf "$dest"
	mkdir -p "$dest"
	# No `--strip-components`: the tarball's own top level IS `boot/`, with no
	# wrapper above it, so stripping one component lands the files at the
	# destination root and leaves nothing at `boot/`. Found by the check below,
	# which is why it is a check rather than a comment.
	tar -xzf "$work/$tarball" -C "$dest"
	rm -rf "$work"
	for f in vmlinuz-lts initramfs-lts modloop-lts; do
		[ -f "$dest/boot/$f" ] || {
			echo "fetch: the tarball did not contain boot/$f" >&2
			return 1
		}
	done
	printf '%s %s\n' "$sha256" "$tarball" > "$dest/.verified"
	echo "fetch: $dest"
	for f in vmlinuz-lts initramfs-lts modloop-lts; do
		ls -l "$dest/boot/$f" | awk '{ printf "fetch:   %10d  %s\n", $5, $9 }'
	done
}

debian() {
	build=20261001-2618
	# **`generic`, not `genericcloud`, and the difference is the kernel.**
	# genericcloud ships `linux-image-cloud-amd64`, trimmed of what a cloud
	# provider's guests never need -- including 9p, so the read-only share of
	# the repository could not mount:
	#
	#     mount: /mnt/repo: unknown filesystem type '9p'
	#
	# which is the share this guest exists to use. That is the same shape as
	# Alpine's `lts` against `virt` above: the variant built for the smaller
	# case lacks exactly what this tier is for, and the larger image buys the
	# whole reason for it.
	image="debian-13-generic-amd64-$build.qcow2"
	# $base/SHA512SUMS -- Debian publishes sha512 for these, not sha256.
	sha512=6f0f93335bdef4ccf523c4317cc663ea52ca23b862667785f3d6d186ab4674a937385ccff0c55996b4b2e4c19e440cdf211e2a75ffa2f6548037ab43950c841d
	base="https://cloud.debian.org/images/cloud/trixie/$build"
	dest="$store/$image"

	# **The genericcloud flavour**, which carries cloud-init and a serial
	# console in its own bootloader configuration -- so it needs nothing typed
	# at a boot prompt, which is the trap the Alpine route spent four boots on.
	if [ -f "$dest" ] &&
		printf '%s  %s\n' "$sha512" "$dest" | sha512sum -c - >/dev/null 2>&1; then
		echo "fetch: $dest is present and verified"
		return 0
	fi

	work=$(mktemp -d "$store/fetch.XXXXXX")
	echo "fetch: $base/$image"
	if ! curl -fsSL --max-time 1800 -o "$work/$image" "$base/$image"; then
		rm -rf "$work"
		echo "fetch: could not download $image" >&2
		return 1
	fi
	if ! printf '%s  %s\n' "$sha512" "$work/$image" | sha512sum -c - >/dev/null 2>&1; then
		got=$(sha512sum "$work/$image" | cut -d' ' -f1)
		rm -rf "$work"
		echo "fetch: $image does not match the pinned checksum" >&2
		echo "fetch:   expected $sha512" >&2
		echo "fetch:   got      $got" >&2
		echo "fetch: check $base/SHA512SUMS and move the pin deliberately" >&2
		return 1
	fi
	# Moved into place only once verified, so an interrupted run never leaves
	# a truncated image where a boot would find it.
	mv "$work/$image" "$dest"
	rm -rf "$work"
	echo "fetch: $dest"
	ls -l "$dest" | awk '{ printf "fetch:   %10d  %s\n", $5, $9 }'
}

case "$want" in
alpine) alpine ;;
debian) debian ;;
all) alpine && debian ;;
*)
	echo "fetch: unknown guest \`$want'; one of alpine, debian, all" >&2
	exit 1
	;;
esac
