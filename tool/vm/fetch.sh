#!/bin/sh
# Fetch the guest images the VM tier boots, into a store outside the tree.
#
#     sh tool/vm/fetch.sh            # into $VM_DIR, default ~/vm
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
# WHY THE STANDARD ISO, AND WHY NO DISK IMAGE
#   It boots diskless from the CD: the kernel, the initramfs and the modloop
#   squashfs holding the modules all travel in the one file, and nothing is
#   written to a disk image. So there is no qcow2, no overlay, and nothing is
#   ever written over the network store this lives on -- which matters, because
#   running a guest disk over NFS has locking and coherency problems that look
#   like guest corruption.
#
#   The netboot flavour was tried first and carries the same three files
#   loose. It is not simpler: the initramfs has to be told where the modloop
#   is, which means serving it over http or attaching it as a filesystem the
#   init will go looking through. The ISO already contains it, and the modules
#   are the whole reason this tier exists.
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

version=3.21.0
branch=v3.21
arch=x86_64
# `standard` and not `virt`, for the reason measured above.
iso="alpine-standard-$version-$arch.iso"
# Read once from $base/$iso.sha256, by hand, and pinned here.
sha256=201e2ba601be5b861345a308591e3e547bf6d210945dfaab3e3251b8dea64b8b
base="https://dl-cdn.alpinelinux.org/alpine/$branch/releases/$arch"

store=${VM_DIR:-$HOME/vm}
dest="$store/$iso"

for tool in curl sha256sum; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "fetch: $tool is not installed" >&2
		exit 1
	}
done

# Already here and intact is a no-op, so this is safe to call from a make
# target -- and the hash is re-checked rather than trusted, because a truncated
# download from an interrupted run is exactly what a later run would otherwise
# find and boot.
if [ -f "$dest" ] && printf '%s  %s\n' "$sha256" "$dest" | sha256sum -c - >/dev/null 2>&1; then
	echo "fetch: $dest is present and verified"
	exit 0
fi

mkdir -p "$store"
work=$(mktemp -d "$store/fetch.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

echo "fetch: $base/$iso"
curl -fsSL --max-time 900 -o "$work/$iso" "$base/$iso"

# Checked before it is put where a boot would find it, so a bad download never
# becomes a file a later run trusts.
if ! printf '%s  %s\n' "$sha256" "$work/$iso" | sha256sum -c - >/dev/null 2>&1; then
	got=$(sha256sum "$work/$iso" | cut -d' ' -f1)
	echo "fetch: $iso does not match the pinned checksum" >&2
	echo "fetch:   expected $sha256" >&2
	echo "fetch:   got      $got" >&2
	echo "fetch: either the mirror served something else or the pin is stale;" >&2
	echo "fetch:   check $base/$iso.sha256 and move the pin deliberately" >&2
	exit 1
fi

mv "$work/$iso" "$dest"
echo "fetch: $dest"
ls -l "$dest" | awk '{ printf "fetch:   %10d  %s\n", $5, $9 }'
