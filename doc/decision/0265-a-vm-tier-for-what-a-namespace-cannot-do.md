# 0265: A VM tier, for exactly what a namespace cannot do

Status: accepted; the fetch and the boot are built, the automation is not
Date: 2026-10-07
Milestone: a second test tier, asked for by the copyright holder

## Context

`make live` runs 61 scripts under `unshare -rn`, against real netlink and real
interfaces on the host's kernel. **Eight of them name something a namespace
cannot provide** -- real root, module loading, `/dev/vhci`, `/dev/ppp` or
systemd: `bluetooth.sh`, `hwsim.sh`, `ppp.sh`, `pppoe-session.sh`,
`delegation.sh`, `killmode.sh`, `select.sh`, `sandbox_writes.sh`. Four skipped
in the run of 2026-10-07, and `sandbox_writes.sh` ends that target by refusing
outright, which is why it was moved last.

Two more gaps are structural rather than per-script. netcfgd ships **three init
integrations** -- `packaging/systemd`, `packaging/openrc`, `packaging/procd` --
and the machine this was written on runs sysvinit, so not one of the three is
exercised anywhere; the systemd unit's sandbox is checked statically and its
real behaviour not at all. And **every kernel measurement in this directory
says "measured on 6.12"** because 6.12 is the only kernel there is, including
the `l3mdev` answers taken the same day as this record.

## Decision

**Two tiers, and the VM tier first, because it needs nothing installed.**
Measured on the machine asking the question:

    qemu-system-x86_64, qemu-img   present
    /dev/kvm                       present, mode crw-rw-rw- -- usable
                                   without kvm-group membership
    systemd-nspawn, machinectl     MISSING (systemd-container)
    debootstrap, mmdebstrap        MISSING

So the VM tier is buildable today and accelerated; the nspawn tier needs two
packages a root may install. **And with KVM the VM tier largely subsumes what
nspawn was wanted for**: an Alpine guest is OpenRC natively and a Debian guest
would be systemd, which is two of the three init systems without
`systemd-container` at all. The nspawn tier is therefore deferred until boot
time is measured and found to be the bottleneck, rather than built on the
assumption that it will be.

**Several hosts on a wire is not a reason for VMs.** `unshare -rn` plus veth
already does it, and `delegation.sh` already runs a real kea talking to a real
odhcp6c that way. What a VM buys is its own kernel, its own modules and its own
init; the tier is scoped to those and to nothing else.

**The `lts` flavour, not `virt`**, read out of the kernel configs that ship in
the same tarball as plain text:

    symbol                   lts   virt
    MAC80211_HWSIM            m     no     real radios, hwsim.sh
    BT_HCIVHCI                m     no     /dev/vhci, bluetooth.sh
    PPPOE                     m     no     ppp.sh, pppoe-session.sh

Those three are the capabilities the tier exists for and `virt` has none of
them. Everything else the suite wants -- VRF, WireGuard, VXLAN, macvlan, ifb,
cake, bonding, geneve -- is a module in both. `virt` would buy a 20 MB modloop
against 192 MB and a faster boot, and none of the reason for the tier.

**The standard ISO, booted diskless.** The kernel, the initramfs and the
modloop travel in the one file and nothing is written to a disk image: no
qcow2, no overlay, and nothing ever written to the store the image lives on.
That last part is load-bearing rather than tidy, because the store is NFS and
running a guest disk over NFS has locking and coherency problems that present
as guest corruption.

**Images live outside the tree**, in `$VM_DIR`, default `~/vm`, which the
copyright holder pointed at `/home/funk/mnt/dl180g6-03/vm` -- 46 T with 28 T
free, against 23 G free on the local root. `tool/vm/fetch.sh` fetches one
artifact against a **pinned, published sha256**, verifies before it moves the
file where a boot would find it, and re-verifies on every call so a truncated
download from an interrupted run cannot be found and booted later.

A pin cannot say it has been superseded, which `evidence.md` is explicit about,
and it is still right here: every run should boot the same kernel, and moving
to a new one is a commit somebody reviews rather than whatever the mirror
served today.

## What was measured, not assumed

**A guest boots.** `qemu-system-x86_64 -enable-kvm -nographic -boot d -cdrom`,
with a boot line handed to ISOLINUX over the serial port:

```text
ISOLINUX 6.04 6.04-pre1 ETCD
boot: lts console=ttyS0,115200 quiet

Welcome to Alpine Linux 3.21
Kernel 6.12.1-3-lts on an x86_64 (/dev/ttyS0)
localhost login:
```

That is **6.12.1-3-lts against the host's 6.12.107** -- a second kernel, which
is the thing the records' single-kernel caveat has been waiting for.

**The netboot flavour was tried first and dropped.** It carries the same three
files loose, and the initramfs has to be told where the modloop is; given the
ISO as media it answered `Mounting boot media failed` and dropped to its
recovery shell, with `alpine_dev=cdrom` making no difference. The ISO's own
initramfs finds its own CD, which is what it is for.

## What this leaves, and the one thing it rules out

**Automation is not built, and driving the console is ruled out rather than
untried.** Feeding qemu's stdin a timed sequence -- a boot line, then a login,
then commands -- does not work, and the reason generalises:

```text
localhost login: tyS0,115200 quiet
Password:
Login incorrect
```

qemu buffers the whole stream and hands it to one serial port, while the
*consumer* of that port changes underneath it: ISOLINUX took `lts console=t`
and the remaining `tyS0,115200 quiet` arrived later at a login prompt that had
not existed when it was written. **A single input stream with a changing reader
cannot be driven blind**, and no amount of sleeping fixes the shape -- it only
moves which consumer gets which fragment.

So the guest must run its own script: an **apkovl**, the overlay Alpine looks
for on attached media, with the serial port used for output only. `mformat` and
`mcopy` are present, so the FAT image that carries it can be built without
root. The repository reaches the guest over a read-only 9p share, so there is
no image to rebuild in the loop, and the inter-guest wire is
`-netdev socket,mcast=` -- a shared L2 segment between N qemu processes, with
no bridge and no privilege.

**Deliberately not done here**: the apkovl and the multi-guest wire, the nspawn
tier, and procd -- which needs an OpenWrt image rather than an Alpine one and
is the one of the three init systems this tier does not reach.

**And a VM is a process, which is the one way it is kinder than a container.**
`running-code.md` warns that an outer `timeout` bounds a wrapper and not a
container, because the container belongs to the daemon; qemu is a direct child,
so `timeout` does stop it, and it was seen to:
`terminating on signal 15 from pid ... (timeout)`. The discipline that still
applies is checking afterwards -- and `pgrep -f qemu-system` matches its own
command line, which is `running-code.md`'s self-matching watcher met again, so
`ps -C qemu-system-x86_64` is what answers. `pgrep -x` cannot be used either:
the name is longer than 15 characters and it says so.
