# 0265: A VM tier, for exactly what a namespace cannot do

Status: accepted; built and measured -- `make vm` boots a guest and runs a
payload in it, and `make vm-cluster` boots two to five on a shared wire. What
is left is named under "What this leaves": the nspawn tier and procd.
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

## What it took, and the shape of every failure on the way

**It works**, and the measured result is the tier's whole justification:

```text
kernel: 6.12.1-3-lts                  the host is 6.12.107
openrc: rc-status (OpenRC) 0.55.1     one of the three init systems shipped
module: mac80211_hwsim loaded         phys: phy0 phy1
module: hci_vhci loaded               vhci: present
module: pppoe loaded
VM-PAYLOAD-END rc=0
```

Two radios and a `/dev/vhci` inside a guest, in about ten seconds of boot.

**Four boots failed first, and three of them failed by succeeding.** That is
the shape worth keeping, because it is the one a harness cannot notice on its
own:

- the netboot initramfs given the ISO as media answered `Mounting boot media
  failed`; it is not built to mount a CD, and `alpine_dev=cdrom` changed
  nothing;
- the ISO through ISOLINUX, boot line sent as one `printf`, arrived
  **truncated mid-word** -- `boot: lts console=ttyS0,115200 ip=dhcp apk`;
- the same sent a character at a time with a pause arrived with its **head**
  eaten -- `boot: 15200 ip=dhcp apkovl=http://...` -- the prompt not yet
  existing when the typing began.

**The middle two then booted perfectly, having dropped the instruction that
was the point of sending them.** ISOLINUX polls the serial port and loses
characters at both ends, and no amount of sleeping fixes it: the start of the
line needs the prompt to exist and the end needs it to still be reading, and
nothing outside the guest can observe either. So nothing is typed. The kernel
and initramfs are booted directly and the command line is an argument, where
it cannot be misheard.

- the fourth boot fetched the overlay, built a root from the mirror, powered
  off in 10.3 seconds -- and said `Loading modules ...modprobe: can't change
  directory to '/lib/modules'`, which is this tier with its one reason
  removed. **`modloop` is not in the initramfs's own option list**, read out
  of the extracted `init` rather than guessed: `modloop=` on the command line
  reaches nothing. The squashfs is attached as a read-only disk and mounted by
  the wrapper instead, which needs no cooperation from the guest's init.

**And the payload ran on that fourth boot while printing nothing.** It was
detectable only because it powered the guest off, which nothing else does:
OpenRC's `local` service does not put its scripts' output on the serial port.
The wrapper redirects to `/dev/console` explicitly. That is why the harness
distinguishes *the payload never started* from *the payload failed* -- a guest
that dies before reaching the script must not read as a pass, and for one boot
it did.

**One payload error is worth keeping too, because it reads as a missing
capability.** `modprobe vhci` reports `module vhci not found in modules.dep`.
The config symbol is `BT_HCIVHCI` and the module is `hci_vhci`; the name was
wrong and the message is indistinguishable from the feature being absent.

## What this leaves

**Driving the console is ruled out rather than untried**, per the above, and
the evidence is:

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

**The wire is built and the requirement on it was measured.** `make vm-cluster`
boots two to five guests on a qemu multicast socket -- a shared layer 2 segment
between N qemu processes, with no bridge, no tap and no privilege. Three
guests, every pair reachable:

```text
guest 1 of 3 at 10.42.0.1/24      peers: 2 of 2 reachable
guest 2 of 3 at 10.42.0.2/24      peers: 2 of 2 reachable
guest 3 of 3 at 10.42.0.3/24      peers: 2 of 2 reachable
```

**`localaddr=127.0.0.1` on that socket is a requirement, not a precaution**,
and it was measured by removing it and changing nothing else:

    with localaddr       3 packets transmitted, 0% packet loss
    without              3 packets transmitted, 100% packet loss

Unbound, the socket leaves by whatever interface the host's routing chooses and
the guests never see each other. **The run that first passed had changed two
things at once** -- this flag, and an iproute2-only `ip -4 -br` in the payload
that busybox answers with a usage message and an empty string -- so it said
nothing about which mattered. The control is what separates them, and
`evidence.md`'s rule is why it was taken rather than assumed.

The port is per-run, because two sessions on this machine would otherwise share
a segment and see each other's traffic; the MAC is per-index, because identical
MACs on one segment is a switch learning one address on every port, which looks
like the network dropping frames rather than like a configuration error.

**And the diagnostic payload reports rather than asserts, which is a trap worth
naming.** `wire.sh` prints packet counters and neighbour tables and does not
fail, so `run.sh` printed `ok, 2 guest(s)` for the control run in which the wire
was completely dead. That is correct for a diagnostic and is exactly the line
somebody quotes later as a pass, so it says so in its own header. `cluster.sh`
is the one that asserts, by comparing reachable peers against expected peers.

**The repository reaches the guest over a read-only 9p share**, so no image is
rebuilt in the loop: `repo /mnt/repo 9p ro,relatime,access=client,trans=virtio`,
28 entries at the root. Read-only on both sides -- qemu is told `readonly` and
so is the mount -- because a guest that could write there would be a test
editing the source it is testing.

### The one thing still blocking netcfgd's own tests, measured

**The host's binary cannot run in the guest, and the symptom does not say so.**
The host builds against glibc and the guest is musl:

```text
netcfgd: /mnt/repo/target/debug/netcfgd: not found
```

That is a file which plainly exists, reported as missing, because what is
missing is its interpreter -- `/lib64/ld-linux-x86-64.so.2`. Worth recording in
those words, because "not found" on an executable that is present reads as a
broken share rather than as a libc mismatch.

Only `x86_64-unknown-linux-gnu` is installed here; there is no musl target, and
`packaging/alpine/APKBUILD.in` builds with Alpine's own cargo *inside* Alpine,
so the existing Alpine packaging path offers no cross-build to borrow. Three
ways, none of them chosen here because the choice is the holder's:

- **Alpine guest, built inside it.** Needs nothing installed; minutes per run
  with no persistent cache, and the network for crates. It would exercise the
  musl build the APKBUILD produces and nothing currently checks.
- **Debian guest, host binary over the share.** Matches the development libc,
  so the existing live scripts run unmodified. Costs a Debian image and its own
  unattended-boot plumbing, which Alpine's apkovl gave cheaply.
- **A musl target on this host**, if Debian packages one -- one root action,
  then the Alpine guest runs the cross-built binary directly.

**`capability.sh` asserts, and its first version did not.** It ended with an
`echo`, so its status was that echo's and `make vm` would have reported a pass
with not one module loaded -- a gate over a capability it never checked, which
is the shape this tree keeps finding and which went into its own new harness
anyway. It counts failures and returns them now, and the assertion was watched
failing: a module name that cannot exist gives
`FAIL: not_a_real_module did not load` and `run.sh` exits 1.

It also checks that `mac80211_hwsim` **made a radio** rather than merely
loading, because a module can load and do nothing and a `modprobe` status
cannot see that -- and `phy0` is what `hwsim.sh` actually wants. Likewise
`/dev/vhci` as a device node rather than `hci_vhci` as a load, that node being
what `bluetooth.sh` opens.

**Deliberately not done here**: the nspawn tier, and procd -- which needs an
OpenWrt image rather than an Alpine one and is the one of the three init
systems this tier does not reach.

**And a VM is a process, which is the one way it is kinder than a container.**
`running-code.md` warns that an outer `timeout` bounds a wrapper and not a
container, because the container belongs to the daemon; qemu is a direct child,
so `timeout` does stop it, and it was seen to:
`terminating on signal 15 from pid ... (timeout)`. The discipline that still
applies is checking afterwards -- and `pgrep -f qemu-system` matches its own
command line, which is `running-code.md`'s self-matching watcher met again, so
`ps -C qemu-system-x86_64` is what answers. `pgrep -x` cannot be used either:
the name is longer than 15 characters and it says so.
