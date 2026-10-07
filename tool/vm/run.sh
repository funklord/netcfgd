#!/bin/sh
# Boot a guest, run a script in it, and bring back what it said.
#
#     sh tool/vm/run.sh tool/vm/payload/capability.sh        # one guest
#     sh tool/vm/run.sh tool/vm/payload/cluster.sh 3         # three, on a wire
#
# TERMINATION, because this starts a virtual machine and a web server.
#   The guest runs under `timeout $VM_TIMEOUT` (default 180) and qemu is a
#   direct child, so the signal reaches it -- unlike a container, which belongs
#   to its daemon and survives an outer timeout. The payload's last act is
#   `poweroff`, so the ordinary exit is the guest's own. The HTTP server is
#   killed by the EXIT trap, by pid, and the work directory goes with it.
#   Verified afterwards with `ps -C qemu-system-x86_64`: `pgrep -f qemu-system`
#   matches its own command line, and `pgrep -x` cannot match a name longer
#   than fifteen characters and says so.
#
# HOW THE PAYLOAD GETS IN, AND WHY NOT THROUGH THE CONSOLE
#   Through an apkovl -- Alpine's own overlay -- fetched over HTTP from a server
#   on this machine, which the guest reaches at the user-net gateway 10.0.2.2.
#   `init` in the initramfs takes `apkovl=` as a URL and wgets it (`is_url`
#   accepts http), and OpenRC's `local` service runs what the overlay drops in
#   `/etc/local.d`.
#
#   **Driving the console instead does not work, and the reason is worth
#   keeping.** qemu buffers its stdin into one serial port while the consumer
#   of that port changes underneath it. Feeding a boot line, a login and then
#   commands produced:
#
#       localhost login: tyS0,115200 quiet
#       Password:
#       Login incorrect
#
#   ISOLINUX had taken `lts console=t` and the remainder arrived at a login
#   prompt that did not exist when it was written. A single input stream with a
#   changing reader cannot be driven blind, and sleeping longer only moves
#   which consumer gets which fragment. So exactly one line is typed -- the
#   boot line, at a prompt that waits for it -- and everything else arrives
#   through the overlay. Any fragment that leaks lands at the login prompt and
#   costs a failed login, which nothing depends on.
#
# WHY THE ISO RATHER THAN -kernel/-initrd
#   Full control of the command line is tempting and costs the modules. The
#   initramfs does not fetch the modloop; it adds `modloop` as a sysinit
#   service and the booted system finds the squashfs on its media. The ISO
#   carries it, and the modules are the whole reason this tier exists (0265).
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
store=${VM_DIR:-$HOME/vm}
payload=${1:-}
count=${2:-${VM_COUNT:-1}}
timeout_s=${VM_TIMEOUT:-180}
repo_url=${VM_REPO:-http://dl-cdn.alpinelinux.org/alpine/v3.21/main}

die() {
	echo "run: $1" >&2
	exit 1
}

[ -n "$payload" ] || die "usage: run.sh <payload.sh> [count]"
case "$count" in
1 | 2 | 3 | 4 | 5) ;;
*) die "count is 1 to 5, not \`$count'" ;;
esac
[ -f "$payload" ] || die "no such payload: $payload"
for f in vmlinuz-lts initramfs-lts modloop-lts; do
	[ -f "$store/alpine-3.21.0-x86_64/boot/$f" ] ||
		die "no $f in $store; run tool/vm/fetch.sh first"
done
for tool in qemu-system-x86_64 python3 tar; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
done
# Refused rather than run slowly. Without KVM this is software emulation, and
# a tier whose whole justification is running a second kernel is not worth
# twenty minutes a boot -- the honest answer is to say why it cannot run.
[ -w /dev/kvm ] || die "/dev/kvm is not writable, so this would emulate rather than virtualise"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-vm.XXXXXX")
server=
cleanup() {
	[ -n "$server" ] && kill "$server" 2>/dev/null
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

# The overlay: the payload, and the runlevel symlink that makes OpenRC run it.
mkdir -p "$work/ovl/etc/local.d" "$work/ovl/etc/runlevels/default"
# **Everything goes to /dev/console explicitly, because OpenRC swallows it.**
# The first working boot ran the payload -- it powered the guest off, and
# nothing else does -- and printed not one of its lines, because the `local`
# service's output does not reach the serial port. So the wrapper redirects to
# the console device rather than trusting the service's stdout.
#
# **And the modules are mounted here rather than asked for.** The initramfs's
# own option list does not contain `modloop`, so `modloop=` on the command line
# reaches nothing: the first boot fetched the overlay, built a root from the
# mirror, and then said
#
#     Loading modules ...modprobe: can't change directory to '/lib/modules'
#
# which is this tier with its one reason removed. The squashfs is attached as a
# read-only disk instead and mounted the way Alpine's own service would, which
# needs no cooperation from the guest's init at all.
{
	echo '#!/bin/sh'
	echo '# Written by tool/vm/run.sh.'
	echo 'exec > /dev/console 2>&1'
	echo '# Which guest this is, from the command line, so one payload can'
	echo '# serve every member of the cluster.'
	echo 'VM_INDEX=$(sed -n "s/.*vm_index=\\([0-9]*\\).*/\\1/p" /proc/cmdline)'
	echo 'VM_COUNT=$(sed -n "s/.*vm_count=\\([0-9]*\\).*/\\1/p" /proc/cmdline)'
	echo 'export VM_INDEX VM_COUNT'
	echo 'mkdir -p /.modloop /lib/modules'
	echo 'if mount -t squashfs -o ro /dev/vda /.modloop 2>/dev/null; then'
	echo '	mount --bind /.modloop/modules /lib/modules 2>/dev/null ||'
	echo '		ln -sfn /.modloop/modules/* /lib/modules/ 2>/dev/null'
	echo 'fi'
	echo '# The repository, read-only, so a payload can reach the tree it is'
	echo '# testing without an image being rebuilt. Read-only on both sides:'
	echo '# qemu is told readonly and so is the mount, because a guest that'
	echo '# could write here would be a test editing the source it is testing.'
	echo 'mkdir -p /mnt/repo'
	echo 'modprobe 9pnet_virtio 2>/dev/null'
	echo 'mount -t 9p -o trans=virtio,version=9p2000.L,ro repo /mnt/repo 2>&1 ||'
	echo '	echo "9p: the repository did not mount"'
	echo '# The markers are what the host greps for: a payload that dies'
	echo '# silently must not read as one that passed.'
	echo 'echo "VM-PAYLOAD-BEGIN"'
	cat "$payload"
	echo 'status=$?'
	echo 'echo "VM-PAYLOAD-END rc=$status"'
	echo 'poweroff'
} > "$work/ovl/etc/local.d/payload.start"
chmod 0755 "$work/ovl/etc/local.d/payload.start"
ln -s /etc/init.d/local "$work/ovl/etc/runlevels/default/local"

( cd "$work/ovl" && tar -czf "$work/test.apkovl.tar.gz" . )

# Bound to loopback: the guest reaches it through the user-net gateway, and
# nothing else on the network can. Port 0 lets the kernel choose, so two runs
# do not collide.
python3 -c '
import http.server, socketserver, sys, threading, os
os.chdir(sys.argv[1])
class Quiet(http.server.SimpleHTTPRequestHandler):
	def log_message(self, *a):
		pass
httpd = socketserver.TCPServer(("127.0.0.1", 0), Quiet)
print(httpd.server_address[1], flush=True)
httpd.serve_forever()
' "$work" > "$work/port" 2>"$work/server.log" &
server=$!

# Wait for the port rather than sleeping a guess at it: the server prints it
# once it is bound, so an empty file means not yet listening.
waited=0
while [ ! -s "$work/port" ]; do
	waited=$((waited + 1))
	[ "$waited" -gt 100 ] && die "the overlay server never bound a port"
	sleep 0.1
done
port=$(cat "$work/port")

echo "run: serving the overlay on 127.0.0.1:$port"
echo "run: booting, up to ${timeout_s}s"

# **Nothing is typed, and two attempts at typing are why.**
# ISOLINUX reads the serial port by polling, and it loses characters at both
# ends. Sent as one `printf` the line arrived truncated mid-word:
#
#     boot: lts console=ttyS0,115200 ip=dhcp apk
#
# Sent a character at a time with a pause, the tail arrived whole and the
# HEAD was eaten, because the prompt was not ready when the typing began:
#
#     boot: 15200 ip=dhcp apkovl=http://10.0.2.2:41283/... quiet
#
# Both boots then SUCCEEDED, having dropped the instruction that was the
# point -- which is the worst shape a failure can take. There is no sleep that
# fixes it: the start of the line needs the prompt to exist and the end of it
# needs the prompt to still be reading, and nothing on this side can see
# either. So the kernel and initramfs are booted directly and the command line
# is an argument, where it cannot be misheard.
#
# The cost is that the initramfs then has to be told everything the ISO's
# bootloader knew. `modloop=` is served from this machine out of the same
# directory as the overlay -- the file is already in the store, so it is a
# symlink and not a copy -- and `alpine_repo` points at the mirror, which the
# guest reaches through user-net's NAT.
# **The wire between guests is a multicast socket**, which is a shared L2
# segment between N qemu processes with no bridge, no tap and no privilege --
# and `localaddr=127.0.0.1` on it is a requirement rather than a precaution,
# measured by removing it and changing nothing else:
#
#     with localaddr      3 packets transmitted, 0% packet loss
#     without             3 packets transmitted, 100% packet loss
#
# Unbound, the socket leaves by whatever interface the host's routing chooses
# and the guests never see each other. The first passing run had changed two
# things at once -- this flag and a busybox incompatibility in the payload --
# so it said nothing about which mattered; this is the one-variable control.
#
# so the "two to five machines" this tier was asked for costs nothing beyond
# the guests themselves. The port is per-run, because two sessions on this
# machine would otherwise share a segment and see each other's traffic.
#
# Each guest keeps user-net as its first NIC, for the overlay fetch and the
# mirror, and the wire is its second. The MAC is per-index: identical MACs on
# one segment is a switch learning the same address on every port, which looks
# like the network dropping frames rather than like a configuration error.
mcast_port=$(( 20000 + $$ % 20000 ))
pids=
rc=0
i=1
while [ "$i" -le "$count" ]; do
	timeout "$timeout_s" qemu-system-x86_64 \
		-enable-kvm -m 1024 -smp 2 -nographic -no-reboot \
		-kernel "$store/alpine-3.21.0-x86_64/boot/vmlinuz-lts" \
		-initrd "$store/alpine-3.21.0-x86_64/boot/initramfs-lts" \
		-append "console=ttyS0,115200 ip=dhcp quiet \
modules=loop,squashfs,virtio_net,virtio_pci,virtio_blk \
alpine_repo=$repo_url \
vm_index=$i vm_count=$count \
apkovl=http://10.0.2.2:$port/test.apkovl.tar.gz" \
		-netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
		-netdev socket,id=lan,mcast=230.0.0.42:$mcast_port,localaddr=127.0.0.1 \
		-device virtio-net-pci,netdev=lan,mac=52:54:00:12:34:0$i \
		-drive file="$store/alpine-3.21.0-x86_64/boot/modloop-lts",format=raw,if=virtio,readonly=on \
		-virtfs local,path="$repo",mount_tag=repo,security_model=none,readonly=on \
		< /dev/null > "$work/console.$i.log" 2>&1 &
	pids="$pids $!"
	i=$((i + 1))
done

echo "run: $count guest(s) booting, up to ${timeout_s}s, wire on port $mcast_port"

# Every guest is waited for, and the first non-zero status is kept rather than
# the last: `wait` without this reports whichever finished last, so a failing
# guest beside a passing one would be reported as a pass.
for pid in $pids; do
	wait "$pid" || rc=$?
done

# **Under the build directory, not at the repo root.** The first version wrote
# `$repo/vm-console.log`, which drops an untracked file in the tree on every
# run -- a line in `git status` that nobody put there, which is how a blanket
# `git add` sweeps up something nobody meant to commit. `build/` is already
# ignored, so this costs no ignore rule and leaves the tree as it was found.
# `target/` because it is the one directory `.gitignore` covers at the root --
# `build/` is NOT ignored in this tree, only `gui/build/` and `dist/` are, so
# defaulting there would have reintroduced the untracked file by a new route.
# Checked with `git check-ignore` rather than assumed from the name.
out=${VM_LOG:-$repo/target/vm-console.log}
mkdir -p "$(dirname "$out")"
: > "$out"
failed=0
i=1
while [ "$i" -le "$count" ]; do
	# The console log is kept whole and read from a file, never piped into a
	# reducer: `evidence.md`'s rule, and the only run whose output matters is
	# the one that failed.
	printf '===== guest %s =====\n' "$i" >> "$out"
	tr -d '\r' < "$work/console.$i.log" |
		sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' >> "$out"

	if ! grep -q "VM-PAYLOAD-BEGIN" "$work/console.$i.log"; then
		echo "run: guest $i never reached the payload" >&2
		failed=1
	elif ! grep -q "VM-PAYLOAD-END rc=0" "$work/console.$i.log"; then
		echo "run: guest $i ran the payload and it failed" >&2
		failed=1
	fi
	tr -d '\r' < "$work/console.$i.log" |
		sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' |
		sed -n '/VM-PAYLOAD-BEGIN/,/VM-PAYLOAD-END/p' |
		sed "s/^/run: $i   /"
	i=$((i + 1))
done

if [ "$failed" -ne 0 ]; then
	echo "run: the whole console of every guest is in $out (qemu exited $rc)" >&2
	exit 1
fi
echo "run: ok, $count guest(s), and the consoles are in $out"
