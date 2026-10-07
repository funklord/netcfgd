#!/bin/sh
# Boot a guest, run a script in it, and bring back what it said.
#
#     sh tool/vm/run.sh tool/vm/payload/capability.sh
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
timeout_s=${VM_TIMEOUT:-180}
repo_url=${VM_REPO:-http://dl-cdn.alpinelinux.org/alpine/v3.21/main}

die() {
	echo "run: $1" >&2
	exit 1
}

[ -n "$payload" ] || die "usage: run.sh <payload.sh>"
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
	echo 'mkdir -p /.modloop /lib/modules'
	echo 'if mount -t squashfs -o ro /dev/vda /.modloop 2>/dev/null; then'
	echo '	mount --bind /.modloop/modules /lib/modules 2>/dev/null ||'
	echo '		ln -sfn /.modloop/modules/* /lib/modules/ 2>/dev/null'
	echo 'fi'
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
rc=0
timeout "$timeout_s" qemu-system-x86_64 \
	-enable-kvm -m 1024 -smp 2 -nographic -no-reboot \
	-kernel "$store/alpine-3.21.0-x86_64/boot/vmlinuz-lts" \
	-initrd "$store/alpine-3.21.0-x86_64/boot/initramfs-lts" \
	-append "console=ttyS0,115200 ip=dhcp quiet \
modules=loop,squashfs,virtio_net,virtio_pci,virtio_blk \
alpine_repo=$repo_url \
apkovl=http://10.0.2.2:$port/test.apkovl.tar.gz" \
	-netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
	-drive file="$store/alpine-3.21.0-x86_64/boot/modloop-lts",format=raw,if=virtio,readonly=on \
	< /dev/null \
	> "$work/console.log" 2>&1 || rc=$?

# The console log is kept whole and grepped afterwards, never piped into a
# reducer: `evidence.md`'s rule, and the only time the output matters is the
# run that failed.
out=${VM_LOG:-$repo/vm-console.log}
tr -d '\r' < "$work/console.log" | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' > "$out"

if ! grep -q "VM-PAYLOAD-BEGIN" "$out"; then
	echo "run: the payload never started -- the guest did not reach it" >&2
	echo "run: the whole console is in $out; its last lines were:" >&2
	tail -12 "$out" >&2
	exit 1
fi
sed -n '/VM-PAYLOAD-BEGIN/,/VM-PAYLOAD-END/p' "$out" | sed 's/^/run:   /'
if ! grep -q "VM-PAYLOAD-END rc=0" "$out"; then
	echo "run: the payload did not finish cleanly (qemu exited $rc)" >&2
	exit 1
fi
echo "run: ok, and the console is in $out"
