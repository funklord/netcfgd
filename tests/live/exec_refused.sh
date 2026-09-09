#!/bin/sh
# The four ways a program netcfgd runs does not run, and what it says about each.
#
#     sh tests/live/exec_refused.sh      # needs its own network namespace
#
# WHY THIS EXISTS
#   The third of the three audits (0180 writes, 0181 reads, 0182 execs). The
#   exec side turned out to be sound -- every one of the sixteen sites waits,
#   reads the status and reports with a message naming the program -- so this
#   script exists to keep it that way, and to hold the one thing that was
#   missing: `Permission denied` is two different faults with the same four
#   words from the kernel.
#
#     * a program with no executable bit, which is a `chmod`;
#     * a program that has one, on a filesystem mounted `noexec`, which is a
#       mount option and which no `chmod` will ever touch.
#
#   The second is decision 0178 one layer up: systemd has mounted `/run`
#   `noexec` since v256, netcfgd wrote a hook there, dhcpcd could not execute
#   it, and the journal said `script_runreason: Permission denied` 1,350 times
#   while netcfgd reported success. That took a day to find with the answer
#   sitting in a mount table, which is why the message now says which.
#
# WHAT IT DRIVES
#   A real `ncfg apply` for an interface asking for DHCP, with `PATH` pointed
#   at a directory this script controls, four times over.
#
# WHAT IT DELIBERATELY DOES NOT COVER
#   Whether netcfgd finds the right client -- `dhcpcd.sh` and `dhcp.sh` drive
#   the clients themselves. Here the client is a stub that exits 0, because
#   the subject is the exec and not the lease.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "exec_refused.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "exec_refused.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

# Its own network namespace, refused rather than assumed: this makes an
# interface, and a script that makes interfaces must not do it on the real
# network. `switch_network.sh` left two behind by being run bare.
if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
	skip "this makes an interface and must not do it on the machine's own network; run it under \`unshare -rn\`, as the Makefile does"
fi

# A mount namespace as well, for the `noexec` case, made here for `hooks.sh`'s
# reason: the Makefile gives user and network and no mount.
if [ -z "${NCFG_EXEC_NS:-}" ]; then
	NCFG_EXEC_NS=1
	export NCFG_EXEC_NS
	if unshare -m true 2>/dev/null; then
		exec unshare -m -- sh "$0" "$@"
	fi
	skip "no mount namespace, so a noexec filesystem cannot be made"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-exec.XXXXXX")
cleanup() {
	umount "$work/noexec" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc" "$work/run" "$work/bin" "$work/noexec"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_RESOLV_CONF="$work/resolv.conf"
ncfg="$repo/target/debug/ncfg"

failures=0
contains() {
	case "$2" in
	*"$3"*) echo "ok   $1" ;;
	*)
		echo "FAIL $1"
		echo "       expected to contain: $3"
		echo "       actual:              $2"
		failures=$((failures + 1))
		;;
	esac
}
missing() {
	case "$2" in
	*"$3"*)
		echo "FAIL $1"
		echo "       expected NOT to contain: $3"
		echo "       actual:                  $2"
		failures=$((failures + 1))
		;;
	*) echo "ok   $1" ;;
	esac
}

ip link add exec0 type dummy 2>/dev/null || skip "cannot make a dummy interface"

cat > "$work/etc/netcfgd.conf" <<CONF
interface exec0 {
	config = "dhcp"
}
CONF

apply_with_path() {
	PATH="$1" "$ncfg" apply > "$work/apply.log" 2>&1 || true
	cat "$work/apply.log"
}

# ------------------------------------------------------ not installed at all

said=$(apply_with_path "$work/bin")
contains "no client on PATH says which packages would provide one" \
	"$said" "install dhcpcd, udhcpc or busybox"

# ------------------------------------------------- there, with no exec bit

printf '#!/bin/sh\nexit 0\n' > "$work/bin/dhcpcd"
chmod 0644 "$work/bin/dhcpcd"
said=$(apply_with_path "$work/bin")
contains "a client that is there but not executable is not reported as absent" \
	"$said" "could not run dhcpcd"
missing "and it does not tell the operator to install what they already have" \
	"$said" "install dhcpcd, udhcpc or busybox"
contains "it names the mode it found" "$said" "0644"
contains "and says what is missing from it" "$said" "no executable bit"

# ------------------------------------------------ there, on a noexec mount

chmod 0755 "$work/bin/dhcpcd"
mount -t tmpfs -o noexec tmpfs "$work/noexec" || skip "cannot make a noexec filesystem"
cp "$work/bin/dhcpcd" "$work/noexec/dhcpcd"
chmod 0755 "$work/noexec/dhcpcd"
said=$(apply_with_path "$work/noexec")
contains "an executable client refused anyway names the file" "$said" "noexec/dhcpcd"
contains "and points at the mount rather than the mode" "$said" "noexec"
missing "and does not send the operator to chmod something already executable" \
	"$said" "no executable bit"
umount "$work/noexec"

# ------------------------------------------------------- ran, and failed

printf '#!/bin/sh\necho "dhcpcd: something went wrong" >&2\nexit 3\n' > "$work/bin/dhcpcd"
chmod 0755 "$work/bin/dhcpcd"
said=$(apply_with_path "$work/bin")
contains "a client that runs and fails is reported by its status" "$said" "exited with"
contains "and the status is the one it exited with" "$said" "3"
missing "and that is not confused with being unable to run it" \
	"$said" "could not run dhcpcd"

# --------------------------------------------------------------- the control

# Everything above is a refusal, and a suite of refusals proves nothing unless
# the same path succeeds when it should: an apply that cannot start a client
# for *any* reason would satisfy every check above.
printf '#!/bin/sh\nexit 0\n' > "$work/bin/dhcpcd"
chmod 0755 "$work/bin/dhcpcd"
rc=0
PATH="$work/bin" "$ncfg" apply > "$work/apply-ok.log" 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then
	echo "ok   a client that runs and succeeds is not a failure"
else
	echo "FAIL a client that runs and succeeds is not a failure"
	sed 's/^/       /' "$work/apply-ok.log"
	failures=$((failures + 1))
fi

if [ "$failures" -eq 0 ]; then
	echo "exec_refused.sh: all checks passed"
else
	echo "exec_refused.sh: $failures check(s) failed"
	exit 1
fi
