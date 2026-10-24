#!/bin/sh
# What the kernel answers when it cannot do NAT, and what netcfgd says about it.
#
# Four states and two controls. Each state loads exactly the modules it is
# named for and then blocks autoload, so the construct netcfgd asks for is
# unreachable; the apply that follows is the measurement, and the checks hold
# netcfgd's sentence to what the kernel actually said.
#
# WHAT THIS FOUND, AND WHY IT IS A RIG RATHER THAN A SESSION'S NOTE
#   `ncfg_kernel_hint`'s NAT arm was written keyed on `ENOENT` and
#   `EOPNOTSUPP` together, because 0283 and 0287 both reasoned about
#   `EOPNOTSUPP` and no developer machine can produce either -- the modules are
#   there. Measured here 2026-10-24, kernel 6.12: `ENOENT` for both states,
#   `EOPNOTSUPP` for neither, so the second arm was an untested guess. The same
#   run showed `ENOENT` cannot distinguish a missing module from a table that
#   vanished mid-apply, which is why nftables messages have names now.
#
# TERMINATION
#   No unbounded loop. Each attempt starts one daemon, waits at most six
#   seconds for its socket, and kills it by pid; there are seven attempts
#   including the teardowns, and nothing is left running.
set -u
build=${NCFG_LIVE_BUILD:-/repo/c}
echo "=== guest: uid $(id -u), kernel $(uname -r)"
PATH=/usr/sbin:/sbin:/usr/local/sbin:$PATH
export PATH

failures=0
check() {
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1"
		echo "       expected: $3"
		echo "       actual:   $2"
		failures=$((failures + 1))
	fi
}

for needed in "$build/netcfgd" "$build/ncfg"; do
	[ -x "$needed" ] || {
		echo "natcap: $needed is not there. This rig runs the host-built" >&2
		echo "natcap:   binaries from the share; run \`make -C c\` first." >&2
		exit 1
	}
done
command -v modprobe >/dev/null || { echo "natcap: no modprobe in this image" >&2; exit 1; }

work=$(mktemp -d /tmp/natcap.XXXXXX)
export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
mkdir -p "$work/etc" "$work/run"
# The smallest config that plans a `nat.replace`: one uplink that translates.
cat > "$work/with-nat.conf" <<'CONF'
device wan0 {
	kind   = "dummy"
}
interface wan0 {
	config = "10.9.9.2/24"
	nat    = true
}
CONF
# The same without it, which is what takes the table away again between states.
cat > "$work/no-nat.conf" <<'CONF'
device wan0 {
	kind   = "dummy"
}
interface wan0 {
	config = "10.9.9.2/24"
}
CONF

loaded() { lsmod | awk -v m="$1" '$1 == m { f = 1 } END { print (f ? "yes" : "no") }'; }
allow() { echo /sbin/modprobe > /proc/sys/kernel/modprobe; }
block() { echo /nonexistent/modprobe > /proc/sys/kernel/modprobe; }

# **One module per call, and never silently.** `modprobe dummy nf_tables` reads
# `nf_tables` as a PARAMETER of `dummy` and loads neither -- which is how two
# states of the first draft of this ran with no nf_tables at all while their
# labels said otherwise, and the complaint went to /dev/null.
load() {
	for m in "$@"; do
		out=$(modprobe "$m" 2>&1) || printf '    modprobe %s failed: %s\n' "$m" "$out"
	done
}

apply_now() {   # -> rc, with the output in $work/apply.log
	cp "$1" "$work/etc/netcfgd.conf"
	rm -f "$work/run/netcfgd.sock"
	"$build/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
	pid=$!
	waited=0
	while [ ! -e "$work/run/netcfgd.sock" ] && [ "$waited" -lt 60 ]; do
		waited=$((waited + 1))
		sleep 0.1
	done
	if [ ! -e "$work/run/netcfgd.sock" ]; then
		echo "    the daemon never started:"
		sed 's/^/      /' "$work/daemon.log"
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
		return 125
	fi
	"$build/ncfg" apply > "$work/apply.log" 2>&1
	rc=$?
	kill "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null
	return "$rc"
}

# Back to a machine netcfgd owns nothing on, while autoload still works -- the
# table and the device hold module references, so an unload before this fails
# and every later state silently runs with everything loaded.
teardown() {
	allow
	apply_now "$work/no-nat.conf" >/dev/null 2>&1 || true
	ip link del wan0 2>/dev/null
	out=$(modprobe -r nft_masq nft_chain_nat nft_nat nf_tables nfnetlink 2>&1) ||
		printf '    note: modprobe -r said: %s\n' "$out"
}

said() { grep -q -- "$1" "$work/apply.log" && echo yes || echo no; }

state() {
	printf '     state: nf_tables=%s nft_chain_nat=%s nft_masq=%s autoload=%s\n' \
		"$(loaded nf_tables)" "$(loaded nft_chain_nat)" "$(loaded nft_masq)" \
		"$(cat /proc/sys/kernel/modprobe)"
}

# --- the control that the rig can pass at all ----------------------------
echo
echo "--- a kernel that can do NAT"
allow
load dummy
state
if apply_now "$work/with-nat.conf"; then rc=0; else rc=$?; fi
sed 's/^/     /' "$work/apply.log"
check "a kernel with the modules applies NAT" "$rc" 0
check "  and the plan carried the op this rig is about" "$(said 'nat.replace')" yes

# --- no `nat` chain type -------------------------------------------------
echo
echo "--- nf_tables, with no nft_chain_nat and no nft_masq"
teardown
load dummy nf_tables
block
state
if apply_now "$work/with-nat.conf"; then rc=0; else rc=$?; fi
sed 's/^/     /' "$work/apply.log"
check "a kernel with no nat chain type refuses the apply" "$([ "$rc" -ne 0 ] && echo refused || echo applied)" refused
# **The vacuous pass this is most exposed to**: a converged machine plans no
# `nat.replace`, and the apply then says nothing about the kernel while looking
# like a result.
check "  the plan did contain the nat.replace, so this measured something" "$(said 'nat.replace')" yes
check "  the kernel's answer is ENOENT" "$(said 'ENOENT')" yes
check "  and not EOPNOTSUPP, which 0283 and 0287 both assumed" "$(said 'EOPNOTSUPP')" no
check "  the refused message is named, which is what says which step" \
	"$(said 'NFT_MSG_NEWCHAIN')" yes
check "  the sentence names the module that provides the chain type" \
	"$(said 'nft_chain_nat')" yes
check "  and the one that provides the masquerade" "$(said 'nft_masq')" yes
# **The config symbol as well as the module.** `nft_chain_nat.o` is built by
# `CONFIG_NFT_NAT` and no `CONFIG_NFT_CHAIN_NAT` exists, so a sentence naming
# only the module sends a kernel builder looking for a symbol that is not
# there. `tests/kernel/` is where that was found, by making the mistake.
check "  the config symbol too, which is not the module's name" \
	"$(said 'CONFIG_NFT_NAT')" yes

# --- the chain type, but no masquerade -----------------------------------
echo
echo "--- nf_tables and nft_chain_nat, with no nft_masq"
teardown
load dummy nf_tables nft_chain_nat
block
state
if apply_now "$work/with-nat.conf"; then rc=0; else rc=$?; fi
sed 's/^/     /' "$work/apply.log"
check "a kernel with no masquerade refuses the apply" "$([ "$rc" -ne 0 ] && echo refused || echo applied)" refused
check "  with the nat.replace in the plan" "$(said 'nat.replace')" yes
check "  on ENOENT as well, so one code covers both faults" "$(said 'ENOENT')" yes
check "  and the message named is the rule's, not the chain's" \
	"$(said 'NFT_MSG_NEWRULE')" yes

# --- no nftables at all --------------------------------------------------
echo
echo "--- no nftables module of any kind"
teardown
load dummy
block
state
if apply_now "$work/with-nat.conf"; then rc=0; else rc=$?; fi
sed 's/^/     /' "$work/apply.log"
check "a kernel with no nf_tables refuses the apply" "$([ "$rc" -ne 0 ] && echo refused || echo applied)" refused
# A different arm entirely: the socket will not open, so `kernel_nat.c` says so
# and `ncfg_kernel_hint` is never reached. Checked here because an operator
# meets these two states the same way and the sentences must not be confusable.
check "  saying nf_tables itself is what is missing" "$(said 'cannot reach nftables')" yes
check "  with the socket's own errno rather than a transaction's" \
	"$(said 'Protocol not supported')" yes
check "  and no module-level hint, which would be the wrong advice here" \
	"$(said 'nft_chain_nat')" no

# --- the control on the instrument ---------------------------------------
echo
echo "--- the block itself"
teardown
modprobe -r dummy 2>/dev/null
block
# **Without this the whole rig can pass vacuously.** If autoload were not
# really blocked, every state above would have had every module and the
# refusals would have to come from somewhere else -- so prove the block by
# asking for a module nothing has loaded.
ip link add probe0 type dummy 2>"$work/iperr"
rc=$?
printf '     ip link add type dummy: rc=%s, %s\n' "$rc" "$(cat "$work/iperr")"
check "with autoload blocked, a module nothing loaded cannot arrive" \
	"$([ "$rc" -ne 0 ] && echo refused || echo created)" refused
[ "$rc" -eq 0 ] && ip link del probe0 2>/dev/null
allow
check "and allowing it again lets the same module load" \
	"$(modprobe dummy 2>&1 >/dev/null && echo loaded || echo failed)" loaded

rm -rf "$work"
echo
if [ "$failures" -gt 0 ]; then
	echo "natcap: $failures check(s) failed"
	exit 1
fi
echo "natcap: every check passed"
