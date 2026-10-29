#!/bin/sh
# What the kernel answers when it cannot do what netcfgd asks, and what netcfgd
# says about it.
#
# **The directory is named for NAT and the subject is the capability layer.**
# NAT came first and decisions 0291 and 0292 cite this path, which is why the
# name stayed when the queuing states arrived: a renamed rig would leave two
# accepted records pointing at nothing. Everything here is one question --
# netcfgd asks a kernel for a construct it does not have, and an operator has
# to be able to act on the sentence that comes back.
#
# Six measuring states and four controls: no `nat` chain type, no masquerade,
# no nftables at all, no `cake`, ingress shaping with no `ifb`, and ingress
# shaping with the `ifb` there and the filter path gone -- against a kernel
# that can do NAT, one that can do `cake`, a check that autoload is really
# blocked, and a check that it can be unblocked again. Each state loads exactly the modules it is
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
# The smallest config that plans a `nftables.replace`: one uplink that translates.
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

# The queuing half of the same question (0283's other layer). `cake` is a
# module here where `fq_codel` and `pfifo_fast` are built in, so it is the
# scheduler this rig can take away; ingress shaping adds an `ifb-` device with
# `cls_matchall` and `act_mirred` behind it, all three of them modules.
cat > "$work/with-qdisc.conf" <<'CONF'
device wan0 {
	kind   = "dummy"
	qdisc {
		kind      = "cake"
		bandwidth = "100mbit"
	}
}
interface wan0 {
	config = "10.9.9.2/24"
}
CONF
cat > "$work/with-ingress.conf" <<'CONF'
device wan0 {
	kind   = "dummy"
	qdisc {
		kind              = "cake"
		bandwidth         = "40mbit"
		ingress_bandwidth = "90mbit"
	}
}
interface wan0 {
	config = "10.9.9.2/24"
}
CONF

# **WireGuard, which is a capability with no sentence at all today.** It is a
# module here (`CONFIG_WIREGUARD=m`), netcfgd reaches it by resolving a generic
# netlink family, and an absent module means an absent family -- so this state
# measures what an operator is told when a kernel cannot do WireGuard.
cat > "$work/with-wg.conf" <<'CONF'
device wg0 {
	wireguard {
		private_key = "@secret:wgtest"
		listen_port = 51820
		peer "far" {
			public_key  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
			allowed_ips = ["10.9.0.0/24"]
		}
	}
}
interface wg0 {
	config = "10.9.0.2/24"
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
	# The ifb device an ingress state leaves behind holds `ifb` and, through
	# its filter, `act_mirred` -- so an unload before this fails and the next
	# state runs with the module it was told to do without.
	ip link del ifb-wan0 2>/dev/null
	out=$(modprobe -r nft_masq nft_chain_nat nft_nat nf_tables nfnetlink \
		sch_cake sch_ingress cls_matchall act_mirred ifb 2>&1) ||
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
check "  and the plan carried the op this rig is about" "$(said 'nftables.replace')" yes

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
# `nftables.replace`, and the apply then says nothing about the kernel while looking
# like a result.
check "  the plan did contain the nftables.replace, so this measured something" "$(said 'nftables.replace')" yes
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
check "  with the nftables.replace in the plan" "$(said 'nftables.replace')" yes
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

# --- the queuing half: a scheduler this kernel does not have --------------
echo
echo "--- a kernel that can do cake, which is the control for the two below"
teardown
load dummy sch_cake
allow
state_q() {
	printf '     state: sch_cake=%s cls_matchall=%s act_mirred=%s ifb=%s autoload=%s\n' \
		"$(loaded sch_cake)" "$(loaded cls_matchall)" "$(loaded act_mirred)" \
		"$(loaded ifb)" "$(cat /proc/sys/kernel/modprobe)"
}
state_q
if apply_now "$work/with-qdisc.conf"; then rc=0; else rc=$?; fi
sed 's/^/     /' "$work/apply.log"
check "a kernel with the scheduler sets the qdisc" "$rc" 0
check "  and the plan carried the op" "$(said 'qdisc.set')" yes

echo
echo "--- cake asked for, with sch_cake unreachable"
teardown
load dummy
block
state_q
if apply_now "$work/with-qdisc.conf"; then rc=0; else rc=$?; fi
sed 's/^/     /' "$work/apply.log"
check "a kernel without the scheduler refuses the qdisc" \
	"$([ "$rc" -ne 0 ] && echo refused || echo applied)" refused
check "  with the qdisc.set in the plan, so this measured something" \
	"$(said 'qdisc.set')" yes
check "  and the sentence names the scheduler asked for" "$(said 'cake')" yes
check "  with the module it comes from" "$(said 'sch_<kind>')" yes
check "  and the option that selects it" "$(said 'CONFIG_NET_SCH_CAKE')" yes
check "  on the message the kernel refused" "$(said 'RTM_NEWQDISC')" yes

# --- ingress shaping, whose three modules are separate from the scheduler -
echo
echo "--- ingress shaping with cake present and the filter path unreachable"
teardown
load dummy sch_cake
block
state_q
if apply_now "$work/with-ingress.conf"; then rc=0; else rc=$?; fi
sed 's/^/     /' "$work/apply.log"
check "a kernel with no filter path refuses ingress shaping" \
	"$([ "$rc" -ne 0 ] && echo refused || echo applied)" refused
# Which op fails first is the measurement, not an assumption: the `ifb-`
# device, the ingress qdisc on it, the matchall filter and the mirred action
# are four separate kernel objects and any of them can be the one missing.
printf '     first failure: %s\n' \
	"$(awk '/^(FAIL|netcfgd: .*Error)/ { print; exit }' "$work/apply.log")"
check "  the ifb device is what it stops at, before any filter" \
	"$(said 'could not create ifb-wan0')" yes
check "  and the sentence names the kind's module rather than the errno alone" \
	"$(said 'ifb` for ingress shaping')" yes
# **The thing 0293 changed, asserted from the outside.** This check used to
# say the opposite: the plan died at action 0 and the address on wan0 -- which
# has nothing to do with shaping -- was never applied, seven actions skipped
# behind a feature nothing else depended on. An optional action's failure is
# its own now, so the address applies and the shaping is red.
check "  the address applies anyway, which is what 0293 changed" \
	"$(said 'ok   addr.add wan0')" yes
check "  nothing is skipped behind the shaping" "$(said 'skip ')" no
check "  and the failed action is marked red rather than FAIL" \
	"$(said 'red  link.create ifb-wan0')" yes
check "  with the summary saying how many went unmet" "$(said 'unmet')" yes

echo
echo "--- ingress shaping with the ifb device available and the filter path not"
teardown
# The device and both qdiscs reachable, so the plan gets as far as the filter:
# `clsact` and `ingress` are `sch_ingress`, the shaper is `sch_cake`, and the
# mirror needs `cls_matchall` plus `act_mirred`, which stay unreachable.
load dummy sch_cake ifb sch_ingress
block
state_q
if apply_now "$work/with-ingress.conf"; then rc=0; else rc=$?; fi
sed 's/^/     /' "$work/apply.log"
check "a kernel with no filter or action refuses the redirect" \
	"$([ "$rc" -ne 0 ] && echo refused || echo applied)" refused
check "  on RTM_NEWTFILTER, which is the step that needs them" \
	"$(said 'RTM_NEWTFILTER')" yes
check "  naming both modules" \
	"$([ "$(said 'cls_matchall')" = yes ] && [ "$(said 'act_mirred')" = yes ] && echo yes || echo no)" yes
check "  and both options, which a kernel builder needs" \
	"$([ "$(said 'CONFIG_NET_CLS_MATCHALL')" = yes ] && [ "$(said 'CONFIG_NET_ACT_MIRRED')" = yes ] && echo yes || echo no)" yes
check "  with everything before it applied, which is what makes this the state \
the sentence is about" "$(said 'ok   qdisc.set ifb-wan0')" yes
printf '     first failure: %s\n' \
	"$(awk '/^(FAIL|netcfgd: .*Error)/ { print; exit }' "$work/apply.log")"

# --- wireguard, whose module this kernel can also be made to lack ---------
echo
echo "--- a wireguard device with the module unreachable"
teardown
load dummy
block
printf '     state: wireguard=%s autoload=%s\n' "$(loaded wireguard)" \
	"$(cat /proc/sys/kernel/modprobe)"
# The secret the config names, so the refusal is the kernel's and not a
# missing-key refusal from the compiler.
mkdir -p "$work/etc/secrets"
printf '%s\n' "4GEnJDaZ0/Ie7VCXCbCJ2ZoFhIRNiZH4ZHTPDKrFVVM=" > "$work/etc/secrets/wgtest"
chmod 0600 "$work/etc/secrets/wgtest"
if apply_now "$work/with-wg.conf"; then rc=0; else rc=$?; fi
sed 's/^/     /' "$work/apply.log"
check "a kernel with no wireguard refuses the device" \
	"$([ "$rc" -ne 0 ] && echo refused || echo applied)" refused
printf '     first failure: %s\n' \
	"$(awk '/^(FAIL|red |netcfgd: .*Error)/ { print; exit }' "$work/apply.log")"

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
