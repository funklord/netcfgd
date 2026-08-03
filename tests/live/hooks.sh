#!/bin/sh
# Hooks against a real kernel: materialised, hashed, and actually run.
#
# The fixture harness asserts what the *plan* says about a hook. What it cannot
# assert is that the script exists on disk with the name the config gave it, that
# it is executable, that the hash check passes against the file netcfgd itself
# wrote, and that the phase ordering holds when the actions really run -- four
# things that all live between the compiler and the executor.
#
# The down phases are the reason this exists now: `down` and `post_down` were
# recognised and never run until decision 0063, and the ordering that makes them
# useful is not the obvious one. Teardown is the *last* thing in a plan, so a
# `down` hook fires while the interface still has its addresses -- which is what
# lets it unmount a share or stop a service that is using them. This checks that
# by having the hook look.
#
# Runs under `unshare -rn`: it creates a dummy interface and brings it down.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "hooks.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "hooks.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

work=$(mktemp -d /tmp/ncfg-hooks.XXXXXX)
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/etc" "$work/run"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
ncfg="$repo/target/debug/ncfg"

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

# Each hook appends a line saying what it saw, so the file is a transcript of the
# order things happened in -- and of what the interface looked like at the time.
# `ip addr show` inside the hook is the check that matters for `down`: it says
# whether the address was still there when the script ran.
log=$work/transcript
write_config() {
	cat > "$work/etc/netcfgd.conf" <<CONF
interface hooked0 {
	kind    = "dummy"
	config  = "10.5.0.1/24"
	enabled = $1
	pre_up {
	echo "pre_up addresses=\$(ip -br addr show hooked0 | wc -w)" >> $log
	}
	post_up {
	echo "post_up addr=\$NCFG_ADDR iface=\$NCFG_IFACE phase=\$NCFG_PHASE" >> $log
	echo "post_up addresses=\$(ip -br addr show hooked0 | grep -c 10.5.0.1 || true)" >> $log
	}
	down {
	echo "down addresses=\$(ip -br addr show hooked0 | grep -c 10.5.0.1 || true)" >> $log
	echo "down up=\$(ip -br link show hooked0 | grep -c UP || true)" >> $log
	}
	post_down {
	echo "post_down up=\$(ip -br link show hooked0 | grep -c ' UP ' || true)" >> $log
	}
}
CONF
}

write_config true
if ! "$ncfg" apply > "$work/apply.log" 2>&1; then
	if grep -q 'Operation not permitted' "$work/apply.log"; then
		skip "no CAP_NET_ADMIN (run under unshare -rn)"
	fi
	echo "hooks.sh: apply failed" >&2
	cat "$work/apply.log" >&2
	exit 1
fi

# The materialised script, which is the thing the document only references.
hooks=$(find "$work/run/hooks" -type f 2>/dev/null | wc -l)
check "every hook is materialised under /run" "$hooks" "4"
for file in "$work/run/hooks"/*; do
	[ -x "$file" ] || {
		echo "FAIL a materialised hook is not executable: $file"
		failures=$((failures + 1))
	}
done

# The up half ran, in order, and `post_up` saw the address it was waiting for.
check "pre_up ran"  "$(grep -c '^pre_up ' "$log" || true)"  "1"
check "post_up ran" "$(grep -c '^post_up addr=' "$log" || true)" "1"
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
contains "and its environment names the interface and the phase" \
	"$(grep '^post_up addr' "$log")" "iface=hooked0 phase=post_up"
check "and the address was there by then" \
	"$(sed -n 's/^post_up addresses=//p' "$log")" "1"

# Now the half that did not exist before 0063.
: > "$log"
write_config false
plan=$("$ncfg" plan 2>&1 || true)
contains "an interface going down plans its down hook" "$plan" "hooks[down]"
contains "and its post_down hook"                      "$plan" "hooks[post_down]"
"$ncfg" apply > "$work/apply-down.log" 2>&1 || {
	cat "$work/apply-down.log" >&2
	exit 1
}

check "down ran"      "$(grep -c '^down ' "$log" || true)"      "2"
# And the *up* hooks did not, which is the other half of decision 0063: both were
# emitted unconditionally, so this apply used to run `pre_up`, `down`, `post_down`
# and `post_up` -- in that order, on an interface it was taking away.
check "and the up hooks did not run on the way down" \
	"$(grep -c '^pre_up \|^post_up ' "$log" || true)" "0"
check "post_down ran" "$(grep -c '^post_down ' "$log" || true)" "1"
# The ordering claim, checked by what the hook could see rather than by the plan:
# the address was still on the interface when `down` ran, and the link was still
# up. That is the property that makes a `down` hook useful, and it holds because
# teardown is the last thing in a plan.
check "the address was still there when down ran" \
	"$(sed -n 's/^down addresses=//p' "$log")" "1"
check "and the link was still up" \
	"$(sed -n 's/^down up=//p' "$log")" "1"
check "while post_down saw it down" \
	"$(sed -n 's/^post_down up=//p' "$log")" "0"

# A hook whose file has changed since the compile is not run, and that is a
# failure of the phase rather than a silent skip. `down` is a veto phase, so the
# apply stops -- a `down` script somebody edited under netcfgd is not one netcfgd
# should run while taking an interface away.
#
# **Reaching this needs the daemon and a drift**, which is the finding rather than
# an inconvenience. `ncfg apply` compiles and materialises the hooks microseconds
# before running them, so the hash it checks is of a file it has just written and
# cannot mismatch; and the daemon re-materialises whenever the *config* changes. The
# check therefore only has teeth where the plan comes from a **kernel** change
# against a document compiled earlier -- which is drift, and is exactly the case
# section 2.2 says the hash is for. Decision 0063.
: > "$log"
write_config false
"$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		cat "$work/daemon.log" >&2
		echo "hooks.sh: the daemon never started" >&2
		kill "$daemon" 2>/dev/null || true
		exit 1
	fi
	sleep 0.1
done

# The drift: somebody brings the interface up by hand, against a document that says
# it should be down. Now an apply has a `link.down` to plan and a `down` hook to run
# -- with no config change, so the daemon's materialised file is the one it wrote at
# startup and the tampering below survives.
ip link set hooked0 up
for file in "$work/run/hooks"/*.down.*; do
	echo "echo tampered >> $log" >> "$file"
done

tamper=$("$ncfg" apply --confirm-within 3 2>&1 || true)
# Before the revert, which undoes everything netcfgd has done including creating
# the interface: the interface is still up, because the veto stopped the apply
# before the `link.down` it was bracketing. A hook that cannot be trusted does not
# get to be the thing that takes an interface away quietly.
still=$(ip -br link show hooked0 2>&1)
"$ncfg" revert >/dev/null 2>&1 || true
kill "$daemon" 2>/dev/null || true
wait "$daemon" 2>/dev/null || true

contains "a tampered down hook is refused by hash" "$tamper" \
	"has changed since the configuration was compiled"
contains "and the transition it bracketed did not happen" "$still" "UP"
check "and the tampered line never ran" "$(grep -c tampered "$log" || true)" "0"

# ---------------------------------------------------------------------------
# The `lease` hook, which fires on an address netcfgd did not install. There is no
# DHCP server here and there does not need to be one: netcfgd never sees the
# protocol (0004), so what it reacts to is the address -- and an address put on the
# interface by something other than netcfgd is exactly what a client leaves behind.
# `ip addr add` is that something, and it is real kernel state rather than a fake.
#
# What this cannot check is a real client's timing, which is why the document says
# the first apply of a fresh interface does not fire it: the client is being started
# in that same plan and the address arrives seconds later.
: > "$log"
cat > "$work/etc/netcfgd.conf" <<CONF
interface leased0 {
	kind   = "dummy"
	# A static address beside the lease, so netcfgd's own address is on the same
	# interface: it sorts *before* the one the client adds, so a comparison that
	# forgot to exclude what netcfgd installed would pick this one and the
	# environment check below would say so. A SLAAC address would be the third case
	# and needs a real router advertisement -- the fixtures cover that one.
	config = "dhcp 10.9.9.9/24"
	on lease {
	echo "lease addr=\$NCFG_ADDR iface=\$NCFG_IFACE phase=\$NCFG_PHASE" >> $log
	}
}
CONF

# A stub client, because there is no dhcpcd on this machine and because what is
# under test is netcfgd's reaction to the *address*, not the protocol. netcfgd runs
# `dhcpcd -b -4 <iface>` and expects it to go into the background; a script that
# exits 0 is a client that got no lease, which is a state a real one passes through.
# The address below is what the client would have installed. Faking the client and
# not the protocol is the same line `fake_supplicant.py` draws.
mkdir -p "$work/bin"
cat > "$work/bin/dhcpcd" <<'STUB'
#!/bin/sh
exit 0
STUB
chmod +x "$work/bin/dhcpcd"
PATH="$work/bin:$PATH"
export PATH

ip link add leased0 type dummy
ip link set leased0 up
"$ncfg" apply > "$work/apply-lease.log" 2>&1 || true
check "no lease, no hook" "$(grep -c '^lease ' "$log" || true)" "0"

# What a client does: an address appears that netcfgd did not put there.
ip addr add 192.168.77.5/24 dev leased0
plan=$("$ncfg" plan 2>&1 || true)
contains "an address netcfgd did not install plans the lease hook" "$plan" \
	"hook.run leased0"
contains "and the reason names the address" "$plan" "lease: 192.168.77.5/24"
"$ncfg" apply > "$work/apply-lease2.log" 2>&1 || true
check "the lease hook ran"  "$(grep -c '^lease ' "$log" || true)" "1"
contains "and its environment carries the address" "$(grep '^lease ' "$log")" \
	"addr=192.168.77.5/24 iface=leased0 phase=lease"

# Once per lease, not once per reconcile. This is the check the /run record exists
# for, and the one that fails loudly if the record is not written.
"$ncfg" apply > /dev/null 2>&1 || true
"$ncfg" apply > /dev/null 2>&1 || true
check "and not again on the next two applies" "$(grep -c '^lease ' "$log" || true)" "1"

# And again when the lease moves, which is the other half of "once".
ip addr del 192.168.77.5/24 dev leased0
ip addr add 192.168.77.9/24 dev leased0
"$ncfg" apply > /dev/null 2>&1 || true
check "a changed lease fires it again" "$(grep -c '^lease ' "$log" || true)" "2"
contains "with the new address" "$(tail -1 "$log")" "addr=192.168.77.9/24"

echo
if [ "$failures" -eq 0 ]; then
	echo "hooks.sh: all checks passed"
else
	echo "hooks.sh: $failures failed"
	exit 1
fi
