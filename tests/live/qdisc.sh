#!/bin/sh
# Root qdiscs against a real kernel.
#
# The check that earns this file is the rate. `TCA_CAKE_BASE_RATE64` is bytes
# per second and every human-facing tool takes bits, so the conversion is a
# division by eight that nothing validates -- send bits and the kernel shapes
# at one eighth of what was asked for, which presents as a slow line rather
# than as a bug.
#
# netcfgd reading back its own number proves nothing about that, because a
# factor of eight wrong in both directions round-trips perfectly. So where
# tc(8) is installed, it is asked independently. That check is the reason the
# rest of this exists.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "qdisc.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "qdisc.sh: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"

tc=
for candidate in /sbin/tc /usr/sbin/tc; do
	[ -x "$candidate" ] && tc=$candidate && break
done
command -v tc >/dev/null 2>&1 && tc=$(command -v tc)

work=$(mktemp -d /tmp/ncfg-qdisc.XXXXXX)
daemon=
cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
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

# What netcfgd believes, from its own status output.
qdisc_of() {
	"$ncfg" status 2>/dev/null | awk -v want="$1" '
		/^[^ ]/ { iface = $1 }
		iface == want && $1 == "qdisc" { print $2; found = 1 }
		END { if (!found) print "<none>" }'
}

rate_of() {
	"$ncfg" status 2>/dev/null | awk -v want="$1" '
		/^[^ ]/ { iface = $1 }
		iface == want && $1 == "qdisc" && $3 == "at" { print $4; found = 1 }
		END { if (!found) print "<none>" }'
}

write_config() { cat > "$work/etc/netcfgd.conf"; }

apply() {
	if ! "$ncfg" apply > "$work/apply.log" 2>&1; then
		echo "FAIL apply: $1"
		cat "$work/apply.log"
		failures=$((failures + 1))
	fi
}

start_daemon() {
	"$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon.log" 2>&1 &
	daemon=$!
	waited=0
	while [ ! -e "$work/run/netcfgd.sock" ]; do
		waited=$((waited + 1))
		if [ "$waited" -gt 60 ]; then
			if grep -q 'Operation not permitted' "$work/daemon.log" 2>/dev/null; then
				skip "no CAP_NET_ADMIN (run under unshare -rn)"
			fi
			cat "$work/daemon.log" >&2
			echo "qdisc.sh: the daemon never started" >&2
			exit 1
		fi
		sleep 0.1
	done
}

# veth rather than dummy: a dummy has no transmit queue, so the kernel keeps it
# on `noqueue` and a scheduler set on it would be testing nothing.
write_config <<'CONF'
interface veth0 {
	veth   { peer = "veth1" }
	config = "10.7.0.1/24"
	qdisc  = "fq_codel"
}
CONF

start_daemon
apply "the first apply"
check "the named scheduler is installed" "$(qdisc_of veth0)" "fq_codel"

# Idempotence, against the kernel rather than the fake.
plan=$("$ncfg" plan 2>&1)
check "a second plan has nothing to do" \
	"$(printf '%s' "$plan" | grep -c 'qdisc\.' || true)" "0"

# The rate. Both what netcfgd thinks and -- the point of this file -- what the
# kernel actually holds, read by something that is not netcfgd.
write_config <<'CONF'
interface veth0 {
	veth   { peer = "veth1" }
	config = "10.7.0.1/24"
	qdisc {
		kind      = "cake"
		bandwidth = "100mbit"
	}
}
CONF
apply "shaping the link"
check "the shaping scheduler is installed" "$(qdisc_of veth0)" "cake"
check "netcfgd reports the rate it was given" "$(rate_of veth0)" "100000000"

if [ -n "$tc" ]; then
	# `tc` prints `bandwidth 100Mbit`. A rate sent in bits where bytes were
	# wanted would read as 12Mbit here, and a rate multiplied instead of
	# divided as 800Mbit.
	check "tc(8) agrees about the rate" \
		"$("$tc" qdisc show dev veth0 | sed -n 's/.*bandwidth \([0-9A-Za-z]*\).*/\1/p')" \
		"100Mbit"
else
	echo "note: no tc(8); the independent rate check did not run"
fi

# Changing only the rate still reshapes: the kind matches, and a comparison
# that stopped there would leave the line at the old number.
write_config <<'CONF'
interface veth0 {
	veth   { peer = "veth1" }
	config = "10.7.0.1/24"
	qdisc {
		kind      = "cake"
		bandwidth = "50mbit"
	}
}
CONF
apply "changing only the rate"
check "a rate change alone is noticed" "$(rate_of veth0)" "50000000"

# Dropping `qdisc` restores the kernel default rather than leaving cake in
# place. There is no "no qdisc", so this is a replacement, not a removal.
write_config <<'CONF'
interface veth0 {
	veth   { peer = "veth1" }
	config = "10.7.0.1/24"
}
CONF
apply "dropping the qdisc"
check "the kernel default comes back" "$(qdisc_of veth0)" "noqueue"

# And a qdisc netcfgd did not set is not netcfgd's to reset. Without the
# ownership record this would reset every interface whose config is silent
# about queueing, which is most of them.
if [ -n "$tc" ]; then
	# Establish the precondition rather than assume it. A daemon is running and
	# it watches the configuration directory, so the `write_config` above began
	# a reconcile of its own alongside the explicit `apply` -- and that pass is
	# entitled to reset the qdisc, because when it was planned netcfgd still
	# owned the cake it had set. If it lands *after* the line below, it wipes
	# the foreign qdisc this check is about and the check reports that netcfgd
	# reset somebody else's queueing. It does not; it finished its own work
	# late.
	#
	# Seen once, in a full `make live` inside a container, and not reproducible
	# standalone in twelve consecutive runs on two machines -- which is the same
	# shape as `acl.sh`'s one unreproduced failure, and gets the same treatment:
	# the race is real, so the setup waits for it rather than the deadline being
	# widened. Retrying the assignment is what makes it deterministic; a sleep
	# would only make it likely.
	waited=0
	while :; do
		"$tc" qdisc replace dev veth0 root cake bandwidth 30mbit
		sleep 0.3
		[ "$(qdisc_of veth0)" = "cake" ] && break
		waited=$((waited + 1))
		if [ "$waited" -gt 20 ]; then
			echo "FAIL could not put a foreign qdisc in place to test with"
			failures=$((failures + 1))
			break
		fi
	done
	apply "an apply that says nothing about queueing"
	check "somebody else's qdisc is left alone" "$(qdisc_of veth0)" "cake"
else
	echo "note: no tc(8); the foreign-qdisc check did not run"
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "qdisc.sh: all checks passed"
else
	echo "qdisc.sh: $failures failed"
	exit 1
fi
