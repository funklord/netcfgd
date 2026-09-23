#!/bin/sh
# What each DNS mode delivers, from both implementations.
#
#     unshare -rmn sh tests/live/c_dns_delivery.sh
#
# **`-rmn` and not `-rn`**: this needs a mount namespace as well as a network
# one, and that is the whole safety argument. A resolver delivery writes the
# file that decides whether the machine can resolve a name, and a test for the
# defect that sends it to the wrong place must not be able to cause it. So
# `/etc/resolv.conf` is bind-mounted over a sentinel before anything runs, and
# the sentinel is checked afterwards -- if the mount did not take, the script
# says so and stops rather than proceeding unprotected.
#
# That is not a hypothetical. This port honoured none of `NCFG_RESOLV_CONF`,
# `NCFG_DNSMASQ_CONF` or `NCFG_UNBOUND_CONF` -- the three variables whose whole
# purpose is keeping a test off those files -- and writing the probe that found
# it came within one working directory of rewriting this machine's
# (project.md 10.246, 10.249).
#
# THE TWO FORWARDERS ARE HANDLED DIFFERENTLY, AND THE REASON IS HONEST
#   `/etc/dnsmasq.d` and `/etc/unbound/unbound.conf.d` cannot be bind-mounted
#   over on a machine that does not have them, and creating them would be this
#   script changing the host to test itself. So instead it **checks that they
#   are absent** and runs those two cases only then: a regression that ignored
#   the environment variable would find no directory and refuse, which is
#   harmless. Where a machine does have them, those two cases are skipped and
#   say so. A check that cannot be made safely is not made.
#
# WHAT IS COMPARED
#   Every mode that produces something a third party reads: the file for
#   `write_resolv_conf`, the drop-in for `dnsmasq` and `unbound`, and the
#   arguments and standard input handed to `resolvconf`, `openresolv` and a
#   script of the operator's under `exec`. The last three are a fake on `PATH`
#   that records what it was given, which is the only way to compare a delivery
#   whose other end is somebody else's program.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "c_dns_delivery.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "c_dns_delivery.sh: skipping: $1"
	exit 0
}

[ -x "$repo/c/ncfg" ] || skip "the C ncfg is not built (make -C c)"
[ -x "$repo/target/debug/ncfg" ] || skip "the Rust ncfg is not built, and it is the comparison"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-c-dns.XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM

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

# ------------------------------------------------------- the guard, first

# The sentinel goes under the real `/etc/resolv.conf`, and nothing else in this
# script runs until that is confirmed. A bind mount that silently did not take
# would leave every case below writing the host's file.
sentinel='# SENTINEL: tests/live/c_dns_delivery.sh. If you are reading this in
# /etc/resolv.conf then a bind mount did not take and the guard failed.'
printf '%s\n' "$sentinel" > "$work/sentinel"
if ! mount --bind "$work/sentinel" /etc/resolv.conf 2>/dev/null; then
	skip "cannot bind-mount over /etc/resolv.conf (run under unshare -rmn)"
fi
if [ "$(head -1 /etc/resolv.conf)" != "# SENTINEL: tests/live/c_dns_delivery.sh. If you are reading this in" ]; then
	echo "FAIL the bind mount over /etc/resolv.conf did not take; refusing to continue" >&2
	exit 1
fi
echo "ok   the machine's own resolv.conf is behind a bind mount"

# And the two directories the forwarders default into. Absent is what makes
# those cases safe to run at all.
forwarders_safe=yes
for dir in /etc/dnsmasq.d /etc/unbound/unbound.conf.d; do
	if [ -d "$dir" ]; then
		forwarders_safe=no
	fi
done
if [ "$forwarders_safe" = yes ]; then
	echo "ok   neither forwarder directory exists, so a regression there would refuse"
else
	echo "ok   a forwarder directory exists on this machine; those cases are skipped"
fi

# ---------------------------------------------------------------- the fake

# `resolvconf`, `openresolv` and an `exec` script all end in somebody else's
# program. This is that program: it records its arguments and what it was given
# on standard input, which is the whole of what a delivery hands over.
mkdir -p "$work/bin"
cat > "$work/bin/resolvconf" <<'FAKE'
#!/bin/sh
printf 'argv:'
for one in "$@"; do printf ' %s' "$one"; done
printf '\n'
printf 'stdin: '
cat
printf '\n'
FAKE
chmod 0755 "$work/bin/resolvconf"
cp "$work/bin/resolvconf" "$work/bin/handover"
PATH="$work/bin:$PATH"
export PATH

# ------------------------------------------------------------- the compare

# One mode, both programs, and what each delivered. The recorded output goes to
# a file per program so that a delivery which runs a helper and one which
# writes a file are compared the same way.
delivered() {
	which="$1"
	binary="$2"
	mode="$3"
	tree="$work/$which"
	rm -rf "$tree"
	mkdir -p "$tree/etc" "$tree/run"
	# **Before, not after.** The two programs run one after the other against
	# the same namespace, so the second one has to find the machine the first
	# one found. Removing the device after both had run left the second
	# planning nothing to create, and every case failed on the difference
	# between `link.create` and its absence.
	ip link del f0 2>/dev/null || true
	cat > "$tree/etc/netcfgd.conf" <<CONF
global {
	dns_mode = "$mode"
$4
}
device f0 { kind = "dummy" }
interface f0 {
	config     = "10.9.130.1/24"
	dns        = ["10.9.130.53", "2001:db8:130::53"]
	dns_search = ["corp.example", "lab.example"]
}
CONF
	NCFG_CONFIG_DIR="$tree/etc" NCFG_RUN_DIR="$tree/run" \
		NCFG_RESOLV_CONF="$tree/resolv.conf" \
		NCFG_DNSMASQ_CONF="$tree/dnsmasq.conf" \
		NCFG_UNBOUND_CONF="$tree/unbound.conf" \
		timeout 60 "$binary" apply > "$tree/apply.out" 2>&1 || true
	# **The whole of what the apply said**, rather than the lines this script
	# thought were interesting. A grep for `dns.apply` and `argv:` was the
	# first version, and it turned a configuration both programs *refused*
	# into two identical records of nothing -- a vacuous pass that the length
	# floor below was too generous to catch. What a delivery does is visible
	# in its output or it is not visible at all; the helper writes to the same
	# stream, which is `deliver.c`'s arrangement and is why this works.
	{
		echo "== what the apply said"
		cat "$tree/apply.out"
		for file in resolv.conf dnsmasq.conf unbound.conf; do
			if [ -f "$tree/$file" ]; then
				echo "== $file"
				cat "$tree/$file"
			fi
		done
	} > "$tree/delivered" 2>&1
	sed "s|$tree|<tree>|g" "$tree/delivered"
}

compare() {
	what="$1"
	mode="$2"
	extra="${3:-}"
	rust=$(delivered rust "$repo/target/debug/ncfg" "$mode" "$extra")
	c=$(delivered c "$repo/c/ncfg" "$mode" "$extra")
	# **Not vacuous**, and asked about the subject rather than about the
	# length: the record has to mention the mode by name, which it does
	# whether the mode was delivered (`dns.apply  dns: dnsmasq`) or refused
	# (`unknown dns mode \`exec\``). Two identical records of nothing pass a
	# length floor and fail this.
	case "$rust" in
	*"$mode"*) ;;
	*)
		echo "FAIL $what: neither program mentioned \`$mode\`, so nothing was compared"
		printf '%s\n' "$rust" | head -3 | sed 's/^/       /'
		failures=$((failures + 1))
		return
		;;
	esac
	check "$what" "$c" "$rust"
	if [ -n "${NCFG_SHOW:-}" ]; then printf '%s\n' "$rust" | sed 's/^/       | /'; fi
}

compare "\`none\` delivers nothing, in both" "none"
compare "\`write_resolv_conf\` writes the same file" "write_resolv_conf"
compare "\`resolvconf\` is handed the same arguments and input" "resolvconf"
compare "\`openresolv\` likewise" "openresolv"
# **`exec` is refused by both, deliberately.** The mode exists in the model and
# the configuration language has no way to write the command it would run, so
# accepting the word would compile a mode with nothing to run --
# `lower_global.c` says so where it refuses it. What is compared here is that
# refusal, which is the one place the reader is narrower than the enum.
#
# **Compared as a prefix, which is `agree_gate.py`'s rule and 0263's**: the C
# folds a diagnostic's help onto one line where the Rust prints it as a `help:`
# continuation, so the Rust's first line is the beginning of the C's. Deliberately
# strict about the part that is shared -- a refusal reworded in one program is a
# refusal that has to be reworded in the other.
refusal_of() {
	tree="$work/$1"
	rm -rf "$tree"
	mkdir -p "$tree/etc" "$tree/run"
	printf 'global {\n\tdns_mode = "exec"\n}\n' > "$tree/etc/netcfgd.conf"
	NCFG_CONFIG_DIR="$tree/etc" NCFG_RUN_DIR="$tree/run" \
		NCFG_RESOLV_CONF="$tree/resolv.conf" \
		timeout 60 "$2" apply 2>&1 | grep -m1 '^ncfg: ' | sed "s|$tree|<tree>|g"
}
rust_refusal=$(refusal_of rust "$repo/target/debug/ncfg")
c_refusal=$(refusal_of c "$repo/c/ncfg")
case "$rust_refusal" in
*"unknown dns mode"*) ;;
*)
	echo "FAIL \`exec\`: the Rust no longer refuses it, so this compares nothing"
	failures=$((failures + 1))
	;;
esac
case "$c_refusal" in
"$rust_refusal"*)
	echo "ok   \`exec\` is refused by both, the Rust's words beginning the C's"
	;;
*)
	echo "FAIL \`exec\` is refused differently"
	echo "       rust: $rust_refusal"
	echo "       c   : $c_refusal"
	failures=$((failures + 1))
	;;
esac

if [ "$forwarders_safe" = yes ]; then
	compare "\`dnsmasq\` gets the same drop-in" "dnsmasq"
	compare "\`unbound\` gets the same drop-in" "unbound"
fi

# ------------------------------------------------------- the guard, again

# The strongest thing this script can say, and the reason it is worth saying:
# nothing above reached the file the machine resolves names through.
check "and the machine's resolv.conf was never written" \
	"$(head -1 "$work/sentinel")" \
	"# SENTINEL: tests/live/c_dns_delivery.sh. If you are reading this in"

if [ "$failures" -eq 0 ]; then
	echo "c_dns_delivery.sh: all checks passed"
else
	echo "c_dns_delivery.sh: $failures check(s) failed"
	exit 1
fi
