#!/bin/sh
# Both NetworkManager shims, one fixture, the same questions, diffed.
#
#     unshare -rn sh tool/nm-compare.sh            # the default questions
#     unshare -rn sh tool/nm-compare.sh ASK=...    # one of your own
#
# ## Why this exists rather than reading the two implementations
#
# 0264's port is judged by what libnm believes, and the Rust shim is the thing
# that already passes `tests/live/nm.sh`. So the useful question while porting is
# never "what does this code do" but "where do the two answer differently" --
# and the answer has to come from a CLIENT, because every defect this found was
# invisible from the properties: a device whose `DeviceType` said wireguard while
# its introspection document said ethernet, a `Strength` formula the unit test
# agreed with because both were written by one hand, a `GROUP_CCMP` colliding
# with `KEY_MGMT_PSK` so a WPA3 network rendered as "WPA2 WPA3".
#
# `nm.sh` reports which checks fail. This reports what the difference IS, which
# is the half that says where to look.
#
# ## The fixture is nm.sh's own, read out of it
#
# Not copied. A second copy of that configuration would be a second thing to keep
# right, and the point of comparing against the oracle's own fixture is that a
# difference found here is a difference the oracle will also see.
#
# ## What it does to the machine
#
# Nothing. A private bus, a private netcfgd with its own config, run and resolver
# paths, and dummy links in the namespace `unshare -rn` gives it. The shim is
# given `--session`, so the name is claimed there and never on the system bus
# where a developer's real network manager lives.
#
# ## What stops it
#
# `awaits` is bounded at twenty seconds in tenths; each of the three processes is
# killed by the pid it was started with, in an EXIT trap; nothing starts a process
# inside a loop and nothing matches a process by pattern -- a `pkill` for any of
# these three names on a developer's machine reaches the manager running it.
set -eu

name=nm-compare.sh
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"
c_shim="$repo/adapter/netcfgd-nm/c/netcfgd-nm"
rust_shim="$repo/adapter/netcfgd-nm/target/debug/netcfgd-nm"

# The questions. Each line is a shell command run against whichever shim is up,
# with its output captured; override to ask something else without editing this.
ASK=${ASK:-'
nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device
nmcli -t -f NAME,TYPE,DEVICE,UUID connection show
nmcli -t -f SSID,SIGNAL,SECURITY device wifi list --rescan no
nmcli -t -f GENERAL.STATE,IP4.ADDRESS,IP4.GATEWAY,IP4.DNS device show probe0
'}

skip() { echo "$name: $1" >&2; exit 0; }

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v nmcli >/dev/null 2>&1 || skip "nmcli is not installed"
command -v dbus-daemon >/dev/null 2>&1 || skip "dbus-daemon is not installed"
[ -x "$build/netcfgd" ] || skip "netcfgd is not built"
[ -x "$c_shim" ] || skip "the C shim is not built (make -C adapter/netcfgd-nm/c)"
[ -x "$rust_shim" ] || skip "the Rust shim is not built (cd adapter/netcfgd-nm && cargo build)"
ip link add probe-ns type dummy 2>/dev/null || skip "no namespace to make links in"
ip link del probe-ns 2>/dev/null || true

# Short, because a unix socket path has to fit in sun_path.
answers=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-cmp.XXXXXX")
cleanup_answers() { rm -rf "$answers" 2>/dev/null; return 0; }
trap cleanup_answers EXIT INT TERM

# One shim, brought up against a fresh fixture, asked everything, torn down.
run_one() {
	which=$1
	shim=$2
	out=$3
	work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-c1.XXXXXX")
	daemon= bus= shim_pid=
	# Nested, so the outer trap still removes the answers directory.
	inner() {
		for p in $shim_pid $bus $daemon; do kill "$p" 2>/dev/null; done
		waited=0
		while [ -d "$work" ]; do
			rm -rf "$work" 2>/dev/null && break
			waited=$((waited + 1))
			[ "$waited" -gt 50 ] && break
			sleep 0.1
		done
		return 0
	}
	mkdir -p "$work/etc/secrets" "$work/run" "$work/ctrl"
	export NCFG_CONFIG_DIR="$work/etc" NCFG_RUN_DIR="$work/run"
	# A network namespace is not a mount namespace, so without this the DNS
	# backend writes the resolver of the machine running the comparison.
	export NCFG_RESOLV_CONF="$work/resolv.conf" NCFG_WPA_CTRL_DIR="$work/ctrl"
	printf 'hunter2hunter2' > "$work/etc/secrets/home"
	chmod 600 "$work/etc/secrets/home"
	# Generated, never committed: a private key in a repository is a private key
	# in a repository, however worthless the network it opens.
	head -c 32 /dev/urandom | base64 > "$work/etc/secrets/wg0"
	chmod 600 "$work/etc/secrets/wg0"
	# nm.sh's fixture, read out of nm.sh.
	sed -n "/^cat > \"\$work\/etc\/netcfgd.conf\" <<'CONF'$/,/^CONF$/p" \
		"$repo/tests/live/nm.sh" | sed '1d;$d' > "$work/etc/netcfgd.conf"
	if [ ! -s "$work/etc/netcfgd.conf" ]; then
		echo "$name: could not read nm.sh's fixture; has its heredoc moved?" >&2
		inner
		return 1
	fi

	daemon_flags=
	if "$build/netcfgd" --help 2>&1 | grep -q -- '--try-the-c-daemon'; then
		daemon_flags=--try-the-c-daemon
	fi
	"$build/netcfgd" $daemon_flags > "$work/daemon.log" 2>&1 &
	daemon=$!
	i=0
	while [ ! -e "$work/run/netcfgd.sock" ] && [ "$i" -lt 200 ]; do
		i=$((i + 1)); sleep 0.1
	done
	"$build/ncfg" apply >/dev/null 2>&1 || true

	eval "$(dbus-daemon --session --print-address=1 --print-pid=1 --fork | {
		read -r address_line
		read -r pid_line
		echo "address='$address_line'; bus=$pid_line"
	})"
	# The same daemon wearing both hats, which is what lets an unmodified client
	# talk to a shim that is not running as root.
	export DBUS_SESSION_BUS_ADDRESS="$address" DBUS_SYSTEM_BUS_ADDRESS="$address"
	"$shim" --session > "$work/shim.log" 2>&1 &
	shim_pid=$!
	i=0
	until nmcli general status >/dev/null 2>&1; do
		i=$((i + 1))
		if [ "$i" -gt 200 ]; then
			echo "$name: the $which shim never answered" >&2
			cat "$work/shim.log" >&2
			inner
			return 1
		fi
		sleep 0.1
	done

	: > "$out"
	echo "$ASK" | while IFS= read -r question; do
		[ -n "$question" ] || continue
		printf '=== %s\n' "$question" >> "$out"
		# Sorted, because neither shim promises an order and a diff of two
		# orders is noise that hides the one real difference. The version
		# mismatch warning is nmcli talking about itself.
		sh -c "$question" 2>&1 | grep -v "versions don't match" | LC_ALL=C sort \
			>> "$out" || true
	done
	inner
	return 0
}

run_one rust "$rust_shim" "$answers/rust" || exit 1
run_one c "$c_shim" "$answers/c" || exit 1

if diff -u "$answers/rust" "$answers/c" > "$answers/diff"; then
	echo "$name: the two shims answer identically"
	exit 0
fi
# Single quotes: the first version wrote the legend with backticks around the
# diff markers, which the shell ran as commands -- "-: not found" above a diff.
echo "$name: they differ; a '-' line is the Rust shim and a '+' line the C port"
cat "$answers/diff"
# **Non-zero on a difference**, so this can be used as a gate once the port is
# meant to be finished. While it is not, a difference is information rather than
# a failure, and the exit code says which run this was.
exit 1
