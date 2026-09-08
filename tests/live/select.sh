#!/bin/sh
# netcfgd_select.sh's systemd paths, on a machine with no systemd.
#
# WHY THIS EXISTS
#   The switcher shipped having only ever been run under `--dry-run`, on a
#   development machine with no systemd, and it broke a real one: it masked
#   `wpa_supplicant.service` for *every* selection, because the supplicant sat
#   in the same list as the managers. NetworkManager does not talk to radios
#   itself -- it drives wpa_supplicant over D-Bus -- so NM came up, showed the
#   device and found no networks. Selecting `networkmanager` broke
#   NetworkManager.
#
#   netcfgd was unaffected, which is why it was invisible from the tree: it
#   spawns the wpa_supplicant *binary* with its own `-P` marker and never
#   wants the service. The machine ended with no daemon able to use the radio,
#   which is 0145's outcome by a new route.
#
# HOW IT RUNS WITHOUT SYSTEMD
#   A mount namespace, a tmpfs over /run so `/run/systemd/system` can be
#   created, and a `systemctl` on PATH that records its arguments and exits 0.
#   That is enough: what is under test is *which units this script acts on*,
#   which is a property of the script and not of systemd. What it cannot test
#   is whether systemd then does the right thing, and nothing here pretends
#   to -- the same honesty `killmode.sh` states about checking a declaration
#   rather than a behaviour.
#
#   **A network namespace too, and its absence was a live hazard.** This runs
#   the switcher for real rather than with `--dry-run` -- the `systemctl` calls
#   are caught by the stub, but `kill` is not stubbed and `unshare -rm` shares
#   the host's network namespace. So `stand_down networkmanager` found the
#   machine's actual `wpa_supplicant` by `pgrep -x`, `is_netcfgds` said it was
#   not netcfgd's, `in_our_netns` said it *was* ours because the namespace was
#   shared -- and the test killed the supplicant carrying the network of
#   whoever ran it as root. Nothing in it was wrong except the missing `-n`.
#
#   With `-n` the switcher's own 0167 exclusion does the work: every host
#   process is in a different netns, so none is signalled. That would leave the
#   kill path with no coverage at all, so the namespace gets a process of its
#   own to find -- `sleep` copied to a file named `wpa_supplicant`, which is
#   what `pgrep -x` matches on, since it reads `comm` and a `#!` script would
#   be `sh`.
#
# POSIX sh.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
select_sh="$repo/packaging/netcfgd_select.sh"

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "select.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "select.sh: skipping: $1"
	exit 0
}

[ -r "$select_sh" ] || skip "netcfgd_select.sh is not there"
unshare -rm true 2>/dev/null || skip "no user and mount namespaces here"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-select.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/bin"

# Records and does nothing. `exit 0` because the script reads no status from
# it -- and a stub that failed would test the script's error handling rather
# than its choices.
cat > "$work/bin/systemctl" <<'STUB'
#!/bin/sh
echo "$@" >> "$SEL_LOG"
STUB
cat > "$work/bin/deb-systemd-invoke" <<'STUB'
#!/bin/sh
echo "invoke $@" >> "$SEL_LOG"
STUB
chmod +x "$work/bin/systemctl" "$work/bin/deb-systemd-invoke"

# A decoy for the kill path, inside the namespace and nowhere near anything
# real. `cp` rather than a wrapper script: `pgrep -x` matches `comm`, which the
# kernel takes from the executable.
cp "$(command -v sleep)" "$work/bin/wpa_supplicant" 2>/dev/null || true

unshare -rmn sh -c '
	set -eu
	work=$1; sel=$2
	mount -t tmpfs tmpfs /run
	mkdir -p /run/systemd/system
	export PATH="$work/bin:$PATH"
	# Bounded twice: it exits on its own, and it is killed below whether or not
	# the switcher signalled it.
	decoy=
	if [ -x "$work/bin/wpa_supplicant" ]; then
		"$work/bin/wpa_supplicant" 120 &
		decoy=$!
	fi
	for target in netcfgd networkmanager none; do
		SEL_LOG="$work/$target.log"; export SEL_LOG
		: > "$SEL_LOG"
		sh "$sel" "$target" > "$work/$target.out" 2>&1 || true
	done
	if [ -n "$decoy" ]; then
		kill "$decoy" 2>/dev/null || true
		# Whether the switcher reached it, recorded for the check below. The
		# decoy is gone either way by now, so this asks the log rather than the
		# process table.
		:
	fi
' sh "$work" "$select_sh"

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
count() { grep -c "^$2" "$work/$1.log" 2>/dev/null | head -1; }

# **The regression, asserted where it actually lives.** 10.56 masked
# `wpa_supplicant.service` on *every* selection, including the one that hands
# the machine to NetworkManager -- which drives the supplicant over D-Bus and
# came up unable to scan. The invariant is therefore about the
# **NetworkManager** selection and about recovery, not about masking as such:
# the first version of these checks read "never masks the supplicant", which is
# broader than the incident and forbade the fix below.
check "selecting NetworkManager never masks the supplicant service" \
	"$(count networkmanager 'mask wpa_supplicant')" "0"
check "and gives it back unmasked, enabled and started" \
	"$(count networkmanager 'unmask wpa_supplicant.service')" "1"
check "and none unmasks it, which is how a broken machine recovers" \
	"$(count none 'unmask wpa_supplicant.service')" "1"

# **Selecting netcfgd must mask it, and a stop is not enough.**
# `wpa_supplicant.service` is D-Bus activatable, so `disable` governs boot and
# nothing else: any client asking for `fi.w1.wpa_supplicant1` starts it again.
# `netcfgd-exclusive.conf` conflicts with that unit and `Conflicts=` is
# symmetric, so the revived supplicant does not merely contend for the radio,
# it stops netcfgd -- measured, thirteen seconds after netcfgd started.
check "selecting netcfgd masks the supplicant, which a stop cannot hold down" \
	"$(count netcfgd 'mask wpa_supplicant.service')" "1"
check "and ModemManager, which returns the same way" \
	"$(count netcfgd 'mask ModemManager.service')" "1"
check "while none puts ModemManager back too" \
	"$(count none 'unmask ModemManager.service')" "1"

# The half that must still happen, or the checks above pass by doing nothing.
check "selecting netcfgd masks NetworkManager" \
	"$(count netcfgd 'mask NetworkManager.service')" "1"
check "selecting NetworkManager does not mask NetworkManager" \
	"$(count networkmanager 'mask NetworkManager.service')" "0"
check "and gives NetworkManager the supplicant it needs" \
	"$(count networkmanager 'start wpa_supplicant.service')" "1"

# A resolver is not a network manager. Masking it broke `dns_mode = resolved`,
# which is the arrangement 0007 recommends.
check "no selection masks systemd-resolved" \
	"$(count netcfgd 'mask systemd-resolved')" "0"

# **The kill path fires, and only inside the namespace.** Two things at once:
# that `stand_down` reaches a supplicant another manager left behind, and that
# it reaches *this* one -- the decoy started inside the namespace -- rather than
# whatever the host is running. Before the `-n`, this test signalled the real
# supplicant on the machine running it.
#
# Read from the switcher's own stdout and not from the `systemctl` log: the
# stub records unit arguments, and the kill path never goes near systemctl.
# The first version of this check grepped the wrong file, could only ever read
# zero, and asserted zero -- passing by doing nothing, which is the shape every
# other check here exists to avoid.
check "selecting netcfgd signals a supplicant left behind in our namespace" \
	"$(grep -c 'terminating wpa_supplicant' "$work/netcfgd.out" 2>/dev/null || echo 0)" "1"

# `none` is postrm's, and a machine that cannot start anything is the outcome
# 0145 records.
check "none masks nothing at all" "$(count none 'mask ')" "0"

echo
if [ "$failures" -eq 0 ]; then
	echo "select.sh: all checks passed"
else
	echo "select.sh: $failures check(s) failed"
	exit 1
fi
