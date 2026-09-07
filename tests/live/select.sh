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

unshare -rm sh -c '
	set -eu
	work=$1; sel=$2
	mount -t tmpfs tmpfs /run
	mkdir -p /run/systemd/system
	export PATH="$work/bin:$PATH"
	for target in netcfgd networkmanager none; do
		SEL_LOG="$work/$target.log"; export SEL_LOG
		: > "$SEL_LOG"
		sh "$sel" "$target" >/dev/null 2>&1 || true
	done
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

# **The regression, asserted three ways.** It is one line in the script and
# three different machines' worth of consequence.
check "selecting netcfgd never masks the supplicant service" \
	"$(count netcfgd 'mask wpa_supplicant')" "0"
check "selecting NetworkManager never masks it either" \
	"$(count networkmanager 'mask wpa_supplicant')" "0"
check "and none unmasks it, which is how a broken machine recovers" \
	"$(count none 'unmask wpa_supplicant.service')" "1"

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
