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
# **dhcpcd, because it cannot be swept by argv and is stopped by its own verb.**
# Records rather than acts, like the systemctl stub: what is under test is
# whether the script reaches for `dhcpcd -4 -k <iface>` on the right selections,
# which is a property of the script.
cat > "$work/bin/dhcpcd" <<'STUB'
#!/bin/sh
echo "dhcpcd $@" >> "$SEL_LOG"
STUB
chmod +x "$work/bin/systemctl" "$work/bin/deb-systemd-invoke" "$work/bin/dhcpcd"

# **Two decoys, because the sweep is a question about ownership and one decoy
# can only ever answer half of it.** `sweep_children` takes the processes
# belonging to the manager standing down: somebody else's when that is
# NetworkManager, netcfgd's own when it is netcfgd. A test with one process
# cannot tell a correct sweep from one that kills everything it finds.
#
# Both must be named `wpa_supplicant`, because `pgrep -x` matches `comm`, which
# the kernel takes from the executable file -- so they are two copies under that
# name in different directories. A `#!` wrapper would be `sh` and never match.
#
#   theirs  a copy of `sleep`, plain argv -- stands in for NetworkManager's
#   ours    a copy of `sh`, with `/run/netcfgd/` in its argv -- stands in for a
#           backend netcfgd started and `KillMode=process` left behind (0140)
#
# `sh -c 'sleep 120' <marker>` puts the marker in argv as $0 while the shell
# sleeps, which is what `is_netcfgds` reads.
mkdir -p "$work/theirs" "$work/ours"
cp "$(command -v sleep)" "$work/theirs/wpa_supplicant" 2>/dev/null || true
cp "$(command -v sh)" "$work/ours/wpa_supplicant" 2>/dev/null || true
# **A dhcpcd process too, or the check that dhcpcd is never argv-swept passes by
# finding nothing.** Measured: putting `dhcpcd` back into `children_of` fails no
# check at all without this, because the sweep runs `pgrep -x dhcpcd` in a
# namespace that has none. Not the `$work/bin/dhcpcd` stub, which is a script
# and whose `comm` is `sh`.
cp "$(command -v sleep)" "$work/theirs/dhcpcd" 2>/dev/null || true

# One namespace per target, with fresh decoys each time. The three targets used
# to share one, so a decoy killed by the first was already gone for the third
# and `none` could not be tested at all.
for target in netcfgd networkmanager none; do
	SEL_LOG="$work/$target.log"; export SEL_LOG
	: > "$SEL_LOG"
	unshare -rmn sh -c '
		set -eu
		work=$1; sel=$2; target=$3
		mount -t tmpfs tmpfs /run
		mkdir -p /run/systemd/system
		# netcfgd names every dhcpcd it starts with one of these (0143). The
		# directory listing is the client list, and it has to be read before
		# anything stops netcfgd -- a real stop deletes /run/netcfgd and takes
		# it away, which is the ordering this fixture exists to pin.
		mkdir -p /run/netcfgd/dhcpcd
		: > /run/netcfgd/dhcpcd/probe0-4.conf
		: > /run/netcfgd/dhcpcd/probe1-6.conf
		export PATH="$work/bin:$PATH"
		# Bounded twice: each exits on its own, and each is signalled below
		# whether or not the switcher reached it.
		theirs= ours=
		if [ -x "$work/theirs/wpa_supplicant" ]; then
			"$work/theirs/wpa_supplicant" 120 &
			theirs=$!
		fi
		theirdh=
		if [ -x "$work/theirs/dhcpcd" ]; then
			"$work/theirs/dhcpcd" 120 &
			theirdh=$!
		fi
		if [ -x "$work/ours/wpa_supplicant" ]; then
			"$work/ours/wpa_supplicant" -c "sleep 120" \
				/run/netcfgd/supplicant/decoy.pid &
			ours=$!
		fi
		# Let them reach the process table before the switcher looks.
		waited=0
		while [ "$waited" -lt 20 ]; do
			[ -r "/proc/$ours/cmdline" ] && break
			waited=$((waited + 1))
			sleep 0.05
		done
		# **--no-wait, and it is not a convenience.** Since the switcher
		# confirms the machine is online before announcing success, and this
		# namespace has no network by construction (that is the whole point of
		# -n), every invocation here would otherwise sit out the full deadline
		# and then correctly report failure. What is under test is which units
		# the script acts on; the confirmation has its own checks below.
		sh "$sel" --no-wait "$target" > "$work/$target.out" 2>&1 || true
		# Which survived, recorded from inside where the pids mean something.
		#
		# **`if`, never a trailing `&&`.** Under `set -eu` a false
		# `[ ... ] && cmd` returns 1, and as the last command of this block it
		# aborts before the cleanup below -- which leaked a decoy onto the host
		# and, the failure propagating to the outer `set -e`, killed the whole
		# test before a single check printed. Third time this shape has cost
		# something in this file; written out longhand now.
		#
		# No apostrophes anywhere in this block: it is inside `sh -c ...` under
		# single quotes, and one in a comment ends the quoting. That cost a
		# syntax error on the very edit that added the note above.
		#
		# **Read `/proc/<pid>/cmdline`; do not stat it and do not use
		# `kill -0`.** Both of the obvious forms are wrong in opposite
		# directions. `kill -0` reports a zombie as alive -- these are children
		# of this shell, so a signalled one stays a zombie until it is waited
		# for -- and that read both decoys as surviving every sweep, failing
		# three checks that were describing correct behaviour. `[ -s ]` is
		# worse: procfs reports size 0 for every file, so it calls a *live*
		# process dead and the same checks pass by accident. Measured both ways
		# before this line was written. Reading the content answers correctly
		# for both.
		: > "$work/$target.alive"
		if [ -n "$theirs" ] && [ -n "$(tr -d "\0" 2>/dev/null < "/proc/$theirs/cmdline")" ]; then
			echo theirs >> "$work/$target.alive"
		fi
		if [ -n "$ours" ] && [ -n "$(tr -d "\0" 2>/dev/null < "/proc/$ours/cmdline")" ]; then
			echo ours >> "$work/$target.alive"
		fi
		if [ -n "$theirs" ]; then
			kill "$theirs" 2>/dev/null || true
		fi
		if [ -n "$ours" ]; then
			kill "$ours" 2>/dev/null || true
		fi
		# **By pid, never by `pgrep -x dhcpcd`.** The namespace shares the
		# host pid namespace, so a name sweep here reaches the machine own
		# running client -- which on a box where netcfgd is the network daemon
		# is the thing carrying the network. The switcher is protected from
		# that by its 0167 netns check; a raw cleanup loop is not.
		if [ -n "$theirdh" ]; then
			kill "$theirdh" 2>/dev/null || true
		fi
		exit 0
	' sh "$work" "$select_sh" "$target" || true
done

# **Whatever the namespace did not reap.** The decoys share the host's pid
# namespace -- `unshare -rmn` takes mount, network and user, not pid -- so a
# block that dies before its own cleanup leaves them visible to everything.
# They are harmless (a different netns, so the real switcher's 0167 check skips
# them) and they are still this script's to remove.
for pid in $(pgrep -x wpa_supplicant 2>/dev/null || true); do
	if grep -qa "$work" "/proc/$pid/cmdline" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
	fi
done

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
	"$(grep -c 'terminating wpa_supplicant' "$work/netcfgd.out" 2>/dev/null || true)" "1"

# **And it takes the right one.** Selecting netcfgd stands the other managers
# down, so their supplicant goes and netcfgd's own must not -- netcfgd is about
# to use it. One decoy could not tell this from a sweep that kills whatever it
# finds.
check "and leaves netcfgd's own supplicant alone" \
	"$(grep -c ours "$work/netcfgd.alive" 2>/dev/null || true)" "1"
check "while the other manager's is gone" \
	"$(grep -c theirs "$work/netcfgd.alive" 2>/dev/null || true)" "0"

# **The other direction, which is what a machine is left with after switching
# away.** `stand_down netcfgd` had no `children_of` arm at all, so netcfgd's
# supplicant and DHCP clients survived every selection -- `KillMode=process`
# keeps them alive across the stop on purpose, and nothing else was ever going
# to collect them.
check "selecting NetworkManager sweeps netcfgd's own backends" \
	"$(grep -c ours "$work/networkmanager.alive" 2>/dev/null || true)" "0"

# **`none` is prerm's, and it used to stop nothing while saying otherwise.**
# Reported: "I STILL had to kill orphaned dhcpcd and wpa_supplicant after
# running the script to switch to none."
check "none stops netcfgd's own backends" \
	"$(grep -c ours "$work/none.alive" 2>/dev/null || true)" "0"
# And does not reach for anybody else's: an operator removing netcfgd over a
# NetworkManager connection keeps it.
check "and leaves another manager's supplicant running" \
	"$(grep -c theirs "$work/none.alive" 2>/dev/null || true)" "1"

# **dhcpcd, which no argv sweep can reach.** It calls `setproctitle`, so its
# command line reads `dhcpcd: wlp0s20f3 [ip4]` with netcfgd's marker gone -- and
# a sweep that cannot answer returns "not netcfgd's", which had
# `netcfgd_select.sh netcfgd` proposing to kill the client netcfgd had just
# started. It is stopped from netcfgd's own bookkeeping instead, with dhcpcd's
# own verb, and the family flag matters: a client started with `-4` writes
# `<iface>-4.pid`, and a bare `-k` finds nothing and exits 1 (0070).
check "standing netcfgd down stops the dhcpcd it started" \
	"$(count networkmanager 'dhcpcd -4 -k probe0')" "1"
check "and the DHCPv6 one, by the family it was started with" \
	"$(count networkmanager 'dhcpcd -6 -k probe1')" "1"
check "none stops them too, which is what prerm needs" \
	"$(count none 'dhcpcd -4 -k probe0')" "1"

# **The half that matters most: selecting netcfgd must not stop netcfgd's own
# client.** `stand_down` runs for every manager except the target, so
# `sweep_children netcfgd` is never reached here -- and this is the assertion
# that fails if dhcpcd is ever put back into `children_of`.
check "selecting netcfgd stops no dhcpcd of its own" \
	"$(count netcfgd 'dhcpcd -')" "0"
# And the other route to the same harm: putting `dhcpcd` back into
# `children_of` makes the argv sweep signal it as some other manager's
# leftover. Read from the switcher's own stdout, where that sweep reports.
check "and signals none as another manager's leftover either" \
	"$(grep -c 'terminating dhcpcd' "$work/netcfgd.out" 2>/dev/null || true)" "0"

# `none` is postrm's, and a machine that cannot start anything is the outcome
# 0145 records.
check "none masks nothing at all" "$(count none 'mask ')" "0"

# --------------------------------------------- does it say whether it worked
#
# The switcher used to end by announcing success the moment the last
# `systemctl start` returned, which is a statement about a unit and not about
# the network. Measured on the reporting machine: selecting NetworkManager
# printed "networkmanager is now this machine's network daemon" and the machine
# then spent **13 minutes with no default route**, until somebody ran nmtui.
# The manager was running the whole time; it was waiting for a secret agent it
# could not ask for, and nothing said so.
#
# A fresh network namespace is the ideal place to check this, having exactly no
# default route until one is put there. Both directions, because a confirmation
# that cannot pass is as useless as one that cannot fail.
confirm_out=$work/confirm.out
unshare -rmn sh -c '
	set -eu
	work=$1; sel=$2
	mkdir -p "$work/bin"
	printf "%s\n" "#!/bin/sh" "exit 0" > "$work/bin/systemctl"
	chmod +x "$work/bin/systemctl"
	PATH="$work/bin:$PATH"; export PATH

	# Offline: the namespace has lo, down, and no routes at all.
	sh "$sel" --wait-online=1 netcfgd > "$work/confirm.offline" 2>&1 && echo "EXIT=0" >> "$work/confirm.offline" || echo "EXIT=$?" >> "$work/confirm.offline"

	# Online: a default route through loopback is a real default route, which
	# is all this check claims to read.
	ip link set lo up
	ip route add default dev lo
	sh "$sel" --wait-online=1 netcfgd > "$work/confirm.online" 2>&1 && echo "EXIT=0" >> "$work/confirm.online" || echo "EXIT=$?" >> "$work/confirm.online"
' sh "$work" "$select_sh" > "$confirm_out" 2>&1 || true

check "with no default route it does not claim to have succeeded" \
	"$(grep -c "is now this machine.s network daemon" "$work/confirm.offline" 2>/dev/null || true)" "0"
check "it says the network is not up" \
	"$(grep -c 'the network is not up' "$work/confirm.offline" 2>/dev/null || true)" "1"
check "and it fails, so a script calling it can tell" \
	"$(grep -c '^EXIT=1' "$work/confirm.offline" 2>/dev/null || true)" "1"
# The other side. Without this the two checks above pass with the
# confirmation hard-wired to fail, which would be a switcher that never works.
check "with a default route it does claim to have succeeded" \
	"$(grep -c "is now this machine.s network daemon" "$work/confirm.online" 2>/dev/null || true)" "1"
check "and it succeeds" \
	"$(grep -c '^EXIT=0' "$work/confirm.online" 2>/dev/null || true)" "1"
# And the escape hatch the harness above depends on.
check "--no-wait skips the check entirely" \
	"$(grep -c "is now this machine.s network daemon" "$work/netcfgd.out" 2>/dev/null || true)" "1"

echo
if [ "$failures" -eq 0 ]; then
	echo "select.sh: all checks passed"
else
	echo "select.sh: $failures check(s) failed"
	exit 1
fi
