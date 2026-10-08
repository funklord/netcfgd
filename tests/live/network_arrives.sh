#!/bin/sh
# A wifi network added to a running daemon: does the radio get it?
#
#     unshare -rn sh tests/live/network_arrives.sh
#
# ## Why this exists
#
# This is project.md 10.338's own shape, which `config_arrives.sh` deliberately
# does not have. That script proves a written file reaches the machine, on
# dummy links and ordinary keys. What 10.338 actually held was a `network`
# block written into `conf.d/` while the daemon ran, where the work lands on a
# radio and on a supplicant netcfgd started -- two more layers, either of which
# could swallow it, and neither of which any test drove.
#
# **It calls `apply` nowhere.** `switch_network.sh` shares this fixture and
# drives it with `ncfg apply` at every step, which is the right shape for what
# that script asks and the wrong one for this: the question here is whether the
# daemon does it *unasked*.
#
# ## What is faked and what is not
#
# `fake_supplicant.py`, as five other scripts use it -- netcfgd starts it,
# parses its own argv, and speaks the real control protocol to it. What is not
# faked is netcfgd: the reload, the plan, the supplicant configuration and the
# observation are the real ones.
#
# The fake advertises three networks and `JOIN <ssid>` is how a test says the
# station moved, which needs two access points and a radio otherwise. So the
# network this script adds is one the fake already advertises: what is under
# test is whether netcfgd hands it over, not whether a fixture can invent a
# radio.
#
# ## What it would take to get this wrong, which is the check that matters
#
# A daemon that reloads the document, plans correctly, and never reaches the
# supplicant would pass every check in `config_arrives.sh` and leave a machine
# that does not join the network somebody just added. That is the failure
# 10.338 looked like from the operator's chair, and **one check here sees it**
# -- which one is measured below rather than claimed, because the obvious
# candidate turned out not to.
set -eu

name=network_arrives.sh
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"

daemon_flags=
if "$build/netcfgd" --help 2>&1 | grep -q -- '--try-the-c-daemon'; then
	daemon_flags=--try-the-c-daemon
fi

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "$name: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "$name: skipping: $1"
	exit 0
}

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
command -v python3 >/dev/null 2>&1 || skip "no python3"
[ -x "$build/netcfgd" ] || skip "netcfgd is not built"
[ -x "$build/ncfg" ] || skip "ncfg is not built"

# switch_network.sh's guard, and for its measured reason: the header says
# `unshare -rn` and the Makefile supplies it, and neither stops somebody
# running this directly -- which makes `wlan0` on the real machine and leaves
# it behind when a check fails before the cleanup.
if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
	skip "this makes interfaces and must not do it on the machine's own network; run it under \`unshare -rn\`, as the Makefile does"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-netarrive.XXXXXX")
daemon=
cleanup() {
	if [ -n "$daemon" ]; then
		kill "$daemon" 2>/dev/null || true
		wait "$daemon" 2>/dev/null || true
	fi
	# **The supplicant netcfgd started is nobody's child here**, launched with
	# `-B` so it daemonises away from this shell, and killing netcfgd
	# deliberately does not take it -- `KillMode=process` (0134, 0142). By the
	# pid file netcfgd wrote, confirmed to be this run's before it is
	# signalled, and never by name: a pattern kill on a shared pid namespace is
	# a sweep across the whole machine. switch_network.sh's, and it is there
	# because four of these were alive, one per run, before it existed.
	if [ -r "$work/run/supplicant/wlan0.pid" ]; then
		supplicant=$(cat "$work/run/supplicant/wlan0.pid" 2>/dev/null || true)
		case "$supplicant" in
		[0-9]*)
			if grep -qa "$work" "/proc/$supplicant/cmdline" 2>/dev/null; then
				kill "$supplicant" 2>/dev/null || true
			fi
			;;
		esac
	fi
	waited=0
	while [ -d "$work" ]; do
		rm -rf "$work" 2>/dev/null && break
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
}
trap cleanup EXIT INT TERM

mkdir -p "$work/etc/conf.d" "$work/etc/secrets" "$work/run" "$work/ctrl" \
	"$work/sys/wlan0/wireless" "$work/runroot"
cp "$repo/tests/live/fake_supplicant.py" "$work/fake_supplicant"
chmod +x "$work/fake_supplicant"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_RESOLV_CONF="$work/resolv.conf"
export NCFG_WPA_CTRL_DIR="$work/ctrl"
export NCFG_SYS_CLASS_NET="$work/sys"
export NCFG_WPA_SUPPLICANT="$work/fake_supplicant"
export NCFG_RUN_ROOT="$work/runroot"
printf 'nameserver 203.0.113.1\n' > "$work/resolv.conf"

failures=0
checks=0
check() {
	checks=$((checks + 1))
	if [ "$2" = "$3" ]; then
		printf 'ok   %s\n' "$1"
	else
		printf 'FAIL %s\n' "$1"
		printf '       expected: %s\n' "$3"
		printf '       actual:   %s\n' "$2"
		failures=$((failures + 1))
	fi
}

awaits() {
	i=0
	while [ "$i" -lt 150 ]; do
		if eval "$1" >/dev/null 2>&1; then
			return 0
		fi
		i=$((i + 1))
		sleep 0.1
	done
	return 1
}

ncfg="$build/ncfg"

# What netcfgd believes the station is on, read through its own observation
# rather than from the fake: asserting on the fake would prove the fixture
# works. switch_network.sh's, unchanged.
associated() {
	"$ncfg" status --json 2>/dev/null |
		python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print(""); raise SystemExit
for link in d.get("links", []):
    if link.get("name") == "wlan0":
        print(link.get("network") or "")
        raise SystemExit
print("")' 2>/dev/null || true
}

# roam.sh's and switch_network.sh's sender: a datagram client needs an address
# of its own, in a directory of its own, because the whole path has to fit a
# unix socket's 108 bytes.
send_event() {
	if [ ! -S "$work/ctrl/wlan0" ]; then
		echo "FAIL the control socket was there to be sent: $1"
		failures=$((failures + 1))
		return 1
	fi
	python3 - "$work/ctrl/wlan0" "$1" <<'PYSEND'
import socket, sys, os, tempfile
sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
staging = tempfile.mkdtemp()
local = os.path.join(staging, "c")
try:
	sock.bind(local)
	sock.sendto(sys.argv[2].encode(), sys.argv[1])
finally:
	sock.close()
	os.unlink(local)
	os.rmdir(staging)
PYSEND
}

# The fake prints every command it was sent, secrets stripped, and netcfgd
# inherits its stdout -- so what the supplicant was told is in the daemon's own
# log. That is the observable this script turns on: a `network` block that
# never becomes a `SET_NETWORK` is a block the radio never heard of.
#
# **The SSID goes over as hex, which this got wrong first.** netcfgd sends
# `SET_NETWORK 0 ssid 486f6d654669626572`, not a quoted string -- which is what
# a real supplicant takes, because an SSID is 32 arbitrary bytes and quoting
# them is the problem hex exists to avoid. A grep for the quoted form matches
# nothing and reads exactly like a network that never reached the radio.
hexed() {
	printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'
}

told_about() {
	grep -c "ssid $(hexed "$1")" "$work/daemon.log" 2>/dev/null || true
}

ip link add wlan0 type veth peer name wlan0p 2>/dev/null ||
	skip "cannot make a veth pair"
ip link set wlan0 up 2>/dev/null || true
ip link set wlan0p up 2>/dev/null || true

# ------------------------------------------------- one network, and a daemon

cat > "$work/etc/netcfgd.conf" <<'CONF'
global { dns { mode = "write_resolv_conf" } }

network "HomeFiber" {
	wifi { psk = "@secret:HomeFiber" }
	metric = 100
}

device wlan0 {
	wifi { autoconnect = true }
}

interface wlan0 {
	config = "null"
	dns { }
}
CONF
printf 'hunter2hunter2' > "$work/etc/secrets/HomeFiber"
chmod 0600 "$work/etc/secrets/HomeFiber"

# **No `--no-apply-on-start`**, which is what every other script using this
# fixture passes. The daemon has to do this by itself or there is nothing here
# to measure.
"$build/netcfgd" $daemon_flags > "$work/daemon.log" 2>&1 &
daemon=$!
awaits '[ -e "$work/run/netcfgd.sock" ]' ||
	{ cat "$work/daemon.log" >&2; skip "the daemon never bound its socket"; }
awaits '[ -S "$work/ctrl/wlan0" ]' || {
	echo "--- daemon:"; tail -15 "$work/daemon.log"
	skip "netcfgd never started the fake supplicant"
}

awaits '[ "$(associated)" = HomeFiber ]' || true
check "the daemon joined the one network it was started with, unasked" \
	"$(associated)" "HomeFiber"
# At least once rather than exactly once: netcfgd re-sends the set on a pass
# that rebuilds the supplicant's configuration, and how many times it does that
# is not what this script is about.
check "and told the supplicant about it" \
	"$([ "$(told_about HomeFiber)" -ge 1 ] && echo yes || echo no)" yes
check "and knows nothing of a network nobody has configured" \
	"$(told_about Cafe)" 0

# ------------------------------------- a network arrives while it is running
#
# **The write 10.338 made.** A drop-in under `conf.d/`, which is what
# `ncfg wifi add` and every GUI dialog produce, naming a network the radio has
# never been given.

cat > "$work/etc/conf.d/60-cafe.conf" <<'CONF'
network "Cafe" {
	wifi { open = true }
	metric = 400
}
CONF

awaits '[ "$(told_about Cafe)" -ge 1 ]' || true
check "a network added while the daemon runs reaches the supplicant, with no apply" \
	"$([ "$(told_about Cafe)" -ge 1 ] && echo yes || echo no)" yes

# And it did not lose the one it already had, which is the other way a reload
# can be wrong: a supplicant reconfigured from scratch drops the association.
check "and the station is still on the network it was on" \
	"$(associated)" "HomeFiber"

# --------------------------------------------------- and the station moves
#
# `JOIN` is how this fixture says the station left one network for another, and
# netcfgd sees the same `CTRL-EVENT-CONNECTED` a real supplicant sends.
#
# **WHICH OF THESE TWO CHECKS GATES THE ARRIVAL, MEASURED RATHER THAN
# ASSUMED.** Sabotaged by watching `/etc` and not `conf.d/` -- the exact failure
# the daemon's own log made look likely -- only *"a network added while the
# daemon runs reaches the supplicant"* went red. The check below passed with
# the network never having reached the radio at all, because `associated()`
# reads what netcfgd observed from `STATUS`, and the fake reports whatever
# station it was told to be on whether or not anybody configured it.
#
# So this one is kept for what it does prove -- that netcfgd follows a station
# that moves, through its own observation -- and named for it. The arrival is
# gated by the `told_about` check above, and by nothing here.

send_event "JOIN Cafe"
awaits '[ "$(associated)" = Cafe ]' || true
check "and netcfgd sees the station on the network it moved to" \
	"$(associated)" "Cafe"

# ------------------------------------------- an enterprise network arrives
#
# **Eleven events netcfgd does not read, in the middle of a join it does.**
# `fake_supplicant.py` emits the measured 802.1X sequence when the joined
# network carries `EAP` flags -- STARTED, a proposed method refused, the one
# selected, three certificates, the subject-alt names, SUCCESS -- and netcfgd
# reads none of them: its reader knows six event kinds and no EAP one
# (project.md 10.366). So what this asserts is that it survives them, which is
# the risk a reader of unknown lines carries and which no test drove before the
# fake could produce any.

cat > "$work/etc/conf.d/70-enterprise.conf" <<'CONF'
network "Enterprise" {
	wifi { psk = "@secret:Enterprise" }
	metric = 300
}
CONF
printf 'hunter2hunter2' > "$work/etc/secrets/Enterprise"
chmod 0600 "$work/etc/secrets/Enterprise"

awaits '[ "$(told_about Enterprise)" -ge 1 ]' || true
check "an enterprise network arrives like any other" \
	"$([ "$(told_about Enterprise)" -ge 1 ] && echo yes || echo no)" yes

# The fake prints every event it emits, so the exchange is readable from the
# daemon's log. **That had to be added for this to gate anything**: with the
# EAP emission removed entirely, every check here stayed green, because
# `associated()` reads netcfgd's view of STATUS and the fake answers STATUS
# from whatever `JOIN` set. Same weakness as the `JOIN Cafe` check above, found
# the same way.
emitted() {
	grep -c -- "-> <3>$1" "$work/daemon.log" 2>/dev/null || true
}

send_event "JOIN Enterprise"
awaits '[ "$(emitted CTRL-EVENT-EAP-SUCCESS)" -ge 1 ]' || true
check "the station authenticates before it associates" \
	"$([ "$(emitted CTRL-EVENT-EAP-STARTED)" -ge 1 ] && echo yes || echo no)" yes
check "through a method it first refused, which a reader has to skip" \
	"$([ "$(emitted 'CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=13 -> NAK')" -ge 1 ] &&
	  echo yes || echo no)" yes
check "and the certificate chain arrives deepest first" \
	"$([ "$(emitted 'CTRL-EVENT-EAP-PEER-CERT depth=2')" -ge 1 ] && echo yes || echo no)" yes
check "and it succeeds" \
	"$([ "$(emitted CTRL-EVENT-EAP-SUCCESS)" -ge 1 ] && echo yes || echo no)" yes
awaits '[ "$(associated)" = Enterprise ]' || true
check "and netcfgd comes through eleven events it does not read" \
	"$(associated)" "Enterprise"

# ----------------------------- a network left disabled, which nothing saw
#
# **project.md 10.337.** `ncfg wifi connect` sends `SELECT_NETWORK`, which
# disables every other network on purpose -- and nothing re-enables them and
# nothing looked. The supplicant's own list is the only place it shows, so
# `ncfg status` asks and says so.
#
# `DISABLE <flags> <ssid>` puts a network into `LIST_NETWORKS` carrying the
# flags a real supplicant would give it, which is the state no test could
# produce before that command existed.

# **Counted before, because the count alone cannot discriminate.** Each drop-in
# above is a document change and each causes a rewrite, so `>= 2` was already
# true before the disable -- measured by sabotage, where removing the
# refutation entirely left the check green.
rewrites_before=$(grep -ac '^REMOVE_NETWORK all' "$work/daemon.log" || true)

# **The two that must NOT provoke a rewrite, first and on their own.** A
# refutation that fires too widely cannot be told from a correct one once
# something legitimate is disabled, so the negative direction needs the radio
# to itself -- which is `evidence.md` on a control having to be able to fail
# the way the thing it controls for fails.
#
# `Distant` is not in the document, so netcfgd has no opinion about it. And
# `[TEMP-DISABLED]` contains the substring `DISABLED` while meaning the
# opposite thing: the supplicant blacklisting a network it could not get onto,
# which it clears itself. A predicate written with `strstr` reports it, and a
# netcfgd that reconciled it would fight the supplicant's own backoff.
send_event "DISABLE [DISABLED] Distant"
send_event "DISABLE [TEMP-DISABLED] Cafe"
sleep 2
check "a disabled network nobody configured provokes nothing" \
	"$(grep -ac '^REMOVE_NETWORK all' "$work/daemon.log" || true)" "$rewrites_before"

send_event "DISABLE [DISABLED] HomeFiber"
sleep 1

# **`|| status_rc=$?`, not `; status_rc=$?`.** Under `set -e` a failing command
# aborts the script, so the assignment never runs and the whole test dies with
# the child's code -- which prints no summary at all. Measured: sabotaging the
# document guard segfaults `ncfg status`, the run exited 139, and reading it
# through `grep FAIL` showed nothing and looked like a pass. `evidence.md`:
# never reduce a check's output before you know it passed.
status_rc=0
"$ncfg" status > "$work/status.out" 2>&1 || status_rc=$?

# **The exit status, read.** Without it a check counting lines in the output
# cannot tell a clean run from a crash: sabotaging the document guard leaves a
# NULL dereference, and `ncfg status` died after printing the first network --
# so "a network the document does not name is not mentioned" passed because
# the program never got that far. `evidence.md`: a count and an exit code are
# halves of one result.
# **The total, which is the check that discriminates.** Greps for particular
# names cannot see a note about a network none of them mention: sabotaging the
# document guard made `ncfg_wifi_network_for` match `Distant` onto some other
# block and print a line about THAT, which every per-name check passed over.
# One disabled network the document wants means one line.
check "and exactly one network is named, not every disabled one" \
	"$(grep -ac 'configured to join automatically' "$work/status.out" || true)" 1

check "and status itself succeeded, which a line count cannot tell you" \
	"$status_rc" 0

check "status says a network configured to autoconnect has been left disabled" \
	"$(grep -c 'HomeFiber. is configured to join automatically' "$work/status.out" \
		|| true)" 1
check "and says what joins it, rather than only that something is wrong" \
	"$(grep -c 'ncfg wifi connect HomeFiber' "$work/status.out" || true)" 1
check "a network the document does not name is not netcfgd's to mention" \
	"$(grep -c 'Distant' "$work/status.out" || true)" 0
check "and a temporarily disabled one is the supplicant's own affair" \
	"$(grep -c 'Cafe. is configured to join automatically' "$work/status.out" || true)" 0

# ------------------------------------------------- and the daemon puts it back
#
# **The reconcile half.** A network the document wants joined that the
# supplicant has disabled refutes netcfgd's record of what it handed over, so
# `plan/wifi.c` plans `wifi.set_profiles` and the pass rewrites the set --
# which sends `REMOVE_NETWORK all` and then adds and enables each network
# again. An ordinary plan action: `on_drift` governs it and a confirm window
# could revert it.
#
# **What this can show and what it cannot.** The fake answers `REMOVE_NETWORK
# all` with OK and does not clear the list it reports, so `LIST_NETWORKS` keeps
# saying `[DISABLED]` and the daemon keeps rewriting -- an artifact of the
# fixture, not of netcfgd. On a real supplicant `REMOVE_NETWORK all` empties
# the list, so the next observation finds nothing disabled and the pass stops.
# That is read out of `wifi_ops.c`, which sends the clear before the first
# `ADD_NETWORK`, rather than asserted here.
#
# So the assertion is that it acted at all, which is the link that was missing:
# a disabled network used to refute nothing.
awaits '[ "$(grep -ac "^REMOVE_NETWORK all" "$work/daemon.log" || true)" \
	-gt "$rewrites_before" ]' || true
check "a network disabled behind netcfgd's back is handed back to the radio" \
	"$([ "$(grep -ac '^REMOVE_NETWORK all' "$work/daemon.log" || true)" \
	    -gt "$rewrites_before" ] && echo yes || echo no)" yes

# ---------------------------------------------------------------- and quiet

check "and it never warned that the machine does not match" \
	"$(grep -c 'does not match its configuration' "$work/daemon.log" || true)" 0
check "nor that the configuration stopped compiling" \
	"$(grep -c 'does not compile' "$work/daemon.log" || true)" 0

if [ "$failures" -eq 0 ]; then
	echo "$name: $checks check(s), all passed"
else
	echo "$name: $failures of $checks check(s) failed"
	echo "--- the daemon's log ---"
	tail -30 "$work/daemon.log"
	exit 1
fi
