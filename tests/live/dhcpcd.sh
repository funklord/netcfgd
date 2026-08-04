#!/bin/sh
# A real dhcpcd, driving the hook script netcfgd writes for it.
#
#     sh tests/live/dhcpcd.sh
#
# dhcpcd is the *first* client netcfgd looks for, and nothing here had ever run
# one. The generated hook's shape was read out of dhcpcd 10.1.0's own
# `20-resolv.conf`, its `-c` option out of the manual page, and `sh -n` plus
# assertions covered the text -- which checks that the script is shell, not that
# dhcpcd runs it. Driving the busybox half end to end (`dhcp.sh`) found three
# defects; asking the same question of the other client found a fourth, and it
# was worse: netcfgd could not stop a dhcpcd at all. Decision 0070.
#
# ## What it drives
#
#   * a real dhcpcd, with the hook netcfgd generates for it, against
#   * a real `busybox udhcpd` on the far end of a veth pair -- so the server
#     needs no package a machine with busybox does not already have, and
#   * one run with dhcpcd's *own* hooks first, which is the counter-proof:
#     without `-c` a lease sets the machine's hostname and rewrites
#     /etc/resolv.conf. Those are the two things 0061 and 0066 say netcfgd
#     prevents, and asserting that neither happened is worth nothing until
#     something has shown that they otherwise would.
#
# ## Why it makes its own namespaces
#
# Every other script here runs under `unshare -rn` from the Makefile. dhcpcd
# cannot: it drops privileges to an unprivileged user, and a user namespace with
# one mapped uid has nobody to become -- "failed to drop privileges", and it
# exits before it sends a packet. So this needs either real root, or
# `--map-auto`, which maps the subordinate uids from /etc/subuid and wants
# newuidmap installed (the `uidmap` package).
#
# It unshares the mount and UTS namespaces as well, and that is safety rather
# than tidiness:
#
#   * a tmpfs over /run and over dhcpcd's lease directory, so the machine's own
#     dhcpcd -- its control sockets, its pid files, its leases -- is neither read
#     nor disturbed. Both paths are compiled into dhcpcd and no option moves
#     them, which is also why the lease directory being somewhere else is a skip.
#   * a bind mount over /etc/resolv.conf, because the counter-proof deliberately
#     lets dhcpcd's own hook write it.
#   * a UTS namespace, because the counter-proof deliberately lets dhcpcd's own
#     hook set the hostname.
#
# Not under NCFG_LIVE from the Makefile: dhcpcd is a package, and `dhcp.sh`
# already drives the fallback that a machine without it uses.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "dhcpcd.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "dhcpcd.sh: skipping: $1"
	exit 0
}

die() {
	echo "dhcpcd.sh: $1" >&2
	exit 1
}

# netcfgd finds its clients on PATH, and dhcpcd installs into sbin -- which an
# ordinary user's PATH does not have, and the daemon's does. Looking here is what
# lets this run without `sudo -i`.
find_in_sbin() {
	for dir in /usr/sbin /sbin /usr/local/sbin /usr/bin /bin; do
		if [ -x "$dir/$1" ]; then
			echo "$dir/$1"
			return 0
		fi
	done
	return 1
}

# ---------------------------------------------------------------- preflight

command -v ip >/dev/null 2>&1 || skip "no ip(8)"
[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built (cargo build --workspace)"
dhcpcd=$(find_in_sbin dhcpcd) || skip "dhcpcd is not installed (apt install dhcpcd-base)"
command -v busybox >/dev/null 2>&1 || skip "no busybox, which is the server here"
command -v hostname >/dev/null 2>&1 || skip "no hostname(1), which is how the counter-proof is measured"
busybox --list | grep -qx udhcpd || skip "this busybox has no udhcpd applet"
# Debian's path, and dhcpcd's compiled-in default. A build that keeps its leases
# somewhere else would have this test writing to the real directory, which is
# exactly what the namespace exists to prevent.
[ -d /var/lib/dhcpcd ] || skip "dhcpcd's lease directory is not /var/lib/dhcpcd"

# ------------------------------------------------------------- the namespace

if [ -z "${NCFG_DHCPCD_NS:-}" ]; then
	NCFG_DHCPCD_NS=1
	export NCFG_DHCPCD_NS
	if [ "$(id -u)" = 0 ]; then
		# Real root: no user namespace at all, so dhcpcd's own user exists and
		# privilege separation works the way it does on a real machine.
		exec unshare --mount --uts --net -- sh "$0" "$@"
	fi
	command -v newuidmap >/dev/null 2>&1 ||
		skip "dhcpcd drops privileges and an unprivileged namespace needs newuidmap (apt install uidmap)"
	# Probed rather than exec'd straight into: a machine with no subordinate uids
	# in /etc/subuid should get the reason, not `unshare: write failed`.
	unshare --map-root-user --map-auto --mount --uts --net true 2>/dev/null ||
		skip "no subordinate uid range in /etc/subuid, so dhcpcd has nobody to drop privileges to"
	exec unshare --map-root-user --map-auto --mount --uts --net -- sh "$0" "$@"
fi

# From here on: root in a private user, mount, UTS and network namespace.

work=$(mktemp -d /tmp/ncfg-dhcpcd.XXXXXX)
server=
dnsmasq_pid=
cleanup() {
	# By the handle we were given, and before the namespace goes: a process
	# outlives the namespace that held it, and `hwsim.sh` left a root daemon
	# running for exactly this reason. dhcpcd is stopped the way netcfgd stops
	# it, which is also the thing under test.
	"$dhcpcd" -4 -k cli >/dev/null 2>&1 || true
	"$dhcpcd" -6 -k cli >/dev/null 2>&1 || true
	# `if` rather than `[ ... ] && kill`, because under `set -e` an AND-list
	# whose last command fails takes the whole function with it -- and a `kill`
	# of a process that has already been stopped fails. That left the work
	# directory behind on every run that got as far as stopping dnsmasq, which
	# is how it was noticed: five of them in /tmp.
	if [ -n "$dnsmasq_pid" ]; then kill "$dnsmasq_pid" 2>/dev/null || true; fi
	if [ -n "$server" ]; then kill "$server" 2>/dev/null || true; fi
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

mkdir -p "$work/etc" "$work/run"

mount -t tmpfs tmpfs /run || die "cannot put a tmpfs over /run"
mount -t tmpfs tmpfs /var/lib/dhcpcd || die "cannot put a tmpfs over /var/lib/dhcpcd"

# The decoy resolv.conf. `readlink -f` because a machine running
# systemd-resolved points /etc/resolv.conf into /run, which is the tmpfs above --
# so the file has to be made before it can be mounted over.
resolv=$(readlink -f /etc/resolv.conf 2>/dev/null || echo /etc/resolv.conf)
mkdir -p "$(dirname "$resolv")"
[ -e "$resolv" ] || : > "$resolv"
printf 'nameserver 203.0.113.99\n# what was here before dhcpcd ran\n' > "$work/etc-resolv"
mount --bind "$work/etc-resolv" "$resolv" ||
	die "cannot shield $resolv, and the counter-proof would overwrite the real one"

# `localhost` because that is what dhcpcd's 30-hostname requires before it will
# set one: a hook that refuses to act would look exactly like a hook that never
# ran. Through hostname(1) rather than /proc/sys/kernel/hostname, which is not
# writable from a nested user namespace however root the writer is -- procfs
# answers to the namespace that mounted it. dhcpcd's own hook tests for that and
# falls back to the same command, which is why the counter-proof works at all.
hostname localhost

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_RESOLV_CONF="$work/resolv.conf"
# netcfgd looks for its client on PATH. sbin is where dhcpcd lives and is not on
# an ordinary user's, so without this the daemon would fall through to busybox
# and this script would drive the client it is not about.
PATH="$(dirname "$dhcpcd"):$PATH"
export PATH
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
missing() {
	case "$2" in
	*"$3"*)
		echo "FAIL $1"
		echo "       expected NOT to contain: $3"
		echo "       actual:                  $2"
		failures=$((failures + 1))
		;;
	*) echo "ok   $1" ;;
	esac
}

# A lease is not instant: dhcpcd delays IPv4 briefly, then ARP-probes the offered
# address three times before it will use it. Twenty seconds is generous on a veth
# with the server already listening, and a regression here would hang rather than
# fail without the bound.
wait_for() {
	waited=0
	while ! eval "$1" >/dev/null 2>&1; do
		waited=$((waited + 1))
		if [ "$waited" -gt 80 ]; then
			return 1
		fi
		sleep 0.25
	done
	return 0
}

# ------------------------------------------------------------------ the wire

ip link add cli type veth peer name srv
ip link set srv up
ip addr add 10.44.0.1/24 dev srv

cat > "$work/udhcpd.conf" <<EOF
start 10.44.0.20
end 10.44.0.20
interface srv
option subnet 255.255.255.0
option router 10.44.0.1
option dns 10.44.0.53
# Option 15 and option 119, which are two different things on the wire: a domain
# and a search list. dhcpcd prefers 119 where a server sends one, which is the
# precedence netcfgd's hook copies -- and without both being sent, that
# precedence has no subject.
option domain lan.example
option search a.example b.example
# Option 12, which is what dhcpcd's own 30-hostname hook acts on. netcfgd's hook
# must not, and cannot be said to unless a name arrives.
option hostname leased-name
option lease 600
lease_file $work/udhcpd.leases
pidfile $work/udhcpd.pid
EOF
: > "$work/udhcpd.leases"
busybox udhcpd -f "$work/udhcpd.conf" > "$work/udhcpd.log" 2>&1 &
server=$!

# ------------------------------------------- the counter-proof: dhcpcd's hooks

# What a lease does when nothing stops it. This is not netcfgd running: it is
# dhcpcd with the hook directory Debian ships, and it is here so that every
# "netcfgd did not do this" below has a measured "and it otherwise would".
ip link set cli up
"$dhcpcd" -4 -b cli > "$work/stock.log" 2>&1 ||
	die "dhcpcd would not start: $(cat "$work/stock.log")"
if ! wait_for 'ip -4 -br addr show cli | grep -q 10.44.0.20'; then
	echo "       dhcpcd said:"
	sed 's/^/       /' "$work/stock.log"
	echo "       the server said:"
	sed 's/^/       /' "$work/udhcpd.log"
	die "no lease arrived, so nothing below would mean anything"
fi
# The address arriving is *not* the hook having run: dhcpcd installs the address
# and the routes itself and calls the hook afterwards. Waiting on the address and
# asserting on the hook is a race, and it lost one run in three.
wait_for '[ "$(hostname)" != localhost ]' || true
check "dhcpcd's own hooks take the hostname from the lease" \
	"$(hostname)" "leased-name.lan.example"
wait_for 'grep -q 10.44.0.53 "$resolv"' || true
contains "and rewrite the resolver file netcfgd's DNS backend owns" \
	"$(cat "$resolv")" "nameserver 10.44.0.53"

"$dhcpcd" -4 -k cli > "$work/stock-stop.log" 2>&1 || true
wait_for '! ip -4 -br addr show cli | grep -q 10.44.0.20' ||
	die "the counter-proof's client would not let go of the address"
hostname localhost
printf 'nameserver 203.0.113.99\n# what was here before dhcpcd ran\n' > "$work/etc-resolv"

# ------------------------------------------------------------------ netcfgd

# A static address beside the lease, so a teardown has something it must *not*
# remove; a `preference`, which is how the document ranks one link against
# another and is the one thing dhcpcd can act on that busybox udhcpc cannot; a
# DNS mode, so netcfgd owns a resolver file of its own; and an empty `dns { }`
# block, which is how an operator says "use what this network hands out" --
# 0049's third row, and what allows the lease's servers to be delivered at all.
cat > "$work/etc/netcfgd.conf" <<'CONF'
global { dns { mode = "write_resolv_conf" } }

interface cli {
	config     = "dhcp 10.44.9.9/24"
	preference = 512
	dns        { }
}
CONF
printf 'nameserver 203.0.113.99\n# what was here before netcfgd ran\n' > "$work/resolv.conf"

if ! "$ncfg" apply > "$work/apply.log" 2>&1; then
	if grep -q 'Operation not permitted' "$work/apply.log"; then
		skip "no CAP_NET_ADMIN in this namespace"
	fi
	echo "dhcpcd.sh: apply failed" >&2
	cat "$work/apply.log" >&2
	exit 1
fi
contains "netcfgd starts the client" "$(cat "$work/apply.log")" "backend.start cli"

if ! wait_for 'ip -4 -br addr show cli | grep -q 10.44.0.20'; then
	echo "FAIL the lease never reached the interface"
	echo "       the hook netcfgd generated:"
	sed 's/^/       /' "$work/run/dhcpcd/cli.script" 2>/dev/null || true
	echo "       the server said:"
	sed 's/^/       /' "$work/udhcpd.log"
	failures=$((failures + 1))
fi

# And here the wait is on the report, for a second reason as well as the race:
# the two assertions below it are that netcfgd's hook did *not* set the hostname
# and did *not* write /etc/resolv.conf, and a hook that has not run yet satisfies
# both. Waiting until the hook has demonstrably done its one job is what stops
# them passing for the wrong reason.
report=$work/run/reported/cli
wait_for '[ -r "$report" ]' || true

addresses=$(ip -4 -br addr show cli)
contains "the lease is on the interface"           "$addresses" "10.44.0.20/24"
contains "and the static address is still there"   "$addresses" "10.44.9.9/24"
# The preference reached the client. netcfgd does not install the lease's route
# -- the client does -- so the only way a document's ranking can reach it is
# `dhcpcd -m`, and busybox udhcpc has no equivalent. This is the one assertion
# `dhcp.sh` cannot make.
contains "the lease's default route carries the preference the document asked for" \
	"$(ip -4 route show default dev cli)" "metric 512"

# The two things `-c` prevents, now that the counter-proof has shown both happen
# without it. This is the whole of why netcfgd replaces dhcpcd's hook directory
# rather than dropping a file into it.
check "netcfgd's hook leaves the hostname alone" "$(hostname)" "localhost"
missing "and leaves /etc/resolv.conf to whoever owns it" \
	"$(cat "$resolv")" "10.44.0.53"

# The report, which is the only thing netcfgd asked dhcpcd's hook for: a lease's
# nameservers cannot be seen any other way -- netcfgd never speaks DHCP.
if [ -r "$report" ]; then
	echo "ok   the hook wrote an interface report"
else
	echo "FAIL the hook wrote an interface report"
	echo "       $report does not exist"
	failures=$((failures + 1))
fi
contains "naming the lease's nameserver" "$(cat "$report" 2>/dev/null)" "dns=10.44.0.53"
contains "and the search list the server sent" "$(cat "$report" 2>/dev/null)" "search=a.example"
contains "all of it"                          "$(cat "$report" 2>/dev/null)" "search=b.example"
missing "and not the domain option, which option 119 supersedes" \
	"$(cat "$report" 2>/dev/null)" "lan.example"
missing "and never a domain key, which would say where queries go" \
	"$(cat "$report" 2>/dev/null)" "domain="

# The lease is the client's, not netcfgd's (0004), on either client -- so the
# same reasoning `dhcp.sh` spells out applies: `Foreign` on a kernel that
# reports IFA_PROTO and `Unknown` below 5.18, and never `Ours`.
status=$("$ncfg" status 2>/dev/null | sed -n '/^cli /,/^[^ ]/p')
lease_line=$(printf '%s\n' "$status" | grep '10.44.0.20/24' || true)
case "$lease_line" in
*"[Ours]"*)
	echo "FAIL netcfgd claimed the client's lease as its own"
	echo "       actual: $lease_line"
	failures=$((failures + 1))
	;;
*"[Foreign]"* | *"[Unknown]"*) echo "ok   netcfgd reports the lease as somebody else's" ;;
*)
	echo "FAIL netcfgd reports the lease as somebody else's"
	echo "       actual: $lease_line"
	failures=$((failures + 1))
	;;
esac

# The lease arrived after the first apply, so delivering its nameservers is work
# for the next one -- the same asynchrony the `lease` hook has (0064).
contains "the lease's nameservers are work for the next apply" \
	"$("$ncfg" plan 2>&1)" "dns.apply cli"
"$ncfg" apply > "$work/apply-dns.log" 2>&1 || {
	cat "$work/apply-dns.log" >&2
	exit 1
}
resolver=$(cat "$work/resolv.conf")
contains "the lease's nameserver reaches the file netcfgd owns" "$resolver" \
	"nameserver 10.44.0.53"
contains "and its search list"    "$resolver" "search a.example b.example"
missing "and what was there before is gone, because netcfgd owns that file" \
	"$resolver" "203.0.113.99"
# With a client running and a lease delivered, an apply must find nothing to do.
# Section 4: an already-correct state produces zero actions.
contains "and then there is nothing to do" \
	"$("$ncfg" plan 2>&1 | head -1)" "nothing to do"

# --------------------------------------------------------------- stopping it

# The defect this script was written to find. dhcpcd's pid file carries the
# family it was started with -- `cli-4.pid` -- and `dhcpcd -k cli` looks for
# `cli.pid`, says "dhcpcd is not running" and exits 1, which is also what a
# machine with no dhcpcd says. So netcfgd reported a stopped backend while a real
# client kept the lease, kept renewing it, and kept the address. Decision 0070.
pid=$(cat /run/dhcpcd/cli-4.pid 2>/dev/null || echo 0)
if [ "$pid" -gt 0 ]; then
	echo "ok   dhcpcd's pid file names the family it was started with"
else
	echo "FAIL dhcpcd's pid file names the family it was started with"
	echo "       nothing at /run/dhcpcd/cli-4.pid; there is $(ls /run/dhcpcd 2>&1)"
	failures=$((failures + 1))
fi

cat > "$work/etc/netcfgd.conf" <<'CONF'
interface cli { config = "10.44.9.9/24" }
CONF
"$ncfg" apply > "$work/apply-stop.log" 2>&1 || {
	cat "$work/apply-stop.log" >&2
	exit 1
}
contains "dropping dhcp stops the client" "$(cat "$work/apply-stop.log")" "backend.stop cli"
if [ "$pid" -gt 0 ] && wait_for "! kill -0 $pid 2>/dev/null"; then
	echo "ok   and the client is gone"
else
	echo "FAIL and the client is gone"
	echo "       pid $pid is still running, holding the lease it will keep renewing"
	failures=$((failures + 1))
fi

remaining=$(ip -4 -br addr show cli)
contains "the static address survived the client leaving" "$remaining" "10.44.9.9/24"
missing "and the lease address is gone"                   "$remaining" "10.44.0.20"
# The half of the generated hook nothing had ever run: dhcpcd calls it with
# `STOP` on the way out, and that branch removes the report -- so a nameserver
# from a lease that no longer exists does not outlive it.
if [ -e "$report" ]; then
	echo "FAIL and the report went with it"
	echo "       $report still says: $(cat "$report")"
	failures=$((failures + 1))
else
	echo "ok   and the report went with it"
fi

# ------------------------------------------------------------------ DHCPv6

# The other family, which nothing had run either -- and where netcfgd was doing
# about dhcpcd's own hooks what it had been doing about `-k`: nothing at all. A
# `DHCPv6` lease's `20-resolv.conf` rewrites /etc/resolv.conf, which is 0066's
# contention on the side nobody had measured. Decision 0072.
#
# dnsmasq is the server: it is one package, it speaks stateful DHCPv6, and it
# sends the router advertisement whose M flag is what makes a client ask at all.
if ! command -v dnsmasq >/dev/null 2>&1; then
	echo "dhcpcd.sh: no dnsmasq, so the DHCPv6 half is not run (apt install dnsmasq-base)"
else
	ip -6 addr add 2001:db8:44::1/64 dev srv nodad
	# The client end needs its link-local to be past duplicate address detection
	# before anything solicits, which is the same wait `delegation.sh` makes.
	wait_for '[ "$(ip -6 -o addr show dev srv scope link | grep -c tentative)" = 0 ]' || true
	dnsmasq --keep-in-foreground --log-facility="$work/dnsmasq.log" \
		--pid-file="$work/dnsmasq.pid" --dhcp-leasefile="$work/dnsmasq.leases" \
		--user=root --interface=srv --bind-interfaces --no-resolv --port=0 \
		--dhcp-range=2001:db8:44::100,2001:db8:44::120,64,300 \
		--dhcp-option=option6:dns-server,[2001:db8:44::53] \
		--dhcp-option=option6:domain-search,v6.example \
		--enable-ra --ra-param=srv,5,300 > "$work/dnsmasq.out" 2>&1 &
	dnsmasq_pid=$!
	sleep 1
	hook_quarters=40

	# The counter-proof again, on this family: dhcpcd's own hooks, and what they
	# do to a file netcfgd's DNS backend owns.
	printf 'nameserver 203.0.113.99\n# what was here before dhcpcd ran\n' > "$work/etc-resolv"
	"$dhcpcd" -6 -b cli > "$work/stock6.log" 2>&1 || true
	if wait_for 'grep -q 2001:db8:44::53 "$resolv"'; then
		# How long the whole thing took when it was allowed to happen: client
		# start, router solicitation, the DHCPv6 exchange and the hook. The
		# assertion below is a negative one and has no event of its own to wait
		# for, so it waits twice this -- which is a bound measured on this
		# machine in this run rather than a sleep somebody guessed.
		hook_quarters=$waited
		echo "ok   a DHCPv6 lease's own hooks rewrite the resolver file too"
	else
		echo "FAIL a DHCPv6 lease's own hooks rewrite the resolver file too"
		echo "       $resolv says: $(cat "$resolv")"
		echo "       dnsmasq said:"
		sed 's/^/       /' "$work/dnsmasq.log" 2>/dev/null | tail -5
		failures=$((failures + 1))
	fi
	"$dhcpcd" -6 -k cli > /dev/null 2>&1 || true
	wait_for '! ip -6 -br addr show cli | grep -q 2001:db8:44:' || true
	printf 'nameserver 203.0.113.99\n# what was here before netcfgd ran\n' > "$work/etc-resolv"

	# And now netcfgd's turn. `dhcp6` alone: no `dns { }` block, because there is
	# nothing for netcfgd to deliver here -- the point is what dhcpcd must *not*
	# do behind it.
	cat > "$work/etc/netcfgd.conf" <<'CONF'
interface cli {
	config = "dhcp6"
}
CONF
	"$ncfg" apply > "$work/apply6.log" 2>&1 || {
		cat "$work/apply6.log" >&2
		exit 1
	}
	contains "netcfgd starts a DHCPv6 client" "$(cat "$work/apply6.log")" "backend.start cli"
	if wait_for 'ip -6 -br addr show cli | grep -q 2001:db8:44:'; then
		echo "ok   and a DHCPv6 lease reaches the interface"
	else
		echo "FAIL and a DHCPv6 lease reaches the interface"
		echo "       cli has: $(ip -6 -br addr show cli)"
		failures=$((failures + 1))
	fi
	# dhcpcd installs the address and calls its hooks afterwards, so the lease
	# arriving does not mean a hook has finished -- and a check that something
	# did *not* happen is satisfied by it not having happened *yet*. So this
	# waits twice as long as the counter-proof above needed for the whole
	# exchange, and only then asks.
	sleep_quarters=$(( (hook_quarters * 2) + 8 ))
	waited=0
	while [ "$waited" -lt "$sleep_quarters" ]; do
		waited=$((waited + 1))
		sleep 0.25
	done
	missing "and dhcpcd left the resolver file alone this time" \
		"$(cat "$resolv")" "2001:db8:44::53"
	check "and the hostname with it" "$(hostname)" "localhost"

	# 0086. Silencing the v6 client's hooks (0072) stopped it fighting over
	# /etc/resolv.conf and cost the lease its nameservers on the way: nothing
	# carried them, so a v6-only network resolved nothing at all. The client
	# has a script of netcfgd's now, reporting into a fragment of its own
	# rather than into the one file the v4 client already owns.
	fragment=$work/run/reported.d/cli/dhcpcd6
	if wait_for '[ -f "$fragment" ]'; then
		echo "ok   the DHCPv6 client reports through a fragment of its own"
	else
		echo "FAIL the DHCPv6 client reports through a fragment of its own"
		echo "       $work/run/reported.d holds: $(ls -R "$work/run/reported.d" 2>&1)"
		failures=$((failures + 1))
	fi
	check "which carries the lease's nameserver" \
		"$(sed -n 's/^dns=//p' "$fragment" 2>/dev/null | tr '\n' ' ')" \
		"2001:db8:44::53 "
	# A suffix to complete a bare name with, never a routing domain (0049, 0067).
	check "and its search suffix" \
		"$(sed -n 's/^search=//p' "$fragment" 2>/dev/null | tr '\n' ' ')" \
		"v6.example "
	# It reaches the observation, which is what anything downstream reads.
	"$ncfg" status --json > "$work/status6.json" 2>&1 || true
	contains "and it reaches the observation" \
		"$(cat "$work/status6.json")" "2001:db8:44::53"

	# And netcfgd does not deliver them on this document's say-so, which is the
	# half that makes the two decisions agree rather than trade places. The
	# second gate in the reporting contract wants the addressing to come from
	# the report or the interface to have a `dns` block, and `dhcp6` alone is
	# neither. 0072 stopped dhcpcd writing the resolver file; 0086 must not
	# start writing it in dhcpcd's place.
	#
	# `$work/resolv.conf` and not `$resolv`: that one is the system file the
	# counter-proofs above watch dhcpcd rewrite, and asserting a v6 nameserver
	# is absent from it would pass whatever netcfgd did.
	missing "and netcfgd does not deliver them unasked" \
		"$(cat "$work/resolv.conf" 2>/dev/null)" "2001:db8:44::53"

	# With a `dns` block it does, which is the whole point of carrying them.
	cat > "$work/etc/netcfgd.conf" <<'CONF'
global { dns { dns_mode = "write_resolv_conf" } }
interface cli {
	config = "dhcp6"
	dns    = "2001:db8:44::53"
}
CONF
	"$ncfg" apply > "$work/apply6-dns.log" 2>&1 || true
	if wait_for 'grep -q 2001:db8:44::53 "$work/resolv.conf"'; then
		echo "ok   and a document that asks for it gets the lease's resolver"
	else
		echo "FAIL and a document that asks for it gets the lease's resolver"
		echo "       $work/resolv.conf says: $(cat "$work/resolv.conf" 2>/dev/null)"
		echo "       apply said:"
		sed 's/^/       /' "$work/apply6-dns.log"
		failures=$((failures + 1))
	fi
	printf 'nameserver 203.0.113.99\n' > "$work/etc-resolv"
	cat > "$work/etc/netcfgd.conf" <<'CONF'
interface cli {
	config = "dhcp6"
}
CONF
	"$ncfg" apply > "$work/apply6-dns-off.log" 2>&1 || true

	# Stopping it is 0071's arm, from the family that has two clients: there is
	# no odhcp6c here, so this is the dhcpcd half of it.
	v6pid=$(cat /run/dhcpcd/cli-6.pid 2>/dev/null || echo 0)
	cat > "$work/etc/netcfgd.conf" <<'CONF'
interface cli {
}
CONF
	"$ncfg" apply > "$work/apply6-stop.log" 2>&1 || {
		cat "$work/apply6-stop.log" >&2
		exit 1
	}
	if [ "$v6pid" -gt 0 ] && wait_for "! kill -0 $v6pid 2>/dev/null"; then
		echo "ok   and dropping dhcp6 stops the client, which named its own pid file"
	else
		echo "FAIL and dropping dhcp6 stops the client, which named its own pid file"
		echo "       pid $v6pid, and /run/dhcpcd holds $(ls /run/dhcpcd 2>&1)"
		failures=$((failures + 1))
	fi
	kill "$dnsmasq_pid" 2>/dev/null || true
fi

echo
if [ "$failures" -eq 0 ]; then
	echo "dhcpcd.sh: all checks passed"
else
	echo "dhcpcd.sh: $failures failed"
	exit 1
fi
