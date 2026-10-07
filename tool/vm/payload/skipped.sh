# Every live script that skips on the development machine, run in a guest.
#
# These are the ones whose own skip reasons name real root, module loading,
# /dev/vhci, /dev/ppp or a tool the machine has not got. The guest has its own
# kernel and its own init and runs as root, so what each does here is a
# measurement rather than a prediction -- which is why this runs them all and
# reports, instead of being told in advance which ought to work.
#
# **The first version of this file reported nine of nine passing, and all nine
# were wrong.** It tested the exit status of
#
#     NCFG_LIVE=1 sh "$path" 2>&1 | sed 's/^/    /'
#
# which is `sed`'s status and not the script's, so every script "passed" -- six
# of them while printing that they could not run at all. That is `evidence.md`'s
# rule about a pipeline's exit status, written into a payload whose whole job is
# to report statuses. The output goes to a file now and the status read from the
# script itself.
#
# `NCFG_LIVE=1` for each: a skip becomes a failure, so a script that still
# cannot run says so rather than reporting a pass over nothing. Nothing stops on
# a failure -- one script failing must not hide the others.
set -u
cd /mnt/repo || { echo "the repository is not mounted"; exit 1; }

# What the scripts need and the image has not got. Installed here rather than
# through cloud-init's `packages:` so that a name Debian does not carry is
# reported by this payload instead of failing quietly during boot -- the host's
# own apt indices could not answer for the guest's, several of these showing no
# candidate there while the guest has full sources.
echo "=== installing what the scripts need"
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update 2>&1 | tail -2
for pkg in wpasupplicant iw ppp pppoe odhcp6c kea-dhcp6-server radvd \
	network-manager bluez python3-gi; do
	if apt-get -qq -y install "$pkg" >/dev/null 2>&1; then
		echo "    $pkg: installed"
	else
		echo "    $pkg: NOT AVAILABLE"
	fi
done
echo

# **Each script is invoked the way the Makefile invokes it, and the first
# version of this was not.** `make live` runs them in three shapes: `nm.sh` and
# `ppp.sh` under `unshare -rn`, `select.sh` bare with NCFG_LIVE, and the rest
# bare because they make their own namespaces. Running all nine bare put
# `nm.sh` on the guest's real network instead of in the namespace its own
# header documents, where `lo` is down with no address -- so it reported
# `loopback:connected` against an expected `loopback:unavailable` and that read
# as a netcfgd fault when it was this payload's.
#
# A test's environment is part of the test. Inventing a simpler invocation
# than the suite's produces failures that belong to the harness.
needs_netns() {
	case "$1" in
	nm | ppp) return 0 ;;
	*) return 1 ;;
	esac
}

passed=0
failed=0
for script in bluetooth hwsim ppp pppoe-session delegation killmode select nm \
	association; do
	path="tests/live/$script.sh"
	[ -f "$path" ] || {
		echo "=== $script.sh: NOT PRESENT"
		continue
	}
	echo "=== $script.sh"
	# The status is the script's own, read from a file rather than through a
	# pipe. The output is printed afterwards whatever happened, because the run
	# whose output matters is the one that failed.
	if needs_netns "$script"; then
		run="unshare -rn sh -c \"NCFG_LIVE=1 sh $path\""
	else
		run="NCFG_LIVE=1 sh $path"
	fi
	if sh -c "$run" > /tmp/out.$script 2>&1; then
		verdict=passed
		passed=$((passed + 1))
	else
		verdict=FAILED
		failed=$((failed + 1))
	fi
	sed 's/^/    /' < /tmp/out.$script
	echo "    --> $verdict"
done

echo
echo "skipped-scripts: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
