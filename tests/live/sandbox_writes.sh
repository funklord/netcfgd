#!/bin/sh
# Writing files under the sandbox a systemd unit actually imposes.
#
#     sh tests/live/sandbox_writes.sh
#
# The fault this was written for: the unit set `ProtectSystem=full`, which
# mounts /etc read-only, and opened one path back up with
# `ReadWritePaths=-/etc/resolv.conf`. That grants the **file**. Creating a new
# entry in /etc is still refused, and `write_resolv_conf` staged a temporary
# beside the target before renaming it -- so on every systemd machine it failed
# with "Read-only file system" naming a dotfile the operator has never seen,
# for a file they had explicitly made writable.
#
# The unit now sets `ProtectSystem=yes` and `ReadWritePaths=/etc` (0176). The
# blocks below still drive the narrow grant on purpose: a hardened drop-in or a
# read-only root still produces one, and the fallback and the symlink refusal
# are what runs there.
#
# **What every block below cannot see, and the last one now asks.** They make
# their own mounts, so they check what netcfgd does *given* a sandbox rather
# than what the unit's own declaration produces -- and those are different
# questions. `ProtectSystem=full` with `ReadWritePaths=/etc` grants nothing,
# because the remount is applied after the bind mount; this file went on
# passing throughout the period that pairing was shipped. The final block asks
# systemd to impose the unit's real properties and reads back whether /etc is
# writable, with a control that proves the probe can see a sandbox at all.
#
# **This makes the mounts rather than using permissions, and the difference is
# the whole point of the script.** A `chmod a-w` on the directory reproduces
# the symptom for an unprivileged process and not for netcfgd: root has
# CAP_DAC_OVERRIDE and walks through a mode. It does not walk through a
# read-only mount. Measured while writing this -- a first version ran under
# `unshare -rn` with a chmod'd directory, passed, and passed just as happily
# with the fix removed.
#
# Its own namespaces, like slaac.sh and dhcpcd_orphan.sh: it needs mount, and
# `unshare -rn` from the Makefile would already have taken the ones it wants.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "sandbox_writes.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "sandbox_writes.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/ncfg" ] || skip "ncfg is not built"
unshare -rm true 2>/dev/null || skip "no user and mount namespaces here"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-dnssb.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$work/etc" "$work/run" "$work/sys"

cat > "$work/etc/netcfgd.conf" <<'CONF'
global {
	dns {
		mode    = "write_resolv_conf"
		servers = "192.0.2.53 192.0.2.54"
	}
}
CONF

printf 'nameserver 127.0.0.53\n' > "$work/sys/resolv.conf"
# The read-write bind source, standing in for what systemd bind-mounts over a
# path named in ReadWritePaths.
printf 'nameserver 127.0.0.53\n' > "$work/writable"

# The mounts happen inside the namespace, and so does the run, because a mount
# namespace does not outlive the process that made it.
unshare -rm sh -c '
	set -eu
	work=$1
	repo=$2
	mount --bind "$work/sys" "$work/sys"
	mount -o remount,bind,ro "$work/sys"
	mount --bind "$work/writable" "$work/sys/resolv.conf"
	NCFG_CONFIG_DIR="$work/etc" \
	NCFG_RUN_DIR="$work/run" \
	NCFG_RESOLV_CONF="$work/sys/resolv.conf" \
		"$repo/target/debug/ncfg" apply --oneshot > "$work/apply.log" 2>&1 || true
	# Read it back from inside, where the bind mount is visible.
	cat "$work/sys/resolv.conf" > "$work/seen"
' sh "$work" "$repo"

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

check "the delivery reports success" \
	"$(grep -c '^ok   dns.apply' "$work/apply.log" || true)" "1"
check "and nothing complains about a read-only filesystem" \
	"$(grep -ci 'read-only file system' "$work/apply.log" || true)" "0"
check "the servers reached the file" \
	"$(grep -c '^nameserver 192.0.2.53' "$work/seen" || true)" "1"
check "and the old contents are gone" \
	"$(grep -c '^nameserver 127.0.0.53' "$work/seen" || true)" "0"

# **The same shape through the other writer.** `netcfgd-host`'s
# `write_atomically` stages and renames exactly as `netcfgd-dns`'s `replace`
# does, and it is what every config, secret and profile write goes through --
# so it is what the GUI's write verbs reach. The packaged unit grants
# `/etc/netcfgd` as a whole directory, so those writes stage happily today;
# this pins the behaviour for a deployment that grants less, and for the next
# path added under a narrower grant.
mkdir -p "$work/etc2/netcfgd" "$work/run2" "$work/rw2"
printf 'global { }
' > "$work/etc2/netcfgd/netcfgd.conf"
printf 'global { }
' > "$work/rw2/netcfgd.conf"

unshare -rm sh -c '
	set -eu
	work=$1
	repo=$2
	mount --bind "$work/etc2" "$work/etc2"
	mount -o remount,bind,ro "$work/etc2"
	# The tightest grant a hardened unit could write: the config file alone.
	mount --bind "$work/rw2/netcfgd.conf" "$work/etc2/netcfgd/netcfgd.conf"
	NCFG_CONFIG_DIR="$work/etc2/netcfgd" NCFG_RUN_DIR="$work/run2" \
		"$repo/target/debug/ncfg" control set --observe any > "$work/control.log" 2>&1 || true
	cat "$work/etc2/netcfgd/netcfgd.conf" > "$work/seen2"
' sh "$work" "$repo"

check "a config file granted alone is written" \
	"$(grep -c 'observe = "any"' "$work/seen2" || true)" "1"
check "and nothing complains about a read-only filesystem" \
	"$(grep -ci 'read-only file system' "$work/control.log" || true)" "0"

# **The case the first version of this script could not see (0164).**
#
# Everything above uses a REGULAR FILE at resolv.conf, which is what 0161 was
# reproduced against. On any machine running systemd-resolved, /etc/resolv.conf
# is a SYMLINK into /run/systemd/resolve -- and there the two paths 0161 left
# behind do not intersect: staging is refused by the sandbox, and the in-place
# fallback refuses on purpose rather than writing through the link into
# another resolver's state. So the mode could not work at all, which is what
# was reported from a systemd machine.
#
# The fix is the grant: the unit names /etc rather than the one file, so
# netcfgd can unlink the link and put its own file there. Both halves are
# checked -- that the wide grant replaces a symlink, and that the narrow one
# still refuses cleanly rather than scribbling in somebody else's file.
mkdir -p "$work/etc3" "$work/run3" "$work/stub3"
cat > "$work/etc3/netcfgd.conf" <<'CONF'
global {
	dns {
		mode    = "write_resolv_conf"
		servers = "192.0.2.53 192.0.2.54"
	}
}
CONF
mkdir -p "$work/sys3"
printf 'nameserver 127.0.0.53\n' > "$work/stub3/stub-resolv.conf"
ln -s "$work/stub3/stub-resolv.conf" "$work/sys3/resolv.conf"

# a. The packaged grant: /etc writable as a directory.
unshare -rm sh -c '
	set -eu
	work=$1; repo=$2
	mount --bind "$work/sys3" "$work/sys3"
	NCFG_CONFIG_DIR="$work/etc3" NCFG_RUN_DIR="$work/run3" \
	NCFG_RESOLV_CONF="$work/sys3/resolv.conf" \
		"$repo/target/debug/ncfg" apply --oneshot > "$work/sym_wide.log" 2>&1 || true
	cat "$work/sys3/resolv.conf" > "$work/sym_wide.seen" 2>/dev/null || true
	if [ -L "$work/sys3/resolv.conf" ]; then echo link; else echo file; fi > "$work/sym_wide.kind"
' sh "$work" "$repo"

check "a symlinked resolv.conf is replaced when /etc is granted" \
	"$(grep -c '^nameserver 192.0.2.53' "$work/sym_wide.seen" 2>/dev/null || true)" "1"
check "and what is there afterwards is netcfgd's own file, not a link" \
	"$(cat "$work/sym_wide.kind" 2>/dev/null || true)" "file"
check "and the resolver whose link it was keeps its own file untouched" \
	"$(grep -c '^nameserver 127.0.0.53' "$work/stub3/stub-resolv.conf" || true)" "1"

# b. The narrow grant, which is what a hardened drop-in or a read-only root
#    still produces. It must refuse, and must not write through the link.
mkdir -p "$work/sys4" "$work/stub4" "$work/run4"
printf 'nameserver 127.0.0.53\n' > "$work/stub4/stub-resolv.conf"
ln -s "$work/stub4/stub-resolv.conf" "$work/sys4/resolv.conf"
printf 'nameserver 127.0.0.53\n' > "$work/writable4"

unshare -rm sh -c '
	set -eu
	work=$1; repo=$2
	mount --bind "$work/sys4" "$work/sys4"
	mount -o remount,bind,ro "$work/sys4"
	# ReadWritePaths= on a symlink grants the resolved target, not the link.
	mount --bind "$work/writable4" "$work/stub4/stub-resolv.conf"
	NCFG_CONFIG_DIR="$work/etc3" NCFG_RUN_DIR="$work/run4" \
	NCFG_RESOLV_CONF="$work/sys4/resolv.conf" \
		"$repo/target/debug/ncfg" apply --oneshot > "$work/sym_narrow.log" 2>&1 || true
	cat "$work/stub4/stub-resolv.conf" > "$work/sym_narrow.target"
' sh "$work" "$repo"

check "a narrow grant refuses a symlink rather than following it" \
	"$(grep -c 'is a symlink' "$work/sym_narrow.log" || true)" "1"
check "and says so in one line an operator can read" \
	"$(awk '/is a symlink/ {print gsub(/\t/, "")}' "$work/sym_narrow.log" | head -1)" "0"
check "and the other resolver's file is not written through the link" \
	"$(grep -c '^nameserver 192.0.2.53' "$work/sym_narrow.target" || true)" "0"

# **What a refused write SAYS, which is the half that had rotted.**
#
# `write_atomically` stages beside the target and falls back to writing in
# place when the directory refuses it. The fallback opens an existing file on
# purpose (0161) -- so for a file that is not there yet it answers `ENOENT`,
# and that answer replaced the refusal that was the actual cause. Every
# `ncfg config put` of a new drop-in under a read-only /etc was reported as
#
#     could not write /etc/netcfgd/conf.d/thing.conf: No such file or directory
#
# naming a file the operator had just asked to create, as missing. The reason
# was one directory up and was thrown away. `netcfgd-dns`'s copy of the same
# fallback has always carried the staging error into its message; this one is
# the drift the note on that copy predicts.
#
# Driven through a **daemon**, because that is who writes since 0127 and
# because nothing else here does: `sandbox_writes.sh` ran `ncfg` directly, so
# the entire client-asks-daemon collapse had never met a real mount.
mkdir -p "$work/etc5/netcfgd/conf.d" "$work/run5"
printf 'global { }\n' > "$work/etc5/netcfgd/netcfgd.conf"
printf 'global { }\n' > "$work/drop5.conf"

# **`-n` as well as `-m`, unlike every block above.** Those run `ncfg apply
# --oneshot` against a configuration that names only a file in this work
# directory, so they touch nothing else. This one starts the *daemon*, which
# has a reconcile loop and would have run it against the machine's own network
# -- `--no-apply-on-start` and an empty document make that harmless and a
# network namespace makes it impossible, which is the order to want them in.
unshare -rmn sh -c '
	set -eu
	work=$1; repo=$2
	mount --bind "$work/etc5" "$work/etc5"
	mount -o remount,bind,ro "$work/etc5"
	NCFG_CONFIG_DIR="$work/etc5/netcfgd" NCFG_RUN_DIR="$work/run5" \
		"$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon5.log" 2>&1 &
	daemon=$!
	waited=0
	while [ ! -S "$work/run5/netcfgd.sock" ]; do
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
	NCFG_CONFIG_DIR="$work/etc5/netcfgd" NCFG_RUN_DIR="$work/run5" \
		"$repo/target/debug/ncfg" config put thing "$work/drop5.conf" \
		> "$work/put5.log" 2>&1 || true
	kill "$daemon" 2>/dev/null || true
	wait "$daemon" 2>/dev/null || true
' sh "$work" "$repo"

# The control. Everything below is about the wording of a refusal, so a run
# where nothing was refused would pass every one of them by saying nothing.
check "the write was refused, which is what the rest of this is about" \
	"$(grep -ci 'could not write' "$work/put5.log" || true)" "1"
check "the refusal names the directory rather than the file that is not there" \
	"$(grep -c 'conf.d would not take a temporary file' "$work/put5.log" || true)" "1"
check "and gives the kernel's reason for it" \
	"$(grep -ci 'read-only file system' "$work/put5.log" || true)" "1"
# The fallback's own error is an artifact of the fallback: it opens what is
# there, and nothing was.
check "not the fallback's answer about a file nobody asked to open" \
	"$(grep -ci 'no such file or directory' "$work/put5.log" || true)" "0"
check "and it says where a systemd machine grants that directory" \
	"$(grep -c 'ReadWritePaths=' "$work/put5.log" || true)" "1"

# **The other half, for a client with nowhere to send it.** A refusal and "no
# daemon is listening" are two different things to do about one failure, and
# every write verb but `ncfg wifi add` said only the first -- so a reader went
# looking for a mode to change when starting netcfgd would have done. The
# classification is the kernel's error kind rather than the words in the
# message: `ErrorKind::ReadOnlyFilesystem` is the same refusal as
# `PermissionDenied` arriving from a mount instead of a mode, and it was not
# counted, which switched the sentence off in exactly the case it was written
# for.
unshare -rmn sh -c '
	set -eu
	work=$1; repo=$2
	mount --bind "$work/etc5" "$work/etc5"
	mount -o remount,bind,ro "$work/etc5"
	NCFG_CONFIG_DIR="$work/etc5/netcfgd" NCFG_RUN_DIR="$work/nosuchrun" \
		"$repo/target/debug/ncfg" config put thing "$work/drop5.conf" \
		> "$work/put6.log" 2>&1 || true
' sh "$work" "$repo"

check "a refused write with no daemon says the write was refused" \
	"$(grep -ci 'read-only file system' "$work/put6.log" || true)" "1"
check "and that there was nobody to ask instead" \
	"$(grep -c 'nothing is listening on' "$work/put6.log" || true)" "1"

# **Said once at startup, rather than once per write.** 0127 makes netcfgd the
# only writer of its own configuration, so a read-only `/etc/netcfgd` refuses
# every write verb a client has -- one at a time, in front of whoever pressed
# the button. The condition is true from the moment the daemon starts, so that
# is where it is reported: in `systemctl status` and the journal, before
# anybody tries. Reported from an install that met it the other way round.
check "the daemon says at startup that it cannot write its configuration" \
	"$(grep -c 'so no client can store configuration' "$work/daemon5.log" || true)" "1"
check "and names the setting that grants it" \
	"$(grep -c 'ReadWritePaths=' "$work/daemon5.log" || true)" "1"

# The control, and it is the half that decides whether the check above means
# anything: a warning printed unconditionally would pass that grep on every
# machine. The same daemon, the same directory, no read-only mount.
unshare -rmn sh -c '
	set -eu
	work=$1; repo=$2
	NCFG_CONFIG_DIR="$work/etc5/netcfgd" NCFG_RUN_DIR="$work/run7" \
		"$repo/target/debug/netcfgd" --no-apply-on-start > "$work/daemon7.log" 2>&1 &
	daemon=$!
	waited=0
	while [ ! -S "$work/run7/netcfgd.sock" ]; do
		waited=$((waited + 1))
		[ "$waited" -gt 50 ] && break
		sleep 0.1
	done
	kill "$daemon" 2>/dev/null || true
	wait "$daemon" 2>/dev/null || true
' sh "$work" "$repo"
check "and says nothing of the sort when it can write" \
	"$(grep -c 'so no client can store configuration' "$work/daemon7.log" || true)" "0"
check "the control daemon really started, so its silence means something" \
	"$(grep -c 'watching' "$work/daemon7.log" || true)" "1"

# **The grant itself, because every check above depends on it.** A unit that
# narrowed this back to the one file would put the reported fault straight
# back, and the tests above would go on passing case (b) while (a) failed with
# no hint that the unit was the reason.
unit="$repo/packaging/systemd/netcfgd.service"
check "the unit grants the directory rather than the file" \
	"$(grep -c '^ReadWritePaths=/etc$' "$unit")" "1"
check "and no longer grants resolv.conf alone" \
	"$(grep -c '^ReadWritePaths=-*/etc/resolv.conf$' "$unit")" "0"

# **And that the grant does anything, which is a different question and is the
# one this file could not ask.** Everything above makes its own mounts. That is
# deliberate and is what lets the script run on a machine with no systemd -- but
# it means every functional check models a sandbox rather than meeting one, and
# the two checks above assert that a *line is present*. Both were true, and
# green, throughout the period when netcfgd could write nothing under /etc at
# all.
#
# `ProtectSystem=` applies its read-only remount AFTER the `ReadWritePaths=`
# bind mounts, so an entry naming the very path being remounted is covered
# straight back over and grants nothing. `ProtectSystem=full` with
# `ReadWritePaths=/etc` is exactly that pairing. A subpath survives, which is
# why the four narrow paths this file was written against worked and the single
# wide one that replaced them did not. Decision 0176.
#
# Read from the unit rather than restated here, so that changing either line is
# what changes this check. `findmnt -T` names the mount covering a path, which
# answers for `ProtectSystem=yes` too -- there is no /etc mount at all under it,
# and the covering mount is `/`. A write probe would work as well and is not
# used: it would create a file in the real /etc, and this needs to observe
# rather than modify.
if ! command -v systemd-run >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
	note="no systemd here, so the unit's real sandbox is unchecked"
elif [ "$(id -u)" != 0 ]; then
	note="not root, so systemd-run cannot impose the unit's sandbox"
else
	note=
fi
if [ -n "${note:-}" ]; then
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "sandbox_writes.sh: NCFG_LIVE is set but $note" >&2
		exit 1
	fi
	echo "note $note"
else
	protect=$(sed -n 's/^ProtectSystem=\(.*\)$/\1/p' "$unit" | tail -1)
	properties="-p ProtectSystem=$protect"
	for granted in $(sed -n 's/^ReadWritePaths=\(.*\)$/\1/p' "$unit"); do
		properties="$properties -p ReadWritePaths=$granted"
	done
	# Kept apart from `$properties`, because the control below has to impose
	# everything the unit declares *except* this one.
	exec_properties=
	for allowed in $(sed -n 's/^ExecPaths=\(.*\)$/\1/p' "$unit"); do
		exec_properties="$exec_properties -p ExecPaths=$allowed"
	done
	# Bounded from outside as well as by the command: a transient unit that
	# hung would otherwise hold this script for ever.
	etc_state=$(timeout 60 systemd-run --quiet --wait --pipe --collect \
		$properties /bin/sh -c 'findmnt -T /etc -no OPTIONS | cut -d, -f1' \
		2>/dev/null || echo unknown)

	check "the unit's own ProtectSystem= and ReadWritePaths= leave /etc writable" \
		"$etc_state" "rw"

	# **And that a script in netcfgd's runtime directory can be executed.**
	# systemd mounts /run `noexec` by default since v256, and netcfgd writes
	# scripts there for the programs it drives: udhcpc's, odhcp6c's prefix
	# hook, pppd's ip-up and ip-down, and the hook bodies an operator writes
	# inline, which are materialised at 0700 and executed directly. Without
	# `ExecPaths=` every one answers EACCES -- silently for the clients, whose
	# refusal goes to their own log, and absolutely for the hooks: no `pre_up`
	# or `post_up` runs at all.
	#
	# Driven through `sh -c` so the exec is done by a *child*, which is the
	# case that matters: it is udhcpc and pppd that run these, not netcfgd.
	probe_dir=/run/netcfgd
	mkdir -p "$probe_dir" 2>/dev/null || true
	printf '#!/bin/sh\necho EXECOK\n' > "$probe_dir/.sandbox-probe" 2>/dev/null || true
	chmod 0700 "$probe_dir/.sandbox-probe" 2>/dev/null || true
	exec_state=$(timeout 60 systemd-run --quiet --wait --pipe --collect \
		$properties $exec_properties \
		/bin/sh -c "$probe_dir/.sandbox-probe" 2>/dev/null || echo denied)
	check "a script in netcfgd's runtime directory can be executed by a child" \
		"$exec_state" "EXECOK"

	# The control, and this one is not optional: /run is only `noexec` on a
	# systemd new enough to make it so, and on anything older the check above
	# passes for a reason that has nothing to do with the unit. Dropping
	# ExecPaths= has to make it fail, or it is measuring the machine rather
	# than the declaration.
	denied_state=$(timeout 60 systemd-run --quiet --wait --pipe --collect \
		$properties \
		/bin/sh -c "$probe_dir/.sandbox-probe" 2>/dev/null || echo denied)
	check "and cannot without the unit's ExecPaths=, so that line is load-bearing" \
		"$denied_state" "denied"
	rm -f "$probe_dir/.sandbox-probe"

	# **The control, and this check is worth nothing without it.** `rw` above
	# would also be the answer if the properties had failed to apply, if
	# `systemd-run` had ignored them, or if this had probed a path no sandbox
	# covers. Impose a level known to hold /etc read-only and require the
	# probe to see it: that proves the mechanism is being exercised, so the
	# `rw` above is the unit's doing rather than the sandbox's absence.
	sealed=$(timeout 60 systemd-run --quiet --wait --pipe --collect \
		-p ProtectSystem=full -p ReadWritePaths=/etc \
		/bin/sh -c 'findmnt -T /etc -no OPTIONS | cut -d, -f1' \
		2>/dev/null || echo unknown)
	check "and the probe can see a sandbox that does not, so rw means something" \
		"$sealed" "ro"
fi

if [ "$failures" -eq 0 ]; then
	echo "sandbox_writes.sh: all checks passed"
else
	echo "sandbox_writes.sh: $failures check(s) failed"
	sed 's/^/       /' "$work/apply.log" "$work/control.log" 2>/dev/null >&2
	exit 1
fi
