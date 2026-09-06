#!/bin/sh
# Writing files under the sandbox a systemd unit actually imposes.
#
#     sh tests/live/sandbox_writes.sh
#
# `packaging/systemd/netcfgd.service` sets `ProtectSystem=full`, which mounts
# /etc read-only, and opens one path back up with
# `ReadWritePaths=-/etc/resolv.conf`. That grants the **file**. Creating a new
# entry in /etc is still refused, and `write_resolv_conf` staged a temporary
# beside the target before renaming it -- so on every systemd machine it failed
# with "Read-only file system" naming a dotfile the operator has never seen,
# for a file they had explicitly made writable.
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

# **The grant itself, because every check above depends on it.** A unit that
# narrowed this back to the one file would put the reported fault straight
# back, and the tests above would go on passing case (b) while (a) failed with
# no hint that the unit was the reason.
unit="$repo/packaging/systemd/netcfgd.service"
check "the unit grants the directory rather than the file" \
	"$(grep -c '^ReadWritePaths=/etc$' "$unit")" "1"
check "and no longer grants resolv.conf alone" \
	"$(grep -c '^ReadWritePaths=-*/etc/resolv.conf$' "$unit")" "0"

if [ "$failures" -eq 0 ]; then
	echo "sandbox_writes.sh: all checks passed"
else
	echo "sandbox_writes.sh: $failures check(s) failed"
	sed 's/^/       /' "$work/apply.log" "$work/control.log" 2>/dev/null >&2
	exit 1
fi
