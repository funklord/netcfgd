#!/bin/sh
# An 802.1X network, end to end, on a machine with nothing configured.
#
# WHY THIS FILE EXISTS
#   The enterprise path is where the worst fault of M8 was, and it had no live
#   coverage at all: `private_key` was sent to wpa_supplicant as the key's
#   *content*, producing `SET_NETWORK 0 private_key "-----BEGIN PRIVATE KEY-----`
#   -- a filename that does not exist, and a newline in the middle of a
#   line-based control protocol, corrupting every command after it. The only
#   EAP-TLS case in the tree asserted a missing-field error, so nothing ever
#   rendered a complete one.
#
#   What replaced it is `CertSource`: a certificate is either a path on this
#   machine or a reference to content netcfgd holds, and the resolver turns
#   both into a path because wpa_supplicant opens all three as files. That is
#   the machinery this exercises, and the assertion that matters is what
#   arrives on the control socket -- a path that exists, never the content.
#
#   The tier split is the other half. A path in a request is an instruction to
#   open a file as root, so it stays privileged; a `@secret:` reference names
#   content a caller already gave netcfgd, so it is ordinary. Both are checked.
#
# POSIX sh, not bash: this runs wherever the project does.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)

skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "enterprise.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "enterprise.sh: skipping: $1"
	exit 0
}

[ -x "$repo/target/debug/netcfgd" ] || skip "netcfgd is not built"
command -v python3 >/dev/null 2>&1 || skip "python3 is not installed"
command -v ip >/dev/null 2>&1 || skip "iproute2 is not installed"

work=$(mktemp -d /tmp/ncfg-ent.XXXXXX)
ncfg="$repo/target/debug/ncfg"
[ -x "$ncfg" ] || ncfg="$repo/target/debug/netcfgd"
daemon=
failures=0

cleanup() {
	[ -n "$daemon" ] && kill "$daemon" 2>/dev/null
	wait "$daemon" 2>/dev/null || true
	for pidfile in "$work"/run/supplicant/*.pid; do
		[ -e "$pidfile" ] || continue
		kill "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null || true
	done
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

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
lacks() {
	case "$2" in
	*"$3"*)
		echo "FAIL $1"
		echo "       should not contain: $3"
		failures=$((failures + 1))
		;;
	*) echo "ok   $1" ;;
	esac
}

ip link add radio0 type dummy 2>/dev/null || skip "cannot create a dummy link"
ip link set radio0 up
mkdir -p "$work/sys/radio0/wireless" "$work/etc/conf.d" "$work/run" "$work/ctrl"
cp "$repo/tests/live/fake_supplicant.py" "$work/fake_supplicant"
chmod +x "$work/fake_supplicant"

export NCFG_CONFIG_DIR="$work/etc"
export NCFG_RUN_DIR="$work/run"
export NCFG_SYS_CLASS_NET="$work/sys"
export NCFG_WPA_CTRL_DIR="$work/ctrl"
# **Isolated from the host's NetworkManager state.** netcfgd refuses to start a
# supplicant on an interface another manager claims, and it learns that from the
# files NM leaves under `/run/NetworkManager/devices/<ifindex>`. On a developer
# machine those exist for real interfaces -- including `lo`, index 1 -- so
# without this a test would read the host's NM and be refused for reasons that
# have nothing to do with what it is testing. `displace.sh` points this at a
# tree it populates on purpose; everything else points it at an empty one.
mkdir -p "$work/runroot"
export NCFG_RUN_ROOT="$work/runroot"
export NCFG_WPA_SUPPLICANT="$work/fake_supplicant"

: > "$work/etc/netcfgd.conf"
"$repo/target/debug/netcfgd" > "$work/daemon.log" 2>&1 &
daemon=$!
waited=0
while [ ! -e "$work/run/netcfgd.sock" ]; do
	waited=$((waited + 1))
	if [ "$waited" -gt 60 ]; then
		cat "$work/daemon.log" >&2
		echo "enterprise.sh: the daemon never started" >&2
		exit 1
	fi
	sleep 0.1
done

"$ncfg" wifi activate radio0 > "$work/activate.log" 2>&1 ||
	{ cat "$work/activate.log" >&2; echo "enterprise.sh: activate failed" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. A certificate is content netcfgd holds, put there over the socket.
#
# Not a path: a request naming one would be an instruction to open a file as
# root, which is a much larger permission than "remember this certificate".
pem="$work/corp-ca.pem"
{
	echo "-----BEGIN CERTIFICATE-----"
	echo "TUlJRkFrZUNlcnRpZmljYXRlRm9yQVRlc3RPbmx5Tm90UmVhbA=="
	echo "-----END CERTIFICATE-----"
} > "$pem"

"$ncfg" secret set corp-ca < "$pem" > "$work/secret.log" 2>&1 ||
	{ cat "$work/secret.log" >&2; echo "enterprise.sh: secret set failed" >&2; exit 1; }
check "a stored certificate is written at 0600" \
	"$(stat -c '%a' "$work/etc/secrets/corp-ca" 2>/dev/null || echo missing)" "600"

# ---------------------------------------------------------------------------
# 2. Adding the network, with the certificate named rather than pasted.
printf 'corp-password\n' | "$ncfg" wifi add eduroam \
	--eap peap --identity 'you@corp.example' --phase2 mschapv2 \
	--ca-cert '@secret:corp-ca' > "$work/add.log" 2>&1 ||
	{ cat "$work/add.log" >&2; echo "enterprise.sh: the enterprise add failed" >&2; exit 1; }

block=$(cat "$work/etc/conf.d/wifi-eduroam.conf" 2>/dev/null || echo "")
contains "the network block says which EAP method" "$block" 'eap = "peap"'
contains "and who you are to the authentication server" "$block" 'you@corp.example'
contains "and the inner method" "$block" 'mschapv2'
contains "and names the stored certificate" "$block" '@secret:corp-ca'
contains "and refers to the credential rather than holding it" "$block" 'password = "@secret:eduroam"'
lacks "the password is not in the configuration" "$block" "corp-password"
lacks "nor is the certificate's content" "$block" "BEGIN CERTIFICATE"
check "the credential is stored at 0600" \
	"$(stat -c '%a' "$work/etc/secrets/eduroam" 2>/dev/null || echo missing)" "600"

# ---------------------------------------------------------------------------
# 3. What reaches the supplicant, which is the half that was wrong.
"$ncfg" wifi connect eduroam > "$work/connect.log" 2>&1 || true
waited=0
while ! grep -q "SET_NETWORK.*key_mgmt" "$work/daemon.log" 2>/dev/null; do
	waited=$((waited + 1))
	[ "$waited" -gt 60 ] && break
	sleep 0.1
done
sent=$(cat "$work/daemon.log" 2>/dev/null || echo "")

contains "the supplicant is told this is 802.1X" "$sent" "key_mgmt WPA-EAP FT-EAP"
contains "and which method" "$sent" "eap PEAP"
contains "and the inner method" "$sent" "phase2"

# **The fault this file exists for.** wpa_supplicant opens `ca_cert` as a file,
# so what must arrive is a path -- and a certificate stored as content has to
# be written out first. Content on this line was a filename that does not
# exist and a newline through a line-based protocol.
lacks "the certificate's content never reaches the control socket" \
	"$sent" "BEGIN CERTIFICATE"
contains "a path does instead" "$sent" "$work/run/certs"

# The path the supplicant was actually given, taken out of what it was sent
# rather than guessed. The first version of this assumed the file was named
# after the secret and it is named after the field, so the checks below were
# looking at a path netcfgd had never written -- a test asserting its own guess
# rather than the program's behaviour.
materialised=$(printf '%s\n' "$sent" |
	sed -n 's/.*SET_NETWORK 0 ca_cert "\([^"]*\)".*/\1/p' | head -1)
check "the supplicant was given a path at all" \
	"$([ -n "$materialised" ] && echo yes || echo no)" "yes"
check "and the path is a real file" \
	"$([ -e "$materialised" ] && echo yes || echo no)" "yes"
check "at 0600, because it is key material" \
	"$(stat -c '%a' "$materialised" 2>/dev/null || echo missing)" "600"
check "in a directory only root can enter" \
	"$(stat -c '%a' "$work/run/certs" 2>/dev/null || echo missing)" "700"
contains "holding what was stored" "$(cat "$materialised" 2>/dev/null || echo "")" \
	"BEGIN CERTIFICATE"

# The credential goes under the keyword the method implies, and the fake
# redacts it -- so what is asserted is that the keyword was sent, never the
# value. A test fixture logging a password is the habit this refuses.
# The fake redacts from ` password ` onward, so what it logs for that command
# is the bare `SET_NETWORK 0` -- which is the evidence that the credential was
# sent *and* that nothing wrote it down. Asserting the keyword itself would
# require the fixture to log the thing it exists not to log.
contains "a redacted credential line was sent" "$sent" "SET_NETWORK 0
"
lacks "and no credential value is in any log" "$sent" "corp-password"

# ---------------------------------------------------------------------------
# 4. A certificate given as a path is a privileged request, and is refused.
printf 'other-password\n' | "$ncfg" wifi add other \
	--eap peap --identity 'you@corp.example' \
	--ca-cert /etc/ssl/certs/ca-certificates.crt > "$work/path.log" 2>&1 || true
contains "a certificate given as a path is refused from a client" \
	"$(cat "$work/path.log")" "ncfg secret set"
check "and no network was written for it" \
	"$([ -e "$work/etc/conf.d/wifi-other.conf" ] && echo yes || echo no)" "no"

echo
if [ "$failures" -eq 0 ]; then
	echo "enterprise.sh: all checks passed"
else
	echo "enterprise.sh: $failures failed"
	exit 1
fi
