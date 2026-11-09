#!/bin/sh
# Every setting netcfgd sends a supplicant, accepted by a real one.
#
#     unshare -rn sh tests/live/c_supplicant_settings.sh
#
# A configuration with a network of every kind netcfgd renders -- open, WPA2,
# WPA3, the transition between them, OWE, hidden, pinned to a BSSID, held back
# from autoconnect, and EAP by PEAP, TTLS, TLS and PWD with stored
# certificates -- compiled the way the daemon compiles it, and every setting
# for every network under every MAC policy sent to `wpa_supplicant -Dwired` on
# loopback by `c/examples/live_supplicant`, which says why the parser is the
# thing being asked. Until 0317 the Rust's `live.rs` asked it of the Rust.
#
# The supplicant associates with nothing, so this is about acceptance: a
# setting that does not exist, or a value its parser refuses, fails here
# rather than on somebody's laptop with the network silently not joined.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
build="${NCFG_LIVE_BUILD:-$repo/c}"
skip() {
	if [ -n "${NCFG_LIVE:-}" ]; then
		echo "c_supplicant_settings.sh: NCFG_LIVE is set but this cannot run: $1" >&2
		exit 1
	fi
	echo "c_supplicant_settings.sh: skipping: $1"
	exit 0
}
supplicant=$(command -v wpa_supplicant 2>/dev/null || true)
for candidate in /sbin/wpa_supplicant /usr/sbin/wpa_supplicant; do
	[ -n "$supplicant" ] || { [ -x "$candidate" ] && supplicant=$candidate; }
done
[ -n "$supplicant" ] || skip "wpa_supplicant is not installed"
probe="$build/examples/live_supplicant"
[ -x "$probe" ] || skip "the probe is not built (make -C c examples)"
# Runnable, not merely present: with no arguments it prints its usage and
# exits 2, and a binary whose libc is missing exits 127 from the shell.
usage=0
"$probe" >/dev/null 2>&1 || usage=$?
[ "$usage" -eq 2 ] || skip "the probe will not run here (a glibc build on musl)"

work=$(mktemp -d "${TMPDIR:-/tmp}/ncfg-c-supplicant.XXXXXX")
pid=""
cleanup() {
	[ -n "$pid" ] && kill "$pid" 2>/dev/null || true
	[ -n "$pid" ] && wait "$pid" 2>/dev/null || true
	rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -p "$work/etc/secrets" "$work/ctrl" "$work/stored"
chmod 700 "$work/etc/secrets"

secret() {
	printf '%s' "$2" > "$work/etc/secrets/$1"
	chmod 600 "$work/etc/secrets/$1"
}
secret home "correct horse battery"
secret corp "a password for the office"
# Certificate contents are not read at SET_NETWORK time; the supplicant keeps
# the path. A stored one is written out for it, which is the half being driven.
secret corp-ca "-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----"
secret corp-client "-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----"
secret corp-key "-----BEGIN PRIVATE KEY-----
MIIB
-----END PRIVATE KEY-----"

cat > "$work/etc/netcfgd.conf" <<'CONF'
network "open-cafe" {
	wifi { open = true }
}
network "home" {
	wifi { psk = "@secret:home" }
}
network "home-wpa3" {
	wifi {
		psk   = "@secret:home"
		proto = "wpa3"
	}
}
network "home-both" {
	wifi {
		psk   = "@secret:home"
		proto = "wpa2+wpa3"
	}
}
network "enhanced-open" {
	wifi { owe = true }
}
network "hidden-one" {
	hidden = true
	metric = 100
	wifi { psk = "@secret:home" }
}
network "pinned" {
	bssid = "02:00:00:00:00:01"
	wifi { psk = "@secret:home" }
}
network "manual" {
	wifi {
		psk         = "@secret:home"
		autoconnect = false
	}
}
network "a \"quoted\" name with spaces" {
	wifi { open = true }
}
network "corp-peap" {
	wifi {
		eap                 = "peap"
		identity            = "someone@corp.example"
		anonymous_identity  = "anonymous@corp.example"
		password            = "@secret:corp"
		ca_cert             = "@secret:corp-ca"
		domain_suffix_match = "corp.example"
		phase2              = "auth=MSCHAPV2"
	}
}
network "corp-ttls" {
	wifi {
		eap                 = "ttls"
		identity            = "someone@corp.example"
		password            = "@secret:corp"
		ca_cert             = "@secret:corp-ca"
		domain_suffix_match = "corp.example"
		phase2              = "auth=PAP"
	}
}
network "corp-tls" {
	wifi {
		eap                 = "tls"
		identity            = "someone@corp.example"
		ca_cert             = "@secret:corp-ca"
		client_cert         = "@secret:corp-client"
		private_key         = "@secret:corp-key"
		domain_suffix_match = "corp.example"
	}
}
network "corp-pwd" {
	wifi {
		eap      = "pwd"
		identity = "someone@corp.example"
		password = "@secret:corp"
	}
}
CONF

# Loopback, as `live.rs` used: no interface to create, and only the namespace
# privilege the supplicant itself needs.
"$supplicant" -Dwired -i lo -C "$work/ctrl" > "$work/supplicant.log" 2>&1 &
pid=$!
waited=0
while [ "$waited" -lt 50 ] && ! [ -S "$work/ctrl/lo" ]; do
	sleep 0.1
	waited=$((waited + 1))
done
if ! [ -S "$work/ctrl/lo" ]; then
	tail -3 "$work/supplicant.log" >&2
	skip "no control socket appeared (CAP_NET_ADMIN in this namespace?)"
fi

failures=0
"$probe" "$work/etc" "$work/ctrl" lo "$work/stored" > "$work/probe.out" 2>&1 || failures=1
cat "$work/probe.out"

# **Not vacuous**: the probe refuses a configuration with no networks, and this
# counts what it sent rather than trusting its last line.
sent=$(grep -c ' setting(s) accepted$' "$work/probe.out" || true)
if [ "$sent" -lt 39 ]; then
	echo "FAIL only $sent network(s) were sent whole; 13 networks under 3 policies is 39"
	failures=1
fi
# And a stored certificate really was written for the supplicant to read.
if ! ls "$work/stored" 2>/dev/null | grep -q .; then
	echo "FAIL no stored certificate was written out, so the TLS networks named nothing"
	failures=1
fi

if [ "$failures" -eq 0 ]; then
	echo "c_supplicant_settings.sh: all checks passed"
else
	echo "c_supplicant_settings.sh: some settings were refused"
	exit 1
fi
