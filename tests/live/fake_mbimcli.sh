#!/bin/sh
# An mbimcli with no modem behind it.
#
# The same trade as fake_hostapd.py and for the same reason: the one thing this
# repository cannot produce on demand is hardware. What is faked is the modem,
# not the format -- every line below is the `g_print` from libmbim 1.32's
# `mbimcli_print_ip_config` in `src/mbimcli/mbimcli-helpers.c`, spacing
# included, because the helper parses it with `sed` and the spacing is what it
# matches on.
#
# Two things a plausible fake would get wrong and this one does not:
#
#   - the labels are the same in the IPv4 and IPv6 sections, so a parser that
#     tracked which section it was in would work here and on a real modem, and
#     one that keyed on the label alone works too. The addresses say which
#     family they are.
#   - `MTU:` is printed with eight leading spaces and `IP [0]:` with five. The
#     alignment is decorative to a human and load-bearing to a `sed`.
#
# Records what it was asked to do in $FAKE_MBIMCLI_LOG so a test can assert the
# helper really connected rather than only that it wrote a file.

set -eu

[ -n "${FAKE_MBIMCLI_LOG:-}" ] && printf '%s\n' "$*" >> "$FAKE_MBIMCLI_LOG"

for argument in "$@"; do
	case $argument in
	--connect=*)
		# `mbimcli --connect` prints a summary that the helper discards. What
		# matters is the exit status.
		if [ -n "${FAKE_MBIMCLI_CONNECT_FAILS:-}" ]; then
			echo "error: operation failed: Failure" >&2
			exit 1
		fi
		echo "[/dev/cdc-wdm0] Successfully connected"
		exit 0
		;;
	--disconnect*)
		echo "[/dev/cdc-wdm0] Successfully disconnected"
		exit 0
		;;
	--query-connection-state*)
		# Read from a file so a test can drop the bearer underneath a running
		# monitor, which is the only way to exercise the thing the monitor
		# exists for. Tab-indented, as libmbim's g_print writes it.
		state=activated
		[ -n "${FAKE_MBIMCLI_STATE_FILE:-}" ] && [ -f "$FAKE_MBIMCLI_STATE_FILE" ] \
			&& state=$(cat "$FAKE_MBIMCLI_STATE_FILE")
		printf '[/dev/cdc-wdm0] Connection status:\n'
		printf '\t      Session ID: %s\n' "'0'"
		printf '\tActivation state: %s\n' "'$state'"
		printf '\tVoice call state: %s\n' "'none'"
		exit 0
		;;
	--query-ip-configuration*)
		if [ -n "${FAKE_MBIMCLI_NO_ADDRESS:-}" ]; then
			# A bearer that came up and got nothing. Real, and the reason the
			# helper refuses to write a report for it.
			printf '\n[/dev/cdc-wdm0] IPv4 configuration available: %s\n' "'none'"
			printf '\n[/dev/cdc-wdm0] IPv6 configuration available: %s\n' "'none'"
			exit 0
		fi
		# Exactly libmbim's spacing: five spaces before `IP`, four before
		# `Gateway` and `DNS`, eight before `MTU`.
		printf '\n[/dev/cdc-wdm0] IPv4 configuration available: %s\n' "'address, gateway, dns, mtu'"
		printf "     IP [0]: '10.64.1.23/30'\n"
		printf "    Gateway: '10.64.1.24'\n"
		printf "    DNS [0]: '8.8.8.8'\n"
		printf "    DNS [1]: '8.8.4.4'\n"
		printf "        MTU: '1428'\n"
		printf '\n[/dev/cdc-wdm0] IPv6 configuration available: %s\n' "'address, gateway, dns'"
		printf "     IP [0]: '2001:db8::2/64'\n"
		printf "    Gateway: '2001:db8::1'\n"
		printf "    DNS [0]: '2001:4860:4860::8888'\n"
		exit 0
		;;
	esac
done

echo "fake_mbimcli.sh: nothing asked for" >&2
exit 1
