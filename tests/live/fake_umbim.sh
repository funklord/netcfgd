#!/bin/sh
# A fake `umbim`, for tests/live/umbim.sh.
#
# umbim's real output is `field: value` lines and its real behaviour is a
# sequence of stateful calls carrying a transaction id. Both are reproduced
# here, because what the helper gets wrong is the *sequence* rather than the
# parsing: a modem that answers `caps` and refuses `attach` is the failure
# mode, and a fake that answers everything cannot show it.
#
# Records what it was asked in $FAKE_UMBIM_LOG so a test can assert the order.
set -eu

[ -n "${FAKE_UMBIM_LOG:-}" ] && printf '%s\n' "$*" >> "$FAKE_UMBIM_LOG"

command=
while [ $# -gt 0 ]; do
	case $1 in
	-n) shift ;;
	-t) shift 2 ;;
	-d) shift 2 ;;
	*) command=$1; shift; break ;;
	esac
done

case $command in
caps|pinstate|subscriber|attach)
	echo "  ${command}: ok"
	;;
registration)
	# The failure the monitor loop exists to notice.
	if [ -n "${FAKE_UMBIM_DEREGISTERED:-}" ]; then
		echo "  registration: deregistered" >&2
		exit 1
	fi
	echo "  registerstate: home"
	;;
connect)
	if [ -n "${FAKE_UMBIM_CONNECT_FAILS:-}" ]; then
		echo "  connect: failed" >&2
		exit 1
	fi
	echo "  connect: activated"
	;;
config)
	if [ -n "${FAKE_UMBIM_NO_ADDRESS:-}" ]; then
		echo "  ipv4mtu: 1500"
		exit 0
	fi
	# Deliberately without a prefix on the v4 address and with one on the v6,
	# because real firmware does both and the helper has to cope with each.
	echo "  ipv4address: 10.64.1.23"
	echo "  ipv4gateway: 10.64.1.24"
	echo "  ipv4dnsserver: 8.8.8.8"
	echo "  ipv4mtu: 1500"
	echo "  ipv6address: 2001:db8::2/64"
	echo "  ipv6dnsserver: 2001:4860:4860::8888"
	;;
disconnect)
	echo "  disconnect: ok"
	;;
*)
	echo "fake_umbim.sh: nothing asked for" >&2
	exit 2
	;;
esac
