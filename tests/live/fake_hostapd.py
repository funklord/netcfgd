#!/usr/bin/env python3
"""A hostapd control socket with stations on it.

The same trade as fake_supplicant.py, for the same reason: the one thing this
repository cannot produce on demand is a radio, and without one no station ever
associates. ap.sh drives a *real* hostapd -- which is what proves netcfgd
generates a file it accepts -- but a hostapd with no radio has no clients, so
nothing downstream of "who is connected" can be exercised against it.

This is a fake radio, not a fake protocol. The wire format is the real one and
the replies are copied from hostapd 2.10's own `hostapd_ctrl_iface_sta_mib` and
`hostapd_get_sta_info` in `src/ap/ctrl_iface_ap.c`, including the two things a
plausible fake would get wrong:

  - a station whose driver statistics could not be read prints none of them,
    so `signal=` and `rx_bytes=` are simply absent rather than zero
  - the walk ends with an *empty* reply, because the MIB printer returns zero
    bytes for a null station

    fake_hostapd.py <ctrl-dir> <interface>
"""

import os
import socket
import sys

# address, authorized, and whether the driver could be read for it.
#
# Three stations covering the cases that render differently: an ordinary
# authorized client with full statistics, one that is associated but has not
# finished authenticating, and one the driver would not answer about.
STATIONS = [
    ("00:11:22:33:44:55", True, True),
    ("aa:bb:cc:dd:ee:ff", True, False),
    ("66:77:88:99:aa:bb", False, True),
]


def mib(index):
    """One station's block, exactly as hostapd orders it."""
    address, authorized, has_stats = STATIONS[index]
    flags = "[AUTH][ASSOC][AUTHORIZED][SHORT_PREAMBLE][WMM][HT]" if authorized \
        else "[AUTH][ASSOC]"
    block = (
        f"{address}\n"
        f"flags={flags}\n"
        "aid=1\n"
        "capability=0x431\n"
        "listen_interval=10\n"
        "supported_rates=02 04 0b 16 0c 12 18 24 30 48 60 6c\n"
        "timeout_next=NULLFUNC POLL\n"
    )
    if not has_stats:
        # hostapd_get_sta_info returns 0 without writing anything when
        # hostapd_drv_read_sta_data fails. The station is still listed.
        return block
    return block + (
        "rx_packets=1234\n"
        "tx_packets=5678\n"
        f"rx_bytes={100000 * (index + 1)}\n"
        f"tx_bytes={200000 * (index + 1)}\n"
        "inactive_msec=40\n"
        f"signal={-52 - index * 9}\n"
        "rx_rate_info=650 mcs 7 shortGI\n"
        "tx_rate_info=650 mcs 7 shortGI\n"
        f"connected_time={3600 * (index + 1)}\n"
    )


def index_of(address):
    for index, (candidate, _, _) in enumerate(STATIONS):
        if candidate.lower() == address.strip().lower():
            return index
    return None


def answer(command):
    if command == "PING":
        return "PONG\n"
    if command == "STA-FIRST":
        # Empty when nobody is associated, which is the same answer as the end
        # of the walk. Both are "no station", and hostapd does not distinguish.
        return mib(0) if STATIONS else ""
    if command.startswith("STA-NEXT "):
        index = index_of(command[len("STA-NEXT "):])
        if index is None:
            # An address hostapd does not know. It answers FAIL, and the walk
            # has to stop rather than treating it as a station.
            return "FAIL\n"
        if index + 1 >= len(STATIONS):
            return ""
        return mib(index + 1)
    if command.startswith("STA "):
        index = index_of(command[len("STA "):])
        return mib(index) if index is not None else "FAIL\n"
    # The ACL and deauthentication commands, so a test can assert that netcfgd
    # sent them rather than only that it returned without an error.
    if command.startswith(("DENY_ACL ", "ACCEPT_ACL ", "DEAUTHENTICATE ")):
        return "OK\n"
    # Everything else. FAIL is a real hostapd answer; inventing a success would
    # make a test pass for a command that did nothing.
    return "FAIL\n"


def main():
    if len(sys.argv) != 3:
        print("fake_hostapd.py <ctrl-dir> <interface>", file=sys.stderr)
        return 2
    ctrl_dir, interface = sys.argv[1], sys.argv[2]
    os.makedirs(ctrl_dir, exist_ok=True)
    path = os.path.join(ctrl_dir, interface)
    if os.path.exists(path):
        os.unlink(path)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(path)
    # Announce readiness on stdout so the shell waits rather than sleeping.
    print("ready", flush=True)

    try:
        while True:
            data, sender = server.recvfrom(4096)
            command = data.decode(errors="replace").strip()
            print(f"cmd: {command}", flush=True)
            try:
                server.sendto(answer(command).encode(), sender)
            except OSError:
                # The client went away between its request and our reply, which
                # is ordinary for a one-shot command.
                pass
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        if os.path.exists(path):
            os.unlink(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
