#!/usr/bin/env python3
"""A wpa_supplicant control socket with canned answers.

The one thing this repository cannot produce on demand is a radio. wifi.sh
already drives a *real* wpa_supplicant, which is what proves netcfgd's client
speaks the protocol correctly -- but a real supplicant with no radio finds no
networks, so nothing downstream of "the scan returned" can be exercised.

That matters for the NetworkManager shim, whose entire job downstream of a scan
is arithmetic: dBm becomes a percentage, a boolean and the configuration become
three bitfields, hex becomes octets. Those are the conversions a client
actually renders, and they are untestable against an empty list.

So this answers the four commands netcfgd sends, with results chosen to have
known answers on the other side. It is a fake radio, not a fake supplicant
protocol: the wire format here is the real one, and if netcfgd's parser changes
its mind about it, wifi.sh is what notices.

    fake_supplicant.py <ctrl-dir> <interface>

Speaks the same unix datagram protocol wpa_supplicant does: a client binds its
own address, sends a command, and gets one reply.
"""

import os
import socket
import sys

# BSSID, frequency, signal (dBm), flags, ssid.
#
# The signal levels are chosen for what they become. -40 dBm is NM's top of
# scale and must give 100; -100 is the bottom and must give 0; -53 is what a
# real NetworkManager reported as 79 while the shim was written, and is the one
# cross-check available for the conversion.
NETWORKS = [
    ("00:11:22:33:44:55", 2412, -53, "[WPA2-PSK-CCMP][ESS]", "HomeFiber"),
    ("66:77:88:99:aa:bb", 5180, -40, "[ESS]", "Cafe"),
    ("cc:dd:ee:ff:00:11", 2437, -100, "[WPA2-PSK-CCMP][WPS][ESS]", "Distant"),
]

# The one this fake radio claims to be associated with.
ASSOCIATED = NETWORKS[0]


def hexify(text):
    return "".join(f"{byte:02x}" for byte in text.encode())


def scan_results():
    header = "bssid / frequency / signal level / flags / ssid"
    rows = [
        f"{bssid}\t{frequency}\t{signal}\t{flags}\t{ssid}"
        for bssid, frequency, signal, flags, ssid in NETWORKS
    ]
    return "\n".join([header, *rows]) + "\n"


def status():
    bssid, frequency, _signal, _flags, ssid = ASSOCIATED
    return (
        f"bssid={bssid}\n"
        f"freq={frequency}\n"
        f"ssid={ssid}\n"
        "wpa_state=COMPLETED\n"
        "key_mgmt=WPA2-PSK\n"
    )


def answer(command):
    if command == "PING":
        return "PONG\n"
    if command == "SCAN":
        return "OK\n"
    if command == "SCAN_RESULTS":
        return scan_results()
    if command == "STATUS":
        return status()
    if command == "LIST_NETWORKS":
        # Empty, so netcfgd adds the network rather than selecting one it
        # thinks is already there. Exercising the add is the point.
        return "network id / ssid / bssid / flags\n"
    # The association commands, answered the way a supplicant would. This is
    # what lets a test assert that a D-Bus `ActivateConnection` became a
    # `SELECT_NETWORK` on a control socket, rather than only that it returned
    # without an error.
    if command == "ADD_NETWORK":
        return "0\n"
    if command.startswith(("SET_NETWORK ", "ENABLE_NETWORK ", "SELECT_NETWORK ",
                           "DISABLE_NETWORK ", "REMOVE_NETWORK ", "SET ")):
        return "OK\n"
    if command == "DISCONNECT":
        return "OK\n"
    # Everything netcfgd might send that this does not model. FAIL is a real
    # supplicant answer and netcfgd handles it; inventing a success would make
    # a test pass for a command that did nothing.
    return "FAIL\n"


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[-3], file=sys.stderr)
        return 2
    ctrl_dir, interface = sys.argv[1], sys.argv[2]
    os.makedirs(ctrl_dir, exist_ok=True)
    path = os.path.join(ctrl_dir, interface)
    if os.path.exists(path):
        os.unlink(path)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(path)
    # Announce readiness on stdout so the shell can wait for it rather than
    # sleeping and hoping.
    print("ready", flush=True)

    try:
        while True:
            data, sender = server.recvfrom(4096)
            command = data.decode(errors="replace").strip()
            # Logged so a test can assert which commands a D-Bus call produced.
            # Secrets are redacted: `SET_NETWORK 0 psk "..."` carries the
            # passphrase, and a test fixture writing one to a log is the habit
            # this project refuses to get into.
            first = command.split(" psk ")[0].split(" sae_password ")[0]
            print(first, flush=True)
            if sender:
                server.sendto(answer(command).encode(), sender)
    except (KeyboardInterrupt, OSError):
        pass
    finally:
        server.close()
        if os.path.exists(path):
            os.unlink(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
