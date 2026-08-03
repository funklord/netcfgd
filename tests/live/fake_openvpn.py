#!/usr/bin/env python3
"""An openvpn that binds a management socket and never touches a network.

The same trade as fake_hostapd.py: what cannot be produced on demand here is a
VPN server. What is faked is the daemon, not the protocol -- the management
interface is a real unix *stream* socket speaking the real line format, which
is the half netcfgd actually talks to.

Two things a plausible fake would get wrong, both from
`/usr/share/doc/openvpn/management-notes.txt`:

  - the daemon greets a new client with a `>INFO:` line before anything is
    asked, and emits further `>`-prefixed notifications whenever it likes. A
    client that reads the first line as its answer gets the greeting, and its
    stop silently does nothing.
  - the answer to a command is `SUCCESS: ...` or `ERROR: ...`, not `OK`.

Invoked the way netcfgd invokes openvpn, so the arguments are asserted rather
than assumed: --config, --dev, --management PATH unix, --daemon, --log.
"""

import os
import socket
import sys
import threading
import time


def serve(path, log, pid_file=None):
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if os.path.exists(path):
        os.unlink(path)
    server.bind(path)
    server.listen(4)

    def handle(conn):
        # The greeting, before the client has said anything. This is the line a
        # naive client mistakes for its reply.
        conn.sendall(b">INFO:OpenVPN Management Interface Version 5 -- type 'help'\r\n")
        buffered = b""
        while True:
            data = conn.recv(4096)
            if not data:
                return
            buffered += data
            while b"\n" in buffered:
                line, buffered = buffered.split(b"\n", 1)
                command = line.decode(errors="replace").strip()
                with open(log, "a") as handle_log:
                    handle_log.write(command + "\n")
                if command.startswith("signal ") and os.environ.get(
                    "FAKE_OPENVPN_REFUSES_SIGNAL"
                ):
                    # A daemon that will not stop. Rare, and the reason the
                    # reply is parsed at all rather than written and forgotten.
                    conn.sendall(b"ERROR: could not send signal\r\n")
                elif command.startswith("signal "):
                    which = command.split(None, 1)[1]
                    conn.sendall(f"SUCCESS: signal {which} thrown\r\n".encode())
                    if which == "SIGTERM":
                        conn.close()
                        # openvpn removes its own socket on the way out, and
                        # its pid file with it.
                        if os.path.exists(path):
                            os.unlink(path)
                        if pid_file and os.path.exists(pid_file):
                            os.unlink(pid_file)
                        os._exit(0)
                elif command == "state":
                    conn.sendall(b"1,CONNECTED,SUCCESS,10.8.0.2,,\r\nEND\r\n")
                else:
                    conn.sendall(b"ERROR: unknown command\r\n")

    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def main():
    arguments = sys.argv[1:]
    log = os.environ.get("FAKE_OPENVPN_LOG", "/dev/null")
    with open(log, "a") as handle:
        handle.write("argv: " + " ".join(arguments) + "\n")

    if os.environ.get("FAKE_OPENVPN_FAILS"):
        # What a real one prints for a file it will not take. The helper quotes
        # this back, so the wording is what an operator sees.
        print("Options error: In [CMD-LINE]: Error opening configuration file")
        return 1

    socket_path = None
    for index, argument in enumerate(arguments):
        if argument == "--management" and index + 1 < len(arguments):
            socket_path = arguments[index + 1]

    if socket_path is None:
        print("fake_openvpn.py: netcfgd did not ask for a management socket")
        return 1

    pid_file = None
    for index, argument in enumerate(arguments):
        if argument == "--writepid" and index + 1 < len(arguments):
            pid_file = arguments[index + 1]

    # `--daemon` means the invocation returns and the process keeps going.
    if os.fork() != 0:
        return 0
    os.setsid()
    # The pid file is the child's, written before the socket is bound -- which
    # is the order openvpn does it in (`possibly_become_daemon` then the
    # management interface) and the whole reason netcfgd asks for one: between
    # the fork above and the bind below there is nothing else to find this
    # process by. Decision 0074.
    if pid_file:
        with open(pid_file, "w") as handle:
            handle.write(f"{os.getpid()}\n")
    # A machine under load takes a while to get from one to the other, and this
    # is how a test asks for that window on purpose. Faking the *timing* rather
    # than the protocol, which is the line this file has always drawn.
    delay = os.environ.get("FAKE_OPENVPN_BIND_DELAY")
    if delay:
        time.sleep(float(delay))
    serve(socket_path, log, pid_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
