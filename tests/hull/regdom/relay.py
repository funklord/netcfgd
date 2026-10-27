#!/usr/bin/env python3
"""Carry mac80211_hwsim's frames between two kernels, over UDP.

What `wmediumd` does inside one machine, stretched across two: this registers
with hwsim over generic netlink, which makes the kernel hand every frame its
radios transmit to this process instead of delivering it, and it forwards
each one to the relay in the other vm, which injects it into its own radios.

It exists for one reason (project.md 10.585): the regulatory domain is one
setting per kernel, so an access point transmitting on a channel the
station's domain forbids needs a kernel of its own.

**Every frame is reported acknowledged** unless the sender asked for no
acknowledgement. The medium is lossless, and without the report mac80211
retries every unicast frame and authentication times out -- which would read
as a regulatory refusal and is not one.

The receiving radios are named by index (`--radios 0`), from which hwsim's
address for each is computed: `42:00:00:00:<idx>:00`, its permanent address
`02:...` with the 0x40 bit set. That address is the one hwsim reports as the
transmitter, so every transmitter seen is logged against the computed set --
a relay injecting to the wrong address would otherwise drop every frame
silently.

HOW IT STOPS: on SIGTERM or SIGINT, and in any case after `--lifetime`
seconds (600). It writes `--stats` every second while it runs.
"""
import argparse
import os
import select
import signal
import socket
import struct
import sys
import time

NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
NLM_F_REQUEST = 0x1
NLM_F_ACK = 0x4
NLMSG_ERROR = 0x2

# From drivers/net/wireless/virtual/mac80211_hwsim.h, v6.12.
CMD_REGISTER = 1
CMD_FRAME = 2
CMD_TX_INFO_FRAME = 3
ATTR_ADDR_RECEIVER = 1
ATTR_ADDR_TRANSMITTER = 2
ATTR_FRAME = 3
ATTR_FLAGS = 4
ATTR_RX_RATE = 5
ATTR_SIGNAL = 6
ATTR_TX_INFO = 7
ATTR_COOKIE = 8
ATTR_FREQ = 19
ATTR_TX_INFO_FLAGS = 21
TX_CTL_NO_ACK = 1 << 1
TX_STAT_ACK = 1 << 2

SIGNAL_DBM = -50


def nla(kind: int, data: bytes) -> bytes:
	length = 4 + len(data)
	return struct.pack("=HH", length, kind) + data + b"\0" * ((4 - length % 4) % 4)


def u32(value: int) -> bytes:
	return struct.pack("=I", value & 0xFFFFFFFF)


def parse_attrs(buf: bytes) -> dict[int, bytes]:
	found: dict[int, bytes] = {}
	at = 0
	while at + 4 <= len(buf):
		length, kind = struct.unpack_from("=HH", buf, at)
		if length < 4:
			break
		found[kind & 0x3FFF] = buf[at + 4:at + length]
		at += (length + 3) & ~3
	return found


class Genl:
	def __init__(self) -> None:
		self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
		self.sock.bind((0, 0))
		self.seq = 0

	def send(self, family: int, cmd: int, payload: bytes, flags: int = NLM_F_REQUEST) -> None:
		self.seq += 1
		body = struct.pack("=BBH", cmd, 1, 0) + payload
		header = struct.pack("=IHHII", 16 + len(body), family, flags, self.seq, 0)
		self.sock.send(header + body)

	def receive(self) -> list[tuple[int, int, dict[int, bytes]]]:
		"""(type, cmd or error code, attributes) for each message read."""
		data = self.sock.recv(1 << 16)
		messages = []
		at = 0
		while at + 16 <= len(data):
			length, kind, _flags, _seq, _pid = struct.unpack_from("=IHHII", data, at)
			if length < 16:
				break
			body = data[at + 16:at + length]
			if kind == NLMSG_ERROR:
				messages.append((kind, struct.unpack_from("=i", body)[0], {}))
			elif len(body) >= 4:
				messages.append((kind, body[0], parse_attrs(body[4:])))
			at += (length + 3) & ~3
		return messages

	def family(self, name: str) -> int:
		self.send(GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
			nla(CTRL_ATTR_FAMILY_NAME, name.encode() + b"\0"))
		for kind, code, attrs in self.receive():
			if kind == NLMSG_ERROR and code != 0:
				sys.exit(f"relay: no generic netlink family {name}: error {code}")
			if CTRL_ATTR_FAMILY_ID in attrs:
				return struct.unpack("=H", attrs[CTRL_ATTR_FAMILY_ID][:2])[0]
		sys.exit(f"relay: the kernel did not name {name}'s family id")


def hwsim_address(index: int) -> bytes:
	return bytes([0x42, 0, 0, index >> 8 & 0xFF, index & 0xFF, 0])


def text(address: bytes) -> str:
	return ":".join(f"{octet:02x}" for octet in address)


def main() -> int:
	parser = argparse.ArgumentParser()
	parser.add_argument("--peer", required=True, help="the other relay's address")
	parser.add_argument("--port", type=int, default=7123)
	parser.add_argument("--radios", required=True,
		help="comma-separated indices of the local radios to deliver to")
	parser.add_argument("--stats", required=True, help="a file rewritten every second")
	parser.add_argument("--lifetime", type=int, default=600)
	args = parser.parse_args()

	receivers = [hwsim_address(int(i)) for i in args.radios.split(",")]
	genl = Genl()
	family = genl.family("MAC80211_HWSIM")
	genl.send(family, CMD_REGISTER, b"", NLM_F_REQUEST | NLM_F_ACK)
	for kind, code, _attrs in genl.receive():
		if kind == NLMSG_ERROR and code != 0:
			sys.exit(f"relay: hwsim refused the registration: error {code}")

	air = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	air.bind(("0.0.0.0", args.port))
	peer = (args.peer, args.port)

	stopping = False

	def stop(_signum: int, _frame: object) -> None:
		nonlocal stopping
		stopping = True

	signal.signal(signal.SIGTERM, stop)
	signal.signal(signal.SIGINT, stop)

	sent = received = refused = 0
	transmitters: set[str] = set()
	deadline = time.monotonic() + args.lifetime
	written = 0.0

	def write_stats() -> None:
		expected = {text(r) for r in receivers}
		strangers = sorted(transmitters - expected)
		with open(args.stats + ".new", "w") as out:
			out.write(f"sent {sent}\nreceived {received}\nrefused {refused}\n")
			out.write(f"transmitters {' '.join(sorted(transmitters)) or '-'}\n")
			out.write(f"unexpected {' '.join(strangers) or '-'}\n")
		os.replace(args.stats + ".new", args.stats)

	while not stopping and time.monotonic() < deadline:
		try:
			ready, _, _ = select.select([genl.sock, air], [], [], 0.5)
		except InterruptedError:
			continue
		for source in ready:
			if source is genl.sock:
				for kind, code, attrs in genl.receive():
					if kind == NLMSG_ERROR:
						if code != 0:
							refused += 1
						continue
					if code != CMD_FRAME or ATTR_FRAME not in attrs:
						continue
					transmitter = attrs[ATTR_ADDR_TRANSMITTER]
					transmitters.add(text(transmitter))
					flags = struct.unpack("=I", attrs[ATTR_FLAGS][:4])[0]
					if not flags & TX_CTL_NO_ACK:
						flags |= TX_STAT_ACK
					report = (nla(ATTR_ADDR_TRANSMITTER, transmitter)
						+ nla(ATTR_FLAGS, u32(flags))
						+ nla(ATTR_TX_INFO, attrs[ATTR_TX_INFO])
						+ nla(ATTR_SIGNAL, u32(SIGNAL_DBM))
						+ nla(ATTR_COOKIE, attrs[ATTR_COOKIE]))
					if ATTR_TX_INFO_FLAGS in attrs:
						report += nla(ATTR_TX_INFO_FLAGS, attrs[ATTR_TX_INFO_FLAGS])
					genl.send(family, CMD_TX_INFO_FRAME, report)
					freq = attrs.get(ATTR_FREQ, u32(0))[:4]
					air.sendto(freq + attrs[ATTR_FRAME], peer)
					sent += 1
			else:
				packet = air.recv(1 << 16)
				if len(packet) < 5:
					continue
				freq = struct.unpack("=I", packet[:4])[0]
				for receiver in receivers:
					frame = (nla(ATTR_ADDR_RECEIVER, receiver)
						+ nla(ATTR_FRAME, packet[4:])
						+ nla(ATTR_RX_RATE, u32(1))
						+ nla(ATTR_SIGNAL, u32(SIGNAL_DBM)))
					if freq:
						frame += nla(ATTR_FREQ, u32(freq))
					genl.send(family, CMD_FRAME, frame)
				received += 1
		if time.monotonic() - written >= 1.0:
			write_stats()
			written = time.monotonic()
	write_stats()
	return 0


if __name__ == "__main__":
	sys.exit(main())
