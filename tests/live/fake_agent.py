#!/usr/bin/env python3
"""A NetworkManager secret agent that answers with a canned passphrase.

The other half of the secret bridge. A real agent is `nm-applet` putting a
dialog on the screen and waiting for somebody to type; what matters for a test
is the protocol around that -- registering, being called with the right
arguments, and having the answer end up in netcfgd's secret provider rather
than in a config file.

    fake_agent.py <passphrase> [--cancel]

`--cancel` makes it refuse the way a user pressing Escape does, which is the
case that must not leave a half-written credential behind.

Registers on whatever bus DBUS_SYSTEM_BUS_ADDRESS points at, because that is
where the shim is in the live test. Prints one line per event so the shell can
assert on what happened.
"""

import sys

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

AGENT_PATH = "/org/freedesktop/NetworkManager/SecretAgent"
AGENT_INTERFACE = "org.freedesktop.NetworkManager.SecretAgent"
MANAGER_PATH = "/org/freedesktop/NetworkManager/AgentManager"
MANAGER_INTERFACE = "org.freedesktop.NetworkManager.AgentManager"
NM_NAME = "org.freedesktop.NetworkManager"


class Agent(dbus.service.Object):
	def __init__(self, bus, passphrase, cancel):
		super().__init__(bus, AGENT_PATH)
		self.passphrase = passphrase
		self.cancel = cancel

	@dbus.service.method(
	    AGENT_INTERFACE, in_signature="a{sa{sv}}osasu", out_signature="a{sa{sv}}"
	)
	def GetSecrets(self, connection, path, setting_name, hints, flags):
		# Logged so the test can assert the shim asked for the right thing, and
		# asked with the flags that let a real agent show a dialog.
		name = connection.get("connection", {}).get("id", "?")
		print(f"asked id={name} setting={setting_name} flags={int(flags)}", flush=True)
		if self.cancel:
			# What a real agent raises when somebody presses Escape. The error
			# name is NM's own, and the shim has to treat it as an answer
			# rather than as a fault of its own.
			raise dbus.DBusException(
			    "the user cancelled",
			    name="org.freedesktop.NetworkManager.SecretAgent.UserCanceled",
			)
		return {setting_name: {"psk": self.passphrase}}

	@dbus.service.method(AGENT_INTERFACE, in_signature="a{sa{sv}}os", out_signature="")
	def CancelGetSecrets(self, connection, path, setting_name):
		print("cancelled", flush=True)

	@dbus.service.method(AGENT_INTERFACE, in_signature="a{sa{sv}}os", out_signature="")
	def SaveSecrets(self, connection, path, setting_name):
		print("save", flush=True)

	@dbus.service.method(AGENT_INTERFACE, in_signature="a{sa{sv}}os", out_signature="")
	def DeleteSecrets(self, connection, path, setting_name):
		print("delete", flush=True)


def main():
	arguments = sys.argv[1:]
	cancel = "--cancel" in arguments
	arguments = [argument for argument in arguments if argument != "--cancel"]
	if len(arguments) != 1:
		print(__doc__.strip().splitlines()[4], file=sys.stderr)
		return 2
	passphrase = arguments[0]

	dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
	# The system bus, which in the live test is a private daemon the script
	# started -- GDBus and dbus-python both honour DBUS_SYSTEM_BUS_ADDRESS.
	bus = dbus.SystemBus()

	agent = Agent(bus, passphrase, cancel)
	manager = dbus.Interface(
	    bus.get_object(NM_NAME, MANAGER_PATH), MANAGER_INTERFACE
	)
	loop = GLib.MainLoop()

	# Register from inside the running loop, not before it.
	#
	# `Register` tells the shim this agent can be asked and the printed line
	# tells the test the same thing, and neither was true yet: dbus-python
	# dispatches incoming calls from the GLib main context, and nothing iterated
	# it until `loop.run()`. An idle callback runs on the loop's first
	# iteration, so by the time anybody is told this agent is available, it is.
	#
	# **This was investigated as the cause of the intermittent cancelled-prompt
	# failure and was not it** -- the failure survived the change, and the real
	# cause was the shim asking *nmcli's* agent, which cannot answer while it
	# waits for the activation reply (0107). Kept anyway: announcing readiness
	# before being able to answer is wrong on its own terms, and this is where
	# the next person will look.
	GLib.idle_add(announce)
	try:
		loop.run()
	except KeyboardInterrupt:
		pass
	finally:
		del agent
	return 0


if __name__ == "__main__":
	sys.exit(main())
