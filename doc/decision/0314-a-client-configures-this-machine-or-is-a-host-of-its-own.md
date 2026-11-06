# 0314: a client configures this machine, or is a host of its own

Status: accepted
Date: 2026-11-06
Milestone: fuzznet integration (project.md 10.737, 10.738)
Amends: [0313](0313-every-fuzznet-program-is-whole-and-netcfgd-has-its-own-node.md), whose user's node left running and "client and node are one" this replaces

## The holder's words

"For now we only have netcfgd as root and clients as users." A user daemon "hinged
on needing it for something on each user, we don't yet need it".

"Think of it as different roles of a client and daemon. In the normal case a client
exists to configure a daemon running as root, which relays and synchronizes with
other machines with a similar setup. But in some cases the client is used to control
a remote host, in which case the client needs to have an identity/key as a host.
This is always the case if running on mobile, as it isn't a device being configured.
Though on mobile the client may need to be split up into client/daemon for other
reasons."

Asked for what was best, and shown this, the holder said go ahead, adding that a
capability and permission profile system (ui-client, one-shot-client, rootd, userd,
vault) may come to handle the hard configurations generically, and is in design.

fuzznet's terms (its sec 906): a host is one user's presence on a machine; daemons
and clients are its processes; a client does not touch the disk or relay; a host's
key is made at the daemon's first start.

## The decision

**Two roles.**

- **Configuring this machine, the normal case.** The client has no key, no store and
  no process of its own. It speaks to the root netcfgd over the local socket, and the
  OS says who it is. Root relays and synchronises. The person joins nothing.
- **Controlling a remote host.** The person is a host of their own, with a key,
  second on the machine, made by joining: `ncfg join` or the phone's first screen.
  Only that makes one, so `--at` with no store refuses and says to join. Always so on
  a phone; a machine with no root netcfgd has this role only.

**The key and store belong to a daemon, `ncfg host`, so a client still never touches
the disk,** and the split is the same on a desktop as on a phone, which has it as
`libncfghost.so`. It does not relay or synchronise for anybody.

**It lives only with its clients.** Each holds a shared lock on a file beside the
socket for as long as it runs. The daemon started for them looks each second, and
stops ten seconds after nobody holds it (10.738 says why ten). The kernel keeps the count, so a client that crashes is
counted out, and a daemon restarting in place after a join loses nothing. The client
takes the lock before it starts the daemon, so a new one has no grace period to need;
the daemon takes it exclusively to stop, so a client arriving then waits for the exit
and starts another rather than holding a daemon on its way out. `ncfg host` typed by
hand stays up until stopped.

**On a phone it stays the app's child, with no foreground service,** until something
has to happen while the app is closed.

## Rejected

- **The client running that core in-process.** It would write the disk, and the
  client would stop being one.
- **A resident user daemon, or a user unit.** Nothing needs one yet; 0313's left-up
  node was one in all but name, and the second it was said to save was never measured.
  It was 250 ms, and that was the client's own poll.
- **Reaching a remote through root as `local:alice`.** Root's key would then act for a
  person, and the remote could not tell who. It is also not what the holder described.
- **Counting holders on a socket of the daemon's.** A join restarts the process in
  place, which would drop every holder, and a socket needs a race closing that a lock
  does not have.

## Not decided

The profile system, which may fold both roles into something general. Nothing here
should be built to anticipate it: a role today is what a client asked for, not a type.
