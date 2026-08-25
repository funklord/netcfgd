# 0030: A GUI is an editor of config files

Status: accepted
Date: 2026-07-31
Milestone: M7

## Context

Design section 9.4's promise: a wifi network created from a desktop applet is a
plain text file you can diff and commit, and `ncfg plan`, drift detection and
hooks apply to it identically with no second code path. That is the write half
of the NM shim, and the last piece of tier 1 that changes anything on disk.

Everything else in the shim so far has been a projection outward. This is the
one direction where a foreign model can push inward, so it is the one that
needed the most deciding.

## The path is not the one the design doc names

Section 9.4 says `/etc/netcfgd/conf.d/nm/`, a directory. **It is
`/etc/netcfgd/conf.d/nm-<id>.conf` instead, flat.**

netcfgd reads `conf.d/*.conf` and does not descend. A file in a subdirectory is
not skipped with a warning -- it is never read at all, which was checked by
putting one there rather than assumed from the code. So the design doc's path
would have produced a GUI that appeared to create networks and a daemon that
never saw one.

Making the loader recursive would have been a small change. It is refused
because the justification would have been "the adapter would prefer a tidier
path", and constraint 6 exists precisely to refuse changes with that shape. The
prefix gives everything the directory was for: machine-generated files are
identifiable at a glance, greppable, and removable in one glob.

The prefix is also the **marker**. "Is this profile one the shim wrote?" is
answered by asking the filesystem whether `nm-<id>.conf` exists, which means the
answer survives a restart and nothing has to remember it. Section 9.4's rule
that hand-written blocks stay read-only is then enforced by a file test rather
than by a list this program keeps.

## The credential goes to the provider, not into the block

A client sends the passphrase in the settings dictionary. It is written to
`/etc/netcfgd/secrets/<id>` at mode 0600 -- set by the open, not by a chmod
afterwards, for the reason decision 0026 gives -- and the block gets
`psk = "@secret:<id>"`.

That is constraint 5 applied to a file a GUI created: the configuration holds a
reference, and the value lives where the provider looks. Deleting the profile
takes the credential with it, because leaving a passphrase on disk for a network
nothing refers to is the kind of thing nobody ever notices to clean up.

**An update carries no passphrase, and that is not an error.** A client editing
a profile sends back what `GetSettings` gave it, and `GetSettings` never
includes the secret (decision 0029). Requiring one would refuse every edit that
was not a password change -- which is what happened the first time
`nmcli connection modify` was pointed at this. An update with no passphrase and
a stored one leaves the stored one alone.

## What could not be translated is written into the file

NM's settings dictionary says things netcfgd cannot. Rather than dropping them
silently, the generated file carries a comment naming each one:

```
# The client also asked for the settings below. netcfgd has no way to
# say them, so they are recorded here rather than silently discarded:
#   connection.autoconnect-ports
```

A lossy translation that says nothing is how somebody finds out months later
that a setting never took effect. Empty values are not reported -- every NM
profile carries a dozen empty arrays, and a note listing those is one nobody
reads, which makes the line that matters invisible.

## Who may write

Changing the configuration is the `admin` tier's business (decision 0013). The
caller's uid comes from the bus -- `GetConnectionUnixUser` on the connection,
not the sender name in the message, which a client controls -- and the tier
comes from the document netcfgd already handed over. So the policy is netcfgd's
own rather than a second one invented here.

Root always may, for the daemon's own reason: a configuration naming a group
and thereby locking root out would be unrecoverable without editing the file the
daemon is refusing to let you reach.

**A `Group` principal is refused rather than approximated.** A message bus
reports a caller's user and not its supplementary groups, so evaluating
`group:netdev` would mean guessing which groups that uid is usually in. Guessing
is not a thing to do in an authorization check. The refusal says so and names
`ncfg`, which sees real credentials over a unix socket and does not have to
guess. That is a genuine gap in what a desktop can do on a machine configured
that way, and it is a smaller one than a check that is right most of the time.

## A method cannot unregister the object it was called on

`Delete` removes the file, and the object standing for that profile then has to
go. Doing both inside the method deadlocks: zbus holds a lock on the interface
for the duration of the call, and the main loop's unregistration waits for it.
The symptom was `Connection 'Secure' ... Timeout expired (10 seconds)` from
`nmcli`, with the file correctly deleted -- the work had happened and the reply
never came.

So every write posts a `Reload` job and returns. The main loop re-reads the
configuration and reconciles the objects, which it can only do once the method
has finished. `AddConnection` is the exception in one direction: it registers
the *new* object inline before answering, because a client reads the path it
returns immediately, and adding an object nothing is executing on takes no lock
anybody holds. Without it `nmcli` reported "operation succeeded but object
/org/freedesktop/NetworkManager/Settings/1 does not exist".

## A file that breaks the configuration is taken back out

`AddConnection` reloads before answering, so a block that does not compile is
reported as a failed call rather than as a machine that quietly stopped
reconciling. If the reload fails the file is removed and the configuration
reloaded again, and the error says so. A GUI must not be able to leave a machine
with a configuration that will not compile.

## What is still not here

Enterprise networks: an `eap` block needs a method, an identity and certificate
paths, which is more than a connect dialog's settings dictionary carries.
Refused by name, pointing at decision 0008.

Wired profiles: an interface is configured by an `interface` block, which is a
file to edit rather than a profile to create. Refused by name -- a client that
got a generic failure would have no way to learn that distinction, which is the
whole difference between netcfgd's model and NM's.

The `AgentManager` secret bridge, which is how a client supplies a passphrase
interactively rather than in the settings dictionary. That is the last piece of
tier 1.
