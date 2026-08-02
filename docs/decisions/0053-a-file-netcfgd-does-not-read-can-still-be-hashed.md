# 0053: A file netcfgd does not read can still be hashed

Status: accepted
Date: 2026-08-02
Milestone: finishes what [0052](0052-a-daemon-is-compared-to-what-it-was-started-with.md) started

## Context

0052 gave every daemon netcfgd starts an answer to "is what is running still what
the document says". Every daemon but one: an `OpenVPN` tunnel, whose
configuration netcfgd deliberately never reads.

Decision 0046 is emphatic about that and remains right. `openvpn --help` lists
253 top-level options against hostapd's couple of dozen; a `.ovpn` is a file an
operator is *given* rather than a rendering of an intent netcfgd holds; and a
netcfgd that parsed it would be a netcfgd that owned it. So an edited `.ovpn`
changed nothing until the tunnel restarted for some other reason -- the last
thing an operator could change that netcfgd would not see.

The question this record answers is narrow: **can netcfgd notice that a file
changed without reading it?**

## Decision

Yes, and the project already does it twice.

**A hook's `sha256` is exactly this** (project.md section 2.2): netcfgd
materialises a shell script it does not interpret, records the hash, and drift
detection notices when the script changes underneath. Nothing about that makes
netcfgd the author of the script.

So netcfgd records `sha256(.ovpn)` when it starts a tunnel, hashes the file
again on the next observation, and publishes `ObservedBackend::config_matches`
-- a boolean, for the reason 0052's `secret_matches` is one: the comparison
needs a file a pure planner may not read, so it happens where the file is and
only the answer travels.

A difference restarts the tunnel, which drops it for as long as the handshake
takes. The plan says that in those words, because nothing else will.

**This does not weaken 0046.** Reading bytes to hash them is not reading a
configuration: netcfgd still cannot tell you what is in that file, still passes
it to openvpn unopened, and still has no opinion about any of its 253 options.
What it can now say is "this is not the file the running tunnel was started
from", which is a statement about netcfgd's own past rather than about
OpenVPN's configuration language.

## Alternatives considered

**An `mtime` instead of a hash.** Cheaper, and wrong in both directions: a
`cp` that preserves timestamps changes the file without moving it, and an
editor that writes and rewrites moves it without changing anything. A hash
answers the question that was asked.

**Nothing, with the limitation written down.** Genuinely tenable -- it is what
0046 implied and what the code did for as long as tunnels have existed here.
Rejected because every other backend now answers the question, and a
reconciler that notices an edited SSID, an edited passphrase and a renumbered
prefix but not an edited `.ovpn` is one whose coverage an operator cannot
predict. Predictable is the product.

**Compare the file's contents.** Never considered seriously; it is 0046 with
extra steps.

## Consequences

- A tunnel started by a netcfgd too old to write the record reports `None` and
  is left alone. So does a file that cannot be read at all -- "the operator's
  file is not there" is a different statement from "it changed", and only one
  of them is a reason to restart a working tunnel.
- The record is removed when the tunnel is stopped, because it describes a
  tunnel that is not running.
- The hash is written *after* openvpn accepted the file. A hash of a
  configuration the daemon refused is a record of nothing.
- Everything netcfgd starts is now compared to what the document says. The next
  thing of this shape would be a backend netcfgd does not start.
