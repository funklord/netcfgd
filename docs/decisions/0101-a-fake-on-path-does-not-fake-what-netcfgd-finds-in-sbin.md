# 0101: a fake on `PATH` does not fake what netcfgd finds in `sbin`

Status: accepted
Date: 2026-08-04
Milestone: what closing 0100's Alpine skips found

## Context

[0100](0100-kill-0-calls-a-zombie-alive.md) ran the suite on Alpine and left
thirteen scripts skipping on packages the image did not have. Alpine has nearly
all of them — including hostapd 2.11 and wpa_supplicant 2.11, both newer than
Debian's. Installing them ran nine more scripts, and turned up something that is
not about Alpine at all.

`openvpn.sh` fakes the daemon on purpose: it exists to check *the command line
netcfgd builds*, which needs no VPN and no openvpn. It copies
`fake_openvpn.py` to `$work/bin/openvpn` and puts that first on `PATH`.

netcfgd does not look at `PATH` first:

```rust
for dir in ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin"] { ... }
std::env::var_os("PATH").and_then(...)
```

which is **right**, and documented as such: openvpn lives in `/usr/sbin`, and
that is not on a non-root `PATH` on Debian and several others. The consequence
is that the fake cannot win. On any machine with openvpn installed, netcfgd ran
the real daemon, the fake's log stayed empty, and **20 of the script's 45 checks
failed**.

Reproduced on Debian, so it was never an Alpine question:

| | without the package | with it |
| --- | --- | --- |
| Debian, openvpn 2.6.14 | 45 checks pass | 20 fail |
| Alpine, openvpn 2.7.5 | 45 checks pass | 20 fail |

This is `project.md`'s own recorded disease — *"a script that skips on a missing
package is a script whose failures nobody sees"* — with the polarity reversed
and therefore worse. `tunnel.sh` was red wherever openvpn was installed and
green elsewhere because it *skips*. `openvpn.sh` never skips: it is the script
written so the daemon does not have to be installed at all, and it was green
here only because this machine happens not to have the package.

## Decision

**`NCFG_OPENVPN` overrides the search**, in the same family as
`NCFG_WPA_CTRL_DIR`, `NCFG_RESOLV_CONF` and `NCFG_SYS_ROOT`, and for the same
stated reason: a test needs to point at something that is not the real one.

Not a convenience, and the doc comment says so. The alternatives were worse:

- **make the script skip when openvpn is installed** — that is the disease, not
  the cure. It would silently stop testing the command line on exactly the
  machines a developer is most likely to be using;
- **put the fake somewhere the search reaches** — the first directory is
  `/usr/sbin`, so the test would have to write into the real one;
- **search `PATH` first** — wrong for netcfgd, which is why the order is what it
  is.

The other faked daemons do not need this. `fake_hostapd.py` and
`fake_supplicant.py` bind a **control socket**; netcfgd talks to the socket and
never spawns the binary, and the socket directory is already overridable. Only
openvpn is faked by replacing the program.

**The skip messages name both distributions.** Seventeen of them said `apt
install ...`, which is advice being read on a machine where it is wrong now that
the suite runs on Alpine. Several package names genuinely differ —
`dhcpcd-base`/`dhcpcd`, `pppoe`/`ppp-pppoe`, `uidmap`/`shadow-uidmap`,
`dnsmasq-base`/`dnsmasq`, `network-manager`/`networkmanager`.

## The gates

The break is the state before the fix, and it is only visible with the package
installed — so it runs in a container of each distribution: remove the override,
keep openvpn, and the same 20 checks go red on both. With it, 45 pass on both.

## The size budget, re-baselined

`make size` was passing on tolerance: 2263576 bytes against a 2210328 limit,
2.41% of a 3% band, with 13 KB left. The file's own header says spending the
tolerance on features makes the next feature fail for the wrong reason, and that
was one page away from happening.

Measured rather than attributed, by building the release binary at six points
across the twenty-eight commits since the last entry. The interesting row is the
last: five changes — the `pre_down` teardown ordering, the dangling-dependency
fix, a supplicant's `answering`, two package formats and the zombie check —
land in **+0 bytes**. The linker pads to 4 KB pages, which this file already
knew, so a change smaller than a page is invisible and several can hide inside
one until they cross together. Nothing overspent; 2.41% accumulated four
kilobytes at a time.

## What is left, on Alpine

Three scripts still fail there, and none of them is netcfgd:

- **`tunnel.sh` against openvpn 2.7.5.** The test's own `.ovpn` uses a static
  key with no TLS, and 2.7 refuses to start on it: *"No tls-client or tls-server
  option in configuration detected... OpenVPN 2.8 will remove the
  functionality"*. netcfgd hands the operator's file over unread
  ([0046](0046-netcfgd-does-not-generate-openvpns-configuration.md)), so the
  configuration is the *test's* and this says nothing about the daemon — but it
  does mean this script cannot run against a current openvpn, and 2.8 will make
  that permanent.
- **`ppp.sh`**, one check: "and stops where an unprivileged machine has to".
- **`slaac.sh`**, which never reaches its checks because dnsmasq does not start
  under `unshare -rn` — and it fails the same way on the Debian host, so it is
  not an Alpine property either.

Recorded rather than fixed. Each is its own piece of work, and the first is the
one with a deadline attached to it.
