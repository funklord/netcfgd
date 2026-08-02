# 0046: The .ovpn file is the operator's

Status: accepted
Date: 2026-08-02
Milestone: the first half of what 0036 called the VPN end-stage

## Context

Decision 0036 put VPN in netcfgd rather than in the shim, and said how it
fits: "netcfgd writes a configuration and supervises a daemon, as it does for
`pppd`, `wpa_supplicant` and `hostapd`." OpenVPN first, IPsec later and harder.

Half of that sentence turns out to be wrong for OpenVPN, and finding out which
half is what this record is for.

## A tunnel is an interface, exactly as a PPPoE session is

`InterfaceKind::OpenVpn`, not a `vpn` block that an interface references.

The precedent is `Pppoe` and it fits without adjustment. The interface *is* the
session: `openvpn` creates the `tun` device, so `plan_link_creation` must not
try to make one; the backend is a prerequisite planned before any addressing;
and the device appears seconds after the daemon starts, which means "waits for
the session" is a later reconcile rather than a later action in this plan. Every
one of those sentences is already written about PPPoE, and re-deriving them for
a second tunnel type would be how the two come to disagree.

## netcfgd does **not** generate the configuration

This is the opposite call from decision 0026, which has netcfgd generate
hostapd's file, and the reason is a number.

**`openvpn --help` lists 253 top-level options.** hostapd's expressible surface
is a couple of dozen keys that netcfgd owns completely and refuses by name where
it cannot render them. A netcfgd that expressed OpenVPN's surface would be a
second OpenVPN configuration language, permanently behind the first.

The second reason is what the artefact *is*. A `.ovpn` file is a thing an
operator is **given** -- by an employer, by a provider, by a colleague -- and
often signed or bundled with inline certificates. It is not a rendering of an
intent netcfgd holds; it is an input. Constraint 1 is about netcfgd not keeping
a second copy of state it owns, and this is not state netcfgd owns.

There is precedent in the model already: `EapConfig` carries `ca_cert` and
`client_cert` as *paths* to files netcfgd does not own and does not read. X.509
material got this treatment at M3 and nothing has wanted it back.

So the document points at the file:

```
interface vpn0 {
	openvpn { config = "/etc/openvpn/work.ovpn" }
}
```

### What that costs, stated rather than discovered

netcfgd cannot tell an operator that their `.ovpn` is wrong, cannot refuse an
option it does not understand, and cannot answer "why is it like this?" about
anything inside the file. `ncfg explain` stops at the file's edge.

That is a real loss against the hostapd model and it is the price of not owning
253 options. It is mitigated by exactly one thing: OpenVPN reports its own
errors, and netcfgd surfaces them the way it surfaces hostapd's -- the daemon's
own words, quoted, rather than an exit status.

## Stopped through its management socket, not by signal

`--management <path> unix` gives OpenVPN a line-oriented text protocol on a
unix socket, and `signal SIGTERM` over it stops the daemon.

That is the third time this shape has appeared -- `wpa_supplicant` and `hostapd`
are the others -- and decision 0014's sentence about it applies unchanged:
killing a process by name would reach a daemon netcfgd did not start. An
operator's own OpenVPN tunnels are common and netcfgd must not touch them.

It is a *stream* socket where `wpa_ctrl` is a datagram one, so the client is new
code rather than a reuse. It is small, and being able to stop only the daemon
netcfgd started is worth it.

## What is deliberately not decided here

**Who configures the tunnel's addresses and routes.** OpenVPN does it itself by
default, and `--route-noexec --ifconfig-noexec` plus an `--up` script would hand
that to netcfgd -- reporting through `/run` exactly as the modem helper does,
which would make netcfgd the single writer it is everywhere else.

That is attractive and it is not this decision. PPPoE has the same open question
and the same answer today: the daemon configures its own interface and netcfgd
observes. Two tunnel types behaving alike is worth more than one of them being
ideal, and changing both is a decision with its own record.

**Credentials.** `--auth-user-pass FILE` takes a two-line file, which netcfgd
would write under `/run` at 0600 from a `SecretRef` -- the same trade the
hostapd passphrase and the `pppd` options file already make. It is not in the
first slice because a `.ovpn` with inline certificates needs no password at all,
and that is the case worth having working first.

**IPsec.** Untouched. 0036 already says strongswan and libreswan disagree about
nearly everything, and nothing here makes that easier.

## Schema

`InterfaceKind` gains `OpenVpn` and `BackendKind` gains one to match. Both are
new variants in frozen enums, so both are a **major** bump were this released;
the version stays 1.0 because decision 0038 pins it until the first release.
The witness moves, and `make schema-bless` has to be run deliberately.
