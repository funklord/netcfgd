# 0303: the LAN's DHCP and DNS server offers what a router offers

Status: accepted
Date: 2026-10-31
Milestone: the router side, after the DNS forwarder (project.md 10.619)
Amends: [0297](0297-a-dhcp-server-is-policy-served-by-dnsmasq.md), [0301](0301-the-lan-is-answered-by-a-dns-forwarder.md)

## Context

0297 gave the LAN addresses: a range, a lease, DNS servers and reservations.
0301 made the same dnsmasq answer DNS. That is enough for a laptop on a LAN
and short of what an operator setting up a router expects to find, which the
holder put as **"we need fully functional dhcp and dns server config too, if
unifi has it, we probably want it too"** (2026-10-31).

UniFi Network's per-network DHCP and DNS settings, read as the list to meet:
a default gateway, a domain name, NTP servers, network boot (a boot server
and file), a TFTP server, a WPAD URL, custom DHCP options typed as text, IP,
integer, boolean or hex, DHCP relay, DHCPv6 with a range, the clients' leases
shown, and local DNS records -- host, alias, mail, text, service records and
forwarding a domain to another server.

## Decision

**Every one of them is policy in the `dhcp_server` block or beside it, and
dnsmasq serves it**, as 0297 and 0301 settled. Nothing here makes netcfgd
answer a request itself.

**The standard options are keys of their own**, not custom options, because
each has a meaning netcfgd can check and an operator reads by name:

| Key | Offered as | Checked |
|---|---|---|
| `gateway` | option 3 | an IPv4 address inside the network served; absent, the interface's own |
| `domain` | option 15, and the forwarder's local domain | a DNS name |
| `ntp` | option 42 | IPv4 addresses |
| `boot_file`, `boot_server` | the BOOTP file and next-server fields | a file name with no comma or quote; an IPv4 address, and only with a file |
| `tftp_server` | option 66 | a DNS name or address |
| `wpad` | option 252 | an `http://` or `https://` URL |

**`domain` also names the LAN under the forwarder**: with `dns_forward`, a
lease's name answers as `name.domain`, and the domain is answered locally
and never sent upstream (`local=/domain/`).

**Custom options are typed, never raw text.** `option "voip" { code = 150;
ip = ["10.0.0.5"] }`, with exactly one of `ip`, `text`, `u8`, `u16`, `u32`,
`bool` or `hex`, encoded by netcfgd into what dnsmasq is given. Raw
`dhcp-option=` text would let a document say anything dnsmasq can, which is
0294's reason for refusing raw nftables text; and an untyped number is
ambiguous on the wire, since dnsmasq guesses an unknown option's width. A
code that one of the keys above already sets is refused, so one option has
one spelling.

**Local DNS records are a top-level block**, because they are the router's
names rather than one LAN's: `dns_record "nas.home.lan" { address =
["192.168.1.10"] }`, with `cname`, `mx`, `txt`, `srv` or `forward` in place
of `address`. Every interface whose server forwards DNS answers all of them.
A reservation's name already resolves (0301); a record is for what holds no
lease.

**DHCPv6 is a range within the interface's IPv6 prefix**, given as suffixes
-- `range6 = "::100-::1ff"` -- so it follows a delegated prefix as the prefix
changes, which dnsmasq's `constructor:` does. Router advertisements stay
radvd's: a `range6` with an `advertise` that does not set `managed` is a plan
warning, since hosts are not told to ask.

**Relay is a mode of its own**, `dhcp_relay { servers = [...] }`, refused
beside a `dhcp_server` on one interface: one interface either answers or
passes requests on.

**Leases are shown, not written**: `ncfg status` and the GUI read the lease
file 0297 put under `/run`, which is what UniFi's client list is.

### Deferred, recorded so it is not rediscovered

- **Ad blocking and content filtering.** A blocklist is a list of thousands
  of names fetched from somewhere and refreshed, which is a source, a
  schedule and a size question before it is a dnsmasq line. Its own decision.
- **Upstream servers for the forwarder**, which 0301 rejected and this does
  not reopen: `forward` records cover the one case that needs a different
  upstream, a domain.
- **DHCP guarding** (refusing other DHCP servers on the LAN) is a firewall or
  bridge filter question, not the server's.

## Alternatives considered

**Custom options as `"code,value"` strings.** Rejected above: raw text, and
ambiguous widths.

**Records inside each `dhcp_server`.** Rejected: a router with three LANs
would write its NAS's name three times, the drift 0300 was written to stop.

**`gateway = false` to offer no router.** Not taken now: a LAN with no route
out is rare, and a server offering none is a later key if somebody needs it.
