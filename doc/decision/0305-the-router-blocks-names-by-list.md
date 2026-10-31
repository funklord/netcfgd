# 0305: the router blocks names by list

Status: accepted
Date: 2026-10-31
Milestone: the router side (project.md 10.640)
Amends: [0303](0303-the-lan-server-offers-what-a-router-offers.md)

## Context

0303 deferred ad blocking as "a source, a schedule and a size question
before it is a dnsmasq line". The holder asked for it, as UniFi has it. Each
of the three is answerable from the aims and from measurement.

## Decision

**A named `block_list` block, and a forwarding `dhcp_server` that names the
lists it applies**: UniFi's per-network toggle, with the list written once.

    block_list "ads" {
        file   = ["/var/lib/netcfgd/block/ads.txt"]
        domain = ["doubleclick.net"]
        allow  = ["ok.doubleclick.net"]
    }
    interface "lan0" { dhcp_server { dns_forward = true  block = ["ads"] } }

- **A blocked name answers NXDOMAIN, and so does everything under it**, in
  both families: dnsmasq's `address=/name/`, measured against 2.91. No block
  page and no web server: Pi-hole's old IP-answer mode needed one so that a
  browser did not hang on the router's address, and a name that does not
  exist needs nothing.
- **`allow` takes a name out**, and a subdomain of a blocked name back to the
  upstream (`server=/name/#`, measured), since a list that breaks a site needs
  an exception more than it needs anything else.
- **The source is a file the configuration names.** netcfgd does not fetch:
  the daemon would then hold an HTTP client and its output would depend on a
  remote at apply time. The file is configuration by reference, like a
  drop-in. Refreshing it is a separate step, `ncfg block fetch`, run by
  whatever schedules the operator likes.
- **netcfgd reads each file and writes what dnsmasq sees.** Passing a
  downloaded file to dnsmasq as configuration would let the list's author
  write `dhcp-script=` and run code as root. Every line is reduced to one
  name -- a hosts line, a bare name, `||name^`, or a dnsmasq `address=`,
  `local=` or `server=` line -- checked as a DNS name, and anything else is
  skipped.
- **The schedule is the file's**: a changed file is a changed summary
  digest, so the plan restarts the server, as it does for a changed record.
- **The size is bounded**: a file is read up to 64 MiB and a server blocks at
  most 1,048,576 names. Measured: 300,000 names start in 0.56 s and cost
  dnsmasq about 26 MB. A file that is missing or past the bound is left out
  with a plan warning, so a LAN keeps its DNS when a list is not there yet.
- **Blocking needs `dns_forward`**: the router answers only what it is
  asked. Two ways round it are closed alongside: `use-application-dns.net`
  answers NXDOMAIN wherever a server blocks, which is how Firefox is told not
  to use DNS over HTTPS, and `dns_intercept = true` redirects the LAN's
  port-53 traffic to the router, for devices with a DNS server built in.

## Alternatives considered

**A transparent HTTP(S) proxy.** Rejected: HTTPS is filtered by URL only by
decrypting it, which means a certificate authority on every client, breaks
pinned applications, and puts every password through the router. Without
decrypting, a proxy sees only the TLS server name, which DNS already blocks.

**`addn-hosts` with the file as it is.** Rejected: hosts entries block an
exact name and not its subdomains, and accept only one format.

**netcfgd fetches by URL.** Rejected above. `ncfg block fetch` keeps the
fetching in a command an operator runs, outside the daemon.
