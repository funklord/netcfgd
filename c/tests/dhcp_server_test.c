/*
 * dhcp_server_test.c -- what dnsmasq is given for a DHCP server (decision
 * 0297), against text rather than against a network.
 *
 * WHAT IS CHECKED
 *   That the file serves the interface's network and nothing else: DHCP only
 *   (`port=0`), bound to its interface, authoritative, the range the model
 *   works out, the lease, and a DNS server only where one is named -- since
 *   measured, dnsmasq offers none otherwise. And that the summary the file
 *   carries is the one the planner computes, read back the same.
 */
#include "ncfg/dhcp_server.h"

#include "ncfg/base.h"
#include "testdir.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static int check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
	return condition;
}

static int has_line(const char *text, const char *line)
{
	size_t      length = strlen(line);
	const char *at = text;

	while ((at = strstr(at, line)) != NULL) {
		if ((at == text || at[-1] == '\n') && (at[length] == '\n' || at[length] == '\0')) {
			return 1;
		}
		at += length;
	}
	return 0;
}

int main(void)
{
	const char             *run = testdir_make("dhcp_server");
	char                    address[] = "192.168.1.1/24";
	char                    name[] = "br0";
	char                    dns0[] = "192.168.1.1";
	char                    dns1[] = "9.9.9.9";
	char                   *dns[] = { dns0, dns1 };
	ncfg_address_source_t   source;
	ncfg_dhcp_server_t      server;
	ncfg_interface_t        lan;
	char                    summary[NCFG_DHCP_SERVER_SUMMARY_MAX];
	char                    recorded[NCFG_DHCP_SERVER_SUMMARY_MAX];
	char                    path[NCFG_DHCP_SERVER_PATH_MAX];
	char                    message[NCFG_ERROR_MAX];
	char                   *text;

	memset(&source, 0, sizeof(source));
	source.kind = NCFG_ADDRESS_SOURCE_STATIC;
	source.static_address.address = address;
	memset(&server, 0, sizeof(server));
	memset(&lan, 0, sizeof(lan));
	lan.name = name;
	lan.addressing = &source;
	lan.addressing_count = 1u;
	lan.dhcp_server = &server;

	text = ncfg_dhcp_server_render(NULL, &lan, "/run/netcfgd/dhcp-server/br0.leases", message,
	    sizeof(message));
	check(text && has_line(text, "port=0") && has_line(text, "interface=br0") &&
	    has_line(text, "bind-interfaces") && has_line(text, "dhcp-authoritative"),
	    "a DHCP server is dnsmasq with its DNS side off, bound to its interface");
	check(text && has_line(text, "user=nobody"),
	    "  running as the user its owner check accepts, said rather than defaulted");
	check(text && has_line(text, "dhcp-range=br0,192.168.1.100,192.168.1.249,43200") &&
	    has_line(text, "dhcp-leasefile=/run/netcfgd/dhcp-server/br0.leases"),
	    "  serving the default range for twelve hours, its leases under the run directory");
	check(text && !strstr(text, "dhcp-option=6"),
	    "  and offering no DNS server where none is named");
	free(text);

	/* **The forwarder** (0301): DNS on this interface alone, measured against
	 * 2.91 -- `interface=` also binds loopback, and `except-interface=lo` is
	 * what keeps it off a resolver already there. No `dhcp-option=6`, so the
	 * router is offered; and the summary changes, so turning it on restarts. */
	server.dns_forward = 1;
	text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
	check(text && has_line(text, "port=53") && !has_line(text, "port=0") &&
	        has_line(text, "except-interface=lo") && has_line(text, "interface=br0") &&
	        has_line(text, "domain-needed") && has_line(text, "bogus-priv") &&
	        !strstr(text, "dhcp-option=6"),
	    "a forwarding server answers DNS on its interface alone, offering itself");
	check(ncfg_dhcp_server_summary(NULL, &lan, summary, sizeof(summary)) &&
	        strcmp(summary, "192.168.1.100-192.168.1.249, 43200 s, dns this router, "
	                        "forwarding dns") == 0,
	    "  and says so in its summary, so turning it on is a restart");
	free(text);
	server.dns_forward = 0;

	server.dns = dns;
	server.dns_count = 2u;
	server.lease.has = 1;
	server.lease.value = 3600;
	text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
	check(text && has_line(text, "dhcp-option=6,192.168.1.1,9.9.9.9") &&
	    has_line(text, "dhcp-range=br0,192.168.1.100,192.168.1.249,3600"),
	    "the DNS servers named are offered, in order, and the lease is the one stated");
	check(ncfg_dhcp_server_summary(NULL, &lan, summary, sizeof(summary)) &&
	    strcmp(summary, "192.168.1.100-192.168.1.249, 3600 s, dns 192.168.1.1 9.9.9.9") == 0,
	    "the summary says what is served, in words a plan can show");
	check(text && strstr(text, "# serves: 192.168.1.100-192.168.1.249, 3600 s, dns ") != NULL,
	    "  and the file carries it");
	if (text && ncfg_dhcp_server_config_path(run, "br0", path, sizeof(path), NULL, 0)) {
		char directory[NCFG_DHCP_SERVER_PATH_MAX];

		(void)snprintf(directory, sizeof(directory), "%s/dhcp-server", run);
		testdir_mkdirp(directory);
		check(testdir_write(path, text, strlen(text)) &&
		    ncfg_dhcp_server_recorded(run, "br0", recorded, sizeof(recorded)) &&
		    strcmp(recorded, summary) == 0,
		    "  read back from it as the planner computes it");
	}
	free(text);

	/* Reservations (10.605): one dhcp-host line each, and the summary gains
	 * a count and a digest -- so a changed address is a changed summary. */
	{
		char             host_name[] = "printer";
		char             host_mac[] = "AA:BB:CC:DD:EE:01";
		char             host_address[] = "192.168.1.10";
		char             moved[] = "192.168.1.11";
		ncfg_dhcp_host_t host = { host_name, host_mac, host_address };
		char             before[NCFG_DHCP_SERVER_SUMMARY_MAX];

		server.hosts = &host;
		server.host_count = 1u;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(text && has_line(text, "dhcp-host=AA:BB:CC:DD:EE:01,192.168.1.10,printer"),
		    "a reservation is a dhcp-host line: the MAC, its address and its name");
		free(text);
		check(ncfg_dhcp_server_summary(NULL, &lan, before, sizeof(before)) &&
		    strncmp(before, summary, strlen(summary)) == 0 && strstr(before, ", 1 host "),
		    "  the summary keeps what it said and counts the reservation");
		host.address = moved;
		check(ncfg_dhcp_server_summary(NULL, &lan, recorded, sizeof(recorded)) &&
		    strcmp(recorded, before) != 0,
		    "  and a reservation moved to another address is a different summary");
		host.address = dns0;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(!text && strstr(message, "the interface's own"),
		    "  one given the router's own address renders nothing, and says why");
		free(text);
		server.hosts = NULL;
		server.host_count = 0u;
	}

	/* The standard options (0303): one line each, the domain kept local to a
	 * forwarder, and any of them changing the summary -- since dnsmasq reads
	 * its options only on a restart. */
	{
		char gateway[] = "192.168.1.254";
		char domain[] = "home.lan";
		char ntp0[] = "192.168.1.1";
		char ntp1[] = "192.168.1.2";
		char *ntp[] = { ntp0, ntp1 };
		char boot_file[] = "pxelinux.0";
		char boot_server[] = "192.168.1.5";
		char tftp[] = "tftp.home.lan";
		char wpad[] = "http://wpad.home.lan/wpad.dat";
		char outside[] = "10.0.0.1";
		char comma[] = "a,b";
		char before[NCFG_DHCP_SERVER_SUMMARY_MAX];

		check(ncfg_dhcp_server_summary(NULL, &lan, before, sizeof(before)) &&
		    !strstr(before, "options"),
		    "a server offering no options says nothing of them in its summary");
		server.gateway = gateway;
		server.domain = domain;
		server.ntp = ntp;
		server.ntp_count = 2u;
		server.boot_file = boot_file;
		server.boot_server = boot_server;
		server.tftp_server = tftp;
		server.wpad = wpad;
		server.dns_forward = 1;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(text && has_line(text, "dhcp-option=3,192.168.1.254") &&
		        has_line(text, "domain=home.lan") && has_line(text, "local=/home.lan/") &&
		        has_line(text, "dhcp-option=42,192.168.1.1,192.168.1.2") &&
		        has_line(text, "dhcp-boot=pxelinux.0,,192.168.1.5") &&
		        has_line(text, "dhcp-option=66,\"tftp.home.lan\"") &&
		        has_line(text, "dhcp-option=252,\"http://wpad.home.lan/wpad.dat\""),
		    "the standard options are a line each, the domain answered here alone");
		free(text);
		check(ncfg_dhcp_server_summary(NULL, &lan, recorded, sizeof(recorded)) &&
		        strstr(recorded, ", options ") != NULL,
		    "  and the summary carries their digest");
		strcpy(before, recorded);
		server.ntp_count = 1u;
		check(ncfg_dhcp_server_summary(NULL, &lan, recorded, sizeof(recorded)) &&
		        strcmp(recorded, before) != 0,
		    "  so dropping an NTP server is a different summary, and a restart");
		server.ntp_count = 2u;
		server.boot_server = NULL;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(text && has_line(text, "dhcp-boot=pxelinux.0"),
		    "a boot file with no server is the file alone");
		free(text);
		server.gateway = outside;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(!text && strstr(message, "gateway"),
		    "a gateway off the network renders nothing, and says why");
		free(text);
		server.gateway = gateway;
		server.boot_file = comma;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(!text && strstr(message, "boot_file"),
		    "  and so does a boot file that would end dnsmasq's field");
		free(text);
		server.boot_file = NULL;
		server.boot_server = boot_server;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(!text && strstr(message, "boot_server"),
		    "  and a boot server with no file to fetch from it");
		free(text);
		memset(&server.gateway, 0,
		    sizeof(server) - offsetof(ncfg_dhcp_server_t, gateway));
		server.dns_forward = 0;
	}

	/* Custom options (0303), encoded by type: a bare decimal is sent in the
	 * fewest bytes, so only u8 and bool are decimal. */
	{
		char                ip0[] = "192.168.1.9";
		char               *ips[] = { ip0 };
		char                motd[] = "hello";
		char                raw[] = "01:a2";
		char                one[] = "ff";
		char                n_voip[] = "voip", n_motd[] = "motd", n_mtu[] = "mtu",
		                    n_big[] = "big", n_flag[] = "flag", n_raw[] = "raw",
		                    n_one[] = "one";
		ncfg_dhcp_option_t  options[7];
		char                before[NCFG_DHCP_SERVER_SUMMARY_MAX];

		memset(options, 0, sizeof(options));
		options[0] = (ncfg_dhcp_option_t){ n_voip, 150, NCFG_DHCP_OPTION_IP, ips, 1u, NULL,
			{ 0, 0 } };
		options[1] = (ncfg_dhcp_option_t){ n_motd, 224, NCFG_DHCP_OPTION_TEXT, NULL, 0u, motd,
			{ 0, 0 } };
		options[2] = (ncfg_dhcp_option_t){ n_mtu, 225, NCFG_DHCP_OPTION_U16, NULL, 0u, NULL,
			{ 1, 5 } };
		options[3] = (ncfg_dhcp_option_t){ n_big, 226, NCFG_DHCP_OPTION_U32, NULL, 0u, NULL,
			{ 1, 70000 } };
		options[4] = (ncfg_dhcp_option_t){ n_flag, 227, NCFG_DHCP_OPTION_BOOL, NULL, 0u, NULL,
			{ 1, 1 } };
		options[5] = (ncfg_dhcp_option_t){ n_raw, 228, NCFG_DHCP_OPTION_HEX, NULL, 0u, raw,
			{ 0, 0 } };
		options[6] = (ncfg_dhcp_option_t){ n_one, 229, NCFG_DHCP_OPTION_HEX, NULL, 0u, one,
			{ 0, 0 } };
		check(ncfg_dhcp_server_summary(NULL, &lan, before, sizeof(before)), "a summary to compare");
		server.options = options;
		server.option_count = 7u;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(text && has_line(text, "dhcp-option=150,192.168.1.9") &&
		        has_line(text, "dhcp-option=224,\"hello\"") &&
		        has_line(text, "dhcp-option=225,00:05") &&
		        has_line(text, "dhcp-option=226,00:01:11:70") &&
		        has_line(text, "dhcp-option=227,1") && has_line(text, "dhcp-option=228,01:a2") &&
		        has_line(text, "dhcp-option=229,255"),
		    "custom options are encoded at their type's width, never left to a guess");
		free(text);
		check(ncfg_dhcp_server_summary(NULL, &lan, recorded, sizeof(recorded)) &&
		        strcmp(recorded, before) != 0,
		    "  and change the summary, so adding one restarts the server");
		options[2].number.value = 70000;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(!text && strstr(message, "does not fit its type"),
		    "a u16 too large renders nothing, and says why");
		free(text);
		options[2].number.value = 5;
		options[2].code = 6;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(!text && strstr(message, "`code`"),
		    "  and so does a code a key already sets, so it has one spelling");
		free(text);
		options[2].code = 224;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(!text && strstr(message, "share a name or a code"),
		    "  and two options of one code");
		free(text);
		server.options = NULL;
		server.option_count = 0u;
	}

	/* DNS records (0303): served by a forwarding server, one line per kind,
	 * and in the summary so a changed record restarts it. */
	{
		char              nas[] = "nas.home.lan", files[] = "files.home.lan",
		                  home[] = "home.lan", sip[] = "_sip._udp.home.lan",
		                  corp[] = "corp.example";
		char              v4[] = "192.168.1.10", v6[] = "fd00::10", up[] = "10.0.0.53";
		char             *addresses[] = { v4, v6 };
		char             *upstream[] = { up };
		char              mail[] = "mail.home.lan", spf[] = "v=spf1 -all", pbx[] = "pbx.home.lan";
		ncfg_dns_record_t records[5];
		ncfg_document_t   document;
		char              before[NCFG_DHCP_SERVER_SUMMARY_MAX];

		memset(records, 0, sizeof(records));
		memset(&document, 0, sizeof(document));
		records[0].name = nas;
		records[0].address = addresses;
		records[0].address_count = 2u;
		records[1].name = files;
		records[1].cname = nas;
		records[2].name = home;
		records[2].mx = mail;
		records[2].preference = (ncfg_optint_t){ 1, 5 };
		records[2].txt = spf;
		records[3].name = sip;
		records[3].srv = pbx;
		records[3].port = (ncfg_optint_t){ 1, 5060 };
		records[3].priority = (ncfg_optint_t){ 1, 1 };
		records[4].name = corp;
		records[4].forward = upstream;
		records[4].forward_count = 1u;
		document.dns_records = records;
		document.dns_record_count = 5u;

		text = ncfg_dhcp_server_render(&document, &lan, "/x.leases", message, sizeof(message));
		check(text && !strstr(text, "host-record=") && !strstr(text, "server=/"),
		    "a server that does not forward DNS answers no records");
		free(text);
		check(ncfg_dhcp_server_summary(&document, &lan, before, sizeof(before)) &&
		    !strstr(before, "record"), "  and its summary does not count them");
		server.dns_forward = 1;
		text = ncfg_dhcp_server_render(&document, &lan, "/x.leases", message, sizeof(message));
		check(text && has_line(text, "host-record=nas.home.lan,192.168.1.10,fd00::10") &&
		        has_line(text, "cname=files.home.lan,nas.home.lan") &&
		        has_line(text, "mx-host=home.lan,mail.home.lan,5") &&
		        has_line(text, "txt-record=home.lan,\"v=spf1 -all\"") &&
		        has_line(text, "srv-host=_sip._udp.home.lan,pbx.home.lan,5060,1,0") &&
		        has_line(text, "server=/corp.example/10.0.0.53"),
		    "a forwarding server answers every record, a line per kind");
		free(text);
		check(ncfg_dhcp_server_summary(&document, &lan, before, sizeof(before)) &&
		    strstr(before, ", 5 records "), "  and counts them in its summary");
		records[0].address_count = 1u;
		check(ncfg_dhcp_server_summary(&document, &lan, recorded, sizeof(recorded)) &&
		    strcmp(recorded, before) != 0,
		    "  so a record that loses an address is a restart");
		server.dns_forward = 0;
	}

	/* DHCPv6 (0303): suffixes put in the interface's own prefix by dnsmasq,
	 * refused on an interface that holds none, and in the summary. */
	{
		char                  start6[] = "::100", end6[] = "::1ff", v6[] = "fd00::1/64";
		ncfg_address_source_t sources[2];

		server.range6_start = start6;
		server.range6_end = end6;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(!text && strstr(message, "has none"),
		    "a DHCPv6 range on an interface with no IPv6 prefix renders nothing");
		free(text);
		sources[0] = source;
		memset(&sources[1], 0, sizeof(sources[1]));
		sources[1].kind = NCFG_ADDRESS_SOURCE_STATIC;
		sources[1].static_address.address = v6;
		lan.addressing = sources;
		lan.addressing_count = 2u;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(text && has_line(text, "dhcp-range=::100,::1ff,constructor:br0,64,3600"),
		    "  and on one with a prefix, the suffixes are put in it by dnsmasq");
		free(text);
		check(ncfg_dhcp_server_summary(NULL, &lan, recorded, sizeof(recorded)) &&
		        strstr(recorded, ", dhcpv6 ::100-::1ff"),
		    "  and the summary says so, so turning it on is a restart");
		server.range6_start = NULL;
		server.range6_end = NULL;
		lan.addressing = &source;
		lan.addressing_count = 1u;
	}

	/* Relay (0303): requests passed on from this interface's own address, and
	 * nothing leased here -- so no range, and anything a server offers is
	 * refused beside it. */
	{
		char  upstream[] = "10.9.0.2";
		char  ours[] = "192.168.1.1";
		char *relays[] = { upstream };
		const ncfg_dhcp_server_t serving = server;

		/* A relay carries nothing a server offers, so what the cases above
		 * left set is put aside and restored after. */
		server.lease.has = 0;
		server.dns_count = 0u;
		server.relay = relays;
		server.relay_count = 1u;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(text && has_line(text, "dhcp-relay=192.168.1.1,10.9.0.2") &&
		        has_line(text, "interface=br0") && !strstr(text, "dhcp-range") &&
		        !strstr(text, "dhcp-leasefile"),
		    "a relay passes requests on from the interface's address and leases nothing");
		free(text);
		check(ncfg_dhcp_server_summary(NULL, &lan, recorded, sizeof(recorded)) &&
		        strcmp(recorded, "relay to 10.9.0.2") == 0,
		    "  and its summary is where it relays to");
		server.lease.has = 1;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(!text && strstr(message, "hands out nothing"),
		    "  a lease beside a relay is refused, since leasing is the other server's");
		free(text);
		server.lease.has = 0;
		relays[0] = ours;
		text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
		check(!text && strstr(message, "other than the interface's own"),
		    "  and so is a relay to the interface itself");
		free(text);
		server = serving;
	}

	source.static_address.address = NULL;
	text = ncfg_dhcp_server_render(NULL, &lan, "/x.leases", message, sizeof(message));
	check(!text && strstr(message, "cannot serve DHCP"),
	    "an interface with no address to serve from renders nothing, and says why");
	free(text);

	/* The leases, read back for a station list (10.602). */
	{
		char directory[NCFG_DHCP_SERVER_PATH_MAX];
		char file[NCFG_DHCP_SERVER_PATH_MAX + 32];
		char host[NCFG_DHCP_SERVER_HOSTNAME_MAX];
		char leased[NCFG_ADDRESS_MAX];
		static const char lan_leases[] =
		    "2000 aa:bb:cc:00:00:01 192.168.1.101 phone *\n"
		    "1000 aa:bb:cc:00:00:02 192.168.1.102 gone *\n"
		    "0 aa:bb:cc:00:00:03 192.168.1.103 * *\n"
		    "2000 aa:bb:cc:00:00:04 192.168.1.104 "
		    "a-name-that-is-far-too-long-to-be-a-host-name-and-is-left-out-of-it-x *\n";
		static const char guest[] = "0 AA:BB:CC:00:00:05 10.0.0.105 tv *\n";

		(void)snprintf(directory, sizeof(directory), "%s/dhcp-server", run);
		testdir_mkdirp(directory);
		(void)snprintf(file, sizeof(file), "%s/lan0.leases", directory);
		(void)testdir_write(file, lan_leases, sizeof(lan_leases) - 1u);
		(void)snprintf(file, sizeof(file), "%s/guest0.leases", directory);
		(void)testdir_write(file, guest, sizeof(guest) - 1u);
		check(ncfg_dhcp_server_lease_of(run, "aa:bb:cc:00:00:01", 1500, host, sizeof(host),
		    leased, sizeof(leased)) && strcmp(host, "phone") == 0 &&
		    strcmp(leased, "192.168.1.101") == 0,
		    "a station's name and address come from the lease netcfgd's server gave it");
		check(!ncfg_dhcp_server_lease_of(run, "aa:bb:cc:00:00:02", 1500, host, sizeof(host),
		    leased, sizeof(leased)) && !host[0] && !leased[0],
		    "  and a lease that has expired is none");
		check(ncfg_dhcp_server_lease_of(run, "aa:bb:cc:00:00:03", 99999, host, sizeof(host),
		    leased, sizeof(leased)) && !host[0] && strcmp(leased, "192.168.1.103") == 0,
		    "  one that never expires holds, a client that sent no name has none");
		check(ncfg_dhcp_server_lease_of(run, "aa:bb:cc:00:00:04", 1500, host, sizeof(host),
		    leased, sizeof(leased)) && !host[0] && leased[0],
		    "  and a name too long to be a host name is left out, the address kept");
		check(ncfg_dhcp_server_lease_of(run, "aa:bb:cc:00:00:05", 1500, host, sizeof(host),
		    leased, sizeof(leased)) && strcmp(host, "tv") == 0,
		    "  from whichever interface's server leased it, the address in either case");
		check(!ncfg_dhcp_server_lease_of(run, "aa:bb:cc:00:00:09", 1500, host, sizeof(host),
		    leased, sizeof(leased)),
		    "  and a station no server leased to has nothing");
	}

	/* Every lease at once (0303), for `ncfg status` and the GUI: v4 keyed
	 * by MAC, v6 by IAID with no MAC, the server's `duid` line skipped, an
	 * expired lease left out, and a hostile name dropped with its lease kept. */
	{
		static const char lease_text[] =
		    "2000 aa:bb:cc:00:00:01 192.168.1.101 phone 01:aa:bb:cc:00:00:01\n"
		    "1000 aa:bb:cc:00:00:02 192.168.1.102 gone *\n"
		    "0 AA:BB:CC:00:00:03 192.168.1.103 * *\n"
		    "2000 aa:bb:cc:00:00:04 192.168.1.104 bad;name *\n"
		    "duid 00:01:00:01:2c:5b:3f:aa:aa:bb:cc:dd:ee:ff\n"
		    "2000 12345 fd00:7::188 laptop 00:01:00:01\n"
		    "garbage\n"
		    "2000 aa:bb:cc:00:00:05 not-an-address x *\n";
		ncfg_observed_lease_t *leases = NULL;
		size_t                 count = 0;

		check(ncfg_dhcp_server_leases_in_text(lease_text, 1500, &leases, &count) && count == 4u,
		    "every unexpired lease is read, and nothing that is not one");
		if (count == 4u) {
			check(strcmp(leases[0].address, "192.168.1.101") == 0 &&
			        strcmp(leases[0].mac, "AA:BB:CC:00:00:01") == 0 &&
			        strcmp(leases[0].hostname, "phone") == 0 && leases[0].expires == 2000,
			    "  a v4 lease: its address, its MAC as the document writes one, its name");
			check(strcmp(leases[1].address, "192.168.1.103") == 0 && leases[1].expires == 0 &&
			        !leases[1].hostname[0],
			    "  one that never expires, with no name");
			check(strcmp(leases[2].address, "192.168.1.104") == 0 && !leases[2].hostname[0],
			    "  a name that is not a host name is left out, the lease kept");
			check(strcmp(leases[3].address, "fd00:7::188") == 0 && !leases[3].mac[0] &&
			        strcmp(leases[3].hostname, "laptop") == 0,
			    "  and a v6 lease, which has no MAC, the duid line skipped");
		}
		ncfg_dhcp_server_leases_free(leases, count);
	}

	testdir_remove(run);
	if (failures) {
		printf("%d check(s) failed\n", failures);
		return 1;
	}
	printf("dhcp_server_test: all checks passed\n");
	return 0;
}
