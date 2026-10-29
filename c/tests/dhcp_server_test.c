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

	text = ncfg_dhcp_server_render(&lan, "/run/netcfgd/dhcp-server/br0.leases", message,
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

	server.dns = dns;
	server.dns_count = 2u;
	server.lease.has = 1;
	server.lease.value = 3600;
	text = ncfg_dhcp_server_render(&lan, "/x.leases", message, sizeof(message));
	check(text && has_line(text, "dhcp-option=6,192.168.1.1,9.9.9.9") &&
	    has_line(text, "dhcp-range=br0,192.168.1.100,192.168.1.249,3600"),
	    "the DNS servers named are offered, in order, and the lease is the one stated");
	check(ncfg_dhcp_server_summary(&lan, summary, sizeof(summary)) &&
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

	source.static_address.address = NULL;
	text = ncfg_dhcp_server_render(&lan, "/x.leases", message, sizeof(message));
	check(!text && strstr(message, "cannot serve DHCP"),
	    "an interface with no address to serve from renders nothing, and says why");
	free(text);

	testdir_remove(run);
	if (failures) {
		printf("%d check(s) failed\n", failures);
		return 1;
	}
	printf("dhcp_server_test: all checks passed\n");
	return 0;
}
