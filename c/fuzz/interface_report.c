/*
 * An interface report: the `key=value` lines a tunnel, a cellular helper or a
 * DHCP client writes for netcfgd to take addressing from
 * (doc/interface-report.md).
 *
 * WHY THIS DESERVES A TARGET OF ITS OWN
 *   Root netcfgd parses these on every observation, and since `report_writer`
 *   (10.863) one directory of them can belong to another account -- the one
 *   charon drops to, which answers IKE from the network. 10.875 closed what
 *   that account could do with the files it places; what it writes inside
 *   one is this parser's to survive. No other target reaches it.
 *
 * THE INVARIANTS WORTH ASSERTING
 *   Every value kept is a string that ends inside its allocation, carries no
 *   newline -- a line is the unit, so a value holding one would be two lines
 *   read as one -- and no blank at either end, which `trim` takes off. Every
 *   route has a destination, and a gateway only where it said `via`. And the
 *   whole report frees cleanly, which the sanitizers check.
 */
#include "fuzz.h"

#include "ncfg/base.h"
#include "ncfg/state.h"

#include <stdlib.h>
#include <string.h>

static void kept(const char *value)
{
	size_t length;

	if (!value) {
		abort(); /* a counted entry with nothing in it */
	}
	length = strlen(value);
	if (length == 0u) {
		abort(); /* an empty value is skipped, never kept */
	}
	if (strchr(value, '\n')) {
		abort(); /* two lines read as one */
	}
	if (value[0] == ' ' || value[0] == '\t' || value[length - 1u] == ' ' ||
	    value[length - 1u] == '\t' || value[length - 1u] == '\r') {
		abort(); /* not trimmed */
	}
}

static void all_kept(char **values, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		kept(values[i]);
	}
}

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	ncfg_observed_report_t report;
	char                   err[NCFG_ERROR_MAX];
	size_t                 i;

	if (!ncfg_state_parse_report("tun0", (const char *)data, length, &report, err,
	        sizeof(err))) {
		return 0;
	}
	all_kept(report.addresses, report.address_count);
	all_kept(report.gateways, report.gateway_count);
	all_kept(report.nameservers, report.nameserver_count);
	all_kept(report.search, report.search_count);
	all_kept(report.peers, report.peer_count);
	for (i = 0; i < report.route_count; i++) {
		kept(report.routes[i].destination);
		if (report.routes[i].via) {
			kept(report.routes[i].via);
		}
	}
	if (report.iccid) {
		kept(report.iccid);
	}
	if (report.sim) {
		kept(report.sim);
	}
	ncfg_state_report_free(&report);
	return 0;
}
