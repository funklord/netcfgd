/*
 * script.c -- the script udhcpc runs when a lease changes.
 *
 * See `dhcp.h` for why there has to be one at all -- without `-s` the client
 * obtains a lease and configures nothing (0065) -- and for the three things it
 * deliberately leaves alone. What is here is the rendering, which is pure so
 * that what a lease does to an interface can be read without taking one.
 */
#include "ncfg/dhcp.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Fixed text plus three paths. A ceiling because everything built in this port
 * has one, not because this could plausibly reach it. */
#define SCRIPT_MAX (64u * 1024u)

/*
 * Where a writer stages a report before renaming it into place.
 *
 * `doc/interface-report.md` tells every writer to build a temporary file *in
 * the same directory* and `rename(2)` it over the target, because a rename is
 * the only way to publish a file whole and it has to be on the same
 * filesystem. It did not say what to call it, and the reader took every entry
 * in that directory as an interface name -- so the half-written file the
 * contract exists to hide was read as a report for an interface named after
 * the temporary file. Measured: a report appeared for an interface called
 * `.eth0.tmp.1234`. Decision 0113.
 *
 * **A leading dot**, and the reason is collision rather than convention: dots
 * are ordinary *inside* an interface name -- a VLAN is `eth0.100` -- so a rule
 * about the suffix would skip a real interface, while nothing an interface can
 * be called begins with one. `ncfg_state_read_reports` skips exactly that.
 */
static int staged_path(const char *target, char *out, size_t out_size)
{
	const char *slash = strrchr(target, '/');
	size_t      dir_length = slash ? (size_t)(slash - target) + 1u : 0u;
	int         written;

	written = snprintf(out, out_size, "%.*s.%s.tmp", (int)dir_length, target,
	    slash ? slash + 1 : target);
	return written >= 0 && (size_t)written < out_size;
}

char *ncfg_dhcp_pd_script(const char *iface, const char *target, const char *report, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	char       staged[NCFG_DHCP_PATH_MAX];
	char       router[NCFG_DHCP_PATH_MAX];
	char       addresses[NCFG_DHCP_PATH_MAX];
	char       report_staged[NCFG_DHCP_PATH_MAX];
	char      *out;

	if (!iface || !target || !report) {
		ncfg_error_set(err, err_size,
		    "a prefix hook was rendered with no interface or nowhere to report to");
		return NULL;
	}
	/* `.<iface>.router` beside `.<iface>.tmp`: the staged name less its
	 * suffix, so it shares the leading dot the reader skips. */
	if (!staged_path(target, staged, sizeof(staged)) || strlen(staged) < 4u ||
	    snprintf(router, sizeof(router), "%.*s.router", (int)(strlen(staged) - 4u), staged) >=
	        (int)sizeof(router) ||
	    snprintf(addresses, sizeof(addresses), "%.*s.addresses", (int)(strlen(staged) - 4u),
	        staged) >= (int)sizeof(addresses) ||
	    !staged_path(report, report_staged, sizeof(report_staged))) {
		ncfg_error_set(err, err_size,
		    "the staging name beside %s is longer than this build will build", target);
		return NULL;
	}
	/* The interface goes into the script inside single quotes now, as the
	 * udhcpc script's does, so it is refused there for the same reason. */
	if (strchr(iface, '\'') || strchr(target, '\'') || strchr(report, '\'')) {
		ncfg_error_set(err, err_size,
		    "the prefix hook for %s would carry a single quote, which would end the "
		    "quoting around a name and run what follows it", iface);
		return NULL;
	}
	ncfg_buf_init(&buf, SCRIPT_MAX);
	/*
	 * **`PREFIXES` is odhcp6c's, and there is deliberately no second variable
	 * beside it.** The Rust's carried `$new_dhcp6_prefix` "for dhcpcd" for a
	 * while, which is not a variable dhcpcd sets: the nearest thing it has is
	 * `$new_delegated_dhcp6_prefix`, and that carries the addresses dhcpcd
	 * itself derived from a prefix rather than the prefix. netcfgd does the
	 * deriving (0009 makes a prefix reference an indirection the document
	 * resolves), so there is nothing for dhcpcd to delegate to and the
	 * variable is always empty. `ncfg_dhcp6_client` refuses that pairing
	 * outright, so this script is odhcp6c's and says so (0050).
	 *
	 * Written to a temporary and renamed, which is `doc/interface-report.md`'s
	 * rule and `ncfg_dhcp_udhcpc_script`'s: the observer may read at any
	 * moment and a half-written file reads as a shorter list rather than as an
	 * error. Rewritten rather than appended, because a renewal that changed
	 * the prefix must not leave both.
	 *
	 * `${p%%,*}` strips odhcp6c's trailing lifetimes: it reports
	 * `2001:db8::/56,3600,7200`, and the prefix is everything before the first
	 * comma.
	 */
	ncfg_buf_addf(&buf,
	    "#!/bin/sh\n"
	    "# Written by netcfgd. odhcp6c's configuration step on %s: the prefixes\n"
	    "# it was delegated, one per line (an empty file means the lease is gone);\n"
	    "# its own addresses and the default route, into the kernel; and the name\n"
	    "# servers, as an interface-report fragment.\n"
	    "#\n"
	    "# Run by odhcp6c. dhcpcd cannot report a delegated prefix to a script\n"
	    "# at all -- see doc/decision/0050 -- so netcfgd refuses that pairing\n"
	    "# rather than leaving a variable here that would never be set.\n"
	    "set -u\n"
	    "out='%s'\n"
	    ": > '%s'\n"
	    "for p in ${PREFIXES:-}; do\n"
	    "\tprintf '%%s\\n' \"${p%%%%,*}\" >> '%s'\n"
	    "done\n"
	    "mv '%s' \"$out\"\n",
	    iface, target, staged, staged, staged);
	/*
	 * **And the ISP's router, which is the uplink's IPv6 default route.** An
	 * IPv6 default route only ever comes from a router advertisement --
	 * DHCPv6 has no router option -- and odhcp6c hears the advertisement in
	 * userspace and hands it to this script as `RA_ROUTES`, one
	 * `prefix/len,gateway,valid,priority` each. Nothing installed it: the
	 * kernel's own processing is off on an interface that forwards unless
	 * `accept_ra` is 2, a router forwards, and OpenWrt's netifd had zeroed it
	 * besides. So a router given a prefix had no way out (project.md 10.822).
	 * The udhcpc script installs IPv4's default route for the same reason:
	 * the client has no configuration step of its own.
	 *
	 * The gateway installed is recorded beside the prefixes under a leading
	 * dot, which the report reader skips (0113), so withdrawing it removes
	 * that route and no other: the ISP's advertisement taking the router away,
	 * or the lease going, both arrive here with no `::/0` in the list.
	 */
	/*
	 * **And what the lease gave the uplink itself** (project.md 10.823).
	 * `ADDRESSES` is IA_NA's, `addr/len,preferred,valid` each, and odhcp6c
	 * puts none of them on the interface: installed here, recorded under a
	 * leading dot as the router is, and one that leaves the list removed and
	 * no other. `RDNSS` is DHCPv6's name servers, `RA_DNS` the advertisement's
	 * (`addr,lifetime`), `DOMAINS` the search list: written as the
	 * interface-report fragment `reported.d/<iface>/odhcp6c`, staged and
	 * renamed as every report is, so a dual-stack uplink's udhcpc report and
	 * this one do not overwrite each other (0086). A name server the two lists
	 * share is written once.
	 */
	ncfg_buf_addf(&buf,
	    "\n"
	    "iface='%s'\n"
	    "addresses='%s'\n"
	    "was=\n"
	    "[ -r \"$addresses\" ] && was=$(cat \"$addresses\")\n"
	    "now=\n"
	    "for a in ${ADDRESSES:-}; do\n"
	    "\tnow=\"$now ${a%%%%,*}\"\n"
	    "done\n"
	    "for a in $was; do\n"
	    "\tcase \" $now \" in\n"
	    "\t*\" $a \"*) ;;\n"
	    "\t*) ip -6 addr del \"$a\" dev \"$iface\" 2>/dev/null || true ;;\n"
	    "\tesac\n"
	    "done\n"
	    "for a in $now; do\n"
	    "\tip -6 addr replace \"$a\" dev \"$iface\"\n"
	    "done\n"
	    "if [ -n \"$now\" ]; then\n"
	    "\tprintf '%%s\\n' $now > \"$addresses\"\n"
	    "else\n"
	    "\trm -f \"$addresses\"\n"
	    "fi\n"
	    "\n"
	    "{\n"
	    "\tprintf '# %%s, from DHCPv6. Written by netcfgd.\\n' \"$iface\"\n"
	    "\tseen=\n"
	    "\tfor d in ${RDNSS:-} ${RA_DNS:-}; do\n"
	    "\t\td=${d%%%%,*}\n"
	    "\t\tcase \" $seen \" in\n"
	    "\t\t*\" $d \"*) continue ;;\n"
	    "\t\tesac\n"
	    "\t\tseen=\"$seen $d\"\n"
	    "\t\tprintf 'dns=%%s\\n' \"$d\"\n"
	    "\tdone\n"
	    "\tfor s in ${DOMAINS:-}; do\n"
	    "\t\tprintf 'search=%%s\\n' \"$s\"\n"
	    "\tdone\n"
	    "} > '%s'\n"
	    "mv '%s' '%s'\n",
	    iface, addresses, report_staged, report_staged, report);
	ncfg_buf_addf(&buf,
	    "\n"
	    "router='%s'\n"
	    "gateway=\n"
	    "for r in ${RA_ROUTES:-}; do\n"
	    "\tcase \"$r\" in\n"
	    "\t::/0,*)\n"
	    "\t\tgateway=${r#::/0,}\n"
	    "\t\tgateway=${gateway%%%%,*}\n"
	    "\t\tbreak\n"
	    "\t\t;;\n"
	    "\tesac\n"
	    "done\n"
	    "held=\n"
	    "[ -r \"$router\" ] && held=$(cat \"$router\")\n"
	    "if [ -n \"$held\" ] && [ \"$held\" != \"$gateway\" ]; then\n"
	    "\tip -6 route del default via \"$held\" dev \"$iface\" 2>/dev/null || true\n"
	    "\trm -f \"$router\"\n"
	    "fi\n"
	    "if [ -n \"$gateway\" ]; then\n"
	    "\tip -6 route replace default via \"$gateway\" dev \"$iface\" &&\n"
	    "\t\tprintf '%%s' \"$gateway\" > \"$router\"\n"
	    "fi\n"
	    "exit 0\n",
	    router);
	if (ncfg_buf_failed(&buf)) {
		ncfg_error_set(err, err_size,
		    "the prefix hook for %s is larger than this build will render", iface);
		ncfg_buf_free(&buf);
		return NULL;
	}
	out = ncfg_buf_take(&buf, NULL);
	if (!out) {
		ncfg_error_set(err, err_size, "out of memory rendering the prefix hook for %s",
		    iface);
	}
	ncfg_buf_free(&buf);
	return out;
}

char *ncfg_dhcp_udhcpc_script(const char *iface, const char *state, const char *report,
    char *err, size_t err_size)
{
	ncfg_buf_t buf;
	char       staged[NCFG_DHCP_PATH_MAX];
	char      *out;

	if (!iface || !state || !report) {
		ncfg_error_set(err, err_size,
		    "a udhcpc script was rendered with no interface, no state file or no report");
		return NULL;
	}
	if (!staged_path(report, staged, sizeof(staged))) {
		ncfg_error_set(err, err_size,
		    "the staging name beside %s is longer than this build will build", report);
		return NULL;
	}
	/*
	 * **A single quote in any of these three would end the quoting** and turn
	 * the rest of a path into shell. None of them can hold one -- two are
	 * composed here from a run directory and an interface name, and the third
	 * is the interface name -- but "cannot" is the claim this project checks
	 * rather than makes, and the cost of being wrong is a lease event running
	 * whatever came after the quote as root.
	 */
	if (strchr(iface, '\'') || strchr(state, '\'') || strchr(report, '\'')) {
		ncfg_error_set(err, err_size,
		    "the udhcpc script for %s would carry a single quote, which would end the "
		    "quoting around a path and run what follows it", iface);
		return NULL;
	}

	ncfg_buf_init(&buf, SCRIPT_MAX);
	ncfg_buf_addf(&buf,
	    "#!/bin/sh\n"
	    "# Written by netcfgd for udhcpc on %s. Regenerated on every apply.\n"
	    "#\n"
	    "# udhcpc has no configuration step of its own: without a script it obtains a\n"
	    "# lease and does nothing with it. This installs the address and the default\n"
	    "# route and touches nothing else -- not the MTU, which the config owns, and\n"
	    "# not resolv.conf, which netcfgd's DNS backend owns.\n"
	    "set -u\n"
	    "state='%s'\n"
	    "report='%s'\n"
	    "iface=${interface:?udhcpc did not say which interface}\n"
	    "\n",
	    iface, state, report);
	/* What this script added last time, so `deconfig` removes exactly that and
	 * leaves any address netcfgd itself put on the interface alone. A stock
	 * script flushes, which would delete a static address installed beside the
	 * lease. */
	ncfg_buf_add_text(&buf,
	    "# What this script added last time, so `deconfig` removes exactly that and\n"
	    "# leaves any address netcfgd itself put on the interface alone.\n"
	    "held=\n"
	    "[ -r \"$state\" ] && held=$(cat \"$state\")\n"
	    "\n"
	    "withdraw() {\n"
	    "\t[ -n \"$held\" ] || return 0\n"
	    "\tip -4 route del default dev \"$iface\" 2>/dev/null || true\n"
	    "\tip -4 addr del \"$held\" dev \"$iface\" 2>/dev/null || true\n"
	    "\trm -f \"$state\"\n"
	    "\trm -f \"$report\"\n"
	    "}\n"
	    "\n");
	/* What the server offered, for netcfgd to read. `doc/interface-report.md`
	 * is the format, and 0049 is why a domain is a comment: a server may name
	 * resolvers, and which names use them is the operator's to write down.
	 *
	 * Written to a temporary and renamed, because netcfgd may read at any
	 * moment and a half-written file would be read as a shorter list rather
	 * than as an error. Rewritten rather than appended, so a renewal that
	 * dropped a server does not leave it behind. */
	ncfg_buf_addf(&buf,
	    "# What the server offered, for netcfgd to read: the nameservers, and the\n"
	    "# domain as a comment. doc/interface-report.md is the format and decision\n"
	    "# 0049 is why a domain is a comment -- a server may name resolvers, and\n"
	    "# which names use them is the operator's to write down.\n"
	    "#\n"
	    "# Written to a temporary and renamed, because netcfgd may read at any moment\n"
	    "# and a half-written file would be read as a shorter list rather than as an\n"
	    "# error. Rewritten rather than appended, so a renewal that dropped a server\n"
	    "# does not leave it behind.\n"
	    "report() {\n"
	    "\t{\n"
	    "\t\tprintf '# %%s, from a DHCPv4 lease. Written by netcfgd.\\n' \"$iface\"\n"
	    "\t\tfor server in ${dns:-}; do\n"
	    "\t\t\tprintf 'dns=%%s\\n' \"$server\"\n"
	    "\t\tdone\n"
	    "\t\t# The search list, which is option 119 where the server sent one and\n"
	    "\t\t# option 15 otherwise -- the same precedence dhcpcd's own hook uses.\n"
	    "\t\t# A suffix, never a routing domain: 0067 says which is which.\n"
	    "\t\tfor suffix in ${search:-${domain:-}}; do\n"
	    "\t\t\tprintf 'search=%%s\\n' \"$suffix\"\n"
	    "\t\tdone\n"
	    "\t} > '%s'\n"
	    "\tmv '%s' \"$report\"\n"
	    "}\n"
	    "\n",
	    staged, staged);
	/* `$mask` is a prefix length and `$subnet` is the same thing dotted; `ip`
	 * takes only the first, so a client that sets only `subnet` is refused by
	 * name rather than guessed at. */
	ncfg_buf_add_text(&buf,
	    "case \"${1:-}\" in\n"
	    "bound|renew)\n"
	    "\t: \"${ip:?udhcpc reported no address}\"\n"
	    "\t# A prefix length, which is `$mask`. `$subnet` carries the same thing in\n"
	    "\t# dotted form and `ip` will not take it, so an old client that sets only\n"
	    "\t# `subnet` is refused by name rather than guessed at.\n"
	    "\t: \"${mask:?this udhcpc does not set \\$mask; netcfgd needs a prefix length}\"\n"
	    "\tnew=\"$ip/$mask\"\n"
	    "\t[ \"$new\" = \"$held\" ] || withdraw\n"
	    "\tip -4 addr replace \"$new\" dev \"$iface\"\n"
	    "\tprintf '%s' \"$new\" > \"$state\"\n"
	    "\tif [ -n \"${router:-}\" ]; then\n"
	    "\t\tfor gateway in $router; do\n"
	    "\t\t\tip -4 route replace default via \"$gateway\" dev \"$iface\" && break\n"
	    "\t\tdone\n"
	    "\tfi\n"
	    "\treport\n"
	    "\t;;\n"
	    "deconfig|nak|leasefail)\n"
	    "\t# The lease is gone or was never obtained. `deconfig` also arrives once\n"
	    "\t# before the first lease, when there is nothing recorded and this is a\n"
	    "\t# no-op.\n"
	    "\twithdraw\n"
	    "\t;;\n"
	    "esac\n"
	    "exit 0\n");

	if (ncfg_buf_failed(&buf)) {
		ncfg_error_set(err, err_size,
		    "the udhcpc script for %s is larger than this build will render", iface);
		ncfg_buf_free(&buf);
		return NULL;
	}
	out = ncfg_buf_take(&buf, NULL);
	if (!out) {
		ncfg_error_set(err, err_size, "out of memory rendering the udhcpc script for %s",
		    iface);
	}
	ncfg_buf_free(&buf);
	return out;
}
