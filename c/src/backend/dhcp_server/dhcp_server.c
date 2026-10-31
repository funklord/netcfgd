/*
 * dhcp_server.c -- dnsmasq as a DHCPv4 server, described in dhcp_server.h.
 */
#include "ncfg/dhcp_server.h"

#include "../backend_internal.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/process.h"

#include <ctype.h>
#include <dirent.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

/* A generated file is short; one a hundred times longer is not ours. */
#define DHCP_SERVER_CONFIG_MAX 8192u

/* What dnsmasq says when it will not start. */
static const char *const DHCP_SERVER_MARKERS[] = { "dnsmasq:", "failed", "bad", "error",
	"unknown", "cannot" };

static const char SUMMARY_PREFIX[] = "# serves: ";

/*
 * The user dnsmasq drops to once it holds its sockets, which every
 * distribution has. It matters to the check below: measured in a vm,
 * netcfgd's own running server read as somebody else's, because the owner
 * rule takes root or the asker and dnsmasq was neither by then.
 */
#define DHCP_SERVER_USER "nobody"

int ncfg_dhcp_server_config_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "dhcp-server", iface, ".conf", err, err_size);
}

int ncfg_dhcp_server_pid_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "dhcp-server", iface, ".pid", err, err_size);
}

int ncfg_dhcp_server_leases_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "dhcp-server", iface, ".leases", err,
	    err_size);
}

static int log_path(const char *run, const char *iface, char *out, size_t out_size, char *err,
    size_t err_size)
{
	return ncfg_backend_path(out, out_size, run, "dhcp-server", iface, ".log", err, err_size);
}

/* One more text into an FNV-1a digest, with a separator so "ab","c" and
 * "a","bc" differ. */
static uint32_t digest_text(uint32_t digest, const char *text)
{
	const char *c = text ? text : "";

	for (; *c; c++) {
		digest = (digest ^ (unsigned char)tolower((unsigned char)*c)) * 16777619u;
	}
	return (digest ^ 0u) * 16777619u;
}

/*
 * The options a server offers beyond its range, lease and DNS (0303), as one
 * digest, and whether there are any. Every member that reaches dnsmasq is in
 * it, so changing any of them changes the summary and the planner restarts
 * the server -- which re-reads options only on a restart.
 */
static int options_digest(const ncfg_dhcp_server_t *server, uint32_t *out)
{
	const char *const texts[] = { server->gateway, server->domain, server->boot_file,
		server->boot_server, server->tftp_server, server->wpad };
	uint32_t          digest = 2166136261u;
	int               any = 0;
	size_t            at;

	for (at = 0; at < sizeof(texts) / sizeof(texts[0]); at++) {
		any = any || texts[at] != NULL;
		digest = digest_text(digest, texts[at]);
	}
	for (at = 0; at < server->ntp_count; at++) {
		any = 1;
		digest = digest_text(digest, server->ntp[at]);
	}
	for (at = 0; at < server->option_count; at++) {
		const ncfg_dhcp_option_t *option = &server->options[at];
		char                      number[48];
		size_t                    one;

		any = 1;
		(void)snprintf(number, sizeof(number), "%lld %d %lld %d", (long long)option->code,
		    option->kind, (long long)option->number.value, option->number.has);
		digest = digest_text(digest_text(digest, option->name), number);
		digest = digest_text(digest, option->text);
		for (one = 0; one < option->ip_count; one++) {
			digest = digest_text(digest, option->ip[one]);
		}
	}
	*out = digest;
	return any;
}

/*
 * The router's DNS records (0303), as one digest and a count: what a
 * forwarding server answers itself, so a changed record is a changed summary
 * and a restart -- dnsmasq reads them only then. 0 records where the server
 * does not forward, since it answers none of them.
 */
static size_t records_digest(const ncfg_document_t *document, const ncfg_dhcp_server_t *server,
    uint32_t *out)
{
	uint32_t digest = 2166136261u;
	size_t   at;
	size_t   one;

	if (!document || !server->dns_forward) {
		return 0;
	}
	for (at = 0; at < document->dns_record_count; at++) {
		const ncfg_dns_record_t *record = &document->dns_records[at];
		char                     numbers[96];

		(void)snprintf(numbers, sizeof(numbers), "%d %lld %d %lld %d %lld %d %lld",
		    record->preference.has, (long long)record->preference.value, record->port.has,
		    (long long)record->port.value, record->priority.has,
		    (long long)record->priority.value, record->weight.has,
		    (long long)record->weight.value);
		digest = digest_text(digest_text(digest, record->name), numbers);
		digest = digest_text(digest_text(digest, record->cname), record->mx);
		digest = digest_text(digest_text(digest, record->txt), record->srv);
		for (one = 0; one < record->address_count; one++) {
			digest = digest_text(digest, record->address[one]);
		}
		digest = digest_text(digest, "|");
		for (one = 0; one < record->forward_count; one++) {
			digest = digest_text(digest, record->forward[one]);
		}
	}
	*out = digest;
	return document->dns_record_count;
}

int ncfg_dhcp_server_summary(const ncfg_document_t *document, const ncfg_interface_t *interface,
    char *out, size_t out_size)
{
	const ncfg_dhcp_server_t *server = interface ? interface->dhcp_server : NULL;
	char                      start[NCFG_ADDRESS_MAX];
	char                      end[NCFG_ADDRESS_MAX];
	size_t                    used;
	size_t                    at;

	if (!server || !ncfg_dhcp_server_range(interface, start, end, NULL, NULL)) {
		return 0;
	}
	/* "none" only where nothing answers (0301): a forwarding server with no
	 * `dns` offers itself, so the line says so, and a changed `dns_forward`
	 * is a changed summary and therefore a restart. */
	used = (size_t)snprintf(out, out_size, "%s-%s, %lld s, dns %s", start, end,
	    server->lease.has ? (long long)server->lease.value
	                      : (long long)NCFG_DHCP_SERVER_LEASE_DEFAULT,
	    server->dns_count ? "" : server->dns_forward ? "this router" : "none");
	for (at = 0; at < server->dns_count && used < out_size; at++) {
		used += (size_t)snprintf(out + used, out_size - used, "%s%s", at ? " " : "",
		    server->dns[at]);
	}
	if (server->dns_forward && used < out_size) {
		used += (size_t)snprintf(out + used, out_size - used, ", forwarding dns");
	}
	/* Absent with no DHCPv6, so a server that has none keeps its line. */
	if (server->range6_start && server->range6_end && used < out_size) {
		used += (size_t)snprintf(out + used, out_size - used, ", dhcpv6 %s-%s",
		    server->range6_start, server->range6_end);
	}
	/*
	 * **A count and a digest, not the list** (10.605). The line is bounded
	 * and a router may reserve dozens of hosts, so listing them would make a
	 * long list unservable; but a changed reservation must still read as a
	 * changed summary, or the planner would leave dnsmasq handing out the
	 * old address. The count is what an operator reads in the plan, the
	 * digest what makes any edit a difference. Absent with no reservations,
	 * so a server that has none keeps the line it always had.
	 */
	if (server->host_count && used < out_size) {
		uint32_t digest = 2166136261u;

		for (at = 0; at < server->host_count; at++) {
			const char *parts[3];
			size_t      part;

			parts[0] = server->hosts[at].name;
			parts[1] = server->hosts[at].mac;
			parts[2] = server->hosts[at].address;
			for (part = 0; part < 3u; part++) {
				const char *c = parts[part] ? parts[part] : "";

				for (; *c; c++) {
					digest = (digest ^ (unsigned char)tolower((unsigned char)*c)) *
					    16777619u;
				}
				digest = (digest ^ 0u) * 16777619u;
			}
		}
		used += (size_t)snprintf(out + used, out_size - used, ", %zu host%s %08x",
		    server->host_count, server->host_count == 1u ? "" : "s", (unsigned)digest);
	}
	/* Absent with none, so a server that offers none keeps its line. */
	{
		uint32_t digest;

		size_t   records;

		if (options_digest(server, &digest) && used < out_size) {
			used += (size_t)snprintf(out + used, out_size - used, ", options %08x",
			    (unsigned)digest);
		}
		records = records_digest(document, server, &digest);
		if (records && used < out_size) {
			used += (size_t)snprintf(out + used, out_size - used, ", %zu record%s %08x",
			    records, records == 1u ? "" : "s", (unsigned)digest);
		}
	}
	return used < out_size;
}

int ncfg_dhcp_server_recorded(const char *run, const char *iface, char *out, size_t out_size)
{
	char        path[NCFG_DHCP_SERVER_PATH_MAX];
	char       *text;
	const char *line;
	size_t      length;

	if (!ncfg_dhcp_server_config_path(run, iface, path, sizeof(path), NULL, 0)) {
		return 0;
	}
	text = ncfg_backend_read_file(path, NULL, DHCP_SERVER_CONFIG_MAX);
	if (!text) {
		return 0;
	}
	line = strstr(text, SUMMARY_PREFIX);
	if (!line || (line != text && line[-1] != '\n')) {
		free(text);
		return 0;
	}
	line += strlen(SUMMARY_PREFIX);
	length = strcspn(line, "\n");
	if (length >= out_size) {
		free(text);
		return 0;
	}
	memcpy(out, line, length);
	out[length] = '\0';
	free(text);
	return 1;
}

/*
 * One custom option (0303), encoded by its type rather than left to dnsmasq's
 * guess. dnsmasq sends a bare decimal in the fewest bytes that hold it:
 * measured in `make hull-dhcp-server`, a `u16` of 5 written as `5` reached a
 * client declaring the code `uint16` as nothing, the client refusing the one
 * byte. Colon-separated hex is sent octet for octet. So `u8` and `bool` are
 * decimal, which is one byte, and `u16` and `u32` are hex at their width; a
 * single-octet `hex` has no colon and would read as a number, so it is written
 * as the decimal of its one byte.
 */
static void render_custom_option(ncfg_buf_t *buf, const ncfg_dhcp_option_t *option)
{
	const unsigned long long value = (unsigned long long)option->number.value;
	size_t                   at;

	ncfg_buf_addf(buf, "dhcp-option=%lld,", (long long)option->code);
	switch (option->kind) {
	case NCFG_DHCP_OPTION_IP:
		for (at = 0; at < option->ip_count; at++) {
			ncfg_buf_addf(buf, "%s%s", at ? "," : "", option->ip[at]);
		}
		break;
	case NCFG_DHCP_OPTION_TEXT:
		ncfg_buf_addf(buf, "\"%s\"", option->text);
		break;
	case NCFG_DHCP_OPTION_U16:
		ncfg_buf_addf(buf, "%02llx:%02llx", (value >> 8) & 255u, value & 255u);
		break;
	case NCFG_DHCP_OPTION_U32:
		ncfg_buf_addf(buf, "%02llx:%02llx:%02llx:%02llx", (value >> 24) & 255u,
		    (value >> 16) & 255u, (value >> 8) & 255u, value & 255u);
		break;
	case NCFG_DHCP_OPTION_HEX:
		if (!strchr(option->text, ':')) {
			/* One octet: as decimal, which is one byte. */
			ncfg_buf_addf(buf, "%lu", strtoul(option->text, NULL, 16));
		} else {
			ncfg_buf_add_text(buf, option->text);
		}
		break;
	default:
		ncfg_buf_addf(buf, "%llu", value);
		break;
	}
	ncfg_buf_add_char(buf, '\n');
}

/*
 * The router's DNS records (0303), for a server that forwards. Each was
 * checked by `ncfg_dns_record_check`, so no field holds a comma, a quote or
 * a newline that would end its line. `host-record` answers A and AAAA,
 * `cname` an alias -- dnsmasq answers one only for a target it knows itself,
 * a lease, a reservation or another record -- and `server=/name/` sends the
 * name and everything under it to the servers named.
 */
static void render_records(ncfg_buf_t *buf, const ncfg_document_t *document)
{
	size_t at;
	size_t one;

	for (at = 0; document && at < document->dns_record_count; at++) {
		const ncfg_dns_record_t *record = &document->dns_records[at];

		if (!ncfg_dns_record_check(record, NULL)) {
			continue;
		}
		if (record->address_count) {
			ncfg_buf_addf(buf, "host-record=%s", record->name);
			for (one = 0; one < record->address_count; one++) {
				ncfg_buf_addf(buf, ",%s", record->address[one]);
			}
			ncfg_buf_add_char(buf, '\n');
		}
		if (record->cname) {
			ncfg_buf_addf(buf, "cname=%s,%s\n", record->name, record->cname);
		}
		if (record->mx) {
			ncfg_buf_addf(buf, "mx-host=%s,%s,%lld\n", record->name, record->mx,
			    record->preference.has ? (long long)record->preference.value : 10LL);
		}
		if (record->txt) {
			ncfg_buf_addf(buf, "txt-record=%s,\"%s\"\n", record->name, record->txt);
		}
		if (record->srv) {
			ncfg_buf_addf(buf, "srv-host=%s,%s,%lld,%lld,%lld\n", record->name, record->srv,
			    (long long)record->port.value,
			    record->priority.has ? (long long)record->priority.value : 0LL,
			    record->weight.has ? (long long)record->weight.value : 0LL);
		}
		for (one = 0; one < record->forward_count; one++) {
			ncfg_buf_addf(buf, "server=/%s/%s\n", record->name, record->forward[one]);
		}
	}
}

char *ncfg_dhcp_server_render(const ncfg_document_t *document, const ncfg_interface_t *interface,
    const char *leases_path, char *err, size_t err_size)
{
	const ncfg_dhcp_server_t *server = interface ? interface->dhcp_server : NULL;
	char                      start[NCFG_ADDRESS_MAX];
	char                      end[NCFG_ADDRESS_MAX];
	char                      summary[NCFG_DHCP_SERVER_SUMMARY_MAX];
	const char               *why = NULL;
	ncfg_buf_t                buf;
	size_t                    at;
	char                     *out;

	if (!server || !interface->name) {
		ncfg_error_set(err, err_size, "a DHCP server was rendered with no interface");
		return NULL;
	}
	if (!ncfg_dhcp_server_range(interface, start, end, NULL, &why) ||
	    !ncfg_dhcp_server_summary(document, interface, summary, sizeof(summary))) {
		ncfg_error_set(err, err_size, "%s cannot serve DHCP: %s", interface->name,
		    why ? why : "its range cannot be worked out");
		return NULL;
	}
	ncfg_buf_init(&buf, DHCP_SERVER_CONFIG_MAX);
	ncfg_buf_addf(&buf,
	    "# Written by netcfgd for %s (decision 0297). Do not edit; it is rewritten on apply.\n"
	    "%s%s\n", interface->name, SUMMARY_PREFIX, summary);
	if (server->dns_forward) {
		/* **A forwarder on this interface alone** (0301). `except-interface=lo`
		 * because `interface=` also binds loopback, measured against 2.91:
		 * without it this failed beside a resolver on 127.0.0.1:53 and two
		 * LANs' instances would collide. Upstream is /etc/resolv.conf, the
		 * router's own resolution, re-read when it changes. A bare name and a
		 * private address's reverse lookup are never sent upstream. */
		ncfg_buf_add_text(&buf,
		    "port=53\n"
		    "except-interface=lo\n"
		    "domain-needed\n"
		    "bogus-priv\n");
	} else {
		/* DHCP only: never also a resolver, so it cannot meet a `dns_mode =
		 * "dnsmasq"` delivery on port 53. */
		ncfg_buf_add_text(&buf, "port=0\n");
	}
	ncfg_buf_addf(&buf,
	    "interface=%s\n"
	    /* Measured: what lets two instances serve two interfaces at once. */
	    "bind-interfaces\n"
	    "dhcp-authoritative\n"
	    /* Said rather than left to the build's default, so the owner the
	     * running server is checked against is the one it runs as. */
	    "user=" DHCP_SERVER_USER "\n"
	    "dhcp-range=%s,%s,%s,%lld\n"
	    "dhcp-leasefile=%s\n",
	    interface->name, interface->name, start, end,
	    server->lease.has ? (long long)server->lease.value
	                      : (long long)NCFG_DHCP_SERVER_LEASE_DEFAULT,
	    leases_path ? leases_path : "");
	/* DHCPv6 (0303): the suffixes put in whatever prefix the interface holds
	 * when dnsmasq starts, which is what follows a delegated prefix. No
	 * `enable-ra`: router advertisements are radvd's (0009), and they are
	 * what tells a host to ask. */
	if (server->range6_start && server->range6_end) {
		ncfg_buf_addf(&buf, "dhcp-range=%s,%s,constructor:%s,64,%lld\n",
		    server->range6_start, server->range6_end, interface->name,
		    server->lease.has ? (long long)server->lease.value
		                      : (long long)NCFG_DHCP_SERVER_LEASE_DEFAULT);
	}
	/* One line per reservation: dnsmasq gives this MAC this address and
	 * this name, and never gives the address to anybody else. */
	for (at = 0; at < server->host_count; at++) {
		ncfg_buf_addf(&buf, "dhcp-host=%s,%s,%s\n", server->hosts[at].mac,
		    server->hosts[at].address, server->hosts[at].name);
	}
	if (server->dns_count) {
		ncfg_buf_add_text(&buf, "dhcp-option=6");
		for (at = 0; at < server->dns_count; at++) {
			ncfg_buf_addf(&buf, ",%s", server->dns[at]);
		}
		ncfg_buf_add_char(&buf, '\n');
	}
	/* The standard options (0303), each checked by `ncfg_dhcp_server_range`
	 * above: no quote, comma or newline reaches a line it could end. */
	if (server->gateway) {
		ncfg_buf_addf(&buf, "dhcp-option=3,%s\n", server->gateway);
	}
	if (server->domain) {
		/* Option 15, and the name a lease answers under. With the
		 * forwarder on, the domain is the LAN's own: answered here, never
		 * asked upstream. */
		ncfg_buf_addf(&buf, "domain=%s\n", server->domain);
		if (server->dns_forward) {
			ncfg_buf_addf(&buf, "local=/%s/\n", server->domain);
		}
	}
	if (server->ntp_count) {
		ncfg_buf_add_text(&buf, "dhcp-option=42");
		for (at = 0; at < server->ntp_count; at++) {
			ncfg_buf_addf(&buf, ",%s", server->ntp[at]);
		}
		ncfg_buf_add_char(&buf, '\n');
	}
	if (server->boot_file) {
		/* The file, no server name, and the next-server address where one
		 * is given: dnsmasq's three fields. */
		ncfg_buf_addf(&buf, "dhcp-boot=%s%s%s\n", server->boot_file,
		    server->boot_server ? ",," : "", server->boot_server ? server->boot_server : "");
	}
	if (server->tftp_server) {
		ncfg_buf_addf(&buf, "dhcp-option=66,\"%s\"\n", server->tftp_server);
	}
	if (server->wpad) {
		ncfg_buf_addf(&buf, "dhcp-option=252,\"%s\"\n", server->wpad);
	}
	for (at = 0; at < server->option_count; at++) {
		render_custom_option(&buf, &server->options[at]);
	}
	if (server->dns_forward) {
		render_records(&buf, document);
	}
	if (ncfg_buf_failed(&buf)) {
		ncfg_buf_free(&buf);
		ncfg_error_set(err, err_size, "out of memory rendering the DHCP server on %s",
		    interface->name);
		return NULL;
	}
	out = ncfg_buf_take(&buf, NULL);
	ncfg_buf_free(&buf);
	return out;
}

int ncfg_dhcp_server_start(const char *run, const ncfg_document_t *document,
    const ncfg_interface_t *interface, const char *program, char *err, size_t err_size)
{
	char        dir[NCFG_DHCP_SERVER_PATH_MAX];
	char        config[NCFG_DHCP_SERVER_PATH_MAX];
	char        pid[NCFG_DHCP_SERVER_PATH_MAX];
	char        log[NCFG_DHCP_SERVER_PATH_MAX];
	char        leases[NCFG_DHCP_SERVER_PATH_MAX];
	char        said[NCFG_ERROR_MAX];
	char       *found = NULL;
	char       *text;
	const char *argv[6];
	int         exited_ok = 0;
	int         status = 0;
	int         ok;

	if (!interface || !interface->name) {
		ncfg_error_set(err, err_size, "a DHCP server was started with no interface");
		return 0;
	}
	if (!ncfg_backend_join(dir, sizeof(dir), run, "dhcp-server", err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size) ||
	    !ncfg_dhcp_server_config_path(run, interface->name, config, sizeof(config), err,
	        err_size) ||
	    !ncfg_dhcp_server_pid_path(run, interface->name, pid, sizeof(pid), err, err_size) ||
	    !log_path(run, interface->name, log, sizeof(log), err, err_size) ||
	    !ncfg_dhcp_server_leases_path(run, interface->name, leases, sizeof(leases), err,
	        err_size)) {
		return 0;
	}
	text = ncfg_dhcp_server_render(document, interface, leases, err, err_size);
	if (!text) {
		return 0;
	}
	ok = ncfg_backend_write_file(config, text, strlen(text), 0644, err, err_size);
	free(text);
	if (!ok) {
		return 0;
	}
	if (!program) {
		found = ncfg_backend_find_program("dnsmasq");
		if (!found) {
			ncfg_error_set(err, err_size,
			    "no dnsmasq found for %s; serving DHCP needs the dnsmasq package "
			    "(dnsmasq-base is enough)", interface->name);
			return 0;
		}
		program = found;
	}
	/*
	 * **The path as an argument of its own**, `-C <path>` rather than
	 * `--conf-file=<path>`: `ncfg_process_pid_of` takes the marker as a whole
	 * argument of `/proc/<pid>/cmdline`, so the fused spelling made netcfgd's
	 * own running server read as somebody else's -- measured in a vm, every
	 * plan after the first planned the start again.
	 */
	argv[0] = program;
	argv[1] = "-C";
	argv[2] = config;
	argv[3] = "-x";
	argv[4] = pid;
	argv[5] = NULL;
	if (!ncfg_backend_run(program, argv, log, &exited_ok, &status, err, err_size)) {
		free(found);
		return 0;
	}
	free(found);
	if (!exited_ok) {
		if (ncfg_backend_complaints(log, DHCP_SERVER_MARKERS,
		        sizeof(DHCP_SERVER_MARKERS) / sizeof(DHCP_SERVER_MARKERS[0]), NULL, 0u, 2u, said,
		        sizeof(said))) {
			ncfg_error_set(err, err_size, "dnsmasq would not serve DHCP on %s: %s. Its output "
			    "is in %s", interface->name, said, log);
		} else {
			ncfg_error_set(err, err_size, "dnsmasq would not serve DHCP on %s: it exited with "
			    "status %d. Its output is in %s", interface->name, status, log);
		}
		return 0;
	}
	return 1;
}

pid_t ncfg_dhcp_server_running_pid(const char *run, const char *iface)
{
	char           config[NCFG_DHCP_SERVER_PATH_MAX];
	char           pid_file[NCFG_DHCP_SERVER_PATH_MAX];
	struct passwd *user;
	pid_t          pid;

	/* The generated configuration, in the daemon's own argv, is the marker:
	 * a path netcfgd chose, which an operator's dnsmasq cannot carry. */
	if (!ncfg_dhcp_server_config_path(run, iface, config, sizeof(config), NULL, 0) ||
	    !ncfg_dhcp_server_pid_path(run, iface, pid_file, sizeof(pid_file), NULL, 0)) {
		return 0;
	}
	/* Root's or the asker's, as every backend's -- and then the user it drops
	 * to. That is no wider a door: the pid file is dnsmasq's, written as root
	 * into netcfgd's own directory before it drops, and the marker is a path
	 * netcfgd chose, so a process of `nobody`'s has to be named by both. */
	pid = ncfg_process_pid_of(pid_file, config);
	if (pid > 0) {
		return pid;
	}
	user = getpwnam(DHCP_SERVER_USER);
	return user ? ncfg_process_pid_of_as(pid_file, config, user->pw_uid) : 0;
}

/* radvd's wait, for radvd's reason: a stop that returns while the daemon is
 * still exiting lets a restart start a second one beside it. */
#define DHCP_SERVER_STOP_PATIENCE_MS 1000
#define DHCP_SERVER_STOP_STEP_MS 25

int ncfg_dhcp_server_stop(const char *run, const char *iface, char *err, size_t err_size)
{
	char  pid_file[NCFG_DHCP_SERVER_PATH_MAX];
	pid_t pid = ncfg_dhcp_server_running_pid(run, iface);
	int   waited = 0;

	if (pid <= 0) {
		return 1;
	}
	if (!ncfg_process_terminate(pid, err, err_size)) {
		return 0;
	}
	while (ncfg_dhcp_server_running_pid(run, iface) > 0) {
		struct timespec step;

		if (waited >= DHCP_SERVER_STOP_PATIENCE_MS) {
			ncfg_error_set(err, err_size,
			    "dnsmasq on %s is still running %d ms after SIGTERM; its pid file is left "
			    "in place, so a start that follows sees it rather than beginning a second",
			    iface, DHCP_SERVER_STOP_PATIENCE_MS);
			return 0;
		}
		step.tv_sec = 0;
		step.tv_nsec = (long)DHCP_SERVER_STOP_STEP_MS * 1000000L;
		(void)nanosleep(&step, NULL);
		waited += DHCP_SERVER_STOP_STEP_MS;
	}
	/* The configuration and the leases stay: the one says what was served,
	 * the other who holds which address, and a start reads both. */
	if (ncfg_dhcp_server_pid_path(run, iface, pid_file, sizeof(pid_file), NULL, 0)) {
		(void)unlink(pid_file);
	}
	return 1;
}

/* One lease file's answer for `mac`, or 0. */
/*
 * The lease of one MAC in a lease file's text.
 *
 * Split from the reading so the fuzzer can reach it (project.md 10.622): the
 * name in each line is whatever the client sent, so this is the most hostile
 * input netcfgd parses on the router side -- chosen by any machine on the LAN,
 * written verbatim by dnsmasq, read here.
 */
int ncfg_dhcp_server_lease_in_text(const char *text, const char *mac, long long now,
    char *hostname, size_t hostname_size, char *address, size_t address_size)
{
	const char *line;
	int         found = 0;

	if (!text || !mac || !hostname || !hostname_size || !address || !address_size) {
		return 0;
	}
	for (line = text; !found && line && *line;
	    line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
		long long expiry;
		char      leased_mac[32];
		char      leased_address[NCFG_ADDRESS_MAX];
		char      name[256];

		if (sscanf(line, "%lld %31s %49s %255s", &expiry, leased_mac, leased_address, name) != 4 ||
		    strcasecmp(leased_mac, mac) != 0 || (expiry != 0 && expiry <= now)) {
			continue;
		}
		found = 1;
		(void)snprintf(address, address_size, "%s", leased_address);
		(void)snprintf(hostname, hostname_size, "%s",
		    strcmp(name, "*") != 0 && ncfg_dhcp_server_plain_name(name) ? name : "");
	}
	return found;
}

static int lease_in(const char *path, const char *mac, long long now, char *hostname,
    size_t hostname_size, char *address, size_t address_size)
{
	char *text = ncfg_backend_read_file(path, NULL, 1024u * 1024u);
	int   found;

	if (!text) {
		return 0;
	}
	found = ncfg_dhcp_server_lease_in_text(text, mac, now, hostname, hostname_size, address,
	    address_size);
	free(text);
	return found;
}

int ncfg_dhcp_server_lease_of(const char *run, const char *mac, long long now, char *hostname,
    size_t hostname_size, char *address, size_t address_size)
{
	char           dir[NCFG_DHCP_SERVER_PATH_MAX];
	DIR           *listing;
	struct dirent *entry;
	int            found = 0;

	if (hostname && hostname_size) {
		hostname[0] = '\0';
	}
	if (address && address_size) {
		address[0] = '\0';
	}
	if (!run || !mac || !hostname || !address ||
	    !ncfg_backend_join(dir, sizeof(dir), run, "dhcp-server", NULL, 0)) {
		return 0;
	}
	/* netcfgd's own directory, and only the files whose name says they are
	 * leases; nothing else there is read. */
	listing = opendir(dir);
	if (!listing) {
		return 0;
	}
	while (!found && (entry = readdir(listing)) != NULL) {
		size_t length = strlen(entry->d_name);
		char   path[NCFG_DHCP_SERVER_PATH_MAX * 2u];

		if (length <= 7u || strcmp(entry->d_name + length - 7u, ".leases") != 0) {
			continue;
		}
		if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name) >= sizeof(path)) {
			continue;
		}
		found = lease_in(path, mac, now, hostname, hostname_size, address, address_size);
	}
	(void)closedir(listing);
	return found;
}
