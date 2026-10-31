/*
 * lower_interface.c -- `interface`, which is what runs over a device.
 *
 * The split between this block and `device` is which side a setting means
 * something on: an MTU means something with nothing plugged in, an address
 * does not. 0155 moved the hardware half out in two passes, and the keys it
 * took are still named here rather than left to "unknown interface key" --
 * somebody who wrote `mtu` on an interface had a working configuration, and a
 * message that only said the key was unknown would leave them guessing.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lower_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

/* The two sentences 0155 left behind, said once each. The first is for what
 * pass 1b moved -- what netcfgd creates -- and the second for pass 1a's
 * settings of the adapter itself. */
static const char *const moved_structural =
    "it describes the hardware rather than a connection over it: write `device <name> { ... }` "
    "beside this block and move the line there unchanged";
static const char *const moved_adapter =
    "it describes the hardware rather than a connection over it, so it means something whether "
    "or not anything is connected: write `device <name> { ... }` beside this block and move the "
    "line there unchanged";

/* ------------------------------------------------------------------------ *
 * Hooks
 * ------------------------------------------------------------------------ */

void ncfg_lower_hook(ncfg_lower_ctx_t *ctx, const ncfg_ast_hook_t *hook, const char *owner,
    ncfg_hook_ref_t **list, size_t *count)
{
	ncfg_hook_phase_t phase;
	ncfg_hook_ref_t   built;
	ncfg_hook_ref_t  *slot;
	char              why[NCFG_ERROR_MAX];

	if (!ncfg_hook_phase_from_name(hook->phase, &phase, NULL, 0)) {
		ncfg_diag(ctx, hook->span,
		    "unknown hook phase `%s`: phases: pre_up, up, post_up, pre_down, down, post_down, "
		    "and `on` with carrier, lease, roam, portal or drift", hook->phase);
		return;
	}
	memset(&built, 0, sizeof(built));
	built.phase = (int)phase;
	why[0] = '\0';
	if (!ctx->hooks || !ctx->hooks->record(ctx->hooks->state, (int)phase, owner,
	    hook->body ? hook->body : "", hook->body_length, &built, why, sizeof(why))) {
		ncfg_diag(ctx, hook->span, "%s", why[0] ? why : "this caller cannot accept hooks");
		free(built.path);
		free(built.sha256);
		free(built.run_as);
		return;
	}
	slot = ncfg_push(ctx, list, count, sizeof(*slot));
	if (!slot) {
		free(built.path);
		free(built.sha256);
		free(built.run_as);
		return;
	}
	*slot = built;
}

/* ------------------------------------------------------------------------ *
 * probe
 * ------------------------------------------------------------------------ */

/*
 * `probe { command = "/bin/ping"; args = ["-c1", "1.1.1.1"]; ... }`.
 *
 * The exit status is the answer, so the whole block is a program, how often to
 * run it, how long to wait, and how many results in a row it takes to change
 * netcfgd's mind (0119).
 */
static int lower_probe(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_probe_policy_t *out)
{
	ncfg_probe_policy_t probe;
	size_t              i;

	memset(&probe, 0, sizeof(probe));
	probe.interval = 30;
	probe.timeout = 5;
	probe.down_after = 3;
	probe.up_after = 2;
	probe.hold_down = 0;
	/* On unless the operator says otherwise: an interface that asked for DHCP
	 * and has no lease has nothing a reachability probe could succeed over. */
	probe.require_lease = 1;

	for (i = 0; i < block->items.count; i++) {
		const ncfg_ast_item_t *item = block->items.at[i];
		const ncfg_ast_assignment_t *assignment;
		const char                  *key;
		int64_t                      number;
		int                          flag;

		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		key = assignment->key;
		if (strcmp(key, "command") == 0) {
			free(probe.command);
			probe.command = ncfg_as_string(ctx, assignment->value);
		} else if (strcmp(key, "args") == 0) {
			ncfg_words_t words;
			size_t       at;

			/* Lines rather than words: an argument may contain a space, and a
			 * probe is a program with an argument vector rather than a command
			 * line for a shell to split. */
			if (!ncfg_as_lines(ctx, assignment->value, &words)) {
				ncfg_words_free(&words);
				continue;
			}
			for (at = 0; at < words.count; at++) {
				(void)ncfg_push_string(ctx, &probe.args, &probe.arg_count, words.at[at].text);
			}
			ncfg_words_free(&words);
		} else if (strcmp(key, "interval") == 0) {
			if (ncfg_as_u32(ctx, assignment->value, &number)) {
				probe.interval = number;
			}
		} else if (strcmp(key, "timeout") == 0) {
			if (ncfg_as_u32(ctx, assignment->value, &number)) {
				probe.timeout = number;
			}
		} else if (strcmp(key, "down_after") == 0) {
			if (ncfg_as_u32(ctx, assignment->value, &number)) {
				probe.down_after = number;
			}
		} else if (strcmp(key, "up_after") == 0) {
			if (ncfg_as_u32(ctx, assignment->value, &number)) {
				probe.up_after = number;
			}
		} else if (strcmp(key, "hold_down") == 0) {
			if (ncfg_as_u32(ctx, assignment->value, &number)) {
				probe.hold_down = number;
			}
		} else if (strcmp(key, "require_lease") == 0) {
			/* Default on, and named for what it requires rather than for what
			 * it switches off: `require_lease = false` reads as a decision,
			 * where `skip_lease_check = true` reads as a workaround (0191). */
			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				probe.require_lease = flag;
			}
		} else {
			ncfg_diag(ctx, assignment->span, "`%s` is not valid inside `probe`", key);
		}
	}

	if (!probe.command) {
		goto drop;
	}
	/* Absolute, for the reason a hook path is: netcfgd runs this as root, and
	 * a relative name is whatever `PATH` happens to resolve at the time. */
	if (probe.command[0] != '/') {
		ncfg_diag(ctx, block->span,
		    "`%s` is not an absolute path: a probe runs as root, so it is named by path and "
		    "not found on PATH", probe.command);
		goto drop;
	}
	/* A zero count would mean "change my mind on no evidence", which is not a
	 * faster failover, it is none of the hysteresis the counts exist for. */
	if (probe.down_after == 0 || probe.up_after == 0) {
		ncfg_diag(ctx, block->span,
		    "`up_after` and `down_after` have to be at least 1: they are consecutive-result "
		    "counts; zero would switch on no result");
		goto drop;
	}
	if (probe.interval == 0) {
		ncfg_diag(ctx, block->span, "`interval` has to be at least 1 second");
		goto drop;
	}
	*out = probe;
	return 1;

drop:
	free(probe.command);
	for (i = 0; i < probe.arg_count; i++) {
		free(probe.args[i]);
	}
	free(probe.args);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * advertise
 * ------------------------------------------------------------------------ */

/*
 * `advertise { }`: what this interface tells the hosts behind it.
 *
 * The router half of decision 0009. A LAN addressed out of a delegated prefix
 * has to advertise that prefix or nothing on it configures itself, and the
 * prefix is a *reference* for the same reason the address was: no config file
 * could contain a block an ISP has not handed out yet.
 *
 * netcfgd does not send the advertisement; 0009 hands that to radvd or odhcpd.
 */
/* What one policy owns: its prefixes, their names, and an `exec` command.
 * Shared by the refusal below and by a second `advertise` block replacing the
 * first, which freed the struct and leaked all three. */
static void release_advertise(ncfg_ra_policy_t *policy)
{
	size_t i;

	for (i = 0; i < policy->prefix_count; i++) {
		free(policy->prefixes[i].source);
	}
	free(policy->prefixes);
	free(policy->backend.command);
}

/*
 * `host "printer" { mac = "AA:BB:CC:DD:EE:FF"  address = "192.168.1.10" }`
 * inside `dhcp_server` (10.605). The label is the name dnsmasq gives the host,
 * labelled as an access point or a firewall rule is, because it is the
 * reservation's identity: a plan names it, and two of one name are refused.
 * The address is checked against the network with the range, after the block.
 */
static void lower_dhcp_host(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_dhcp_server_t *server)
{
	ncfg_dhcp_host_t  host;
	ncfg_dhcp_host_t *grown;
	size_t            i;

	memset(&host, 0, sizeof(host));
	host.name = ncfg_require_label(ctx, block);
	if (!host.name) {
		return;
	}
	for (i = 0; i < block->items.count; i++) {
		const ncfg_ast_item_t       *item = block->items.at[i];
		const ncfg_ast_assignment_t *assignment;

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `host`",
			    item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		if (strcmp(assignment->key, "mac") == 0) {
			char *text = ncfg_as_string(ctx, assignment->value);
			char  canonical[18];
			char  why[NCFG_ERROR_MAX];

			if (!text) {
				continue;
			}
			if (!ncfg_hardware_address_strict(text, canonical, sizeof(canonical), why,
			        sizeof(why))) {
				ncfg_diag(ctx, assignment->span, "%s", why);
				free(text);
				continue;
			}
			free(text);
			free(host.mac);
			host.mac = strdup(canonical);
			if (!host.mac) {
				ncfg_lower_oom(ctx);
			}
		} else if (strcmp(assignment->key, "address") == 0) {
			char *text = ncfg_as_string(ctx, assignment->value);

			if (!text) {
				continue;
			}
			free(host.address);
			host.address = text;
		} else {
			ncfg_diag(ctx, assignment->span, "unknown host key `%s`: mac and address",
			    assignment->key);
		}
	}
	if (!host.mac || !host.address) {
		ncfg_diag(ctx, block->span, "host `%s` needs both `mac` and `address`", host.name);
		free(host.name);
		free(host.mac);
		free(host.address);
		return;
	}
	grown = realloc(server->hosts, (server->host_count + 1u) * sizeof(*grown));
	if (!grown) {
		ncfg_lower_oom(ctx);
		free(host.name);
		free(host.mac);
		free(host.address);
		return;
	}
	server->hosts = grown;
	server->hosts[server->host_count++] = host;
}

/*
 * `option "voip" { code = 150; ip = ["10.0.0.5"] }` inside `dhcp_server`
 * (0303): a code and exactly one typed value, whose key is its type. The
 * shapes are `ncfg_dhcp_server_range`'s to check with the rest of the block;
 * here only that one value was given, and hex is lowercased so a document
 * says one thing one way.
 */
static void lower_dhcp_option(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_dhcp_server_t *server)
{
	static const char *const kinds[] = { "ip", "text", "u8", "u16", "u32", "bool", "hex" };
	ncfg_dhcp_option_t  option;
	ncfg_dhcp_option_t *grown;
	int                 has_code = 0;
	int                 values = 0;
	size_t              i;

	memset(&option, 0, sizeof(option));
	option.name = ncfg_require_label(ctx, block);
	if (!option.name) {
		return;
	}
	for (i = 0; i < block->items.count; i++) {
		const ncfg_ast_item_t       *item = block->items.at[i];
		const ncfg_ast_assignment_t *assignment;
		size_t                       kind;

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `option`",
			    item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		if (strcmp(assignment->key, "code") == 0) {
			has_code = ncfg_as_i64(ctx, assignment->value, &option.code);
			continue;
		}
		for (kind = 0; kind < sizeof(kinds) / sizeof(kinds[0]); kind++) {
			if (strcmp(assignment->key, kinds[kind]) == 0) {
				break;
			}
		}
		if (kind == sizeof(kinds) / sizeof(kinds[0])) {
			ncfg_diag(ctx, assignment->span,
			    "unknown option key `%s`: code, and one of ip, text, u8, u16, u32, bool and "
			    "hex", assignment->key);
			continue;
		}
		values++;
		option.kind = (int)kind;
		if (kind == NCFG_DHCP_OPTION_IP) {
			ncfg_words_t words;
			size_t       at;

			if (!ncfg_as_words(ctx, assignment->value, &words)) {
				ncfg_words_free(&words);
				continue;
			}
			for (at = 0; at < words.count; at++) {
				char **more = realloc(option.ip, (option.ip_count + 1u) * sizeof(*more));

				if (!more) {
					ncfg_lower_oom(ctx);
					break;
				}
				option.ip = more;
				option.ip[option.ip_count] = strdup(words.at[at].text);
				if (!option.ip[option.ip_count++]) {
					ncfg_lower_oom(ctx);
				}
			}
			ncfg_words_free(&words);
		} else if (kind == NCFG_DHCP_OPTION_TEXT || kind == NCFG_DHCP_OPTION_HEX) {
			char *text = ncfg_as_string(ctx, assignment->value);
			char *c;

			if (!text) {
				continue;
			}
			for (c = text; kind == NCFG_DHCP_OPTION_HEX && *c; c++) {
				*c = (char)tolower((unsigned char)*c);
			}
			option.text = text;
		} else if (kind == NCFG_DHCP_OPTION_BOOL) {
			int flag;

			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				option.number.has = 1;
				option.number.value = flag;
			}
		} else if (ncfg_as_i64(ctx, assignment->value, &option.number.value)) {
			option.number.has = 1;
		}
	}
	if (!has_code || values != 1) {
		ncfg_diag(ctx, block->span,
		    "option `%s` needs a `code` and exactly one value, keyed by its type: ip, text, "
		    "u8, u16, u32, bool or hex", option.name);
		ncfg_dhcp_option_free(&option);
		return;
	}
	grown = realloc(server->options, (server->option_count + 1u) * sizeof(*grown));
	if (!grown) {
		ncfg_lower_oom(ctx);
		ncfg_dhcp_option_free(&option);
		return;
	}
	server->options = grown;
	server->options[server->option_count++] = option;
}

/* The single-text options (0303): the slot a key fills, NULL for any other
 * key. */
static char **dhcp_server_text_slot(ncfg_dhcp_server_t *server, const char *key)
{
	if (strcmp(key, "gateway") == 0) {
		return &server->gateway;
	}
	if (strcmp(key, "domain") == 0) {
		return &server->domain;
	}
	if (strcmp(key, "boot_file") == 0) {
		return &server->boot_file;
	}
	if (strcmp(key, "boot_server") == 0) {
		return &server->boot_server;
	}
	if (strcmp(key, "tftp_server") == 0) {
		return &server->tftp_server;
	}
	if (strcmp(key, "wpad") == 0) {
		return &server->wpad;
	}
	return NULL;
}

/*
 * `dhcp_server { range = "A-B"  lease = N  dns = [...] }` (0297). The range
 * is checked against the interface's address after the whole block, since
 * `config` may come after this one; here only each value's own shape.
 */
static ncfg_dhcp_server_t *lower_dhcp_server(ncfg_lower_ctx_t *ctx,
    const ncfg_ast_block_t *block)
{
	ncfg_dhcp_server_t *server = calloc(1, sizeof(*server));
	size_t              i;

	if (!server) {
		ncfg_lower_oom(ctx);
		return NULL;
	}
	for (i = 0; i < block->items.count; i++) {
		const ncfg_ast_item_t       *item = block->items.at[i];
		const ncfg_ast_assignment_t *assignment;
		int64_t                      value;

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			if (strcmp(item->as.block.head, "host") == 0) {
				lower_dhcp_host(ctx, &item->as.block, server);
				continue;
			}
			if (strcmp(item->as.block.head, "option") == 0) {
				lower_dhcp_option(ctx, &item->as.block, server);
				continue;
			}
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `dhcp_server`",
			    item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		if (strcmp(assignment->key, "range") == 0) {
			char       *text = ncfg_as_string(ctx, assignment->value);
			char       *dash = text ? strchr(text, '-') : NULL;
			const char *first = text;
			char       *second = dash ? dash + 1 : NULL;
			size_t      length;

			if (!text) {
				continue;
			}
			if (!dash) {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a range: write it as two addresses, "
				    "\"192.168.1.100-192.168.1.249\"", text);
				free(text);
				continue;
			}
			*dash = '\0';
			while (*first == ' ') {
				first++;
			}
			length = strlen(first);
			while (length && first[length - 1u] == ' ') {
				length--;
			}
			while (*second == ' ') {
				second++;
			}
			free(server->range_start);
			free(server->range_end);
			server->range_start = strndup(first, length);
			server->range_end = strdup(second);
			length = server->range_end ? strlen(server->range_end) : 0u;
			while (length && server->range_end[length - 1u] == ' ') {
				server->range_end[--length] = '\0';
			}
			free(text);
			if (!server->range_start || !server->range_end) {
				ncfg_lower_oom(ctx);
			}
		} else if (strcmp(assignment->key, "lease") == 0) {
			if (!ncfg_as_i64(ctx, assignment->value, &value)) {
				continue;
			}
			if (value < NCFG_DHCP_SERVER_LEASE_MIN || value > 4294967295LL) {
				ncfg_diag(ctx, assignment->span,
				    "`lease = %lld` is not a lease dnsmasq takes: seconds, %d or more",
				    (long long)value, NCFG_DHCP_SERVER_LEASE_MIN);
				continue;
			}
			server->lease.has = 1;
			server->lease.value = value;
		} else if (strcmp(assignment->key, "dns") == 0) {
			ncfg_words_t words;
			size_t       at;

			if (!ncfg_as_words(ctx, assignment->value, &words)) {
				ncfg_words_free(&words);
				continue;
			}
			for (at = 0; at < words.count; at++) {
				ncfg_address_t address;
				char         **grown;

				if (!ncfg_address_parse(words.at[at].text, &address, NULL, 0) ||
				    address.is_ipv6 || address.has_prefix) {
					ncfg_diag(ctx, assignment->span,
					    "`%s` is not a DNS server a DHCPv4 server can offer: an IPv4 "
					    "address, with no prefix", words.at[at].text);
					continue;
				}
				grown = realloc(server->dns, (server->dns_count + 1u) * sizeof(*grown));
				if (!grown) {
					ncfg_lower_oom(ctx);
					break;
				}
				server->dns = grown;
				server->dns[server->dns_count] = strdup(words.at[at].text);
				if (!server->dns[server->dns_count++]) {
					ncfg_lower_oom(ctx);
				}
			}
			ncfg_words_free(&words);
		} else if (strcmp(assignment->key, "dns_forward") == 0) {
			int flag;

			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				server->dns_forward = flag;
			}
		} else if (strcmp(assignment->key, "ntp") == 0) {
			/* The shapes are `ncfg_dhcp_server_range`'s to check, with the
			 * rest of the block, so one sentence refuses a bad one wherever
			 * it is met (0303). */
			ncfg_words_t words;
			size_t       at;

			if (!ncfg_as_words(ctx, assignment->value, &words)) {
				ncfg_words_free(&words);
				continue;
			}
			for (at = 0; at < words.count; at++) {
				char **grown = realloc(server->ntp, (server->ntp_count + 1u) * sizeof(*grown));

				if (!grown) {
					ncfg_lower_oom(ctx);
					break;
				}
				server->ntp = grown;
				server->ntp[server->ntp_count] = strdup(words.at[at].text);
				if (!server->ntp[server->ntp_count++]) {
					ncfg_lower_oom(ctx);
				}
			}
			ncfg_words_free(&words);
		} else if (dhcp_server_text_slot(server, assignment->key) != NULL) {
			char **slot = dhcp_server_text_slot(server, assignment->key);
			char  *text = ncfg_as_string(ctx, assignment->value);

			if (text) {
				free(*slot);
				*slot = text;
			}
		} else {
			ncfg_diag(ctx, assignment->span,
			    "unknown dhcp_server key `%s`: range, lease, dns, dns_forward, gateway, "
			    "domain, ntp, boot_file, boot_server, tftp_server and wpad, and `host` "
			    "and `option` blocks", assignment->key);
		}
	}
	return server;
}

/*
 * `port_forward "web" { protocol = "tcp"  port = 443  to = "192.168.1.10"
 * to_port = 8443 }` (0298): one inbound port on this interface, translated to
 * a host behind it. The label is its identity; two of one name, or of one
 * protocol and port, on an interface are refused -- the second would never
 * match.
 */
static void lower_port_forward(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_interface_t *interface)
{
	ncfg_port_forward_t  forward;
	ncfg_port_forward_t *grown;
	int                  has_protocol = 0;
	int                  has_port = 0;
	size_t               i;

	memset(&forward, 0, sizeof(forward));
	forward.name = ncfg_require_label(ctx, block);
	if (!forward.name) {
		return;
	}
	/* The identity in the kernel is `IF/NAME@ROLE` (0299), so the label may
	 * hold neither separator -- nor anything else a comment would carry
	 * badly. */
	for (i = 0; forward.name[i]; i++) {
		const char one = forward.name[i];

		if (!((one >= 'a' && one <= 'z') || (one >= 'A' && one <= 'Z') ||
		        (one >= '0' && one <= '9') || one == '-' || one == '_' || one == '.')) {
			ncfg_diag(ctx, block->span, "port_forward `%s`: a name is letters, digits, `-`, "
			    "`_` and `.`", forward.name);
			free(forward.name);
			return;
		}
	}
	for (i = 0; i < block->items.count; i++) {
		const ncfg_ast_item_t       *item = block->items.at[i];
		const ncfg_ast_assignment_t *assignment;
		int64_t                      value;

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `port_forward`",
			    item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		if (strcmp(assignment->key, "protocol") == 0) {
			char *text = ncfg_as_string(ctx, assignment->value);

			if (!text) {
				continue;
			}
			if (strcmp(text, "tcp") == 0 || strcmp(text, "udp") == 0) {
				forward.protocol = text[0] == 't' ? NCFG_PORT_FORWARD_TCP
				                                  : NCFG_PORT_FORWARD_UDP;
				has_protocol = 1;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a protocol a port forward can match: tcp or udp", text);
			}
			free(text);
		} else if (strcmp(assignment->key, "port") == 0 ||
		    strcmp(assignment->key, "to_port") == 0) {
			if (!ncfg_as_i64(ctx, assignment->value, &value)) {
				continue;
			}
			if (value < 1 || value > 65535) {
				ncfg_diag(ctx, assignment->span, "`%s = %lld` is not a port: 1 to 65535",
				    assignment->key, (long long)value);
				continue;
			}
			if (assignment->key[0] == 'p') {
				forward.port = value;
				has_port = 1;
			} else {
				forward.to_port.has = 1;
				forward.to_port.value = value;
			}
		} else if (strcmp(assignment->key, "hairpin") == 0) {
			int flag;

			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				forward.hairpin.has = 1;
				forward.hairpin.value = flag;
			}
		} else if (strcmp(assignment->key, "to") == 0) {
			char          *text = ncfg_as_string(ctx, assignment->value);
			ncfg_address_t address;

			if (!text) {
				continue;
			}
			/* **A reservation's name** (10.618), so the host's address is
			 * written once, in its `host` block. Anything that is not only
			 * digits and dots and is a plain host name names one; the
			 * address is filled in once every interface has been read,
			 * because the reservation may be on one not read yet. Digits
			 * and dots stay an address, so `192.168.1.300` is refused as
			 * one rather than looked up as a name. */
			if (strspn(text, "0123456789.") != strlen(text) && ncfg_dhcp_server_plain_name(text)) {
				free(forward.to);
				free(forward.to_host);
				forward.to = NULL;
				forward.to_host = text;
				continue;
			}
			if (!ncfg_address_parse(text, &address, NULL, 0) || address.is_ipv6 ||
			    address.has_prefix || address.bytes[0] == 0u || address.bytes[0] == 127u ||
			    address.bytes[0] >= 224u) {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a host a port can be forwarded to: one IPv4 address, not "
				    "loopback, multicast, broadcast or unspecified, or the name of a "
				    "`dhcp_server` reservation", text);
				free(text);
				continue;
			}
			free(forward.to);
			free(forward.to_host);
			forward.to_host = NULL;
			forward.to = text;
		} else {
			ncfg_diag(ctx, assignment->span,
			    "unknown port_forward key `%s`: protocol, port, to, to_port and hairpin",
			    assignment->key);
		}
	}
	if (!has_protocol || !has_port || (!forward.to && !forward.to_host)) {
		ncfg_diag(ctx, block->span, "port_forward `%s` needs a `protocol`, a `port` and a `to`",
		    forward.name);
		free(forward.name);
		free(forward.to);
		free(forward.to_host);
		return;
	}
	for (i = 0; i < interface->port_forward_count; i++) {
		const ncfg_port_forward_t *earlier = &interface->port_forwards[i];

		if (strcmp(earlier->name, forward.name) == 0 ||
		    (earlier->protocol == forward.protocol && earlier->port == forward.port)) {
			ncfg_diag(ctx, block->span,
			    "port_forward `%s` on `%s` has the name or the port of `%s`: the first would "
			    "win and the second would never match", forward.name, interface->name,
			    earlier->name);
			free(forward.name);
			free(forward.to);
			free(forward.to_host);
			return;
		}
	}
	grown = realloc(interface->port_forwards,
	    (interface->port_forward_count + 1u) * sizeof(*grown));
	if (!grown) {
		ncfg_lower_oom(ctx);
		free(forward.name);
		free(forward.to);
		free(forward.to_host);
		return;
	}
	interface->port_forwards = grown;
	interface->port_forwards[interface->port_forward_count++] = forward;
}

static int lower_advertise(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_ra_policy_t *out)
{
	ncfg_ra_policy_t policy;
	size_t           i;

	memset(&policy, 0, sizeof(policy));
	policy.backend.kind = NCFG_RA_BACKEND_AUTO;
	policy.dns = 1;

	for (i = 0; i < block->items.count; i++) {
		const ncfg_ast_item_t       *item = block->items.at[i];
		const ncfg_ast_assignment_t *assignment;
		const char                  *key;
		int                          flag;

		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		key = assignment->key;
		if (strcmp(key, "backend") == 0) {
			char *name = ncfg_as_string(ctx, assignment->value);

			if (!name) {
				goto drop;
			}
			if (strcmp(name, "auto") == 0) {
				policy.backend.kind = NCFG_RA_BACKEND_AUTO;
			} else if (strcmp(name, "radvd") == 0) {
				policy.backend.kind = NCFG_RA_BACKEND_RADVD;
			} else if (strcmp(name, "odhcpd") == 0) {
				policy.backend.kind = NCFG_RA_BACKEND_ODHCPD;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a router advertisement backend: backends: auto, radvd, "
				    "odhcpd", name);
				free(name);
				goto drop;
			}
			free(name);
		} else if (strcmp(key, "prefixes") == 0 || strcmp(key, "prefix") == 0) {
			ncfg_words_t words;
			size_t       at;

			if (!ncfg_as_words(ctx, assignment->value, &words)) {
				ncfg_words_free(&words);
				goto drop;
			}
			for (at = 0; at < words.count; at++) {
				const char        *value = words.at[at].text;
				const char        *slash;
				char               name[64];
				size_t             length;
				int64_t            subnet = 0;
				ncfg_prefix_ref_t *slot;

				if (strncmp(value, "@pd:", 4u) != 0) {
					ncfg_diag(ctx, assignment->span,
					    "`%s` is not a prefix reference: a prefix to advertise is "
					    "`@pd:wan0`, naming the interface whose delegation it comes from "
					    "-- never a prefix itself, which no config file can know", value);
					ncfg_words_free(&words);
					goto drop;
				}
				value += 4;
				slash = strchr(value, '/');
				length = slash ? (size_t)(slash - value) : strlen(value);
				/*
				 * **It used to truncate here, and truncating a reference points it at a
				 * different interface.** `@pd:` and 64 characters, and `@pd:` and 70,
				 * both became the same 63-character source: two configurations naming
				 * different interfaces compiled to one document, with the delegation
				 * taken from a name nobody had written. Nothing validated the source
				 * either, so `@pd:eth 0` and a bare `@pd:` were accepted as well.
				 *
				 * `ncfg_name_ok` is what every other name in the language goes through,
				 * and a name it accepts cannot reach this buffer's length -- so the
				 * length test is a refusal now rather than a silent shortening, and it
				 * has to come first because the check below reads a copy.
				 */
				if (length > NCFG_DELEGATION_SOURCE_MAX) {
					ncfg_diag(ctx, assignment->span,
					    "`%s` is not an interface name: it is longer than any name the kernel "
					    "takes: %s", value, ncfg_link_name_help);
					ncfg_words_free(&words);
					goto drop;
				}
				memcpy(name, value, length);
				name[length] = '\0';
				if (!ncfg_name_ok(ctx, name, assignment->span, ncfg_link_name_help)) {
					ncfg_words_free(&words);
					goto drop;
				}
				if (slash) {
					char         *end;
					unsigned long index = strtoul(slash + 1, &end, 10);

					if (end == slash + 1 || *end != '\0' || index > 65535u) {
						ncfg_diag(ctx, assignment->span, "`%s` is not a subnet number",
						    slash + 1);
						ncfg_words_free(&words);
						goto drop;
					}
					subnet = (int64_t)index;
				}
				slot = ncfg_push(ctx, &policy.prefixes, &policy.prefix_count, sizeof(*slot));
				if (!slot) {
					ncfg_words_free(&words);
					goto drop;
				}
				slot->source = ncfg_dup(ctx, name);
				slot->index = 0;
				slot->subnet = subnet;
			}
			ncfg_words_free(&words);
		} else if (strcmp(key, "managed") == 0) {
			/* The two flags that send a host to a DHCPv6 server for the rest. */
			policy.managed = ncfg_as_bool(ctx, assignment->value, &flag) ? flag : 0;
		} else if (strcmp(key, "other_config") == 0 || strcmp(key, "other") == 0) {
			policy.other_config = ncfg_as_bool(ctx, assignment->value, &flag) ? flag : 0;
		} else if (strcmp(key, "dns") == 0) {
			policy.dns = ncfg_as_bool(ctx, assignment->value, &flag) ? flag : 1;
		} else if (strcmp(key, "lifetime") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &policy.lifetime);
		} else {
			ncfg_diag(ctx, assignment->span,
			    "unknown advertise key `%s`: an advertise block takes backend, prefixes, "
			    "managed, other_config, dns and lifetime", key);
		}
	}

	if (policy.prefix_count == 0) {
		ncfg_diag(ctx, block->span,
		    "an `advertise` block needs a prefix to advertise: `prefixes = [\"@pd:wan0\"]` "
		    "advertises what the ISP delegated to wan0");
		goto drop;
	}
	*out = policy;
	return 1;

drop:
	release_advertise(&policy);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * The interface block
 * ------------------------------------------------------------------------ */

/*
 * `dot1x`, which is wired 802.1X.
 *
 * Decision 0008 puts this on the interface rather than inside a wifi profile,
 * because port-based access control predates radios and is ordinary on campus
 * and corporate wired networks -- nesting it under an SSID made the wired case
 * inexpressible.
 */
static void lower_dot1x(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *inner,
    ncfg_interface_t *interface)
{
	ncfg_wifi_keys_t keys;
	ncfg_security_t  security;
	size_t           i;

	memset(&keys, 0, sizeof(keys));
	for (i = 0; i < inner->items.count; i++) {
		const ncfg_ast_item_t *item = inner->items.at[i];

		if (item->kind == NCFG_AST_ITEM_ASSIGNMENT) {
			ncfg_lower_dot1x_key(ctx, &keys, &item->as.assignment);
		} else if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `dot1x`",
			    item->as.block.head);
		}
	}
	if (!keys.has_eap) {
		ncfg_diag(ctx, inner->span,
		    "a `dot1x` block needs an `eap` method: one of peap, ttls, tls, pwd");
		ncfg_wifi_keys_free(&keys);
		return;
	}
	memset(&security, 0, sizeof(security));
	if (!ncfg_build_security(ctx, &keys, inner, &security)) {
		ncfg_wifi_keys_free(&keys);
		return;
	}
	if (security.kind != NCFG_SECURITY_EAP) {
		ncfg_security_free(&security);
		return;
	}
	if (interface->dot1x) {
		/* A second `dot1x` block replaces the first, and the first's strings
		 * go with it. Wrapped back into a security value because that is where
		 * the free walk for an EAP configuration lives. */
		ncfg_security_t previous;

		memset(&previous, 0, sizeof(previous));
		previous.kind = NCFG_SECURITY_EAP;
		previous.eap = *interface->dot1x;
		ncfg_security_free(&previous);
		free(interface->dot1x);
	}
	interface->dot1x = calloc(1, sizeof(*interface->dot1x));
	if (!interface->dot1x) {
		ncfg_lower_oom(ctx);
		ncfg_security_free(&security);
		return;
	}
	*interface->dot1x = security.eap;
}

/* One `key = value` directly inside an `interface` block. */
static void lower_interface_key(ncfg_lower_ctx_t *ctx, ncfg_interface_t *interface,
    const ncfg_ast_assignment_t *assignment, ncfg_dns_policy_t *dns, int *dns_touched)
{
	const char *key = assignment->key;
	int         flag;

	if (strcmp(key, "config") == 0) {
		ncfg_lower_config(ctx, assignment->value, &interface->addressing,
		    &interface->addressing_count, interface->name);
		return;
	}
	if (strcmp(key, "routes") == 0) {
		ncfg_words_t lines;
		size_t       i;

		if (!ncfg_as_lines(ctx, assignment->value, &lines)) {
			ncfg_words_free(&lines);
			return;
		}
		for (i = 0; i < lines.count; i++) {
			ncfg_route_t route;

			if (!ncfg_lower_route(ctx, &lines.at[i], &route)) {
				continue;
			}
			{
				ncfg_route_t *slot = ncfg_push(ctx, &interface->routes,
				    &interface->route_count, sizeof(*slot));

				if (!slot) {
					free(route.destination);
					free(route.via);
					free(route.src);
					break;
				}
				*slot = route;
				/* Keyed by destination rather than by index, which is what lets
				 * the key survive `ncfg_document_canonicalize` sorting the
				 * routes -- and what `explain.c` asks for. */
				ncfg_record(ctx, ctx->source, lines.at[i].span, "interfaces[%s].routes[%s]",
				    interface->name, route.destination);
			}
		}
		ncfg_words_free(&lines);
		return;
	}
	/*
	 * Moved to `device` by 0155, and named rather than left to "unknown
	 * interface key". The first four say what netcfgd creates, what it is a
	 * port of, and how its egress is shaped; the last two are settings of the
	 * adapter. All of them are true of the hardware before anything runs over
	 * it, which is the test that sorts the two blocks.
	 */
	if (strcmp(key, "kind") == 0 || strcmp(key, "master") == 0 || strcmp(key, "qdisc") == 0 ||
	    strcmp(key, "vlans") == 0) {
		ncfg_diag(ctx, assignment->span,
		    "`%s` belongs in the `device` block now, not `interface`: %s", key,
		    moved_structural);
		return;
	}
	if (strcmp(key, "mtu") == 0 || strcmp(key, "mac") == 0) {
		ncfg_diag(ctx, assignment->span,
		    "`%s` belongs in the `device` block now, not `interface`: %s", key, moved_adapter);
		return;
	}
	if (strcmp(key, "preference") == 0) {
		ncfg_record(ctx, ctx->source, assignment->span, "interfaces[%s].preference",
		    interface->name);
		ncfg_as_u32_opt(ctx, assignment->value, &interface->preference);
		return;
	}
	if (strcmp(key, "ipv6_token") == 0) {
		char          *text = ncfg_as_string(ctx, assignment->value);
		ncfg_address_t address;

		if (!text) {
			return;
		}
		if (!ncfg_address_parse(text, &address, NULL, 0) || address.has_prefix ||
		    !address.is_ipv6) {
			ncfg_diag(ctx, assignment->span, "`%s` is not an IPv6 address", text);
			free(text);
			return;
		}
		/*
		 * A token is an interface identifier, so the prefix bits must be zero
		 * -- `::5`, not `2001:db8::5`. The kernel accepts a full address and
		 * silently uses only the host part, which means a config that looks
		 * like it pins a whole address quietly pins half of one.
		 */
		{
			int  at;
			int  clean = 1;

			for (at = 0; at < 8; at++) {
				if (address.bytes[at] != 0) {
					clean = 0;
				}
			}
			if (!clean) {
				ncfg_diag(ctx, assignment->span,
				    "`%s` has bits set in the prefix half: a token is the host part only, "
				    "such as `::5`; the prefix comes from the router advertisement", text);
				free(text);
				return;
			}
		}
		free(interface->ipv6_token);
		interface->ipv6_token = text;
		return;
	}
	if (strcmp(key, "enabled") == 0) {
		if (ncfg_as_bool(ctx, assignment->value, &flag)) {
			interface->enabled = flag;
		}
		return;
	}
	if (strcmp(key, "forwarding") == 0) {
		if (ncfg_as_bool(ctx, assignment->value, &flag)) {
			interface->forwarding.has = 1;
			interface->forwarding.value = flag;
		}
		return;
	}
	if (strcmp(key, "nat") == 0) {
		if (ncfg_as_bool(ctx, assignment->value, &flag)) {
			interface->nat.has = 1;
			interface->nat.value = flag;
		}
		return;
	}
	if (strcmp(key, "on_drift") == 0) {
		int policy;

		if (ncfg_as_drift(ctx, assignment->value, &policy)) {
			interface->on_drift.has = 1;
			interface->on_drift.value = policy;
		}
		return;
	}
	if (strcmp(key, "guard") == 0) {
		char *reason = ncfg_as_string(ctx, assignment->value);

		if (!reason) {
			return;
		}
		ncfg_record(ctx, ctx->source, assignment->span, "interfaces[%s].guard",
		    interface->name);
		if (!interface->guard) {
			interface->guard = calloc(1, sizeof(*interface->guard));
			if (!interface->guard) {
				ncfg_lower_oom(ctx);
				free(reason);
				return;
			}
		}
		free(interface->guard->reason);
		interface->guard->reason = reason;
		return;
	}
	if (strcmp(key, "dns") == 0 || strcmp(key, "dns_search") == 0 ||
	    strcmp(key, "dns_mode") == 0 || strcmp(key, "dns_domains") == 0) {
		*dns_touched = 1;
		/* All four keys record the one path, and the first of them wins once
		 * the table is canonicalised -- which is right: what a reader is sent
		 * to is where this interface's DNS policy started being written. */
		ncfg_record(ctx, ctx->source, assignment->span, "interfaces[%s].dns", interface->name);
		ncfg_lower_dns_key(ctx, dns, assignment);
		return;
	}
	ncfg_diag(ctx, assignment->span, "unknown interface key `%s`", key);
}

int ncfg_lower_interface(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *block,
    ncfg_interface_t *out)
{
	ncfg_interface_t  interface;
	ncfg_span_t       dhcp_server_span;
	const char       *dhcp_server_source = NULL;
	ncfg_dns_policy_t dns;
	int               dns_touched = 0;
	size_t            i;

	memset(&interface, 0, sizeof(interface));
	memset(&dhcp_server_span, 0, sizeof(dhcp_server_span));
	memset(&dns, 0, sizeof(dns));
	interface.name = ncfg_require_interface_label(ctx, block->block);
	if (!interface.name) {
		return 0;
	}
	interface.enabled = 1;

	for (i = 0; i < block->item_count; i++) {
		const ncfg_ast_item_t *item = block->items[i].item;

		ctx->source = block->items[i].source;
		switch (item->kind) {
		case NCFG_AST_ITEM_ASSIGNMENT:
			lower_interface_key(ctx, &interface, &item->as.assignment, &dns, &dns_touched);
			break;
		case NCFG_AST_ITEM_BLOCK: {
			const ncfg_ast_block_t *inner = &item->as.block;
			const char             *head = inner->head;

			if (strcmp(head, "probe") == 0) {
				ncfg_probe_policy_t probe;

				if (!lower_probe(ctx, inner, &probe)) {
					break;
				}
				/* A second block replaces the first, contents and all: freeing
				 * the struct alone leaked the first's command and arguments,
				 * once per compile, which the daemon does on every edit.
				 * Found by fuzzing `config_parse` (project.md 10.621). */
				if (interface.probe) {
					free(interface.probe->command);
					ncfg_strings_free(interface.probe->args, interface.probe->arg_count);
				}
				free(interface.probe);
				interface.probe = calloc(1, sizeof(*interface.probe));
				if (!interface.probe) {
					ncfg_lower_oom(ctx);
					break;
				}
				*interface.probe = probe;
			} else if (strcmp(head, "dns") == 0) {
				size_t at;

				dns_touched = 1;
				for (at = 0; at < inner->items.count; at++) {
					if (inner->items.at[at]->kind == NCFG_AST_ITEM_ASSIGNMENT) {
						ncfg_lower_dns_key(ctx, &dns, &inner->items.at[at]->as.assignment);
					}
				}
			} else if (strcmp(head, "dot1x") == 0) {
				lower_dot1x(ctx, inner, &interface);
			} else if (ncfg_is_kind_block(head) || strcmp(head, "qdisc") == 0) {
				ncfg_diag(ctx, inner->span,
				    "`%s` belongs in the `device` block now, not `interface`: a bridge, "
				    "bond, vlan, tunnel or qdisc is a property of the hardware -- it exists "
				    "before anything runs over it. Write `device <name> { ... }` and move "
				    "the block there unchanged", head);
			} else if (strcmp(head, "ethtool") == 0) {
				ncfg_diag(ctx, inner->span,
				    "`ethtool` belongs in the `device` block now, not `interface`: speed, "
				    "duplex and autonegotiation are settings of the adapter rather than of "
				    "a connection over it: write `device <name> { ethtool { ... } }` and "
				    "move the block there unchanged");
			} else if (strcmp(head, "port_forward") == 0) {
				lower_port_forward(ctx, inner, &interface);
			} else if (strcmp(head, "dhcp_server") == 0) {
				if (interface.dhcp_server) {
					ncfg_diag(ctx, inner->span,
					    "interface `%s` has a second `dhcp_server` block", interface.name);
					break;
				}
				interface.dhcp_server = lower_dhcp_server(ctx, inner);
				dhcp_server_span = inner->span;
				dhcp_server_source = ctx->source;
			} else if (strcmp(head, "advertise") == 0) {
				ncfg_ra_policy_t advertise;

				if (!lower_advertise(ctx, inner, &advertise)) {
					break;
				}
				/* A second block replaces the first, as the Rust's assignment
				 * does -- and the first is released whole, not just its
				 * struct. */
				if (interface.advertise) {
					release_advertise(interface.advertise);
				}
				free(interface.advertise);
				interface.advertise = calloc(1, sizeof(*interface.advertise));
				if (!interface.advertise) {
					ncfg_lower_oom(ctx);
					break;
				}
				*interface.advertise = advertise;
			} else {
				ncfg_diag(ctx, inner->span, "`%s` is not valid inside `interface`", head);
			}
			break;
		}
		case NCFG_AST_ITEM_HOOK:
			ncfg_lower_hook(ctx, &item->as.hook, interface.name, &interface.hooks,
			    &interface.hook_count);
			break;
		case NCFG_AST_ITEM_INCLUDE:
			ncfg_diag(ctx, item->as.include.span,
			    "include was not resolved before compiling");
			break;
		default:
			break;
		}
	}

	/* The range against the address it is served from, now that `config`
	 * has been read wherever in the block it was (0297). */
	if (interface.dhcp_server) {
		char        start[NCFG_ADDRESS_MAX];
		char        end[NCFG_ADDRESS_MAX];
		char        router[NCFG_ADDRESS_MAX];
		const char *why = NULL;

		if (!ncfg_dhcp_server_range(&interface, start, end, router, &why)) {
			ctx->source = dhcp_server_source;
			ncfg_diag(ctx, dhcp_server_span, "interface `%s` cannot serve DHCP: %s",
			    interface.name, why ? why : "its range cannot be worked out");
			ncfg_dhcp_server_free(interface.dhcp_server);
			interface.dhcp_server = NULL;
		}
	}
	if (dns_touched) {
		interface.dns = calloc(1, sizeof(*interface.dns));
		if (!interface.dns) {
			ncfg_lower_oom(ctx);
		} else {
			*interface.dns = dns;
			memset(&dns, 0, sizeof(dns));
		}
	}
	/* A scope nobody asked for is nobody's to free later, so what was built
	 * and not used goes now rather than leaking. Freeing one that was moved
	 * into the interface is nothing: it was zeroed on the way out. */
	ncfg_dns_policy_free(&dns);

	*out = interface;
	return 1;
}
