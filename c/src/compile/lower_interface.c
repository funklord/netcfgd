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
				if (length >= sizeof(name)) {
					length = sizeof(name) - 1u;
				}
				memcpy(name, value, length);
				name[length] = '\0';
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
	for (i = 0; i < policy.prefix_count; i++) {
		free(policy.prefixes[i].source);
	}
	free(policy.prefixes);
	free(policy.backend.command);
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
	ncfg_dns_policy_t dns;
	int               dns_touched = 0;
	size_t            i;

	memset(&interface, 0, sizeof(interface));
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
			} else if (strcmp(head, "advertise") == 0) {
				ncfg_ra_policy_t advertise;

				if (!lower_advertise(ctx, inner, &advertise)) {
					break;
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
