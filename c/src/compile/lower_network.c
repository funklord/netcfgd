/*
 * lower_network.c -- `network` and `access_point`, and the security both
 * share.
 *
 * A `network` block is a place, not a piece of hardware: it applies to
 * whichever radio is in range of it, which is why it is not bound to a device.
 * An `access_point` is the opposite -- one specific radio doing one specific
 * thing -- and it is bound to one. They are in one file because the `wifi`
 * block inside each is the same block, parsed by the same code, and two
 * readers would eventually accept different spellings of one passphrase.
 */
#include <stdlib.h>
#include <string.h>

#include "lower_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

/*
 * What an operator writes when the network's name is not theirs to state.
 *
 * `ssid = "@bssid"`: the SSID is whatever the access points listed in `bssid`
 * are advertising, read off a scan before the supplicant is configured. The
 * `@` is the DSL's existing mark for a value resolved elsewhere, as in
 * `@secret:NAME`.
 */
static const char *const ssid_from_bssid = "@bssid";

/* ------------------------------------------------------------------------ *
 * The wifi keys
 * ------------------------------------------------------------------------ */

static void cert_source_free(ncfg_cert_source_t *source)
{
	free(source->path);
	free(source->stored.name);
	memset(source, 0, sizeof(*source));
}

void ncfg_wifi_keys_free(ncfg_wifi_keys_t *keys)
{
	free(keys->psk.name);
	free(keys->identity);
	free(keys->anonymous_identity);
	free(keys->password.name);
	cert_source_free(&keys->ca_cert);
	cert_source_free(&keys->client_cert);
	cert_source_free(&keys->private_key);
	free(keys->phase2);
	free(keys->domain_suffix_match);
	memset(keys, 0, sizeof(*keys));
}

void ncfg_lower_wifi_key(ncfg_lower_ctx_t *ctx, ncfg_wifi_keys_t *keys,
    ncfg_wifi_network_t *network, const ncfg_ast_assignment_t *assignment)
{
	const char *key = assignment->key;
	int         flag;

	if (strcmp(key, "psk") == 0) {
		if (ncfg_as_secret(ctx, assignment->value, &keys->psk)) {
			keys->has_psk = 1;
		}
		return;
	}
	if (strcmp(key, "password") == 0) {
		if (ncfg_as_secret(ctx, assignment->value, &keys->password)) {
			keys->has_password = 1;
		}
		return;
	}
	if (strcmp(key, "private_key") == 0) {
		(void)ncfg_as_cert_source(ctx, assignment->value, &keys->private_key);
		return;
	}
	if (strcmp(key, "ca_cert") == 0) {
		(void)ncfg_as_cert_source(ctx, assignment->value, &keys->ca_cert);
		return;
	}
	if (strcmp(key, "client_cert") == 0) {
		(void)ncfg_as_cert_source(ctx, assignment->value, &keys->client_cert);
		return;
	}
	if (strcmp(key, "open") == 0) {
		keys->open = ncfg_as_bool(ctx, assignment->value, &flag) ? flag : 0;
		return;
	}
	if (strcmp(key, "owe") == 0) {
		keys->owe = ncfg_as_bool(ctx, assignment->value, &flag) ? flag : 0;
		return;
	}
	if (strcmp(key, "identity") == 0) {
		free(keys->identity);
		keys->identity = ncfg_as_string(ctx, assignment->value);
		return;
	}
	if (strcmp(key, "anonymous_identity") == 0) {
		free(keys->anonymous_identity);
		keys->anonymous_identity = ncfg_as_string(ctx, assignment->value);
		return;
	}
	if (strcmp(key, "phase2") == 0) {
		/*
		 * **Kept as written, and warned about rather than refused.** A
		 * `phase2` that pins no inner method is inert at the supplicant, not
		 * invalid -- and netcfgd's own example told operators to write the
		 * inert form, so refusing it here would take the wifi off every
		 * machine that copied it, on upgrade, to fix a protection that was
		 * never there. `netcfgd-plan` says so on every plan instead (0218).
		 */
		free(keys->phase2);
		keys->phase2 = ncfg_as_string(ctx, assignment->value);
		return;
	}
	if (strcmp(key, "domain_suffix_match") == 0) {
		free(keys->domain_suffix_match);
		keys->domain_suffix_match = ncfg_as_string(ctx, assignment->value);
		return;
	}
	if (strcmp(key, "priority") == 0) {
		/*
		 * Retired by 0154, and named rather than left to "unknown wifi key".
		 * An operator who wrote `priority` had a working configuration, and
		 * the replacement runs the OTHER WAY UP -- so the one thing they must
		 * not do is copy the number across.
		 */
		ncfg_diag(ctx, assignment->span,
		    "`priority` has been replaced by `metric`, which goes beside `metered` rather "
		    "than inside `wifi` -- and ranks the other way up, lower winning. It now decides "
		    "both which network to join and how its routes rank against every other link, so "
		    "a high `priority` becomes a low `metric`");
		return;
	}
	if (strcmp(key, "autoconnect") == 0) {
		if (ncfg_as_bool(ctx, assignment->value, &flag) && network) {
			network->autoconnect = flag;
		}
		return;
	}
	if (strcmp(key, "proto") == 0) {
		char *name = ncfg_as_string(ctx, assignment->value);

		if (!name) {
			return;
		}
		if (strcmp(name, "wpa2") == 0) {
			keys->proto = NCFG_PSK_PROTO_WPA2;
		} else if (strcmp(name, "wpa3") == 0) {
			keys->proto = NCFG_PSK_PROTO_WPA3;
		} else if (strcmp(name, "wpa2+wpa3") == 0 || strcmp(name, "wpa2wpa3") == 0) {
			keys->proto = NCFG_PSK_PROTO_WPA2_WPA3;
		} else {
			ncfg_diag(ctx, assignment->span,
			    "`%s` is not a WPA generation: one of wpa2, wpa3, wpa2+wpa3", name);
		}
		free(name);
		return;
	}
	if (strcmp(key, "eap") == 0) {
		char *name = ncfg_as_string(ctx, assignment->value);

		if (!name) {
			return;
		}
		if (strcmp(name, "peap") == 0) {
			keys->eap = NCFG_EAP_METHOD_PEAP;
			keys->has_eap = 1;
		} else if (strcmp(name, "ttls") == 0) {
			keys->eap = NCFG_EAP_METHOD_TTLS;
			keys->has_eap = 1;
		} else if (strcmp(name, "tls") == 0) {
			keys->eap = NCFG_EAP_METHOD_TLS;
			keys->has_eap = 1;
		} else if (strcmp(name, "pwd") == 0) {
			keys->eap = NCFG_EAP_METHOD_PWD;
			keys->has_eap = 1;
		} else {
			ncfg_diag(ctx, assignment->span,
			    "`%s` is not an EAP method: one of peap, ttls, tls, pwd", name);
		}
		free(name);
		return;
	}
	ncfg_diag(ctx, assignment->span, "unknown wifi key `%s`", key);
}

/*
 * One `key = value` inside an interface's `dot1x` block.
 *
 * The same keys as a wifi network's EAP, minus the ones that only mean
 * something on a radio. Sharing the key reader rather than duplicating the
 * parsing means the two cannot drift into accepting different spellings of the
 * same thing.
 */
void ncfg_lower_dot1x_key(ncfg_lower_ctx_t *ctx, ncfg_wifi_keys_t *keys,
    const ncfg_ast_assignment_t *assignment)
{
	const char *key = assignment->key;

	if (strcmp(key, "psk") == 0 || strcmp(key, "open") == 0 || strcmp(key, "owe") == 0 ||
	    strcmp(key, "proto") == 0 || strcmp(key, "priority") == 0 ||
	    strcmp(key, "autoconnect") == 0) {
		ncfg_diag(ctx, assignment->span,
		    "`%s` means nothing on a wired port: `dot1x` is EAP only: eap, identity, "
		    "password, ca_cert, client_cert, private_key, phase2, domain_suffix_match", key);
		return;
	}
	ncfg_lower_wifi_key(ctx, keys, NULL, assignment);
}

int ncfg_build_security(ncfg_lower_ctx_t *ctx, ncfg_wifi_keys_t *keys,
    const ncfg_ast_block_t *block, ncfg_security_t *out)
{
	memset(out, 0, sizeof(*out));
	if (keys->has_psk) {
		out->kind = NCFG_SECURITY_PSK;
		out->psk.passphrase = keys->psk;
		out->psk.proto = keys->proto;
		memset(&keys->psk, 0, sizeof(keys->psk));
		keys->has_psk = 0;
		ncfg_wifi_keys_free(keys);
		return 1;
	}
	if (keys->has_eap) {
		if (!keys->identity) {
			ncfg_diag(ctx, block->span, "an EAP network needs an `identity`");
			return 0;
		}
		out->kind = NCFG_SECURITY_EAP;
		out->eap.method = keys->eap;
		out->eap.identity = keys->identity;
		out->eap.anonymous_identity = keys->anonymous_identity;
		if (keys->has_password) {
			out->eap.password = calloc(1, sizeof(*out->eap.password));
			if (!out->eap.password) {
				ncfg_lower_oom(ctx);
				return 0;
			}
			*out->eap.password = keys->password;
			memset(&keys->password, 0, sizeof(keys->password));
			keys->has_password = 0;
		}
		out->eap.ca_cert = keys->ca_cert;
		out->eap.client_cert = keys->client_cert;
		out->eap.private_key = keys->private_key;
		out->eap.phase2 = keys->phase2;
		out->eap.domain_suffix_match = keys->domain_suffix_match;
		keys->identity = NULL;
		keys->anonymous_identity = NULL;
		memset(&keys->ca_cert, 0, sizeof(keys->ca_cert));
		memset(&keys->client_cert, 0, sizeof(keys->client_cert));
		memset(&keys->private_key, 0, sizeof(keys->private_key));
		keys->phase2 = NULL;
		keys->domain_suffix_match = NULL;
		/*
		 * No `ca_cert` check here, and that is a correction rather than an
		 * omission. There used to be one, with a comment saying "not an error,
		 * because plenty of real deployments pin nothing" -- above a
		 * diagnostic, which is the only severity this compiler has. So the
		 * network did not compile, which is exactly what 0017 rejected:
		 * netcfgd refusing a deployment other tools configure fine is how it
		 * gets replaced by one of them. It is a plan warning now (0087).
		 */
		ncfg_wifi_keys_free(keys);
		return 1;
	}
	if (keys->owe) {
		out->kind = NCFG_SECURITY_OWE;
		ncfg_wifi_keys_free(keys);
		return 1;
	}
	out->kind = NCFG_SECURITY_OPEN;
	ncfg_wifi_keys_free(keys);
	return 1;
}

/*
 * A network's `roam { }` block: when to look for a better access point.
 *
 * Three numbers and no module name. The operator says how weak is weak and how
 * often to look; which bgscan module renders that is the supplicant backend's
 * business, the way every other backend detail is.
 *
 * The defaults are `wpa_supplicant`'s own documented example rounded to the
 * number an operator would recognise: -70 dBm is where a link is usually
 * described as poor, 30 seconds is often enough to catch a walk down a
 * corridor, and 300 is quiet enough not to cost airtime while sitting still.
 */
static void lower_roam(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_roam_policy_t *roam)
{
	size_t at;

	roam->signal = -70;
	roam->interval = 30;
	roam->slow_interval = 300;

	for (at = 0; at < block->items.count; at++) {
		const ncfg_ast_item_t       *item = block->items.at[at];
		const ncfg_ast_assignment_t *assignment;
		int64_t                      value;

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `roam`",
			    item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		if (strcmp(assignment->key, "signal") == 0) {
			if (!ncfg_as_i64(ctx, assignment->value, &value)) {
				continue;
			}
			/* A positive dBm would be a signal stronger than the transmitter,
			 * and wpa_supplicant would scan for ever. */
			if (value >= -100 && value < 0) {
				roam->signal = value;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%lld` is not a signal strength: dBm, negative, and between -100 and "
				    "-1; -70 is a weak link", (long long)value);
			}
		} else if (strcmp(assignment->key, "interval") == 0) {
			if (ncfg_as_u32(ctx, assignment->value, &value)) {
				roam->interval = value;
			}
		} else if (strcmp(assignment->key, "slow_interval") == 0) {
			if (ncfg_as_u32(ctx, assignment->value, &value)) {
				roam->slow_interval = value;
			}
		} else {
			ncfg_diag(ctx, assignment->span,
			    "unknown roam key `%s`: signal, interval and slow_interval",
			    assignment->key);
		}
	}

	/* Looking *less* often when the signal is bad than when it is good is the
	 * policy inverted, and it reads as a plausible pair of numbers. */
	if (roam->interval > roam->slow_interval) {
		ncfg_diag(ctx, block->span,
		    "`interval` is how often to look while the signal is weak, so it cannot be longer "
		    "than `slow_interval`: the usual pair is a short interval and a long one: 30 and "
		    "300");
	}
}

int ncfg_lower_wifi_block(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_wifi_network_t *network, ncfg_security_t *out)
{
	ncfg_wifi_keys_t keys;
	size_t           at;
	int              chosen;

	memset(&keys, 0, sizeof(keys));
	keys.proto = NCFG_PSK_PROTO_WPA2_WPA3;
	for (at = 0; at < block->items.count; at++) {
		const ncfg_ast_item_t *item = block->items.at[at];

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			if (strcmp(item->as.block.head, "roam") == 0) {
				ncfg_roam_policy_t roam;

				memset(&roam, 0, sizeof(roam));
				lower_roam(ctx, &item->as.block, &roam);
				if (!network) {
					continue;
				}
				if (!network->roam) {
					network->roam = calloc(1, sizeof(*network->roam));
				}
				if (!network->roam) {
					ncfg_lower_oom(ctx);
					continue;
				}
				*network->roam = roam;
			} else {
				ncfg_diag(ctx, item->as.block.span,
				    "`%s` is not valid inside a network `wifi` block", item->as.block.head);
			}
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		ncfg_lower_wifi_key(ctx, &keys, network, &item->as.assignment);
	}

	/* Exactly one kind of security. Two would mean guessing which the operator
	 * meant, and the wrong guess is a network that either will not join or
	 * joins with less protection than was asked for. */
	chosen = (keys.has_psk ? 1 : 0) + (keys.has_eap ? 1 : 0) + (keys.open ? 1 : 0) +
	    (keys.owe ? 1 : 0);
	if (chosen > 1) {
		ncfg_diag(ctx, block->span,
		    "a network has one kind of security: exactly one of psk, eap, open or owe");
		ncfg_wifi_keys_free(&keys);
		return 0;
	}
	/*
	 * **And exactly one means at least one.** The guard above counts only the
	 * upper bound, so a `wifi` block that names no security at all fell
	 * through to open -- and the guard that refuses a network with no `wifi`
	 * block is keyed on the block being *present*, so three spellings walked
	 * past both:
	 *
	 *     network "Cafe" { wifi { } }
	 *     network "Cafe" { wifi { open = false } }
	 *     network "Cafe" { wifi { owe = false } }
	 *
	 * Measured: all three compile to `security: open`. The middle one is the
	 * reason this is a refusal rather than a warning -- an operator who writes
	 * the word `false` against `open` has said the opposite of what they got,
	 * and the machine then associates in the clear with anything broadcasting
	 * that name.
	 */
	if (chosen == 0) {
		ncfg_diag(ctx, block->span,
		    "this `wifi` block names no security, so it would be an open network: add "
		    "`psk = \"@secret:NAME\"`, or `open = true` if that is meant; `open = false` says "
		    "which kind it is not, not which it is");
		ncfg_wifi_keys_free(&keys);
		return 0;
	}
	if (!ncfg_build_security(ctx, &keys, block, out)) {
		ncfg_wifi_keys_free(&keys);
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * network
 * ------------------------------------------------------------------------ */

static void lower_network_key(ncfg_lower_ctx_t *ctx, ncfg_wifi_network_t *network,
    const ncfg_ast_assignment_t *assignment)
{
	const char *key = assignment->key;
	int         flag;

	if (strcmp(key, "config") == 0) {
		/* No owner: nothing keys a `network` block's addressing, and a path
		 * under `interfaces[...]` would name an interface this list is not
		 * on. */
		ncfg_lower_config(ctx, assignment->value, &network->addressing,
		    &network->addressing_count, NULL);
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
				ncfg_route_t *slot = ncfg_push(ctx, &network->routes, &network->route_count,
				    sizeof(*slot));

				if (!slot) {
					free(route.destination);
					free(route.via);
					free(route.src);
					break;
				}
				*slot = route;
			}
		}
		ncfg_words_free(&lines);
		return;
	}
	if (strcmp(key, "hidden") == 0) {
		if (ncfg_as_bool(ctx, assignment->value, &flag)) {
			network->hidden = flag;
		}
		return;
	}
	if (strcmp(key, "metered") == 0) {
		if (ncfg_as_bool(ctx, assignment->value, &flag)) {
			network->metered = flag;
		}
		return;
	}
	if (strcmp(key, "metric") == 0) {
		/* Beside `metered` rather than inside `wifi`, because it is not about
		 * the radio: it says how this network ranks against every other link
		 * on the machine, including wired ones. */
		ncfg_as_u32_opt(ctx, assignment->value, &network->metric);
		return;
	}
	if (strcmp(key, "ssid") == 0) {
		/* The escape hatch for a name that is not text, given as hex. The
		 * label stays the id, so the network still has one readable handle. */
		char       *text = ncfg_as_string(ctx, assignment->value);
		const char *why = NULL;

		if (!text) {
			return;
		}
		if (strcmp(text, ssid_from_bssid) == 0) {
			/* "I do not know what it is called; ask the access points."
			 * Required rather than inferred from `bssid` alone -- a network's
			 * label is its SSID by default, and quietly changing what that
			 * means for anything carrying a `bssid` would silently re-point
			 * configurations that work today. */
			network->ssid.has = 0;
			network->ssid.length = 0;
		} else if (!ncfg_ssid_from_hex(text, &network->ssid, &why)) {
			ncfg_diag(ctx, assignment->span, "`%s` is not a usable ssid: %s", text, why);
		}
		free(text);
		return;
	}
	if (strcmp(key, "bssid") == 0) {
		/*
		 * One or several. A single access point is a pin and a list is a
		 * choice among them, and both are ordinary ways to describe a site --
		 * so the key takes either rather than making an operator with two
		 * access points write a different key.
		 *
		 * A bare string is one address and is **not** split on whitespace,
		 * unlike every other list-shaped key here. That is deliberate: the
		 * count is what tells a pin from a choice, and a string that split
		 * would make `bssid = "aa:bb:cc:dd:ee:ff"` mean something different
		 * from what it says the moment a stray space got into it.
		 */
		size_t i;

		if (assignment->value->kind == NCFG_AST_LIST) {
			for (i = 0; i < network->bssid_count; i++) {
				free(network->bssid[i]);
			}
			free(network->bssid);
			network->bssid = NULL;
			network->bssid_count = 0;
			for (i = 0; i < assignment->value->entries.count; i++) {
				char *text = ncfg_as_string(ctx, assignment->value->entries.at[i]);

				(void)ncfg_push_string_owned(ctx, &network->bssid, &network->bssid_count,
				    text);
			}
			return;
		}
		{
			char *text = ncfg_as_string(ctx, assignment->value);

			if (!text) {
				return;
			}
			for (i = 0; i < network->bssid_count; i++) {
				free(network->bssid[i]);
			}
			free(network->bssid);
			network->bssid = NULL;
			network->bssid_count = 0;
			(void)ncfg_push_string_owned(ctx, &network->bssid, &network->bssid_count, text);
		}
		return;
	}
	ncfg_diag(ctx, assignment->span, "unknown network key `%s`", key);
}

/*
 * How a network says which access points it means, checked once the whole
 * block is known.
 *
 * Both of these compare a network key (`bssid`) with a `wifi` one (`roam`) or
 * with the label, so neither can be checked inside the inner block: a document
 * that wrote `wifi { }` first would be checked before the pin was read, and the
 * contradiction would be caught or missed depending on which of two lines
 * somebody typed first.
 */
static int network_names_itself(ncfg_lower_ctx_t *ctx, const ncfg_wifi_network_t *network,
    const ncfg_ast_block_t *block)
{
	/* A pin has nowhere to roam. A *list* does -- roaming among a named set is
	 * exactly what an operator who listed their site's access points wants. */
	if (network->roam && network->bssid_count == 1u) {
		ncfg_diag(ctx, block->span,
		    "`%s` is pinned to one access point and also asked to roam between them: drop "
		    "`bssid` to roam anywhere, list more than one to roam among them, or drop `roam` "
		    "to stay pinned", network->id);
		return 0;
	}
	/*
	 * A name read off a scan needs somewhere to read it from. With neither a
	 * name nor an access point the network identifies nothing at all -- and
	 * `wpa_supplicant`'s wildcard, which matches any SSID, is documented as
	 * working for plaintext access points only, because WPA derives its key
	 * from the passphrase *and* the name.
	 */
	if (!network->ssid.has && network->bssid_count == 0) {
		ncfg_diag(ctx, block->span,
		    "`%s` asks for its name to come from its access points and lists none: add "
		    "`bssid = \"aa:bb:cc:dd:ee:ff\"`, or a list of them", network->id);
		return 0;
	}
	return 1;
}

static void network_free(ncfg_wifi_network_t *network)
{
	free(network->id);
	ncfg_strings_free(network->bssid, network->bssid_count);
	free(network->roam);
	ncfg_security_free(&network->security);
	ncfg_address_sources_free(network->addressing, network->addressing_count);
	ncfg_routes_free(network->routes, network->route_count);
	ncfg_dns_policy_free(network->dns);
	free(network->dns);
	ncfg_hooks_free(network->hooks, network->hook_count);
	memset(network, 0, sizeof(*network));
}

int ncfg_lower_network(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *merged,
    ncfg_wifi_network_t *out)
{
	const ncfg_ast_block_t *block = merged->block;
	ncfg_wifi_network_t     network;
	const char             *why = NULL;
	int                     security_seen = 0;
	size_t                  i;

	memset(&network, 0, sizeof(network));
	network.id = ncfg_require_label(ctx, block);
	if (!network.id) {
		return 0;
	}
	network.autoconnect = 1;
	network.security.kind = NCFG_SECURITY_OPEN;

	/*
	 * **A network with no name is one nothing can join.** An SSID may be
	 * empty -- a hidden access point beacons a zero-length one, so an
	 * *observation* has to be able to hold it -- but an operator cannot
	 * configure a network by that name, and `network "" { }` compiled into a
	 * document with an unjoinable entry in it. The rule belongs here, where
	 * the difference between what may be seen and what may be written down is
	 * the difference between the two paths.
	 */
	if (block->label_length == 0) {
		ncfg_diag(ctx, block->span,
		    "a `network` block needs a name: the label is the SSID; a hidden network is "
		    "`hidden = true` beside its own name, not an empty one");
		network_free(&network);
		return 0;
	}
	/* The label is the SSID as written, and it is also the id. That is not a
	 * shortcut: an SSID is what the operator recognises, and giving a network
	 * a separate handle would mean two names for one thing in every
	 * diagnostic. */
	if (!ncfg_ssid_from_bytes(block->label, block->label_length, &network.ssid, &why)) {
		ncfg_diag(ctx, block->span, "`%s` cannot be a network name: %s", block->label, why);
		network_free(&network);
		return 0;
	}

	for (i = 0; i < merged->item_count; i++) {
		const ncfg_ast_item_t *item = merged->items[i].item;

		ctx->source = merged->items[i].source;
		switch (item->kind) {
		case NCFG_AST_ITEM_ASSIGNMENT:
			lower_network_key(ctx, &network, &item->as.assignment);
			break;
		case NCFG_AST_ITEM_BLOCK: {
			const ncfg_ast_block_t *inner = &item->as.block;

			if (strcmp(inner->head, "wifi") == 0) {
				ncfg_security_t security;

				security_seen = 1;
				if (ncfg_lower_wifi_block(ctx, inner, &network, &security)) {
					ncfg_security_free(&network.security);
					network.security = security;
				}
			} else if (strcmp(inner->head, "dns") == 0) {
				size_t at;

				if (!network.dns) {
					network.dns = calloc(1, sizeof(*network.dns));
				}
				if (!network.dns) {
					ncfg_lower_oom(ctx);
					break;
				}
				for (at = 0; at < inner->items.count; at++) {
					if (inner->items.at[at]->kind == NCFG_AST_ITEM_ASSIGNMENT) {
						ncfg_lower_dns_key(ctx, network.dns,
						    &inner->items.at[at]->as.assignment);
					}
				}
			} else {
				ncfg_diag(ctx, inner->span, "`%s` is not valid inside `network`", inner->head);
			}
			break;
		}
		case NCFG_AST_ITEM_HOOK:
			ncfg_lower_hook(ctx, &item->as.hook, network.id, &network.hooks,
			    &network.hook_count);
			break;
		case NCFG_AST_ITEM_INCLUDE:
			ncfg_diag(ctx, item->as.include.span,
			    "include was not resolved before compiling");
			break;
		default:
			break;
		}
	}

	if (!network_names_itself(ctx, &network, block)) {
		goto refused;
	}
	/* An open network is a real thing, but it is almost never what somebody
	 * meant to write, and joining one silently is how a laptop ends up
	 * associating with anything calling itself the same name. */
	if (!security_seen) {
		ncfg_diag(ctx, block->span,
		    "`%s` has no `wifi` block, so it is an open network: add "
		    "`psk = \"@secret:NAME\"`, or `wifi { open = true }` if that is meant",
		    network.id);
		goto refused;
	}
	*out = network;
	return 1;

refused:
	network_free(&network);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * access_point
 * ------------------------------------------------------------------------ */

/*
 * An `access_control` block: which stations an access point talks to.
 *
 * The two lists are alternatives rather than filters that combine, because
 * hostapd reads one or the other and never both (`macaddr_acl`). Writing both
 * is refused here rather than resolved by precedence: a precedence rule would
 * mean an operator's deny list quietly did nothing.
 */
static int lower_access_control(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_access_control_t *out)
{
	int    policy = -1;
	size_t at;

	memset(out, 0, sizeof(*out));
	for (at = 0; at < block->items.count; at++) {
		const ncfg_ast_item_t       *item = block->items.at[at];
		const ncfg_ast_assignment_t *assignment;
		ncfg_words_t                 words;
		size_t                       i;
		int                          chosen;

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `access_control`",
			    item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		if (strcmp(assignment->key, "deny") == 0) {
			chosen = NCFG_ACL_POLICY_DENY;
		} else if (strcmp(assignment->key, "allow") == 0) {
			chosen = NCFG_ACL_POLICY_ALLOW;
		} else {
			ncfg_diag(ctx, assignment->span, "unknown access_control key `%s`",
			    assignment->key);
			continue;
		}
		if (policy >= 0 && policy != chosen) {
			ncfg_diag(ctx, assignment->span,
			    "an access point has one station list, not both an allow and a deny: hostapd "
			    "reads either the accept list or the deny list, never both; say which one "
			    "this access point means");
			goto refused;
		}
		policy = chosen;

		if (!ncfg_as_words(ctx, assignment->value, &words)) {
			ncfg_words_free(&words);
			continue;
		}
		for (i = 0; i < words.count; i++) {
			char  why[NCFG_ERROR_MAX];
			char *station = ncfg_normalize_station(ctx, words.at[i].text, why, sizeof(why));

			if (!station) {
				ncfg_diag(ctx, words.at[i].span, "%s", why);
				continue;
			}
			(void)ncfg_push_string_owned(ctx, &out->stations, &out->station_count, station);
		}
		ncfg_words_free(&words);
	}

	/*
	 * An empty deny list is what every access point without this block already
	 * has, so it means nothing and is accepted in silence. An empty *allow*
	 * list means no station may associate at all, which is a strange thing to
	 * write by accident and a legitimate thing to write on purpose -- so it
	 * compiles, and the planner warns about it.
	 */
	if (policy < 0) {
		goto refused;
	}
	out->policy = policy;
	return 1;

refused:
	ncfg_strings_free(out->stations, out->station_count);
	memset(out, 0, sizeof(*out));
	return 0;
}

/*
 * Which band an access point will actually be brought up in.
 *
 * `band` decides when it is stated. When it is not, the channel decides, and
 * the split is at 14: 1..14 is 2.4 GHz and nothing else, while the numbers
 * above belong to 5 GHz. NULL for a band this build cannot render -- `6`,
 * which the compiler accepts deliberately.
 */
static const char *effective_band(const char *band, int64_t channel)
{
	if (band) {
		if (strcmp(band, "2.4") == 0) {
			return "2.4";
		}
		if (strcmp(band, "5") == 0) {
			return "5";
		}
		return NULL;
	}
	return channel <= 14 ? "2.4" : "5";
}

/*
 * Whether a channel number exists in a band at all.
 *
 * The 5 GHz list is a range rather than the exact set because which of those
 * channels are usable is a regulatory question the kernel answers, not a
 * spelling question this can answer. What this rejects is a number that is in
 * no band, which is a typo rather than a regulatory refusal. Channel 0 is in
 * no band: it is hostapd's spelling of "survey and choose", which an absent
 * `channel` already says.
 */
static int channel_in_band(const char *band, int64_t channel)
{
	if (strcmp(band, "2.4") == 0) {
		return channel >= 1 && channel <= 14;
	}
	return channel >= 36 && channel <= 177;
}

/*
 * The channel and the band, which only mean anything together.
 *
 * Each key is already checked alone: `band` is one of a closed set, and
 * `channel` is a number. The pair was checked nowhere until 0222, so
 * `band = "2.4"` with `channel = 36` compiled, planned, and failed at
 * `ncfg apply` with the interface already up. It also kept the example gate
 * blind, because that gate compiles each block and a render-time refusal is
 * invisible to it.
 */
static int check_channel_in_band(ncfg_lower_ctx_t *ctx, const ncfg_access_point_t *access_point,
    ncfg_span_t channel_span)
{
	const char *band;

	if (!access_point->channel.has) {
		return 1;
	}
	band = effective_band(access_point->band, access_point->channel.value);
	if (!band) {
		/* A band this build cannot render, which `ncfg_lower_band` accepted on
		 * purpose so that the renderer can say so in its own words. */
		return 1;
	}
	if (channel_in_band(band, access_point->channel.value)) {
		return 1;
	}
	ncfg_diag(ctx, channel_span, "channel %lld is not in the %s GHz band: %s",
	    (long long)access_point->channel.value, band,
	    access_point->band
	        ? "2.4 GHz is channels 1-14 and 5 GHz is 36-177; drop `band` to let the channel "
	          "number say which"
	        : "2.4 GHz is channels 1-14 and 5 GHz is 36-177");
	return 0;
}

static void access_point_free(ncfg_access_point_t *access_point)
{
	free(access_point->id);
	free(access_point->device);
	free(access_point->band);
	free(access_point->regdom);
	ncfg_security_free(&access_point->security);
	if (access_point->access_control) {
		ncfg_strings_free(access_point->access_control->stations,
		    access_point->access_control->station_count);
		free(access_point->access_control);
	}
	memset(access_point, 0, sizeof(*access_point));
}

int ncfg_lower_access_point(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *merged,
    ncfg_access_point_t *out)
{
	const ncfg_ast_block_t *block = merged->block;
	ncfg_access_point_t     access_point;
	ncfg_span_t             channel_span = block->span;
	const char             *why = NULL;
	int                     security_seen = 0;
	size_t                  i;

	memset(&access_point, 0, sizeof(access_point));
	access_point.id = ncfg_require_label(ctx, block);
	if (!access_point.id) {
		return 0;
	}
	if (!ncfg_ssid_from_bytes(block->label, block->label_length, &access_point.ssid, &why)) {
		ncfg_diag(ctx, block->span, "`%s` cannot be a network name: %s", block->label, why);
		access_point_free(&access_point);
		return 0;
	}
	access_point.security.kind = NCFG_SECURITY_OPEN;

	for (i = 0; i < merged->item_count; i++) {
		const ncfg_ast_item_t *item = merged->items[i].item;

		ctx->source = merged->items[i].source;
		if (item->kind == NCFG_AST_ITEM_ASSIGNMENT) {
			const ncfg_ast_assignment_t *assignment = &item->as.assignment;
			const char                  *key = assignment->key;
			int                          flag;

			if (strcmp(key, "device") == 0) {
				free(access_point.device);
				access_point.device = ncfg_as_interface_name(ctx, assignment->value);
			} else if (strcmp(key, "channel") == 0) {
				channel_span = assignment->span;
				ncfg_as_narrow_opt(ctx, assignment->value, 65535, &access_point.channel);
			} else if (strcmp(key, "band") == 0) {
				ncfg_lower_band(ctx, &access_point.band, assignment);
			} else if (strcmp(key, "regdom") == 0) {
				ncfg_lower_regdom(ctx, &access_point.regdom, assignment);
			} else if (strcmp(key, "hidden") == 0) {
				/* Not a security measure and not documented as one: it stops
				 * the network appearing in a list and makes every client that
				 * knows it broadcast the name while probing. */
				if (ncfg_as_bool(ctx, assignment->value, &flag)) {
					access_point.hidden = flag;
				}
			} else if (strcmp(key, "ssid") == 0) {
				char *text = ncfg_as_string(ctx, assignment->value);

				if (!text) {
					continue;
				}
				if (!ncfg_ssid_from_hex(text, &access_point.ssid, &why)) {
					ncfg_diag(ctx, assignment->span, "`%s` is not a usable ssid: %s", text,
					    why);
				}
				free(text);
			} else {
				ncfg_diag(ctx, assignment->span, "unknown access_point key `%s`", key);
			}
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_BLOCK) {
			continue;
		}
		if (strcmp(item->as.block.head, "wifi") == 0) {
			ncfg_security_t security;

			/* An access point's security is the same shape as a station's, so
			 * it is parsed by the same code -- with no network behind it,
			 * since the keys that only mean something to a client have nowhere
			 * to go here. */
			security_seen = 1;
			if (ncfg_lower_wifi_block(ctx, &item->as.block, NULL, &security)) {
				ncfg_security_free(&access_point.security);
				access_point.security = security;
			}
		} else if (strcmp(item->as.block.head, "access_control") == 0) {
			ncfg_access_control_t acl;

			if (!lower_access_control(ctx, &item->as.block, &acl)) {
				continue;
			}
			if (!access_point.access_control) {
				access_point.access_control = calloc(1, sizeof(*access_point.access_control));
			} else {
				ncfg_strings_free(access_point.access_control->stations,
				    access_point.access_control->station_count);
			}
			if (!access_point.access_control) {
				ncfg_lower_oom(ctx);
				ncfg_strings_free(acl.stations, acl.station_count);
				continue;
			}
			*access_point.access_control = acl;
		} else {
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `access_point`",
			    item->as.block.head);
		}
	}

	if (!access_point.device) {
		ncfg_diag(ctx, block->span,
		    "access point `%s` does not say which radio runs it: add `device = \"wlan0\"`; "
		    "unlike a `network`, an access point is one radio", access_point.id);
		goto refused;
	}
	if (!security_seen) {
		ncfg_diag(ctx, block->span,
		    "access point `%s` has no `wifi` block, so it would be open: add "
		    "`wifi { psk = \"@secret:NAME\" }`, or `wifi { open = true }`", access_point.id);
		goto refused;
	}
	if (!check_channel_in_band(ctx, &access_point, channel_span)) {
		goto refused;
	}
	*out = access_point;
	return 1;

refused:
	access_point_free(&access_point);
	return 0;
}
