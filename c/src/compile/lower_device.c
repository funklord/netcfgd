/*
 * lower_device.c -- `device`, which is the hardware and whether netcfgd
 * touches it.
 *
 * 0155 moved two things here from `interface`, in two passes, and the test
 * that sorted them is the same both times: **a setting belongs to the device
 * when it means something with nothing connected.** An MTU does, an address
 * does not. Pass 1a brought the adapter's own settings -- mtu, mac, ethtool,
 * the radio and the modem; pass 1b brought the structural half -- what netcfgd
 * creates, what it is a port of, and how its egress is shaped.
 *
 * What is left in `interface` is what runs over the link. The keys that moved
 * are still named there rather than left to "unknown", because an operator who
 * wrote one had a working configuration.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lower_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

/* ------------------------------------------------------------------------ *
 * Queueing
 * ------------------------------------------------------------------------ */

/*
 * One of the schedulers decision 0023 allows, or a diagnostic naming them.
 *
 * The full list is in the message rather than "unknown qdisc", because the set
 * is small, closed, and not guessable: somebody who writes `htb` needs to be
 * told that classful schedulers are out, not that they typed something
 * unrecognised.
 */
int ncfg_qdisc_kind(ncfg_lower_ctx_t *ctx, const char *name, ncfg_span_t span, int *out)
{
	static const char *const names[] = { "fq_codel", "cake", "fq", "pfifo_fast", "noqueue" };
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (strcmp(names[i], name) == 0) {
			*out = (int)i;
			return 1;
		}
	}
	ncfg_diag(ctx, span,
	    "`%s` is not a queueing discipline netcfgd sets: one of fq_codel, cake, fq, "
	    "pfifo_fast, noqueue; netcfgd sets the root qdisc only, so classful schedulers like "
	    "`htb` are out of scope (doc/decision/0023)", name);
	return 0;
}

/* Only `cake` shapes without a class tree; the others queue but do not
 * limit. */
static int qdisc_shapes(int kind)
{
	return kind == NCFG_QDISC_CAKE;
}

static const char *qdisc_name(int kind)
{
	static const char *const names[] = { "fq_codel", "cake", "fq", "pfifo_fast", "noqueue" };

	return names[kind];
}

/*
 * A rate such as `100mbit`, in bits per second.
 *
 * Decimal multipliers, as `tc` uses them: `kbit` is 1000 bits, not 1024. A
 * bare number is bits per second, which is the unit everything else here is
 * in.
 */
static int rate_bits(ncfg_lower_ctx_t *ctx, const char *text, ncfg_span_t span, int64_t *out)
{
	static const struct {
		const char *suffix;
		int64_t     multiplier;
	} units[] = {
		{ "gbit", 1000000000LL },
		{ "mbit", 1000000LL },
		{ "kbit", 1000LL },
		{ "bit", 1LL }
	};
	char          digits[32];
	const char   *start = text;
	size_t        length;
	int64_t       multiplier = 1;
	size_t        i;
	char         *end;
	unsigned long long number;

	while (*start == ' ' || *start == '\t') {
		start++;
	}
	length = strlen(start);
	while (length > 0 && (start[length - 1u] == ' ' || start[length - 1u] == '\t')) {
		length--;
	}
	for (i = 0; i < sizeof(units) / sizeof(units[0]); i++) {
		size_t suffix = strlen(units[i].suffix);

		if (length >= suffix && strncmp(start + length - suffix, units[i].suffix, suffix) == 0) {
			multiplier = units[i].multiplier;
			length -= suffix;
			while (length > 0 && (start[length - 1u] == ' ' || start[length - 1u] == '\t')) {
				length--;
			}
			break;
		}
	}
	if (length == 0 || length >= sizeof(digits)) {
		goto not_a_rate;
	}
	memcpy(digits, start, length);
	digits[length] = '\0';
	number = strtoull(digits, &end, 10);
	if (end == digits || *end != '\0') {
		goto not_a_rate;
	}
	if (number == 0) {
		ncfg_diag(ctx, span, "a shaped rate of zero would pass nothing");
		return 0;
	}
	if (number > (unsigned long long)(9223372036854775807LL / multiplier)) {
		ncfg_diag(ctx, span, "`%s` is too large a rate", text);
		return 0;
	}
	*out = (int64_t)number * multiplier;
	return 1;

not_a_rate:
	ncfg_diag(ctx, span,
	    "`%s` is not a rate: a number and one of `bit`, `kbit`, `mbit`, `gbit`, as in "
	    "`100mbit`", text);
	return 0;
}

int ncfg_lower_qdisc(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_qdisc_policy_t *out)
{
	ncfg_qdisc_policy_t policy;
	ncfg_span_t         bandwidth_span = block->span;
	ncfg_span_t         ingress_span = block->span;
	size_t              at;
	int                 kind_seen = 0;

	memset(&policy, 0, sizeof(policy));
	for (at = 0; at < block->items.count; at++) {
		const ncfg_ast_item_t       *item = block->items.at[at];
		const ncfg_ast_assignment_t *assignment;
		char                        *text;

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `qdisc`",
			    item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		if (strcmp(assignment->key, "kind") == 0) {
			text = ncfg_as_string(ctx, assignment->value);
			if (text) {
				kind_seen = ncfg_qdisc_kind(ctx, text, assignment->span, &policy.kind);
				free(text);
			}
		} else if (strcmp(assignment->key, "bandwidth") == 0) {
			bandwidth_span = assignment->span;
			text = ncfg_as_string(ctx, assignment->value);
			if (text) {
				if (rate_bits(ctx, text, assignment->span, &policy.bandwidth_bits.value)) {
					policy.bandwidth_bits.has = 1;
				}
				free(text);
			}
		} else if (strcmp(assignment->key, "ingress_bandwidth") == 0) {
			ingress_span = assignment->span;
			text = ncfg_as_string(ctx, assignment->value);
			if (text) {
				if (rate_bits(ctx, text, assignment->span,
				    &policy.ingress_bandwidth_bits.value)) {
					policy.ingress_bandwidth_bits.has = 1;
				}
				free(text);
			}
		} else {
			ncfg_diag(ctx, assignment->span, "unknown qdisc key `%s`", assignment->key);
		}
	}

	if (!kind_seen) {
		ncfg_diag(ctx, block->span,
		    "a `qdisc` block needs a `kind`: as in `qdisc { kind = \"cake\"; "
		    "bandwidth = \"100mbit\" }");
		return 0;
	}
	/* Refused rather than ignored. A rate on `fq_codel` is somebody expecting
	 * their line to be shaped, and silently dropping it would leave them with
	 * an unshaped uplink and a config that says otherwise. */
	if (policy.ingress_bandwidth_bits.has && !qdisc_shapes(policy.kind)) {
		ncfg_diag(ctx, ingress_span,
		    "`%s` cannot shape arriving traffic: ingress shaping puts `cake` on an `ifb` "
		    "device, so the scheduler has to be `cake`", qdisc_name(policy.kind));
		return 0;
	}
	if (policy.bandwidth_bits.has && !qdisc_shapes(policy.kind)) {
		ncfg_diag(ctx, bandwidth_span,
		    "`%s` cannot shape to a rate: `cake` is the scheduler that shapes without a class "
		    "tree; the others queue but do not limit", qdisc_name(policy.kind));
		return 0;
	}
	*out = policy;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Bridge VLANs
 * ------------------------------------------------------------------------ */

/*
 * One bridge VLAN: `10`, `10 pvid untagged`, or a range `10-19`.
 *
 * Ranges are expanded here rather than carried in the model. The kernel
 * compresses consecutive ids on the way out and this expands them on the way
 * in, so everything between works in single VLANs and nothing has to know
 * ranges exist.
 */
void ncfg_lower_bridge_vlans(ncfg_lower_ctx_t *ctx, const ncfg_word_t *entry,
    ncfg_bridge_vlan_t **list, size_t *count)
{
	ncfg_words_t     words;
	ncfg_ast_value_t fake;
	const char      *head;
	const char      *dash;
	char            *end;
	unsigned long    first;
	unsigned long    last;
	size_t           at;
	unsigned long    vid;
	int              pvid = 0;
	int              untagged = 0;

	memset(&fake, 0, sizeof(fake));
	fake.kind = NCFG_AST_STRING;
	fake.span = entry->span;
	fake.string = entry->text;
	fake.string_length = strlen(entry->text);
	if (!ncfg_as_words(ctx, &fake, &words) || words.count == 0) {
		ncfg_words_free(&words);
		return;
	}
	head = words.at[0].text;
	dash = strchr(head, '-');
	if (dash) {
		first = strtoul(head, &end, 10);
		if (end != dash) {
			goto done;
		}
		last = strtoul(dash + 1, &end, 10);
		if (end == dash + 1 || *end != '\0') {
			goto done;
		}
	} else {
		first = strtoul(head, &end, 10);
		if (end == head || *end != '\0') {
			goto done;
		}
		last = first;
	}
	if (first > 65535u || last > 65535u) {
		goto done;
	}
	if (first > last) {
		ncfg_diag(ctx, entry->span, "`%s` counts backwards", head);
		goto done;
	}
	/* 0 is not a VLAN and 4095 is reserved. The kernel refuses both, with an
	 * errno rather than a name. */
	if (first == 0 || last > 4094u) {
		ncfg_diag(ctx, entry->span, "`%s` is not a VLAN id: between 1 and 4094", head);
		goto done;
	}

	for (at = 1u; at < words.count; at++) {
		const char *word = words.at[at].text;

		if (strcmp(word, "pvid") == 0) {
			pvid = 1;
		} else if (strcmp(word, "untagged") == 0) {
			untagged = 1;
		} else if (strcmp(word, "tagged") == 0) {
			untagged = 0;
		} else {
			ncfg_diag(ctx, entry->span, "`%s` is not a vlan option: pvid, untagged, tagged",
			    word);
			goto done;
		}
	}
	/* A PVID is where untagged ingress lands, so a range of them would mean
	 * several answers to one question. */
	if (pvid && first != last) {
		ncfg_diag(ctx, entry->span,
		    "a range cannot be the pvid; untagged traffic joins one vlan");
		goto done;
	}

	for (vid = first; vid <= last; vid++) {
		ncfg_bridge_vlan_t *slot = ncfg_push(ctx, list, count, sizeof(*slot));

		if (!slot) {
			break;
		}
		slot->vid = (int64_t)vid;
		slot->pvid = pvid;
		slot->untagged = untagged;
	}

done:
	ncfg_words_free(&words);
}

/* ------------------------------------------------------------------------ *
 * ethtool
 * ------------------------------------------------------------------------ */

static int link_settings_empty(const ncfg_link_settings_t *settings)
{
	return settings->autoneg == NCFG_TOGGLE_UNMANAGED && !settings->speed.has &&
	    settings->duplex == NULL && settings->wol == NULL && !settings->rx_ring.has &&
	    !settings->tx_ring.has && settings->gro == NCFG_TOGGLE_UNMANAGED &&
	    settings->gso == NCFG_TOGGLE_UNMANAGED && settings->tso == NCFG_TOGGLE_UNMANAGED &&
	    settings->rx_checksum == NCFG_TOGGLE_UNMANAGED &&
	    settings->tx_checksum == NCFG_TOGGLE_UNMANAGED;
}

/*
 * A toggle is "on", "off" or "unmanaged" -- three values rather than two,
 * because "leave this one alone" is a different instruction from "turn it
 * off", and a boolean could not say it.
 */
static int lower_toggle(ncfg_lower_ctx_t *ctx, const ncfg_ast_assignment_t *assignment, int *out)
{
	char *name = ncfg_as_string(ctx, assignment->value);
	int   ok = 1;

	if (!name) {
		return 0;
	}
	if (strcmp(name, "on") == 0 || strcmp(name, "true") == 0) {
		*out = NCFG_TOGGLE_ON;
	} else if (strcmp(name, "off") == 0 || strcmp(name, "false") == 0) {
		*out = NCFG_TOGGLE_OFF;
	} else if (strcmp(name, "unmanaged") == 0) {
		*out = NCFG_TOGGLE_UNMANAGED;
	} else {
		ncfg_diag(ctx, assignment->span, "`%s` is not a toggle: one of on, off, unmanaged",
		    name);
		ok = 0;
	}
	free(name);
	return ok;
}

/*
 * An `ethtool` block: the driver-level link settings.
 *
 * **The offloads are applied; the rest is not**, and the reason is
 * verification rather than effort -- a veth takes a features message and
 * refuses a link-modes set with a bare `EINVAL`. Compiled here anyway, so that
 * a configuration that says what it wants survives to the point where somebody
 * can implement it.
 */
static void lower_ethtool(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_link_settings_t *settings)
{
	size_t at;

	for (at = 0; at < block->items.count; at++) {
		const ncfg_ast_item_t       *item = block->items.at[at];
		const ncfg_ast_assignment_t *assignment;
		const char                  *key;
		int                         *toggle = NULL;

		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		key = assignment->key;
		if (strcmp(key, "autoneg") == 0) {
			toggle = &settings->autoneg;
		} else if (strcmp(key, "gro") == 0) {
			toggle = &settings->gro;
		} else if (strcmp(key, "gso") == 0) {
			toggle = &settings->gso;
		} else if (strcmp(key, "tso") == 0) {
			toggle = &settings->tso;
		} else if (strcmp(key, "rx_checksum") == 0) {
			toggle = &settings->rx_checksum;
		} else if (strcmp(key, "tx_checksum") == 0) {
			toggle = &settings->tx_checksum;
		}
		if (toggle) {
			(void)lower_toggle(ctx, assignment, toggle);
			continue;
		}
		if (strcmp(key, "speed") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &settings->speed);
		} else if (strcmp(key, "rx_ring") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &settings->rx_ring);
		} else if (strcmp(key, "tx_ring") == 0) {
			ncfg_as_u32_opt(ctx, assignment->value, &settings->tx_ring);
		} else if (strcmp(key, "duplex") == 0) {
			char *name = ncfg_as_string(ctx, assignment->value);

			if (!name) {
				continue;
			}
			if (strcmp(name, "full") == 0 || strcmp(name, "half") == 0) {
				free(settings->duplex);
				settings->duplex = name;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a duplex setting: one of full, half", name);
				free(name);
			}
		} else if (strcmp(key, "wol") == 0) {
			free(settings->wol);
			settings->wol = ncfg_as_string(ctx, assignment->value);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown ethtool key `%s`", key);
		}
	}
}

/* ------------------------------------------------------------------------ *
 * The radio and the modem
 * ------------------------------------------------------------------------ */

/*
 * The `band` key, checked here rather than at render time.
 *
 * **It used to be a plain string, so any text compiled.** The renderer decides
 * what a band means and refused an unknown one well -- naming the value, the
 * set and the alternative -- but it refused at *apply*, by which time the
 * interface is up and the operator is reading a failed action rather than a
 * config diagnostic. `netcfgd.conf.example` said `band = "5g"`, which is not
 * one of them, so the documented access point could not be started and nothing
 * before `ncfg apply` said so.
 *
 * **`6` is accepted here and refused by the renderer**, deliberately. "Not a
 * band" and "a band this build cannot do" are different answers and the
 * operator needs the second one to stay distinguishable from the first.
 */
void ncfg_lower_band(ncfg_lower_ctx_t *ctx, char **band, const ncfg_ast_assignment_t *assignment)
{
	char *name = ncfg_as_string(ctx, assignment->value);

	if (!name) {
		return;
	}
	if (strcmp(name, "2.4") == 0 || strcmp(name, "5") == 0 || strcmp(name, "6") == 0) {
		free(*band);
		*band = name;
		return;
	}
	ncfg_diag(ctx, assignment->span,
	    "`%s` is not a band: one of 2.4, 5, 6 -- or leave `band` out and let the channel "
	    "number say which", name);
	free(name);
}

/*
 * The `regdom` key, checked here for the reason `ncfg_lower_band` is.
 *
 * **Both `regdom` keys come here, and until 0221 only one did.** The language
 * spells the same setting in two places -- `access_point { regdom }` and
 * `device { wifi { regdom } }` -- and the device's had a second, inline copy of
 * this check that differed in one byte: uppercase-only rather than alphabetic.
 * So `regdom = "se"` compiled as an access point's and was refused as a
 * radio's, with a different help string, in the same file. Merged towards the
 * permissive one, because widening cannot break a configuration that already
 * compiles.
 *
 * **Uppercased on the way in**, so the document holds one spelling of a code
 * that is conventionally capitals and that the renderer capitalises anyway.
 */
void ncfg_lower_regdom(ncfg_lower_ctx_t *ctx, char **regdom,
    const ncfg_ast_assignment_t *assignment)
{
	char *name = ncfg_as_string(ctx, assignment->value);
	int   alphabetic;

	if (!name) {
		return;
	}
	alphabetic = strlen(name) == 2u &&
	    ((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')) &&
	    ((name[1] >= 'a' && name[1] <= 'z') || (name[1] >= 'A' && name[1] <= 'Z'));
	if (!alphabetic) {
		ncfg_diag(ctx, assignment->span,
		    "`%s` is not a regulatory domain: an ISO 3166-1 alpha-2 country code, such as "
		    "\"SE\"", name);
		free(name);
		return;
	}
	if (name[0] >= 'a') {
		name[0] = (char)(name[0] - 32);
	}
	if (name[1] >= 'a') {
		name[1] = (char)(name[1] - 32);
	}
	free(*regdom);
	*regdom = name;
}

/*
 * Whether a URL is one netcfgd can probe with.
 *
 * **`http://` only.** A captive portal works by intercepting a request and
 * answering it with something else, which is what TLS exists to stop: over
 * `https` an interception is a certificate error rather than a redirect, so a
 * check that cannot be intercepted cannot detect interception. Refused with
 * that sentence rather than accepted and quietly useless -- an `https` probe
 * would report "no portal" on precisely the networks it was written for.
 */
static int portal_url(const char *url, char *why, size_t why_size)
{
	const char *rest;
	const char *slash;

	if (strncmp(url, "https://", 8u) == 0) {
		ncfg_error_set(why, why_size,
		    "a captive portal check cannot use `https`: a portal intercepts the request and "
		    "answers it, which TLS prevents -- so an `https` probe reports no portal on "
		    "exactly the networks it is for");
		return 0;
	}
	if (strncmp(url, "http://", 7u) != 0) {
		ncfg_error_set(why, why_size, "`%s` is not an `http://` URL", url);
		return 0;
	}
	/* A host at least. Everything past the first `/` is the path, which may be
	 * empty -- `http://example.com` is a request for `/`. */
	rest = url + 7;
	slash = strchr(rest, '/');
	if (rest == slash || rest[0] == '\0') {
		ncfg_error_set(why, why_size, "`%s` names no host to fetch from", url);
		return 0;
	}
	return 1;
}

/* A `wifi` block inside `device`: how the radio behaves, not what it joins. */
static void lower_wifi_device(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_wifi_device_policy_t *policy)
{
	size_t at;

	policy->backend = NCFG_WIFI_BACKEND_AUTO;
	policy->autoconnect = 1;
	policy->powersave = NCFG_POWERSAVE_DEFAULT;
	policy->mac_policy = NCFG_MAC_POLICY_PERMANENT;
	policy->scan_randomization = 0;

	for (at = 0; at < block->items.count; at++) {
		const ncfg_ast_item_t       *item = block->items.at[at];
		const ncfg_ast_assignment_t *assignment;
		const char                  *key;
		char                        *name;
		int                          flag;

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span,
			    "`%s` is not valid inside a device `wifi` block", item->as.block.head);
			continue;
		}
		if (item->kind == NCFG_AST_ITEM_HOOK) {
			ncfg_diag(ctx, item->as.hook.span,
			    "hooks belong to an interface or a network, not to a radio");
			continue;
		}
		if (item->kind == NCFG_AST_ITEM_INCLUDE) {
			ncfg_diag(ctx, item->as.include.span,
			    "include was not resolved before compiling");
			continue;
		}
		assignment = &item->as.assignment;
		key = assignment->key;
		if (strcmp(key, "backend") == 0) {
			name = ncfg_as_string(ctx, assignment->value);
			if (!name) {
				continue;
			}
			if (strcmp(name, "auto") == 0) {
				policy->backend = NCFG_WIFI_BACKEND_AUTO;
			} else if (strcmp(name, "wpa_supplicant") == 0) {
				policy->backend = NCFG_WIFI_BACKEND_WPA_SUPPLICANT;
			} else if (strcmp(name, "iwd") == 0) {
				/* Accepted by the compiler and refused at use, so the
				 * diagnostic can explain the reason rather than reading as a
				 * typo. Decision 0014: iwd keeps its own network database,
				 * which cannot be reconciled against. */
				policy->backend = NCFG_WIFI_BACKEND_IWD;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a wifi backend: one of auto, wpa_supplicant, iwd", name);
			}
			free(name);
		} else if (strcmp(key, "autoconnect") == 0) {
			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				policy->autoconnect = flag;
			}
		} else if (strcmp(key, "portal_check") == 0) {
			char why[NCFG_ERROR_MAX];

			/* A URL and not a boolean, which is 0061's decision: netcfgd has
			 * no address of its own to fetch, and a default would be a third
			 * party told when this machine joins a network. */
			name = ncfg_as_string(ctx, assignment->value);
			if (!name) {
				continue;
			}
			if (portal_url(name, why, sizeof(why))) {
				free(policy->portal_check);
				policy->portal_check = name;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "%s: `portal_check = \"http://example.com/generate_204\"`", why);
				free(name);
			}
		} else if (strcmp(key, "regdom") == 0) {
			/* Two letters, because a regulatory domain that is not one is
			 * silently ignored by the kernel -- and a radio quietly using the
			 * world-roaming defaults is a difficult thing to notice. The check
			 * is shared with the access point's key of the same name. */
			ncfg_lower_regdom(ctx, &policy->regdom, assignment);
		} else if (strcmp(key, "mac_policy") == 0) {
			name = ncfg_as_string(ctx, assignment->value);
			if (!name) {
				continue;
			}
			if (strcmp(name, "permanent") == 0) {
				policy->mac_policy = NCFG_MAC_POLICY_PERMANENT;
			} else if (strcmp(name, "per_network") == 0) {
				policy->mac_policy = NCFG_MAC_POLICY_PER_NETWORK;
			} else if (strcmp(name, "per_connection") == 0) {
				policy->mac_policy = NCFG_MAC_POLICY_PER_CONNECTION;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a MAC policy: one of permanent, per_network, "
				    "per_connection", name);
			}
			free(name);
		} else if (strcmp(key, "scan_randomization") == 0) {
			if (ncfg_as_bool(ctx, assignment->value, &flag)) {
				policy->scan_randomization = flag;
			}
		} else if (strcmp(key, "powersave") == 0) {
			name = ncfg_as_string(ctx, assignment->value);
			if (!name) {
				continue;
			}
			if (strcmp(name, "default") == 0) {
				policy->powersave = NCFG_POWERSAVE_DEFAULT;
			} else if (strcmp(name, "on") == 0) {
				policy->powersave = NCFG_POWERSAVE_ON;
			} else if (strcmp(name, "off") == 0) {
				policy->powersave = NCFG_POWERSAVE_OFF;
			} else {
				ncfg_diag(ctx, assignment->span,
				    "`%s` is not a powersave setting: one of default, on, off", name);
			}
			free(name);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown wifi device key `%s`", key);
		}
	}
}

/*
 * A value that will be handed to a hook or a helper, checked for the
 * characters that would change what the receiver runs.
 *
 * Not fussiness and not validation of the value's *meaning*: 0150 is explicit
 * that netcfgd must not be clever about an APN, and a SIM source name is the
 * board's word rather than one from a closed set. What is checked is the part
 * netcfgd is responsible for -- these reach `helper/netcfgd-modem-at`, which
 * interpolates the APN into `AT+CGDCONT=1,"IP","<apn>"`, so a quote ends the
 * command early and the rest becomes another one.
 */
static char *check_hook_word(ncfg_lower_ctx_t *ctx, const char *text, ncfg_span_t span,
    const char *what)
{
	size_t at;

	if (text[0] == '\0') {
		ncfg_diag(ctx, span, "%s cannot be empty", what);
		return NULL;
	}
	for (at = 0; text[at]; at++) {
		unsigned char one = (unsigned char)text[at];

		if (one < 0x20u || one == 0x7fu || one == '"' || one == '\\') {
			ncfg_diag(ctx, span,
			    "%s contains a quote, a backslash or a control character: this is passed to "
			    "a hook and to a modem helper that puts it inside a quoted AT command, where "
			    "a quote would end the command early", what);
			return NULL;
		}
	}
	return ncfg_dup(ctx, text);
}

/*
 * A `modem` block inside a `device`: which SIM source, and which APN.
 *
 * Decision 0150: netcfgd chooses the source and says what to do when it will
 * not register, while a `pre_up` hook drives the mux -- a select line is board
 * enablement and this daemon has no GPIO.
 */
static void lower_modem(ncfg_lower_ctx_t *ctx, const ncfg_ast_block_t *block,
    ncfg_modem_policy_t *modem)
{
	size_t at;

	for (at = 0; at < block->items.count; at++) {
		const ncfg_ast_item_t       *item = block->items.at[at];
		const ncfg_ast_assignment_t *assignment;

		if (item->kind == NCFG_AST_ITEM_BLOCK) {
			ncfg_diag(ctx, item->as.block.span, "`%s` is not valid inside `modem`",
			    item->as.block.head);
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_ASSIGNMENT) {
			continue;
		}
		assignment = &item->as.assignment;
		if (strcmp(assignment->key, "sim") == 0) {
			ncfg_words_t words;
			size_t       i;

			for (i = 0; i < modem->sim_count; i++) {
				free(modem->sim[i]);
			}
			free(modem->sim);
			modem->sim = NULL;
			modem->sim_count = 0;
			if (!ncfg_as_words(ctx, assignment->value, &words)) {
				ncfg_words_free(&words);
				continue;
			}
			for (i = 0; i < words.count; i++) {
				char *name = check_hook_word(ctx, words.at[i].text, words.at[i].span,
				    "a SIM source");

				if (!name) {
					continue;
				}
				/* A source named twice is two answers to "what next". */
				if (ncfg_has_string(modem->sim, modem->sim_count, name)) {
					ncfg_diag(ctx, words.at[i].span, "`%s` is listed twice", name);
					free(name);
					continue;
				}
				(void)ncfg_push_string_owned(ctx, &modem->sim, &modem->sim_count, name);
			}
			ncfg_words_free(&words);
		} else if (strcmp(assignment->key, "apn") == 0) {
			char *text = ncfg_as_string(ctx, assignment->value);

			if (!text) {
				continue;
			}
			free(modem->apn);
			modem->apn = check_hook_word(ctx, text, assignment->value->span, "an APN");
			free(text);
		} else {
			ncfg_diag(ctx, assignment->span, "unknown modem key `%s`", assignment->key);
		}
	}
}

/* ------------------------------------------------------------------------ *
 * The device block
 * ------------------------------------------------------------------------ */

/* Whether a `device` key describes what to create rather than how it behaves.
 * Grouped this way because the four are one subject: what netcfgd makes, what
 * it is a port of, and how its egress is shaped (0155 pass 1b). */
static int is_structural_key(const char *key)
{
	return strcmp(key, "master") == 0 || strcmp(key, "vlans") == 0 ||
	    strcmp(key, "kind") == 0 || strcmp(key, "qdisc") == 0;
}

static void lower_structural_key(ncfg_lower_ctx_t *ctx, ncfg_device_t *device,
    const ncfg_ast_assignment_t *assignment)
{
	const char *key = assignment->key;

	if (strcmp(key, "master") == 0) {
		free(device->master);
		device->master = ncfg_as_interface_name(ctx, assignment->value);
		return;
	}
	if (strcmp(key, "vlans") == 0) {
		ncfg_words_t lines;
		size_t       i;

		if (!ncfg_as_lines(ctx, assignment->value, &lines)) {
			ncfg_words_free(&lines);
			return;
		}
		for (i = 0; i < lines.count; i++) {
			ncfg_lower_bridge_vlans(ctx, &lines.at[i], &device->bridge_vlans,
			    &device->bridge_vlan_count);
		}
		ncfg_words_free(&lines);
		return;
	}
	if (strcmp(key, "kind") == 0) {
		char *name = ncfg_as_string(ctx, assignment->value);

		if (!name) {
			return;
		}
		/* The kinds with no parameters, which therefore have no block to be
		 * declared by. `dummy` was creatable by the executor and unsayable in
		 * the config until the pre-freeze audit noticed: a dummy interface is
		 * the ordinary way to hold an address that does not depend on any
		 * cable. */
		if (strcmp(name, "dummy") == 0) {
			device->kind.kind = NCFG_KIND_DUMMY;
		} else if (strcmp(name, "physical") == 0) {
			device->kind.kind = NCFG_KIND_PHYSICAL;
		} else {
			ncfg_diag(ctx, assignment->span, "`%s` is not a device kind", name);
		}
		free(name);
		return;
	}
	/* `qdisc = "fq_codel"`, the shorthand for a scheduler that needs no
	 * parameters -- which is all of them except `cake`. */
	{
		char *name = ncfg_as_string(ctx, assignment->value);
		int   kind;

		free(device->qdisc);
		device->qdisc = NULL;
		if (!name) {
			return;
		}
		if (ncfg_qdisc_kind(ctx, name, assignment->span, &kind)) {
			device->qdisc = calloc(1, sizeof(*device->qdisc));
			if (!device->qdisc) {
				ncfg_lower_oom(ctx);
			} else {
				device->qdisc->kind = kind;
			}
		}
		free(name);
	}
}

int ncfg_lower_device(ncfg_lower_ctx_t *ctx, const ncfg_merged_block_t *block,
    ncfg_device_t *out)
{
	ncfg_device_t device;
	size_t        i;

	memset(&device, 0, sizeof(device));
	device.name = ncfg_require_interface_label(ctx, block->block);
	if (!device.name) {
		return 0;
	}
	device.managed = 1;
	device.on_unmanage = NCFG_ON_UNMANAGE_LEAVE;
	device.kind.kind = NCFG_KIND_PHYSICAL;

	for (i = 0; i < block->item_count; i++) {
		const ncfg_ast_item_t *item = block->items[i].item;

		ctx->source = block->items[i].source;
		if (item->kind == NCFG_AST_ITEM_ASSIGNMENT) {
			const ncfg_ast_assignment_t *assignment = &item->as.assignment;
			const char                  *key = assignment->key;
			int                          flag;

			if (strcmp(key, "managed") == 0) {
				if (ncfg_as_bool(ctx, assignment->value, &flag)) {
					device.managed = flag;
				}
			} else if (strcmp(key, "on_unmanage") == 0) {
				char *name = ncfg_as_string(ctx, assignment->value);

				if (!name) {
					continue;
				}
				if (strcmp(name, "leave") == 0) {
					device.on_unmanage = NCFG_ON_UNMANAGE_LEAVE;
				} else if (strcmp(name, "clear") == 0) {
					device.on_unmanage = NCFG_ON_UNMANAGE_CLEAR;
				} else {
					ncfg_diag(ctx, assignment->span,
					    "`%s` is not an `on_unmanage` policy: `leave` walks away and "
					    "changes nothing, which is what you want when handing an interface "
					    "to another daemon. `clear` removes everything netcfgd owns first, "
					    "which is what you want when the hardware is leaving your hands",
					    name);
				}
				free(name);
			} else if (is_structural_key(key)) {
				lower_structural_key(ctx, &device, assignment);
			} else if (strcmp(key, "mtu") == 0) {
				ncfg_as_u32_opt(ctx, assignment->value, &device.mtu);
			} else if (strcmp(key, "mac") == 0) {
				free(device.mac);
				device.mac = ncfg_as_string(ctx, assignment->value);
			} else {
				ncfg_diag(ctx, assignment->span, "unknown device key `%s`", key);
			}
			continue;
		}
		if (item->kind == NCFG_AST_ITEM_HOOK) {
			ncfg_diag(ctx, item->as.hook.span, "hooks belong to an interface, not to a device");
			continue;
		}
		if (item->kind == NCFG_AST_ITEM_INCLUDE) {
			ncfg_diag(ctx, item->as.include.span, "include was not resolved before compiling");
			continue;
		}
		if (item->kind != NCFG_AST_ITEM_BLOCK) {
			continue;
		}
		{
			const ncfg_ast_block_t *inner = &item->as.block;
			const char             *head = inner->head;

			if (ncfg_is_kind_block(head)) {
				ncfg_interface_kind_t kind;

				memset(&kind, 0, sizeof(kind));
				if (ncfg_lower_kind_block(ctx, inner, &kind)) {
					device.kind = kind;
				}
			} else if (strcmp(head, "qdisc") == 0) {
				ncfg_qdisc_policy_t policy;

				free(device.qdisc);
				device.qdisc = NULL;
				if (!ncfg_lower_qdisc(ctx, inner, &policy)) {
					continue;
				}
				device.qdisc = calloc(1, sizeof(*device.qdisc));
				if (!device.qdisc) {
					ncfg_lower_oom(ctx);
				} else {
					*device.qdisc = policy;
				}
			} else if (strcmp(head, "ethtool") == 0) {
				ncfg_link_settings_t settings;

				memset(&settings, 0, sizeof(settings));
				lower_ethtool(ctx, inner, &settings);
				if (link_settings_empty(&settings)) {
					free(settings.duplex);
					free(settings.wol);
					continue;
				}
				if (!device.link_settings) {
					device.link_settings = calloc(1, sizeof(*device.link_settings));
				}
				if (!device.link_settings) {
					ncfg_lower_oom(ctx);
					free(settings.duplex);
					free(settings.wol);
				} else {
					free(device.link_settings->duplex);
					free(device.link_settings->wol);
					*device.link_settings = settings;
				}
			} else if (strcmp(head, "wifi") == 0) {
				if (!device.wifi) {
					device.wifi = calloc(1, sizeof(*device.wifi));
				}
				if (!device.wifi) {
					ncfg_lower_oom(ctx);
					continue;
				}
				lower_wifi_device(ctx, inner, device.wifi);
			} else if (strcmp(head, "modem") == 0) {
				if (!device.modem) {
					device.modem = calloc(1, sizeof(*device.modem));
				}
				if (!device.modem) {
					ncfg_lower_oom(ctx);
					continue;
				}
				lower_modem(ctx, inner, device.modem);
			} else {
				ncfg_diag(ctx, inner->span, "`%s` is not valid inside `device`", head);
			}
		}
	}

	*out = device;
	return 1;
}
