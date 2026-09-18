/*
 * lower.c -- turning what was written into what it means.
 *
 * The walk over the merged blocks, the three passes that can only run once
 * every block has been read, and the pipeline `ncfg_compile` is.
 *
 * **Every diagnostic here can point at the text that caused it**, which is why
 * the AST carries spans rather than being lowered as it is parsed. The three
 * end passes are the exception worth naming: a bridge's member, a linkset's
 * member and the device an ingress shaper needs may each be declared later in
 * the file, or in a drop-in that has not been reached yet, so they are checked
 * afterwards -- against the span of the block that mentioned them, never the
 * top of a file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lower_internal.h"

#include "ncfg/base.h"
#include "ncfg/value.h"

/*
 * The longest interface name the kernel will take.
 *
 * `IFNAMSIZ` is 16 including the terminator, so 15 characters.
 */
#define IFNAMSIZ_MAX 15

/*
 * How far a linkset may reach through other linksets before this gives up.
 *
 * The cycle walk terminates on its own -- a name already on the path is the
 * cycle it is looking for -- so the depth is bounded by the number of distinct
 * sets. That is a bound on paper and not one on this stack: nothing limits how
 * many blocks a file may have, and a configuration is something an unprivileged
 * edit can produce on a daemon that re-reads its directory whenever anything in
 * it changes. Sixty-four is far past any real composition of link groups.
 */
#define LINKSET_CHAIN_MAX 64

/* Where a block was, for the checks that run after every block has been
 * read. Three passes need the same three fields, so they share one. */
typedef struct {
	char       *name;
	char       *other;
	ncfg_span_t span;
	const char *source;
} deferred_t;

static void deferred_free(deferred_t *list, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		free(list[i].name);
		free(list[i].other);
	}
	free(list);
}

/* ------------------------------------------------------------------------ *
 * The refusing hook sink
 * ------------------------------------------------------------------------ */

static int refuse_hook(void *state, int phase, const char *owner, const char *body,
    size_t body_length, ncfg_hook_ref_t *out, char *err, size_t err_size)
{
	(void)state;
	(void)phase;
	(void)owner;
	(void)body;
	(void)body_length;
	(void)out;
	ncfg_error_set(err, err_size, "this caller cannot accept hooks");
	return 0;
}

const ncfg_hook_sink_t *ncfg_hook_sink_refusing(void)
{
	static const ncfg_hook_sink_t sink = { refuse_hook, NULL };

	return &sink;
}

/* ------------------------------------------------------------------------ *
 * Looking things up in a half-built document
 * ------------------------------------------------------------------------ */

/*
 * Whether the document already declares something by this name.
 *
 * **Devices as well as interfaces.** 0155 pass 1a made `device` the block that
 * declares a link, so a check that read only `interfaces` could not see the
 * spelling an operator now reaches for.
 */
static int declares(const ncfg_document_t *document, const char *name)
{
	size_t i;

	for (i = 0; i < document->interface_count; i++) {
		if (strcmp(document->interfaces[i].name, name) == 0) {
			return 1;
		}
	}
	for (i = 0; i < document->device_count; i++) {
		if (strcmp(document->devices[i].name, name) == 0) {
			return 1;
		}
	}
	return 0;
}

static const ncfg_linkset_t *find_linkset(const ncfg_document_t *document, const char *name)
{
	size_t i;

	for (i = 0; i < document->linkset_count; i++) {
		if (strcmp(document->linksets[i].name, name) == 0) {
			return &document->linksets[i];
		}
	}
	return NULL;
}

/* Whether a linkset member names something this document describes. */
static int resolves(const ncfg_document_t *document, const char *name)
{
	size_t i;

	if (declares(document, name)) {
		return 1;
	}
	for (i = 0; i < document->network_count; i++) {
		if (strcmp(document->networks[i].id, name) == 0) {
			return 1;
		}
	}
	return find_linkset(document, name) != NULL;
}

/* A fresh device with the defaults an unwritten one gets. */
static ncfg_device_t *push_device(ncfg_lower_ctx_t *ctx, const char *name)
{
	ncfg_device_t *device = ncfg_push(ctx, &ctx->document->devices, &ctx->document->device_count,
	    sizeof(*ctx->document->devices));

	if (!device) {
		return NULL;
	}
	device->name = ncfg_dup(ctx, name);
	device->managed = 1;
	device->on_unmanage = NCFG_ON_UNMANAGE_LEAVE;
	device->kind.kind = NCFG_KIND_PHYSICAL;
	return device;
}

/* ------------------------------------------------------------------------ *
 * Membership
 * ------------------------------------------------------------------------ */

/*
 * Turn `bridge { members = ... }` into `master` on each member.
 *
 * Membership can be written from either end -- the master listing its members
 * or a member naming its master -- and the model holds only the second, since
 * that is the direction the kernel works in and the direction the planner
 * reads. Before this existed the `members` list was accepted and ignored: a
 * bridge would be created empty and the apply would report success, which is
 * the worst way for a feature to be missing.
 */
static void expand_members(ncfg_lower_ctx_t *ctx, const deferred_t *memberships, size_t count)
{
	ncfg_document_t *document = ctx->document;
	size_t           i;
	size_t           at;

	for (i = 0; i < count; i++) {
		const char    *member = memberships[i].name;
		const char    *master = memberships[i].other;
		ncfg_device_t *existing = NULL;

		ctx->source = memberships[i].source;
		if (strcmp(member, master) == 0) {
			ncfg_diag(ctx, memberships[i].span, "`%s` lists itself as a member", master);
			continue;
		}
		for (at = 0; at < document->device_count; at++) {
			if (strcmp(document->devices[at].name, member) == 0) {
				existing = &document->devices[at];
				break;
			}
		}
		if (existing) {
			if (!existing->master) {
				existing->master = ncfg_dup(ctx, master);
			} else if (strcmp(existing->master, master) != 0) {
				/* Said twice, differently. One of them is wrong and guessing
				 * which would put an interface in the wrong bridge. Said twice
				 * consistently is harmless, and common in a config assembled
				 * from drop-ins. */
				ncfg_diag(ctx, memberships[i].span,
				    "`%s` is listed as a member of `%s` but has `master = \"%s\"`: a device "
				    "has one master; remove one of the two", member, master,
				    existing->master);
			}
			continue;
		}
		/*
		 * A member with no `device` block of its own. Creating one is what
		 * makes `bridge { members = "eth0 eth1" }` work on its own, which is
		 * the shape design section 3.2 uses and the shape somebody converting
		 * from another tool will write.
		 *
		 * A device rather than an interface since 0155 pass 1b: a bridge port
		 * has no address of its own, so what a member needs is exactly the
		 * device half.
		 */
		{
			ncfg_device_t *fresh = push_device(ctx, member);

			if (fresh) {
				fresh->master = ncfg_dup(ctx, master);
			}
		}
	}
}

/* ------------------------------------------------------------------------ *
 * Ingress shaping
 * ------------------------------------------------------------------------ */

/*
 * Turn `ingress_bandwidth` into an `ifb` device plus a redirect.
 *
 * The kernel cannot queue traffic on the way in, because by the time it can be
 * classified it has already arrived. The standard answer -- and the only one
 * -- is to redirect it onto an intermediate device, where it becomes egress
 * and can be shaped like anything else.
 *
 * Synthesised here rather than built at apply time so that the whole thing is
 * in the document: `ncfg plan` names the device it will create, teardown goes
 * through the ordinary link machinery, and nothing in the executor has to know
 * that an `ifb` is special.
 */
static void expand_ingress_shapers(ncfg_lower_ctx_t *ctx, const deferred_t *shapers, size_t count)
{
	ncfg_document_t *document = ctx->document;
	size_t           i;
	size_t           at;

	for (i = 0; i < count; i++) {
		const char *name = shapers[i].name;
		char        device[IFNAMSIZ_MAX + 8];
		int64_t     rate = 0;
		int         found = 0;

		ctx->source = shapers[i].source;
		(void)snprintf(device, sizeof(device), "ifb-%s", name);
		if (strlen(device) > (size_t)IFNAMSIZ_MAX) {
			ncfg_diag(ctx, shapers[i].span,
			    "`%s` is too long a name to shape arriving traffic on: ingress shaping needs "
			    "a device called `%s`, and the kernel allows %d characters; rename the "
			    "interface to %d or fewer", name, device, IFNAMSIZ_MAX,
			    IFNAMSIZ_MAX - (int)strlen("ifb-"));
			continue;
		}
		/*
		 * A name collision means the operator already has something called
		 * `ifb-something`. Refused rather than merged: netcfgd would otherwise
		 * take over a device somebody else declared.
		 *
		 * **Devices as well as interfaces**, and the device half was missing.
		 * The collision was still caught, by the generic duplicate-device
		 * check, which tells them "duplicate device entry: ifb-e0" about a
		 * device they wrote exactly once and says nothing about the ingress
		 * shaping that needs the name. The whole point of this check is the
		 * sentence, so a check that fires only for the retired spelling is a
		 * sentence nobody gets.
		 */
		if (declares(document, device)) {
			ncfg_diag(ctx, shapers[i].span,
			    "`%s` is declared, and ingress shaping on `%s` needs to create a device of "
			    "that name", device, name);
			continue;
		}
		for (at = 0; at < document->device_count; at++) {
			ncfg_device_t *shaped = &document->devices[at];

			if (strcmp(shaped->name, name) != 0) {
				continue;
			}
			free(shaped->ingress_redirect);
			shaped->ingress_redirect = ncfg_dup(ctx, device);
			if (shaped->qdisc && shaped->qdisc->ingress_bandwidth_bits.has) {
				rate = shaped->qdisc->ingress_bandwidth_bits.value;
				shaped->qdisc->ingress_bandwidth_bits.has = 0;
				shaped->qdisc->ingress_bandwidth_bits.value = 0;
				found = 1;
			}
			break;
		}
		if (!found) {
			continue;
		}
		/*
		 * **A device with no interface, which is the state 0155 predicted.**
		 * An `ifb` carries no address and never will: it exists to have
		 * traffic redirected onto it so the egress qdisc can shape what
		 * arrived. Before pass 1b it had to be an interface because that was
		 * the only type that could say `kind`, and it carried eleven fields of
		 * absence to say so.
		 */
		{
			ncfg_device_t *ifb = push_device(ctx, device);

			if (!ifb) {
				continue;
			}
			ifb->kind.kind = NCFG_KIND_IFB;
			ifb->qdisc = calloc(1, sizeof(*ifb->qdisc));
			if (!ifb->qdisc) {
				ncfg_lower_oom(ctx);
				continue;
			}
			ifb->qdisc->kind = NCFG_QDISC_CAKE;
			ifb->qdisc->bandwidth_bits.has = 1;
			ifb->qdisc->bandwidth_bits.value = rate;
			ifb->qdisc->ingress = 1;
		}
	}

	/*
	 * **Every interface names hardware, so every interface gets a device.** An
	 * operator who wrote only `interface eth0 { config = "dhcp" }` has said
	 * nothing about the adapter, and the honest reading of that is a physical
	 * device with defaults -- not the absence of one. Without this the device
	 * walks skip such an interface entirely, and the walks are where creation,
	 * enslavement and the "no such device" warning live since 0155 pass 1b.
	 *
	 * Synthesised rather than required, because requiring a `device` block for
	 * every interface would make the common configuration twice as long to say
	 * the same thing.
	 */
	for (i = 0; i < document->interface_count; i++) {
		const char *name = document->interfaces[i].name;
		int         named = 0;

		for (at = 0; at < document->device_count; at++) {
			if (strcmp(document->devices[at].name, name) == 0) {
				named = 1;
				break;
			}
		}
		if (!named) {
			(void)push_device(ctx, name);
		}
	}
}

/* ------------------------------------------------------------------------ *
 * Linksets
 * ------------------------------------------------------------------------ */

/*
 * The chain by which a set reaches itself, or 0 where it does not.
 *
 * Depth-first with the path carried, so the diagnostic can print the way round:
 * "uplink -> office -> uplink" is a fix somebody can act on and "there is a
 * cycle" is not.
 */
static int linkset_cycle(const ncfg_document_t *document, const char *name,
    const char **path, size_t depth, ncfg_buf_t *chain)
{
	const ncfg_linkset_t *set;
	size_t                at;
	size_t                i;

	for (at = 0; at < depth; at++) {
		if (strcmp(path[at], name) != 0) {
			continue;
		}
		for (i = at; i < depth; i++) {
			ncfg_buf_add_text(chain, path[i]);
			ncfg_buf_add_text(chain, " -> ");
		}
		ncfg_buf_add_text(chain, name);
		return 1;
	}
	set = find_linkset(document, name);
	if (!set || depth >= LINKSET_CHAIN_MAX) {
		return 0;
	}
	path[depth] = name;
	for (i = 0; i < set->member_count; i++) {
		if (linkset_cycle(document, set->members[i], path, depth + 1u, chain)) {
			return 1;
		}
	}
	return 0;
}

/*
 * The linkset checks that need the whole document.
 *
 * Three things, none of which can be seen from one block: a member that
 * resolves to nothing, a set that shares a name with a link, and a set that
 * contains itself through a chain of other sets.
 */
static void check_linksets(ncfg_lower_ctx_t *ctx, const deferred_t *spans, size_t count)
{
	const ncfg_document_t *document = ctx->document;
	size_t                 i;
	size_t                 at;

	for (i = 0; i < count; i++) {
		const char           *name = spans[i].name;
		const ncfg_linkset_t *set = find_linkset(document, name);
		const char           *path[LINKSET_CHAIN_MAX];
		ncfg_buf_t            chain;

		ctx->source = spans[i].source;
		if (!set) {
			continue;
		}
		/* **A set with no members is refused.** It can choose nothing, so it
		 * is either a block somebody started and did not finish or one whose
		 * members were removed elsewhere -- and as `uplink` it would answer
		 * "disconnected" for ever with nothing saying why. */
		if (set->member_count == 0) {
			ncfg_diag(ctx, spans[i].span,
			    "`%s` has no members: a linkset chooses between links, so it needs some",
			    name);
		}
		/* A set called `eth0` beside an interface called `eth0` cannot be
		 * referred to: every reference is by name, and a member naming that
		 * would mean two things at once. */
		if (declares(document, name)) {
			ncfg_diag(ctx, spans[i].span,
			    "`%s` is already the name of a link on this machine: a linkset is referred "
			    "to by name, so it needs one of its own", name);
		} else {
			for (at = 0; at < document->network_count; at++) {
				if (strcmp(document->networks[at].id, name) != 0) {
					continue;
				}
				ncfg_diag(ctx, spans[i].span,
				    "`%s` is already the name of a link on this machine: a linkset is "
				    "referred to by name, so it needs one of its own", name);
				break;
			}
		}
		for (at = 0; at < set->member_count; at++) {
			if (resolves(document, set->members[at])) {
				continue;
			}
			ncfg_diag(ctx, spans[i].span,
			    "`%s` lists `%s`, which this configuration does not describe: a member is an "
			    "interface, a device, a `network` block or another linkset, by name", name,
			    set->members[at]);
		}

		ncfg_buf_init(&chain, 0);
		if (linkset_cycle(document, name, path, 0, &chain) && !ncfg_buf_failed(&chain)) {
			ncfg_diag(ctx, spans[i].span,
			    "`%s` contains itself: %s: a linkset may contain another, but not one that "
			    "contains it back", name, ncfg_buf_text(&chain));
		}
		ncfg_buf_free(&chain);
	}
}

/* ------------------------------------------------------------------------ *
 * The walk
 * ------------------------------------------------------------------------ */

static int remember(ncfg_lower_ctx_t *ctx, deferred_t **list, size_t *count, const char *name,
    const char *other, ncfg_span_t span, const char *source)
{
	deferred_t *slot = ncfg_push(ctx, list, count, sizeof(*slot));

	if (!slot) {
		return 0;
	}
	slot->name = ncfg_dup(ctx, name);
	slot->other = other ? ncfg_dup(ctx, other) : NULL;
	slot->span = span;
	slot->source = source;
	return 1;
}

ncfg_document_t *ncfg_lower(const ncfg_merged_t *merged, const ncfg_hook_sink_t *hooks,
    ncfg_lower_diags_t *diags, char *err, size_t err_size)
{
	return ncfg_lower_with_provenance(merged, hooks, NULL, diags, err, err_size);
}

ncfg_document_t *ncfg_lower_with_provenance(const ncfg_merged_t *merged,
    const ncfg_hook_sink_t *hooks, ncfg_provenance_t *provenance, ncfg_lower_diags_t *diags,
    char *err, size_t err_size)
{
	ncfg_lower_ctx_t ctx;
	/* `(member, master, where the master's block is)`, so a conflict points at
	 * the line that declared the membership rather than at the top of a
	 * file. */
	deferred_t      *memberships = NULL;
	size_t           membership_count = 0;
	/* Each interface asking to shape arriving traffic. Collected here rather
	 * than found later because the expansion can fail -- on a name too long
	 * for the kernel -- and a diagnostic pointing at the top of the file would
	 * be useless. */
	deferred_t      *shapers = NULL;
	size_t           shaper_count = 0;
	/* Each linkset, for the checks that can only run once every block has been
	 * read. */
	deferred_t      *linksets = NULL;
	size_t           linkset_count = 0;
	size_t           i;

	memset(&ctx, 0, sizeof(ctx));
	ctx.diags = diags;
	ctx.hooks = hooks ? hooks : ncfg_hook_sink_refusing();
	ctx.provenance = provenance;
	ctx.document = ncfg_document_new(err, err_size);
	if (!ctx.document) {
		ncfg_provenance_free(provenance);
		return NULL;
	}

	for (i = 0; i < merged->assignment_count; i++) {
		ctx.source = merged->assignments[i].source;
		ncfg_lower_global_key(&ctx, merged->assignments[i].assignment);
	}

	for (i = 0; i < merged->block_count; i++) {
		const ncfg_merged_block_t *block = &merged->blocks[i];
		const char                *head = block->block->head;

		ctx.source = block->source;
		if (strcmp(head, "global") == 0) {
			ncfg_lower_global_block(&ctx, block);
		} else if (strcmp(head, "device") == 0) {
			ncfg_device_t device;

			if (!ncfg_lower_device(&ctx, block, &device)) {
				continue;
			}
			/* Membership and ingress shaping are read off the device now: both
			 * follow from `kind` and `qdisc`, which 0155 pass 1b moved
			 * here. */
			{
				char *const *members = NULL;
				size_t       member_count = 0;
				size_t       at;

				if (device.kind.kind == NCFG_KIND_BRIDGE) {
					members = device.kind.bridge.members;
					member_count = device.kind.bridge.member_count;
				} else if (device.kind.kind == NCFG_KIND_BOND) {
					members = device.kind.bond.members;
					member_count = device.kind.bond.member_count;
				}
				for (at = 0; at < member_count; at++) {
					(void)remember(&ctx, &memberships, &membership_count, members[at],
					    device.name, block->block->span, block->source);
				}
			}
			if (device.qdisc && device.qdisc->ingress_bandwidth_bits.has) {
				(void)remember(&ctx, &shapers, &shaper_count, device.name, NULL,
				    block->block->span, block->source);
			}
			{
				ncfg_device_t *slot = ncfg_push(&ctx, &ctx.document->devices,
				    &ctx.document->device_count, sizeof(*slot));

				if (slot) {
					*slot = device;
				}
			}
		} else if (strcmp(head, "bluetooth") == 0) {
			ncfg_bluetooth_device_t device;

			if (!ncfg_lower_bluetooth(&ctx, block, &device)) {
				continue;
			}
			{
				ncfg_bluetooth_device_t *slot = ncfg_push(&ctx, &ctx.document->bluetooth,
				    &ctx.document->bluetooth_count, sizeof(*slot));

				if (slot) {
					*slot = device;
				}
			}
		} else if (strcmp(head, "interface") == 0) {
			ncfg_interface_t interface;

			if (!ncfg_lower_interface(&ctx, block, &interface)) {
				continue;
			}
			/* `block->source` rather than `ctx.source`, which the walk over the
			 * block's items has just moved: see `ncfg_record`. */
			ncfg_record(&ctx, block->source, block->block->span, "interfaces[%s]",
			    interface.name);
			{
				ncfg_interface_t *slot = ncfg_push(&ctx, &ctx.document->interfaces,
				    &ctx.document->interface_count, sizeof(*slot));

				if (slot) {
					*slot = interface;
				}
			}
		} else if (strcmp(head, "rule") == 0) {
			ncfg_routing_rule_t rule;

			if (!ncfg_lower_rule(&ctx, block, &rule)) {
				continue;
			}
			ncfg_record(&ctx, block->source, block->block->span, "rule.%s", rule.id);
			{
				ncfg_routing_rule_t *slot = ncfg_push(&ctx, &ctx.document->rules,
				    &ctx.document->rule_count, sizeof(*slot));

				if (slot) {
					*slot = rule;
				}
			}
		} else if (strcmp(head, "access_point") == 0) {
			ncfg_access_point_t access_point;

			if (!ncfg_lower_access_point(&ctx, block, &access_point)) {
				continue;
			}
			ncfg_record(&ctx, block->source, block->block->span, "access_point.%s",
			    access_point.id);
			{
				ncfg_access_point_t *slot = ncfg_push(&ctx, &ctx.document->access_points,
				    &ctx.document->access_point_count, sizeof(*slot));

				if (slot) {
					*slot = access_point;
				}
			}
		} else if (strcmp(head, "network") == 0) {
			ncfg_wifi_network_t network;

			if (!ncfg_lower_network(&ctx, block, &network)) {
				continue;
			}
			ncfg_record(&ctx, block->source, block->block->span, "network.%s", network.id);
			{
				ncfg_wifi_network_t *slot = ncfg_push(&ctx, &ctx.document->networks,
				    &ctx.document->network_count, sizeof(*slot));

				if (slot) {
					*slot = network;
				}
			}
		} else if (strcmp(head, "linkset") == 0) {
			ncfg_linkset_t set;

			if (!ncfg_lower_linkset(&ctx, block, &set)) {
				continue;
			}
			ncfg_record(&ctx, block->source, block->block->span, "linkset.%s", set.name);
			/* Checked after the loop rather than here: a member may name a
			 * block that has not been read yet, and refusing a forward
			 * reference would make the answer depend on which drop-in the
			 * loader happened to open first. */
			(void)remember(&ctx, &linksets, &linkset_count, set.name, NULL,
			    block->block->span, block->source);
			{
				ncfg_linkset_t *slot = ncfg_push(&ctx, &ctx.document->linksets,
				    &ctx.document->linkset_count, sizeof(*slot));

				if (slot) {
					*slot = set;
				} else {
					ncfg_strings_free(set.members, set.member_count);
					free(set.name);
				}
			}
		} else {
			ncfg_diag(&ctx, block->block->span,
			    "unknown top-level block `%s`: the top-level blocks are interface, network, "
			    "device, rule, linkset, access_point and global", head);
		}
	}

	expand_members(&ctx, memberships, membership_count);
	expand_ingress_shapers(&ctx, shapers, shaper_count);
	check_linksets(&ctx, linksets, linkset_count);

	deferred_free(memberships, membership_count);
	deferred_free(shapers, shaper_count);
	deferred_free(linksets, linkset_count);

	/*
	 * A table for a document nobody gets is a table of paths into nothing, so
	 * either failure empties it. It is the caller's own structure and it is
	 * left usable rather than merely emptied -- `ncfg_provenance_free` is
	 * `base.h`'s one-free-per-aggregate, and freeing one never filled in is
	 * nothing.
	 */
	if (ctx.failed) {
		ncfg_document_free(ctx.document);
		ncfg_provenance_free(provenance);
		ncfg_error_set(err, err_size, "out of memory compiling the configuration");
		return NULL;
	}
	if (ncfg_diags_any(&ctx)) {
		ncfg_document_free(ctx.document);
		ncfg_provenance_free(provenance);
		ncfg_error_set(err, err_size, "%s",
		    (diags && diags->count) ? diags->at[0].message : "the configuration was refused");
		return NULL;
	}
	return ctx.document;
}

/* ------------------------------------------------------------------------ *
 * The pipeline
 * ------------------------------------------------------------------------ */

ncfg_document_t *ncfg_compile(const ncfg_source_t *sources, size_t count,
    const ncfg_hook_sink_t *hooks, ncfg_lower_diags_t *diags, char *err, size_t err_size)
{
	return ncfg_compile_with_provenance(sources, count, hooks, NULL, diags, err, err_size);
}

ncfg_document_t *ncfg_compile_with_provenance(const ncfg_source_t *sources, size_t count,
    const ncfg_hook_sink_t *hooks, ncfg_provenance_t *provenance, ncfg_lower_diags_t *diags,
    char *err, size_t err_size)
{
	ncfg_lower_diags_t  local = { 0 };
	ncfg_lower_diags_t *kept = diags ? diags : &local;
	ncfg_merged_t      *merged = NULL;
	ncfg_document_t    *document;
	size_t              i;

	if (!ncfg_merge(sources, count, &merged, kept, err, err_size)) {
		ncfg_provenance_free(provenance);
		ncfg_lower_diags_free(&local);
		return NULL;
	}
	document = ncfg_lower_with_provenance(merged, hooks, provenance, kept, err, err_size);
	ncfg_merged_free(merged);
	if (!document) {
		ncfg_lower_diags_free(&local);
		return NULL;
	}
	/*
	 * Ordered by path with the first record for a path kept, which is what
	 * makes two compiles of one configuration produce one `provenance.json` --
	 * the whole reason the positions are a side table rather than fields of
	 * the document. Canonicalising the table before the document, as the Rust
	 * does, because the two are independent: the document's own walk sorts
	 * interfaces, routes and members, and touches neither an addressing list
	 * nor anything a key is built from.
	 */
	if (provenance && !ncfg_provenance_canonicalize(provenance, err, err_size)) {
		ncfg_provenance_free(provenance);
		ncfg_document_free(document);
		ncfg_lower_diags_free(&local);
		return NULL;
	}

	/*
	 * A host-wide "no networking" is applied here rather than by the planner,
	 * so that `ncfg show` and `ncfg plan` say what netcfgd actually wants. A
	 * planner rule would leave the document describing a configuration that
	 * something downstream quietly ignores, which is the shape of every
	 * "netcfgd says it is configured and the machine is not" report.
	 *
	 * It exists because a profile cannot say "every interface on this machine,
	 * down": the language has no wildcard, so it would have to name them, and
	 * the names differ per machine. One host-wide key says it once.
	 */
	if (document->globals.networking == NCFG_NETWORKING_OFF) {
		for (i = 0; i < document->interface_count; i++) {
			document->interfaces[i].enabled = 0;
		}
	}

	/*
	 * Canonicalise before validating so that a diagnostic about, say, a
	 * duplicate interface names the same entry every time regardless of which
	 * drop-in file introduced it.
	 */
	ncfg_document_canonicalize(document);
	if (!ncfg_document_validate(document, err, err_size)) {
		ncfg_lower_ctx_t ctx;
		ncfg_span_t      start;

		/* The document's own sentence, carried as a diagnostic so that one
		 * caller sees one kind of failure. It has no line to point at: the
		 * invariants it checks are about the document as a whole, and the
		 * first line of the first file is the least misleading place to say
		 * so. */
		memset(&ctx, 0, sizeof(ctx));
		memset(&start, 0, sizeof(start));
		start.line = 1;
		start.column = 1;
		ctx.diags = kept;
		ctx.source = count ? sources[0].name : NULL;
		ncfg_diag(&ctx, start, "%s", err);
		ncfg_document_free(document);
		ncfg_provenance_free(provenance);
		ncfg_lower_diags_free(&local);
		return NULL;
	}
	ncfg_lower_diags_free(&local);
	return document;
}
