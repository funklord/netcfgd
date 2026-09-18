/*
 * offload.c -- the `ethtool` block: the offloads, and a sentence for the rest.
 *
 * WHY ONLY THE OFFLOADS
 *   The model also carries ring sizes, link modes and wake-on-LAN, and those
 *   are not applied. The reason is verification rather than effort: a veth
 *   takes a features message and refuses a link-modes set with a bare
 *   `EINVAL`, while ring and wake-on-LAN messages are `EOPNOTSUPP` on anything
 *   that is not a physical NIC. Every netlink defect this project has shipped
 *   was found by writing to a real kernel and reading it back, so what can
 *   only be exercised against hardware the suite cannot safely write to stays
 *   unimplemented -- and stays *named*, field by field rather than as one
 *   blanket sentence. An operator who set only `gro` should not be told their
 *   configuration is ignored.
 *
 * ONE MODEL FIELD IS SEVERAL KERNEL FEATURES
 *   `tx_checksum` is three, because a driver offers whichever its hardware
 *   has. So "on" for such a field means **any** of them and "off" means
 *   **all** of them, which is what `ethtool -K dev tx on|off` does.
 *
 * THE LINK MAY NOT EXIST YET
 *   This is the first apply and the device is about to be created, so nothing
 *   is known about its offloads: every named one is planned and the action
 *   waits on the creation. Skipping instead is what made a fresh apply leave
 *   the offloads at the driver default and need a second run.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <stdlib.h>
#include <string.h>

/*
 * The kernel's own feature names, per model field.
 *
 * **This belongs beside the model** -- it is `netcfgd_model::interface::
 * offload_names`, and the reader that has to agree with this writer is the
 * observer's `read_offloads`, which fills `ncfg_observed_link_t.offloads` with
 * exactly these strings. That seam is not implemented in this build, so the
 * planner is the only caller and the table is here rather than in a header
 * nothing else includes yet. **The second caller takes this one** rather than
 * writing its own: two lists of feature names in two places is how a feature
 * comes to be turned on under one spelling and read back under another.
 *
 * The names rather than the kernel's bit indices, which are not stable across
 * versions and are not a wire contract; `ethtool.h` says why at length.
 */
static const char *const offload_gro[] = { "rx-gro" };
static const char *const offload_gso[] = { "tx-generic-segmentation" };
static const char *const offload_tso[] = { "tx-tcp-segmentation" };
static const char *const offload_rx_checksum[] = { "rx-checksum" };
static const char *const offload_tx_checksum[] = { "tx-checksum-ip-generic",
	"tx-checksum-ipv4", "tx-checksum-ipv6" };

typedef struct {
	int                       toggle; /* ncfg_toggle_t */
	const char *const        *names;
	size_t                    name_count;
} ncfg_offload_field_t;

#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

/* Whether one kernel feature name is currently on. */
static int held_on(const ncfg_observed_link_t *link, const char *name)
{
	size_t i;

	if (!link) {
		return 0;
	}
	for (i = 0; i < link->offload_count; i++) {
		if (link->offloads[i] && strcmp(link->offloads[i], name) == 0) {
			return 1;
		}
	}
	return 0;
}

static int compare_features(const void *left, const void *right)
{
	const ncfg_offload_t *a = left;
	const ncfg_offload_t *b = right;
	int                   by_name = strcmp(a->name, b->name);

	if (by_name != 0) {
		return by_name;
	}
	return a->wanted - b->wanted;
}

/* `rx-gro=true tx-checksum-ipv4=false`, which is what a reason line shows. */
static const char *describe(ncfg_plan_t *plan, const ncfg_offload_t *features, size_t count)
{
	ncfg_buf_t  buf;
	const char *text;
	size_t      i;

	ncfg_buf_init(&buf, 0);
	for (i = 0; i < count; i++) {
		ncfg_buf_addf(&buf, "%s%s=%s", i ? " " : "", features[i].name,
		    features[i].wanted ? "true" : "false");
	}
	text = ncfg_plan_intern(plan, ncfg_buf_text(&buf));
	ncfg_buf_free(&buf);
	return text ? text : "<absent>";
}

/*
 * Say which half of an `ethtool` block is recognised and not applied.
 *
 * Field by field rather than as one sentence, and only where the document
 * states the field: the offloads beside them *are* applied, and telling an
 * operator who wrote `gro = true` that their block is ignored would be false.
 */
static void warn_unapplied(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	const ncfg_link_settings_t *settings = device->link_settings;
	const char                 *stated[6];
	size_t                      count = 0;
	ncfg_buf_t                  buf;
	size_t                      i;

	if (settings->autoneg != NCFG_TOGGLE_UNMANAGED) {
		stated[count++] = "autoneg";
	}
	if (settings->speed.has) {
		stated[count++] = "speed";
	}
	if (settings->duplex) {
		stated[count++] = "duplex";
	}
	if (settings->wol) {
		stated[count++] = "wol";
	}
	if (settings->rx_ring.has) {
		stated[count++] = "rx_ring";
	}
	if (settings->tx_ring.has) {
		stated[count++] = "tx_ring";
	}
	if (count == 0u) {
		return;
	}
	ncfg_buf_init(&buf, 0);
	for (i = 0; i < count; i++) {
		ncfg_buf_addf(&buf, "%s%s", i ? "`, `" : "", stated[i]);
	}
	ncfg_plan_warnf(builder->plan, device->name,
	    "`%s` in the ethtool block are recognised but not applied by this build. They "
	    "can only be exercised against a physical NIC, and an encoder nobody has run "
	    "against one is how the last three netlink bugs here got in. The offloads are "
	    "applied.",
	    ncfg_buf_text(&buf));
	ncfg_buf_free(&buf);
}

/*
 * The offloads on every device whose `ethtool` block names one.
 *
 * **Devices, not interfaces**: an offload belongs to the adapter, so a device
 * with no `interface` block still gets its offloads.
 */
void ncfg_plan_offloads(ncfg_builder_t *builder)
{
	size_t at;

	for (at = 0; at < builder->desired->device_count; at++) {
		const ncfg_device_t        *device = &builder->desired->devices[at];
		const ncfg_link_settings_t *settings = device->link_settings;
		const ncfg_observed_link_t *link;
		ncfg_offload_field_t        fields[5];
		ncfg_offload_t             *wanted;
		ncfg_offload_t             *inverse_features;
		ncfg_plan_ids_t             gate = { NULL, 0, 0 };
		ncfg_op_t                   op;
		ncfg_op_t                   inverse;
		ncfg_reason_t               reason;
		size_t                      room = 0;
		size_t                      count = 0;
		size_t                      i;
		size_t                      j;

		if (!settings) {
			continue;
		}
		warn_unapplied(builder, device);
		link = ncfg_observed_link(builder->observed, device->name);

		fields[0].toggle = settings->gro;
		fields[0].names = offload_gro;
		fields[0].name_count = COUNT(offload_gro);
		fields[1].toggle = settings->gso;
		fields[1].names = offload_gso;
		fields[1].name_count = COUNT(offload_gso);
		fields[2].toggle = settings->tso;
		fields[2].names = offload_tso;
		fields[2].name_count = COUNT(offload_tso);
		fields[3].toggle = settings->rx_checksum;
		fields[3].names = offload_rx_checksum;
		fields[3].name_count = COUNT(offload_rx_checksum);
		fields[4].toggle = settings->tx_checksum;
		fields[4].names = offload_tx_checksum;
		fields[4].name_count = COUNT(offload_tx_checksum);

		for (i = 0; i < COUNT(fields); i++) {
			room += fields[i].name_count;
		}
		wanted = calloc(room, sizeof(*wanted));
		inverse_features = calloc(room, sizeof(*inverse_features));
		if (!wanted || !inverse_features) {
			free(wanted);
			free(inverse_features);
			builder->plan->failed = 1;
			return;
		}

		for (i = 0; i < COUNT(fields); i++) {
			int on;
			int held = 0;

			if (fields[i].toggle == NCFG_TOGGLE_UNMANAGED) {
				continue;
			}
			on = fields[i].toggle == NCFG_TOGGLE_ON;
			/* "On" for a field covering several kernel features means any of
			 * them; "off" means all of them. */
			for (j = 0; j < fields[i].name_count; j++) {
				if (held_on(link, fields[i].names[j])) {
					held = 1;
				}
			}
			if (link && held == on) {
				continue;
			}
			for (j = 0; j < fields[i].name_count; j++) {
				wanted[count].name = fields[i].names[j];
				wanted[count].wanted = on;
				count++;
			}
		}
		if (count == 0u) {
			free(wanted);
			free(inverse_features);
			continue;
		}
		qsort(wanted, count, sizeof(*wanted), compare_features);
		for (i = 0; i < count; i++) {
			inverse_features[i].name = wanted[i].name;
			inverse_features[i].wanted = held_on(link, wanted[i].name);
		}

		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_SET_OFFLOADS;
		op.u.set_offloads.name = device->name;
		op.u.set_offloads.features = wanted;
		op.u.set_offloads.feature_count = count;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_LINK_SET_OFFLOADS;
		inverse.u.set_offloads.name = device->name;
		inverse.u.set_offloads.features = inverse_features;
		inverse.u.set_offloads.feature_count = count;
		reason = ncfg_plan_reason_differs(device->name, "ethtool",
		    describe(builder->plan, wanted, count),
		    describe(builder->plan, inverse_features, count));
		ncfg_builder_gate(builder, device->name, &gate);
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, &inverse);
		ncfg_plan_ids_free(&gate);
		/* `ncfg_plan_add` copies the feature list into the plan's arena, so
		 * these two are the caller's to give back -- the same bargain every
		 * string an op names is under. */
		free(wanted);
		free(inverse_features);
	}
}
