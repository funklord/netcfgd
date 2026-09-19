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
 * The kernel's own feature names, per model field, are `document.h`'s.
 *
 * They lived here while the planner was the only caller, above a comment
 * saying the second caller would take this table rather than write its own.
 * `src/observe/offloads.c` is that caller -- it fills
 * `ncfg_observed_link_t.offloads` with exactly these strings, which is what
 * `held_on` below reads back -- so the table moved to the model, where
 * `ncfg_bond_mode_number`'s paragraph already says why a numbering two modules
 * must agree on belongs there. Nothing in this file names a feature any more.
 */

/*
 * Whether a `link.set_offloads` could move this feature at all.
 *
 * The device holds some regardless of what it is asked for -- `ethtool -k`
 * prints them `[fixed]` -- and `observed.h` says how the observation knows.
 * Planning one of those is an action that must fail, on every pass, for ever:
 * the executor writes the request, the kernel keeps what it had, the next
 * observation reports the same thing and the planner asks again. That is the
 * convergence failure 10.194 records and this is the guard that closes it.
 */
static int is_fixed(const ncfg_observed_link_t *link, const char *name)
{
	size_t i;

	if (!link) {
		return 0;
	}
	for (i = 0; i < link->offloads_fixed_count; i++) {
		if (link->offloads_fixed[i] && strcmp(link->offloads_fixed[i], name) == 0) {
			return 1;
		}
	}
	return 0;
}

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
 * Say which half of an `ethtool` block is applied by nothing, and whose gap it
 * is.
 *
 * Field by field rather than as one sentence, and only where the document
 * states the field: the offloads beside them *are* applied, and telling an
 * operator who wrote `gro = true` that their block is ignored would be false.
 *
 * **It used to end "not applied by this build", which is a promise nobody
 * checked.** Settled against `crates/` the way 10.180 settled the last three:
 * `crates/netcfgd-plan/src/lib.rs:714` is this same warning, field for field
 * and almost word for word, and the encoder it is waiting on does not exist on
 * either side -- `crates/netcfgd-sys/src/ethtool.rs` defines
 * `ETHTOOL_MSG_FEATURES_GET` and `..._SET` and no other message at all, which
 * is exactly what `ethtool.h` here carries. So an operator was being told to
 * wait for a release, and the reason in the same sentence says why there will
 * not be one until somebody can write to a real NIC. `warn_unbuilt` is what
 * says that difference, and having it in one place is what stops this sentence
 * going stale again.
 */
static void warn_unapplied(ncfg_builder_t *builder, const ncfg_device_t *device)
{
	const ncfg_link_settings_t *settings = device->link_settings;
	const char                 *stated[6];
	size_t                      count = 0;
	ncfg_buf_t                  buf;
	ncfg_buf_t                  block;
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
	/*
	 * **The whole of it has to arrive**, and this one has no room to spare:
	 * `ncfg_plan_warnf` formats into `NCFG_ERROR_MAX` and marks what it had to
	 * cut, and all six fields plus `warn_unbuilt`'s tail is 481 of 512
	 * characters. Nothing here varies -- the six names are literals and the
	 * device is the warning's interface rather than part of the sentence -- so
	 * that number is the worst case rather than a sample, and
	 * `plan_gaps_test.c` asserts the last words of it.
	 */
	ncfg_buf_init(&block, 0);
	ncfg_buf_addf(&block,
	    "`%s` in the `ethtool` block %s recognised and applied by nothing: %s can "
	    "only be exercised against a physical NIC, and an encoder nobody has run "
	    "against one is how the last three netlink bugs here got in. The offloads are "
	    "applied",
	    ncfg_buf_text(&buf), count == 1u ? "is" : "are", count == 1u ? "it" : "they");
	ncfg_plan_warn_unbuilt(builder, device->name, ncfg_buf_text(&block));
	ncfg_buf_free(&block);
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

		for (i = 0; i < NCFG_OFFLOAD_FIELD_COUNT; i++) {
			size_t named = 0;

			(void)ncfg_offload_field_names((int)i, &named);
			room += named;
		}
		wanted = calloc(room, sizeof(*wanted));
		inverse_features = calloc(room, sizeof(*inverse_features));
		if (!wanted || !inverse_features) {
			free(wanted);
			free(inverse_features);
			builder->plan->failed = 1;
			return;
		}

		for (i = 0; i < NCFG_OFFLOAD_FIELD_COUNT; i++) {
			const char *const *names;
			size_t             named = 0;
			int                toggle = ncfg_link_settings_offload(settings, (int)i);
			int                on;
			int                held = 0;

			if (toggle == NCFG_TOGGLE_UNMANAGED) {
				continue;
			}
			names = ncfg_offload_field_names((int)i, &named);
			if (!names) {
				continue;
			}
			on = toggle == NCFG_TOGGLE_ON;
			/* "On" for a field covering several kernel features means any of
			 * them; "off" means all of them. */
			for (j = 0; j < named; j++) {
				if (held_on(link, names[j])) {
					held = 1;
				}
			}
			if (link && held == on) {
				continue;
			}
			/*
			 * **The ones the device will not move are left out, by name.**
			 * Per kernel feature rather than per field, because a field can
			 * cover several and a device commonly fixes one of them: `lo`
			 * holds `rx-checksum` and `tx-checksum-ip-generic` whatever it is
			 * asked, and dropping the whole `checksum` field over that would
			 * stop netcfgd setting the ones it can.
			 */
			for (j = 0; j < named; j++) {
				if (is_fixed(link, names[j])) {
					ncfg_plan_warnf(builder->plan, device->name,
					    "%s holds `%s` %s whatever it is asked, so netcfgd is "
					    "not asking: the device reports it as fixed, and a "
					    "`link.set_offloads` for it would fail on every pass "
					    "for ever", device->name, names[j],
					    held_on(link, names[j]) ? "on" : "off");
					continue;
				}
				wanted[count].name = names[j];
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
