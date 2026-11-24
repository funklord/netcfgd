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

#include <stdio.h>
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
 * convergence failure 10.225 records and this is the guard that closes it.
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

/* ------------------------------------------------------------------------ *
 * Link modes
 * ------------------------------------------------------------------------ */

static const char *describe_modes(ncfg_plan_t *plan, int autoneg, int64_t speed, int duplex)
{
	ncfg_buf_t  buf;
	const char *text;

	ncfg_buf_init(&buf, 0);
	ncfg_buf_addf(&buf, "autoneg=%s", autoneg < 0 ? "?" : autoneg ? "on" : "off");
	if (speed > 0) {
		ncfg_buf_addf(&buf, " speed=%lld", (long long)speed);
	}
	if (duplex >= 0) {
		ncfg_buf_addf(&buf, " duplex=%s", duplex ? "full" : "half");
	}
	text = ncfg_plan_intern(plan, ncfg_buf_text(&buf));
	ncfg_buf_free(&buf);
	return text ? text : "<absent>";
}

/*
 * `link.set_link_modes` for every device whose `ethtool` block states
 * `autoneg`, `speed` or `duplex` and whose link says otherwise.
 *
 * **What is compared depends on what is wanted.** With autonegotiation off,
 * speed and duplex are the setting, and they are compared. With it on, the
 * speed and duplex the kernel reports are what the two ends agreed, not what
 * was asked -- comparing them would plan a set on every pass for a link that
 * negotiated something else -- so only `autoneg` itself is compared, and any
 * speed or duplex stated beside it rides along with that change.
 *
 * **A link with no carrier cannot say its speed**, and that is the case
 * netrescue's forcing rungs meet (0326): `observe.h`'s record of what was last
 * forced stands in for the kernel's answer then, and is overruled by it the
 * moment there is a carrier. A link that answers nothing at all -- no ethtool
 * link modes, most virtual devices -- is warned about rather than planned
 * for, since the set would fail on every pass.
 */
void ncfg_plan_link_modes(ncfg_builder_t *builder)
{
	size_t at;

	for (at = 0; at < builder->desired->device_count; at++) {
		const ncfg_device_t        *device = &builder->desired->devices[at];
		const ncfg_link_settings_t *settings = device->link_settings;
		const ncfg_observed_link_t *link;
		ncfg_plan_ids_t             gate = { NULL, 0, 0 };
		ncfg_op_t                   op;
		ncfg_op_t                   inverse;
		ncfg_reason_t               reason;
		int                         want_autoneg, want_duplex, have_duplex;
		int64_t                     want_speed;
		int                         differs = 0;

		if (!settings || (settings->autoneg == NCFG_TOGGLE_UNMANAGED && !settings->speed.has &&
		    !settings->duplex)) {
			continue;
		}
		link = ncfg_observed_link(builder->observed, device->name);
		if (!link) {
			continue;
		}
		if (!link->autoneg.has) {
			ncfg_plan_warnf(builder->plan, device->name,
			    "%s does not report autonegotiation, speed or duplex, so netcfgd "
			    "sets none of them: most virtual devices have no link modes", device->name);
			continue;
		}
		want_autoneg = settings->autoneg == NCFG_TOGGLE_UNMANAGED ? -1 :
		    settings->autoneg == NCFG_TOGGLE_ON ? 1 : 0;
		want_speed = settings->speed.has ? settings->speed.value : 0;
		want_duplex = !settings->duplex ? -1 : strcmp(settings->duplex, "full") == 0 ? 1 : 0;
		have_duplex = !link->duplex ? -1 : strcmp(link->duplex, "full") == 0 ? 1 : 0;

		if (want_autoneg >= 0 && want_autoneg != link->autoneg.value) {
			differs = 1;
		}
		/* Speed and duplex are the setting only where the link does not
		 * negotiate, which is what it is about to be or already is. */
		if (want_autoneg == 0 || (want_autoneg < 0 && !link->autoneg.value)) {
			if (want_speed > 0 && (!link->speed.has || link->speed.value != want_speed)) {
				differs = 1;
			}
			if (want_duplex >= 0 && have_duplex != want_duplex) {
				differs = 1;
			}
		}
		if (!differs) {
			continue;
		}

		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_SET_LINK_MODES;
		op.u.set_link_modes.name = device->name;
		op.u.set_link_modes.autoneg = want_autoneg;
		op.u.set_link_modes.speed = (uint32_t)want_speed;
		op.u.set_link_modes.duplex = want_duplex;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_LINK_SET_LINK_MODES;
		inverse.u.set_link_modes.name = device->name;
		inverse.u.set_link_modes.autoneg = link->autoneg.value ? 1 : 0;
		/* Back to negotiating needs nothing more; back to a forced mode
		 * needs the mode, where it was known. */
		inverse.u.set_link_modes.speed =
		    !link->autoneg.value && link->speed.has ? (uint32_t)link->speed.value : 0u;
		inverse.u.set_link_modes.duplex = !link->autoneg.value ? have_duplex : -1;
		reason = ncfg_plan_reason_differs(device->name, "ethtool",
		    describe_modes(builder->plan, want_autoneg, want_speed, want_duplex),
		    describe_modes(builder->plan, link->autoneg.value,
		        link->speed.has ? link->speed.value : 0, have_duplex));
		ncfg_builder_gate(builder, device->name, &gate);
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, &inverse);
		ncfg_plan_ids_free(&gate);
	}
}

/* ------------------------------------------------------------------------ *
 * Ring sizes
 * ------------------------------------------------------------------------ */

/*
 * `link.set_rings` for every device whose `ethtool` block states `rx_ring` or
 * `tx_ring` and whose link says another. A size past the maximum the device
 * reports is warned about and not asked for: the driver would refuse it on
 * every pass. A link that reports no rings is warned about rather than
 * planned for, as a link with no link modes is.
 */
void ncfg_plan_rings(ncfg_builder_t *builder)
{
	size_t at;

	for (at = 0; at < builder->desired->device_count; at++) {
		const ncfg_device_t        *device = &builder->desired->devices[at];
		const ncfg_link_settings_t *settings = device->link_settings;
		const ncfg_observed_link_t *link;
		ncfg_plan_ids_t             gate = { NULL, 0, 0 };
		ncfg_op_t                   op;
		ncfg_op_t                   inverse;
		ncfg_reason_t               reason;
		uint32_t                    rx = 0, tx = 0;
		char                        wanted[64], had[64];

		if (!settings || (!settings->rx_ring.has && !settings->tx_ring.has)) {
			continue;
		}
		link = ncfg_observed_link(builder->observed, device->name);
		if (!link) {
			continue;
		}
		if (!link->rx_ring.has || !link->tx_ring.has) {
			ncfg_plan_warnf(builder->plan, device->name,
			    "%s does not report its ring sizes, so netcfgd sets neither: most "
			    "virtual devices have no rings to size", device->name);
			continue;
		}
		if (settings->rx_ring.has && settings->rx_ring.value != link->rx_ring.value) {
			if (link->rx_ring_max.has && settings->rx_ring.value > link->rx_ring_max.value) {
				ncfg_plan_warnf(builder->plan, device->name,
				    "%s's receive ring can be at most %lld, so `rx_ring = %lld` is not "
				    "asked for", device->name, (long long)link->rx_ring_max.value,
				    (long long)settings->rx_ring.value);
			} else {
				rx = (uint32_t)settings->rx_ring.value;
			}
		}
		if (settings->tx_ring.has && settings->tx_ring.value != link->tx_ring.value) {
			if (link->tx_ring_max.has && settings->tx_ring.value > link->tx_ring_max.value) {
				ncfg_plan_warnf(builder->plan, device->name,
				    "%s's transmit ring can be at most %lld, so `tx_ring = %lld` is not "
				    "asked for", device->name, (long long)link->tx_ring_max.value,
				    (long long)settings->tx_ring.value);
			} else {
				tx = (uint32_t)settings->tx_ring.value;
			}
		}
		if (rx == 0u && tx == 0u) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_SET_RINGS;
		op.u.set_rings.name = device->name;
		op.u.set_rings.rx = rx;
		op.u.set_rings.tx = tx;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_LINK_SET_RINGS;
		inverse.u.set_rings.name = device->name;
		inverse.u.set_rings.rx = rx != 0u ? (uint32_t)link->rx_ring.value : 0u;
		inverse.u.set_rings.tx = tx != 0u ? (uint32_t)link->tx_ring.value : 0u;
		(void)snprintf(wanted, sizeof(wanted), "rx=%lld tx=%lld",
		    (long long)(rx ? rx : (uint32_t)link->rx_ring.value),
		    (long long)(tx ? tx : (uint32_t)link->tx_ring.value));
		(void)snprintf(had, sizeof(had), "rx=%lld tx=%lld", (long long)link->rx_ring.value,
		    (long long)link->tx_ring.value);
		reason = ncfg_plan_reason_differs(device->name, "ethtool",
		    ncfg_plan_intern(builder->plan, wanted), ncfg_plan_intern(builder->plan, had));
		ncfg_builder_gate(builder, device->name, &gate);
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, &inverse);
		ncfg_plan_ids_free(&gate);
	}
}

/* ------------------------------------------------------------------------ *
 * Wake-on-LAN
 * ------------------------------------------------------------------------ */

/*
 * `link.set_wol` for every device whose `ethtool` block states `wol` and
 * whose link has other modes on (10.917). Only the managed six are compared,
 * so a `magicsecure` somebody else set is neither undone nor a difference on
 * every pass. A mode the device does not support is warned about and the
 * set not asked for, since the driver would refuse it every time; a device
 * that reports no modes is warned about too, unless the document asks for
 * none -- `off` on a device that cannot wake is already true.
 */
void ncfg_plan_wol(ncfg_builder_t *builder)
{
	size_t at;

	for (at = 0; at < builder->desired->device_count; at++) {
		const ncfg_device_t        *device = &builder->desired->devices[at];
		const ncfg_link_settings_t *settings = device->link_settings;
		const ncfg_observed_link_t *link;
		ncfg_plan_ids_t             gate = { NULL, 0, 0 };
		ncfg_op_t                   op;
		ncfg_op_t                   inverse;
		ncfg_reason_t               reason;
		uint32_t                    wanted;
		uint32_t                    had;
		char                        wanted_text[16];
		char                        had_text[16];

		if (!settings || !settings->wol || !ncfg_wol_modes(settings->wol, &wanted)) {
			continue;
		}
		link = ncfg_observed_link(builder->observed, device->name);
		if (!link) {
			continue;
		}
		if (!link->wol.has || !link->wol_supported.has) {
			if (wanted != 0u) {
				ncfg_plan_warnf(builder->plan, device->name,
				    "%s reports no wake-on-LAN modes, so `wol = \"%s\"` is not asked for: "
				    "no virtual device can wake a machine", device->name, settings->wol);
			}
			continue;
		}
		if (wanted & ~(uint32_t)link->wol_supported.value) {
			ncfg_wol_text((uint32_t)link->wol_supported.value & NCFG_WOL_MANAGED, had_text,
			    sizeof(had_text));
			ncfg_plan_warnf(builder->plan, device->name,
			    "%s can wake on `%s` only, so `wol = \"%s\"` is not asked for",
			    device->name, had_text, settings->wol);
			continue;
		}
		had = (uint32_t)link->wol.value & NCFG_WOL_MANAGED;
		if (had == wanted) {
			continue;
		}
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_LINK_SET_WOL;
		op.u.set_wol.name = device->name;
		op.u.set_wol.modes = wanted;
		memset(&inverse, 0, sizeof(inverse));
		inverse.kind = NCFG_OP_LINK_SET_WOL;
		inverse.u.set_wol.name = device->name;
		inverse.u.set_wol.modes = had;
		ncfg_wol_text(wanted, wanted_text, sizeof(wanted_text));
		ncfg_wol_text(had, had_text, sizeof(had_text));
		reason = ncfg_plan_reason_differs(device->name, "wol",
		    ncfg_plan_intern(builder->plan, wanted_text),
		    ncfg_plan_intern(builder->plan, had_text));
		ncfg_builder_gate(builder, device->name, &gate);
		(void)ncfg_builder_push(builder, &op, &reason, gate.ids, gate.count, &inverse);
		ncfg_plan_ids_free(&gate);
	}
}
