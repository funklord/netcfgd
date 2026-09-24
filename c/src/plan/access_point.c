/*
 * access_point.c -- the hostapd a radio runs: started as the interface's
 * prerequisite, restarted when what it was started with stops matching the
 * document, and stopped when no block asks for it any more.
 *
 * WHY THIS IS A PREREQUISITE AND NOT A LATE PASS
 *   `dot1x.c`'s shape, and the Rust plans the two from one function for that
 *   reason: an 802.1X port that has not authenticated, a radio that is not
 *   running its access point, a radio that has not associated and a PPP
 *   interface that does not exist are four spellings of "there is nothing here
 *   to address yet", and all four belong in the same place in the order.
 *
 *   Here the cost of getting it backwards is the interface's own addresses.
 *   hostapd puts the radio into AP mode through nl80211, which is a mode
 *   change on a link the kernel will only take while it is down -- so an
 *   address added first is an address that may not be there afterwards, and
 *   the plan would have reported it applied. `plan.h` says the action list is
 *   itself a valid execution order, so "before the addressing" has to mean
 *   *earlier in the list*, which is what makes the call site the thing that
 *   decides it: `ncfg_plan_interface_contents` emits this between `link.up`
 *   and the addressing, and `build.c`'s sequence -- which runs after the whole
 *   interface walk -- could not.
 *
 * WHY THE TEARDOWN'S RULE LIVES HERE TOO
 *   `dot1x.c`'s reason, unchanged: the conditions that start a backend and the
 *   conditions that keep one have to stay the same, and a rule in two files is
 *   one that eventually disagrees with itself. Wrong in the permissive
 *   direction leaves an access point nobody owns; wrong in the other direction
 *   is netcfgd starting hostapd and killing it on every reconcile, for ever.
 *
 *   The start has one condition the teardown does not, and it is deliberate.
 *   An interface carrying a `dot1x` block takes the supplicant arm and no
 *   other -- the Rust returns at the first prerequisite it finds -- so an
 *   interface that somehow carries both never starts an access point. The
 *   teardown does not repeat that: it is the permissive direction, and an
 *   access point this build declined to start is not one to stop.
 *
 * WHY A RESTART AND NOT A RELOAD
 *   There is no reload to plan. hostapd reads its file once, at startup
 *   (0026), and `backend_ops.c` refuses `backend.reload` for every kind but
 *   the router advertisement daemon in as many words -- "an access point's
 *   would be a restart" -- because a reload that stops and starts hides a
 *   deauthenticated LAN behind a gentle word. So the plan says stop and start,
 *   and the warning beside it says what that costs.
 *
 * WHAT IS COMPARED, AND WHY IT IS NOT THE FILE
 *   hostapd reports almost nothing back: `GET_CONFIG` gives the SSID and the
 *   ciphers and says nothing about the channel, the band or the regulatory
 *   domain. So the only account of what a running access point is offering is
 *   netcfgd's own record of what it started -- `started_with`, in the model's
 *   vocabulary rather than hostapd's -- and every comparison below is the
 *   document against that record.
 *
 *   **Each one compares the value that would be written, never the value as
 *   the document states it.** An absent `channel` is `channel=0` in the file,
 *   an absent `band` is whatever the channel implies, and a `regdom` is
 *   uppercased on the way out. Comparing any of those as written is true on
 *   every pass, and a plan that restarts an access point on every reconcile is
 *   a permanent deauthentication loop for a document nobody has touched --
 *   which the Rust records having shipped, twice, from both directions (0222).
 *   That is why `ncfg_access_point_effective_band` and `ncfg_security_key_mgmt`
 *   are called rather than reimplemented: one rule with two implementations is
 *   the same loop with a longer fuse.
 */
#include "plan_internal.h"

#include "ncfg/base.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------------ *
 * The prerequisite, and whether a running one is still asked for
 * ------------------------------------------------------------------------ */

int ncfg_plan_access_point_wanted(const ncfg_document_t *desired, const char *name)
{
	size_t i;

	if (!name) {
		return 0;
	}
	/*
	 * The document still naming an access point on this device. **Not "this
	 * device is a radio"**: a radio whose `access_point` block was deleted is
	 * exactly the case that has to stop hostapd, and the radio is still a
	 * radio.
	 */
	for (i = 0; i < desired->access_point_count; i++) {
		if (desired->access_points[i].device &&
		    strcmp(desired->access_points[i].device, name) == 0) {
			return 1;
		}
	}
	return 0;
}

void ncfg_plan_access_point(ncfg_builder_t *builder, const ncfg_interface_t *interface,
    const ncfg_plan_ids_t *base, ncfg_plan_ids_t *out)
{
	/* One prerequisite per interface, the supplicant first. See the header. */
	if (interface->dot1x) {
		return;
	}
	if (!ncfg_plan_access_point_wanted(builder->desired, interface->name)) {
		return;
	}
	/*
	 * Through the same function a DHCP client is started by, which is what
	 * carries 0079's restart limit and rule 3's wait for `link.up` here
	 * without a second copy of either. A radio hostapd is already running on
	 * is left alone: the identity comparison below is what notices a running
	 * one holding something else, and it is the *only* thing that may, because
	 * an access point cannot be handed anything while it runs.
	 */
	ncfg_plan_backend(builder, interface->name, NCFG_BACKEND_ACCESS_POINT, "access_point",
	    base, out);
}

/*
 * An access point on a device the document does not declare an interface for.
 *
 * **This is what the blanket sentence that used to stand here narrowed to.**
 * That one said no access point was started, configured or restarted at all,
 * and this file makes it untrue; what survives is the one arrangement in which
 * nothing still happens, and it is silent otherwise. hostapd is started as an
 * interface's prerequisite and an interface that is not in the document is
 * never passed over, so an `access_point` naming a device with no `interface`
 * block produces an empty plan and no explanation -- which is the failure a
 * warning pass exists to prevent, arrived at by deleting a warning.
 */
/*
 * A radio carrying more than one access point, where only the first runs.
 *
 * **One BSS per radio is what this build does.** Both halves at once needs a
 * second virtual interface on the phy, which netcfgd does not create -- so the
 * second `access_point` block naming a device is read, kept, and never
 * started, and the plan that starts the first looks exactly like a plan that
 * did everything asked of it.
 *
 * Said once, by the block that *is* started, and naming the ones that are not:
 * a sentence per ignored block would tell an operator with three of them the
 * same thing three times without ever saying which one won.
 */
static void warn_second_access_point(ncfg_builder_t *builder,
    const ncfg_access_point_t *point)
{
	ncfg_buf_t ignored;
	size_t     count = 0;
	size_t     i;

	if (!point->device) {
		return;
	}
	ncfg_buf_init(&ignored, 0);
	for (i = 0; i < builder->desired->access_point_count; i++) {
		const ncfg_access_point_t *other = &builder->desired->access_points[i];

		if (!other->device || strcmp(other->device, point->device) != 0) {
			continue;
		}
		/* The first block on this device is the one that runs, and anything
		 * before this one in the list means this is not it. */
		if (other == point) {
			break;
		}
		ncfg_buf_free(&ignored);
		return;
	}
	for (i = 0; i < builder->desired->access_point_count; i++) {
		const ncfg_access_point_t *other = &builder->desired->access_points[i];

		if (other == point || !other->device ||
		    strcmp(other->device, point->device) != 0) {
			continue;
		}
		ncfg_buf_addf(&ignored, "%s%s", count ? "`, `" : "", other->id);
		count++;
	}
	if (count != 0u) {
		ncfg_plan_warnf(builder->plan, point->device,
		    "`%s` has more than one access point and this build runs one BSS per "
		    "radio, so `%s` is started and `%s` %s not",
		    point->device, point->id, ncfg_buf_text(&ignored),
		    count == 1u ? "is" : "are");
	}
	ncfg_buf_free(&ignored);
}

/*
 * Whether this device's address comes from somewhere other than its own
 * `interface` block.
 *
 * A bridged access point is the ordinary way to put wireless clients on the
 * wired subnet: the address belongs to the bridge and the radio has none, and
 * it is working correctly. The Rust's own comment records that the warning
 * below fired on exactly that arrangement when it was first written, calling
 * the right answer broken -- "a true statement about one interface offered as
 * a verdict on the whole" (0202).
 *
 * Both spellings, because a document may name members from the bridge or a
 * master from the member and the two mean the same thing.
 */
static int address_is_somewhere_else(const ncfg_document_t *desired, const char *device)
{
	size_t i;
	size_t at;

	for (i = 0; i < desired->device_count; i++) {
		const ncfg_device_t *other = &desired->devices[i];

		if (other->name && strcmp(other->name, device) == 0 && other->master) {
			return 1;
		}
		if (other->kind.kind != NCFG_KIND_BRIDGE) {
			continue;
		}
		for (at = 0; at < other->kind.bridge.member_count; at++) {
			const char *member = other->kind.bridge.members[at];

			if (member && strcmp(member, device) == 0) {
				return 1;
			}
		}
	}
	return 0;
}

/*
 * An access point on an interface with no address.
 *
 * **hostapd running is not an access point working.** The warning above says
 * `interface wlan0 { }` is enough, and it is -- enough to bring the radio up
 * and start hostapd. Following it exactly gives a beaconing SSID a station
 * can associate with and then nothing on this end to talk to, because netcfgd
 * serves no DHCP either. So an address here is necessary and not sufficient,
 * and the sentence says both halves.
 *
 * Only where there IS an `interface` block: with none, the warning above is
 * the one to read, and two warnings about the same missing thing is one of
 * them being noise.
 */
static void warn_no_address(ncfg_builder_t *builder, const ncfg_access_point_t *point)
{
	const ncfg_interface_t *interface = ncfg_plan_interface(builder->desired, point->device);

	if (!interface || interface->addressing_count > 0u) {
		return;
	}
	if (address_is_somewhere_else(builder->desired, point->device)) {
		return;
	}
	ncfg_plan_warnf(builder->plan, point->device,
	    "access point `%s` runs on `%s`, which has no address: a station can associate "
	    "and then has nothing here to talk to. netcfgd runs hostapd and serves no DHCP, "
	    "so give the interface an address -- `interface %s { config = \"192.168.4.1/24\" "
	    "}` -- and run a DHCP server on it, or expect every station to be configured by "
	    "hand",
	    point->id, point->device, point->device);
}

/*
 * An `allow` list with nothing in it.
 *
 * A legitimate thing to write -- it is how an access point is closed without
 * taking it down -- and an easy thing to arrive at by deleting the last
 * station from a list. It compiles either way, because a compile diagnostic
 * is a failure and this is not one, so the difference between the two is said
 * here rather than refused there.
 */
static void warn_empty_allow(ncfg_builder_t *builder, const ncfg_access_point_t *point)
{
	if (!point->access_control || point->access_control->policy != NCFG_ACL_POLICY_ALLOW ||
	    point->access_control->station_count > 0u) {
		return;
	}
	ncfg_plan_warnf(builder->plan, point->device,
	    "access point `%s` has an empty `allow` list, so no station can associate with "
	    "it at all. Remove the `access_control` block to let everyone in",
	    point->id);
}

void ncfg_plan_access_point_warn(ncfg_builder_t *builder)
{
	size_t i;

	for (i = 0; i < builder->desired->access_point_count; i++) {
		const ncfg_access_point_t *point = &builder->desired->access_points[i];

		if (!point->device || ncfg_plan_interface(builder->desired, point->device)) {
			continue;
		}
		ncfg_plan_warnf(builder->plan, point->device,
		    "access point `%s` runs on `%s`, which has no `interface` block, so nothing "
		    "brings the radio up and nothing starts hostapd on it. Adding "
		    "`interface %s { }` is enough",
		    point->id, point->device, point->device);
	}
	for (i = 0; i < builder->desired->access_point_count; i++) {
		const ncfg_access_point_t *point = &builder->desired->access_points[i];

		/*
		 * **A silent access point that is working correctly.** A DFS channel
		 * has to be listened on before the radio may beacon, so hostapd comes
		 * up, says nothing for a minute or so, and only then appears in a
		 * scan. Every part of netcfgd reports success meanwhile, which is
		 * exactly when somebody starts looking for the fault.
		 */
		if (point->channel.has &&
		    ncfg_channel_needs_radar_detection(point->channel.value)) {
			ncfg_plan_warnf(builder->plan, point->device,
			    "access point `%s` is on channel %lld, which is shared with radar "
			    "in most regulatory domains: the radio has to listen on it before "
			    "it may beacon, so the access point will be silent for a minute or "
			    "so after this apply returns -- longer on some channels. Channels "
			    "36 to 48 and 149 upwards need no such wait",
			    point->id, (long long)point->channel.value);
		}
		warn_no_address(builder, point);
		warn_empty_allow(builder, point);
		warn_second_access_point(builder, point);
	}
}

/* ------------------------------------------------------------------------ *
 * The restart
 * ------------------------------------------------------------------------ */

/*
 * The stop and the start, as one pair with one reason.
 *
 * Answers whether the restart was planned at all. A guard can refuse the stop
 * and an unmanaged device drops it, and emitting the start on its own would
 * bring the access point up a *second* time rather than back up.
 */
static int restart(ncfg_builder_t *builder, const char *device, const ncfg_reason_t *reason)
{
	ncfg_op_t stop;
	ncfg_op_t start;
	uint32_t  id;

	memset(&stop, 0, sizeof(stop));
	stop.kind = NCFG_OP_BACKEND_STOP;
	stop.u.backend.kind = NCFG_BACKEND_ACCESS_POINT;
	stop.u.backend.iface = device;
	memset(&start, 0, sizeof(start));
	start.kind = NCFG_OP_BACKEND_START;
	start.u.backend.kind = NCFG_BACKEND_ACCESS_POINT;
	start.u.backend.iface = device;

	id = ncfg_builder_push(builder, &stop, reason, NULL, 0, &start);
	if (id == NCFG_PLAN_NO_ACTION) {
		return 0;
	}
	(void)ncfg_builder_push(builder, &start, reason, &id, 1u, &stop);
	return 1;
}

/* An SSID as the document writes it: lowercase hex, because 802.11 places no
 * encoding requirement on one and a name that is not text still has to reach a
 * reason line. `document.h` has the whole of the reason. */
static void ssid_hex(const ncfg_ssid_t *ssid, char *out, size_t out_size)
{
	static const char digits[] = "0123456789abcdef";
	size_t            at;

	for (at = 0u; at < ssid->length && (at * 2u) + 2u < out_size; at++) {
		out[at * 2u] = digits[ssid->bytes[at] >> 4];
		out[(at * 2u) + 1u] = digits[ssid->bytes[at] & 0x0fu];
	}
	out[at * 2u] = '\0';
}

/* A channel as the operator would read it back, never a bare `0`: absent and
 * zero are one statement to hostapd and two different things to say. */
static void channel_text(const ncfg_optint_t *channel, char *out, size_t out_size)
{
	if (!channel->has) {
		(void)snprintf(out, out_size, "<absent>");
		return;
	}
	(void)snprintf(out, out_size, "%lld", (long long)channel->value);
}

/* The regulatory domain as the renderer writes it, which is upper case. */
static void regdom_text(const char *regdom, char *out, size_t out_size)
{
	size_t at;

	if (!regdom) {
		(void)snprintf(out, out_size, "<absent>");
		return;
	}
	for (at = 0u; regdom[at] != '\0' && at + 1u < out_size; at++) {
		char letter = regdom[at];

		if (letter >= 'a' && letter <= 'z') {
			letter = (char)(letter - ('a' - 'A'));
		}
		out[at] = letter;
	}
	out[at] = '\0';
}

/* Two optional strings, where absent equals absent. */
static int same_text(const char *left, const char *right)
{
	if (!left || !right) {
		return left == right;
	}
	return strcmp(left, right) == 0;
}

int ncfg_plan_access_point_restart_identity(ncfg_builder_t *builder,
    const ncfg_access_point_t *point, const ncfg_observed_backend_t *running)
{
	const ncfg_observed_access_point_t *started = running->started_with;
	const char                         *device = point->device;
	const char                         *field;
	char                                desired[NCFG_SSID_MAX_LEN * 2u + 1u];
	char                                observed[NCFG_SSID_MAX_LEN * 2u + 1u];
	ncfg_reason_t                       reason;

	if (!started) {
		/*
		 * **Said rather than passed over, because the silence is the whole
		 * hazard.** With no record there is nothing to compare the document
		 * against, so an edited identity plans nothing and hostapd goes on
		 * offering what it was started with -- which looks exactly like a
		 * converged machine. The station lists are the one part of the block
		 * that can still be converged, because they are read back out of the
		 * running process rather than out of a record.
		 */
		ncfg_plan_warnf(builder->plan, device,
		    "netcfgd has no record of what the access point running on %s was started "
		    "with, so an edited `ssid`, `band`, `channel`, `security`, `hidden` or "
		    "`regdom` is not noticed and hostapd goes on offering what it has: its "
		    "station lists are the only part of the block that converges without being "
		    "restarted",
		    device);
		return 0;
	}

	if (started->ssid.length != point->ssid.length ||
	    memcmp(started->ssid.bytes, point->ssid.bytes, point->ssid.length) != 0) {
		field = "access_point.ssid";
		ssid_hex(&point->ssid, desired, sizeof(desired));
		ssid_hex(&started->ssid, observed, sizeof(observed));
	} else if ((point->channel.has ? point->channel.value : 0) !=
	    (started->channel.has ? started->channel.value : 0)) {
		/*
		 * **The number this build would write, against the number in the file
		 * it wrote.** An absent `channel` is hostapd's `channel=0` -- "survey
		 * and choose" -- so absent and `0` are one statement and compare
		 * equal, while absent against `36` is an operator who deleted the line
		 * to get automatic selection back and must not be left pinned to 36.
		 * The Rust shipped both halves of this wrong in turn (0222): comparing
		 * `None` against `Some(0)` restarted for ever, and the guard that
		 * silenced it silenced the real edit with it.
		 */
		field = "access_point.channel";
		channel_text(&point->channel, desired, sizeof(desired));
		channel_text(&started->channel, observed, sizeof(observed));
	} else if (!same_text(ncfg_access_point_effective_band(point->band, &point->channel),
	    started->band)) {
		/*
		 * Derived before comparing, for the reason the channel is. An absent
		 * `band` means "work it out from the channel" and the file records
		 * what was worked out, so comparing the two as written restarts an
		 * access point that never changed -- and guarding on the document
		 * having stated one leaves an operator who deleted `band = "5"` on 5
		 * GHz for ever with nothing in the plan to say so.
		 *
		 * **Rendered as the effective band as well, which the Rust does not
		 * do**: it compares the derived value and then prints the stated one,
		 * so deleting `band = "5"` produces a reason with an empty desired
		 * field. project.md records it.
		 */
		field = "access_point.band";
		(void)snprintf(desired, sizeof(desired), "%s",
		    ncfg_access_point_effective_band(point->band, &point->channel) ?
		    ncfg_access_point_effective_band(point->band, &point->channel) : "<absent>");
		(void)snprintf(observed, sizeof(observed), "%s",
		    started->band ? started->band : "<absent>");
	} else if (!same_text(ncfg_security_key_mgmt(&point->security), started->key_mgmt)) {
		/*
		 * **The generation, which nothing else notices changing.** hostapd
		 * reads its file once, so an access point started as WPA2 goes on
		 * offering WPA2 however the document is edited -- and the secret
		 * comparison below says nothing about it, because changing `proto`
		 * with the same passphrase changes no secret. A document that says
		 * WPA3 against a radio running WPA2 is the one disagreement here that
		 * costs more than a restart.
		 */
		field = "access_point.wifi.proto";
		(void)snprintf(desired, sizeof(desired), "%s",
		    ncfg_security_key_mgmt(&point->security) ?
		    ncfg_security_key_mgmt(&point->security) : "open");
		(void)snprintf(observed, sizeof(observed), "%s",
		    started->key_mgmt ? started->key_mgmt : "open");
	} else if ((started->hidden != 0) != (point->hidden != 0)) {
		/* `ignore_broadcast_ssid` is written only when asked, so its absence
		 * is "not hidden" rather than "not known" and needs no guard. */
		field = "access_point.hidden";
		(void)snprintf(desired, sizeof(desired), "%s", point->hidden ? "true" : "false");
		(void)snprintf(observed, sizeof(observed), "%s", started->hidden ? "true" : "false");
	} else if ((point->regdom || started->regdom) &&
	    !(point->regdom && started->regdom && strcasecmp(point->regdom, started->regdom) == 0)) {
		/* Compared case-insensitively and printed upper case, which is what
		 * the renderer writes: a document saying `se` against a file saying
		 * `SE` is the same access point, and comparing them as written is the
		 * channel arm's defect reached from another direction. */
		field = "access_point.regdom";
		regdom_text(point->regdom, desired, sizeof(desired));
		regdom_text(started->regdom, observed, sizeof(observed));
	} else if (running->secret_matches.has && !running->secret_matches.value) {
		/*
		 * The value is not here and must not be. What the observation carries
		 * is the answer, computed where both halves were already in hand
		 * (0052) -- so the reason names the field and says which way it went,
		 * and nothing in this plan can print a passphrase.
		 */
		field = "access_point.wifi.psk";
		(void)snprintf(desired, sizeof(desired), "the secret store's");
		(void)snprintf(observed, sizeof(observed), "what the access point was started with");
	} else {
		return 0;
	}

	ncfg_plan_warnf(builder->plan, device,
	    "%s changed, which hostapd only reads at startup, so the access point on %s is "
	    "restarted -- every station associated with it is deauthenticated and reconnects",
	    field, device);
	reason = ncfg_plan_reason_differs(device, field, desired, observed);
	return restart(builder, device, &reason);
}

void ncfg_plan_access_point_restart_policy(ncfg_builder_t *builder, const char *device,
    const ncfg_observed_policy_t *live, const ncfg_access_control_t *wanted)
{
	const char   *desired = wanted ? ncfg_plan_acl_policy_word(wanted->policy) : "<absent>";
	const char   *observed = live->kind == NCFG_OBSERVED_POLICY_SET ?
	    ncfg_plan_acl_policy_word(live->policy) : "<absent>";
	ncfg_reason_t reason;

	/*
	 * The one change to an `access_control` block that cannot be made in
	 * place, and it is unavoidable for a different reason from the identity
	 * above. `macaddr_acl` *is* settable over the control socket -- but
	 * nothing disassociates on the change and nothing reports it back, so
	 * netcfgd would be converging a value it could never confirm, and the
	 * failure mode is an open network reported as a closed one.
	 */
	ncfg_plan_warnf(builder->plan, device,
	    "the access control policy on %s changed, which hostapd only reads at startup, so "
	    "the access point is restarted -- every station associated with it is "
	    "deauthenticated and reconnects. Changing the stations in a list does not cost "
	    "this",
	    device);
	reason = ncfg_plan_reason_differs(device, "access_point.access_control.policy", desired,
	    observed);
	(void)restart(builder, device, &reason);
}
