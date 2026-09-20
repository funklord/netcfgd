/*
 * access_control.c -- what a running access point is admitting, and whether it
 * is answering at all.
 *
 * THREE ANSWERS OUT OF ONE ROUND TRIP
 *   This is the one observation pass that talks to a daemon rather than reading
 *   a file, and the connection it makes answers three things at once:
 *
 *     * **`answering`**, which is 0078's question and the reason the field
 *       exists apart from `running`. A wedged hostapd holds its socket, holds
 *       its pid, serves nobody, and answered `running: true` to everything
 *       netcfgd had until this. The round trip below already had to be made;
 *       what was missing was writing down that it succeeded.
 *     * **`access_control`**, the two lists hostapd is actually holding.
 *       **Both** lists, because the document names only one (0039) -- so the
 *       other has to be observed to notice it is not empty, which is the only
 *       way to see from outside that an operator flipped the policy under a
 *       running access point.
 *     * **`started_with`**, the access point as it was started, read back out
 *       of the configuration netcfgd generated. hostapd reads that file once,
 *       so an access point started as WPA2 goes on offering WPA2 however the
 *       document is edited, and nothing else notices.
 *
 * WHY A FAILED CONNECTION IS NOT SILENCE
 *   Everywhere else in this module an unreadable input leaves the field absent.
 *   Here a connection that fails is `answering: false` -- a **statement**,
 *   because the record says a daemon is running and the socket says otherwise,
 *   and the socket is closer to the truth. It is still not a statement about
 *   the *lists*: those stay absent, because "hostapd denies nobody" and
 *   "netcfgd could not ask" are different answers and only the first may be
 *   reconciled against.
 *
 * WHY THE POLICY COMES FROM A FILE AND THE LISTS FROM THE SOCKET
 *   `macaddr_acl` is not readable over the control interface -- hostapd exposes
 *   the lists and not which one it is enforcing -- so `ncfg_hostapd_acl_path`'s
 *   first line carries the record 0041 needs. The two halves are asked of the
 *   two places that have them, which is why `ncfg_hostapd_recorded_policy` has
 *   three answers rather than two.
 */
#include "ncfg/observe.h"

#include "observe_internal.h"

#include "ncfg/base.h"
#include "ncfg/hostapd.h"
#include "ncfg/supplicant.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The access point as it was started, out of the generated configuration.
 *
 * Every field is optional because the renderer omits what the document did not
 * ask for, and an absent line has to mean the same thing the document's
 * absence means or the two would never compare equal. `ignore_broadcast_ssid`
 * absent is "not hidden" rather than "not known"; `wpa_key_mgmt` absent is an
 * open network, which is the statement the document makes too.
 */
static ncfg_observed_access_point_t *started_with(const char *run_dir, const char *device)
{
	char                          path[NCFG_HOSTAPD_PATH_MAX];
	char                          value[256];
	char                         *text;
	ncfg_observed_access_point_t *out;

	if (!ncfg_hostapd_config_path(run_dir, device, path, sizeof(path), NULL, 0)) {
		return NULL;
	}
	text = observe_read_generated(path);
	if (!text) {
		return NULL;
	}
	out = calloc(1u, sizeof(*out));
	if (!out) {
		free(text);
		return NULL;
	}
	/*
	 * `ssid2=` and not `ssid=`, because an SSID is 0..32 arbitrary octets and
	 * `ssid=` is text -- which is what the renderer writes and why
	 * `ncfg_ssid_parse_hex` is published: one decoder for the hex, whichever
	 * file it came out of.
	 */
	if (observe_config_value(text, "ssid2", value, sizeof(value))) {
		(void)ncfg_ssid_parse_hex(value, strlen(value), &out->ssid, NULL, 0);
	}
	if (observe_config_value(text, "hw_mode", value, sizeof(value))) {
		const char *band = ncfg_hostapd_band_of_hw_mode(value);

		out->band = band ? observe_dup(band) : NULL;
	}
	if (observe_config_value(text, "channel", value, sizeof(value))) {
		char *stop = NULL;
		long  channel = strtol(value, &stop, 10);

		if (stop && stop != value && *stop == '\0' && channel >= 0) {
			out->channel.has = 1;
			out->channel.value = channel;
		}
	}
	if (observe_config_value(text, "wpa_key_mgmt", value, sizeof(value))) {
		out->key_mgmt = observe_dup(value);
	}
	if (observe_config_value(text, "ignore_broadcast_ssid", value, sizeof(value))) {
		out->hidden = strcmp(value, "1") == 0;
	}
	/*
	 * As hostapd spells it, which is upper case: the renderer uppercases on the
	 * way in, and comparing a document's `se` against a file's `SE` would
	 * differ on every pass and restart the access point for a document nobody
	 * had touched.
	 */
	if (observe_config_value(text, "country_code", value, sizeof(value))) {
		out->regdom = observe_dup(value);
	}
	free(text);
	return out;
}

/* One of hostapd's two lists, asked and parsed. */
static int list_of(ncfg_supplicant_client_t *client, const char *command, char ***out,
    size_t *count)
{
	char body[NCFG_SUPPLICANT_REPLY_MAX];
	char why[NCFG_ERROR_MAX];

	body[0] = '\0';
	why[0] = '\0';
	if (!ncfg_supplicant_ask(client, command, body, sizeof(body), why, sizeof(why))) {
		return 0;
	}
	return ncfg_hostapd_parse_acl_show(body, out, count, why, sizeof(why));
}

int ncfg_observe_access_control(ncfg_observed_t *observed, const char *run_dir, int patience_ms,
    char *err, size_t err_size)
{
	char   directory[NCFG_HOSTAPD_PATH_MAX];
	size_t at;

	if (!observed || !run_dir || !run_dir[0]) {
		ncfg_error_set(err, err_size,
		    "an access control round needs an observation and the run directory the "
		    "daemons were started under");
		return 0;
	}
	if (!ncfg_hostapd_ctrl_dir(run_dir, directory, sizeof(directory), NULL, 0)) {
		return 1;
	}
	for (at = 0; at < observed->backend_count; at++) {
		ncfg_observed_backend_t        *backend = &observed->backends[at];
		ncfg_supplicant_client_t       *client;
		ncfg_observed_access_control_t *lists;
		char                          **denied = NULL;
		char                          **accepted = NULL;
		size_t                          denied_count = 0;
		size_t                          accepted_count = 0;

		if (backend->kind != NCFG_BACKEND_ACCESS_POINT || !backend->running ||
		    !backend->interface) {
			continue;
		}
		client = ncfg_supplicant_connect_within(directory, backend->interface,
		    patience_ms > 0 ? patience_ms : NCFG_SUPPLICANT_IMPATIENT_MS, NULL, 0);
		if (!client) {
			/*
			 * **A statement, and the only one this module makes out of a
			 * failure.** The record says this daemon is running; the socket
			 * says otherwise, and the socket is closer to the truth. The
			 * lists stay absent, because that is a different question.
			 */
			backend->answering.has = 1;
			backend->answering.value = 0;
			continue;
		}
		if (!list_of(client, "DENY_ACL SHOW", &denied, &denied_count) ||
		    !list_of(client, "ACCEPT_ACL SHOW", &accepted, &accepted_count)) {
			/*
			 * Connected and then would not answer, or answered something this
			 * build cannot parse. Either way it is not serving netcfgd, which
			 * is what `answering` is for -- and the lists say nothing, because
			 * half of them is not a smaller answer to the same question.
			 */
			backend->answering.has = 1;
			backend->answering.value = 0;
			ncfg_hostapd_stations_free(denied, denied_count);
			ncfg_hostapd_stations_free(accepted, accepted_count);
			ncfg_supplicant_client_free(client);
			continue;
		}
		ncfg_supplicant_client_free(client);
		backend->answering.has = 1;
		backend->answering.value = 1;
		lists = calloc(1u, sizeof(*lists));
		if (!lists) {
			ncfg_hostapd_stations_free(denied, denied_count);
			ncfg_hostapd_stations_free(accepted, accepted_count);
			ncfg_error_set(err, err_size,
			    "out of memory recording what %s is admitting", backend->interface);
			return 0;
		}
		ncfg_hostapd_recorded_policy(run_dir, backend->interface, &lists->policy);
		lists->denied = denied;
		lists->denied_count = denied_count;
		lists->accepted = accepted;
		lists->accepted_count = accepted_count;
		ncfg_observed_access_control_free(backend->access_control);
		backend->access_control = lists;
		ncfg_observed_access_point_free(backend->started_with);
		backend->started_with = started_with(run_dir, backend->interface);
	}
	return 1;
}
