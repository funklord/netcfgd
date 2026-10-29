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
#include "ncfg/buf.h"
#include "ncfg/hostapd.h"
#include "ncfg/supplicant.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
	if (observe_config_value(text, "mobility_domain", value, sizeof(value))) {
		out->mobility_domain = observe_dup(value);
	}
	if (observe_config_value(text, "wds_sta", value, sizeof(value))) {
		out->wds = strcmp(value, "1") == 0;
	}
	if (observe_config_value(text, "rrm_neighbor_report", value, sizeof(value))) {
		out->neighbour_reports = strcmp(value, "1") == 0;
	}
	if (observe_config_value(text, "ieee80211n", value, sizeof(value))) {
		out->high_throughput = strcmp(value, "1") == 0;
	}
	if (observe_config_value(text, "ht_capab", value, sizeof(value))) {
		out->forty_mhz = strstr(value, "HT40") != NULL;
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

static int by_address(const void *left, const void *right)
{
	return strcmp(((const ncfg_hostapd_station_t *)left)->address,
	    ((const ncfg_hostapd_station_t *)right)->address);
}

int ncfg_observe_hostapd_stations(struct ncfg_supplicant_client *client,
    ncfg_hostapd_station_t **out, size_t *count)
{
	ncfg_buf_t collected;
	char       command[64];
	char       body[NCFG_SUPPLICANT_REPLY_MAX];
	char       why[NCFG_ERROR_MAX];
	char      *bytes;
	size_t     length = 0u;
	size_t     at;

	*out = NULL;
	*count = 0u;
	/*
	 * **Walked into a buffer**, and an `ncfg_buf_t` rather than an array of
	 * the bound: that is a quarter of a megabyte on the stack for a walk that
	 * usually finds three. The buffer's failure is sticky and read once, and
	 * `ncfg_buf_take` hands over memory from `malloc` -- aligned for any type,
	 * which is what makes the cast below defined rather than merely working.
	 */
	ncfg_buf_init(&collected, 0);
	(void)snprintf(command, sizeof(command), "%s", "STA-FIRST");
	for (at = 0; at < NCFG_HOSTAPD_STATION_WALK_MAX; at++) {
		ncfg_hostapd_station_t station;

		if (!ncfg_supplicant_ask(client, command, body, sizeof(body), why, sizeof(why))) {
			break;
		}
		if (!ncfg_hostapd_parse_station(body, &station)) {
			break;
		}
		ncfg_buf_add(&collected, &station, sizeof(station));
		if ((size_t)snprintf(command, sizeof(command), "STA-NEXT %s", station.address) >=
		    sizeof(command)) {
			break;
		}
	}
	if (ncfg_buf_failed(&collected)) {
		ncfg_buf_free(&collected);
		return 0;
	}
	bytes = ncfg_buf_take(&collected, &length);
	ncfg_buf_free(&collected);
	*out = bytes ? (ncfg_hostapd_station_t *)(void *)bytes : NULL;
	*count = *out ? length / sizeof(**out) : 0u;
	/* By address: hostapd's walk is its hash order, which differs between runs
	 * of one machine. */
	if (*count > 1u) {
		qsort(*out, *count, sizeof(**out), by_address);
	}
	return 1;
}

static void free_neighbours(ncfg_observed_neighbour_t *list, size_t count)
{
	size_t at;

	for (at = 0; at < count; at++) {
		free(list[at].bssid);
		free(list[at].ssid);
		free(list[at].nr);
	}
	free(list);
}

/*
 * hostapd's neighbour list, one `BSSID ssid=HEX nr=HEX` per line (10.595,
 * measured). A line that is not that shape is skipped rather than failing the
 * round: the station lists are what converging needs, and a neighbour list
 * this build cannot read is one it plans nothing against.
 */
static int neighbours_of(ncfg_supplicant_client_t *client, ncfg_observed_neighbour_t **out,
    size_t *count)
{
	char        body[NCFG_SUPPLICANT_REPLY_MAX];
	char        why[NCFG_ERROR_MAX];
	const char *line;

	*out = NULL;
	*count = 0;
	if (!ncfg_supplicant_ask(client, "SHOW_NEIGHBOR", body, sizeof(body), why, sizeof(why))) {
		return 1;
	}
	for (line = body; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
		char                       bssid[NCFG_STATION_ADDRESS_SIZE];
		char                       ssid[80];
		char                       nr[256];
		char                       normal[NCFG_STATION_ADDRESS_SIZE];
		ncfg_observed_neighbour_t *grown;

		if (sscanf(line, "%17s ssid=%79s nr=%255[0-9a-fA-F]", bssid, ssid, nr) != 3 ||
		    !ncfg_station_address_normalize(bssid, normal, sizeof(normal), NULL, 0)) {
			continue;
		}
		grown = realloc(*out, (*count + 1u) * sizeof(**out));
		if (!grown) {
			return 0;
		}
		*out = grown;
		(*out)[*count].bssid = observe_dup(normal);
		(*out)[*count].ssid = observe_dup(ssid);
		(*out)[*count].nr = observe_dup(nr);
		(*count)++;
		if (!(*out)[*count - 1u].bssid || !(*out)[*count - 1u].ssid || !(*out)[*count - 1u].nr) {
			return 0;
		}
	}
	return 1;
}

static void free_steerable(ncfg_observed_steerable_t *list, size_t count)
{
	size_t at;

	for (at = 0; at < count; at++) {
		free(list[at].address);
	}
	free(list);
}

/*
 * The ones that take BSS transition requests, with the two numbers steering
 * decides on (10.595 item 2). 0 only for memory.
 */
static int steerable_of(const ncfg_hostapd_station_t *found, size_t found_count,
    ncfg_observed_steerable_t **out, size_t *count)
{
	size_t at;

	*out = NULL;
	*count = 0u;
	for (at = 0; at < found_count; at++) {
		ncfg_observed_steerable_t *grown;

		if (!found[at].bss_transition) {
			continue;
		}
		grown = realloc(*out, (*count + 1u) * sizeof(**out));
		if (!grown) {
			return 0;
		}
		*out = grown;
		(*out)[*count].address = observe_dup(found[at].address);
		(*out)[*count].signal = found[at].signal_dbm;
		(*out)[*count].connected = found[at].connected_seconds;
		(*out)[*count].inactive = found[at].inactive_msec;
		if (!(*out)[(*count)++].address) {
			return 0;
		}
	}
	return 1;
}

/* The addresses alone, for the observation, and the steerable ones beside. */
static int associated_of(ncfg_supplicant_client_t *client, char ***out, size_t *count,
    ncfg_observed_steerable_t **steerable, size_t *steerable_count)
{
	ncfg_hostapd_station_t *found = NULL;
	size_t                  found_count = 0u;
	size_t                  at;

	*out = NULL;
	*count = 0u;
	*steerable = NULL;
	*steerable_count = 0u;
	if (!ncfg_observe_hostapd_stations(client, &found, &found_count)) {
		return 0;
	}
	if (!steerable_of(found, found_count, steerable, steerable_count)) {
		free_steerable(*steerable, *steerable_count);
		*steerable = NULL;
		*steerable_count = 0u;
		free(found);
		return 0;
	}
	if (found_count) {
		*out = calloc(found_count, sizeof(**out));
		if (!*out) {
			free(found);
			return 0;
		}
	}
	for (at = 0; at < found_count; at++) {
		(*out)[at] = observe_dup(found[at].address);
		if (!(*out)[at]) {
			ncfg_hostapd_stations_free(*out, at);
			*out = NULL;
			free(found);
			return 0;
		}
	}
	*count = found_count;
	free(found);
	return 1;
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
		char                          **associated = NULL;
		size_t                          denied_count = 0;
		size_t                          accepted_count = 0;
		size_t                          associated_count = 0;
		ncfg_observed_neighbour_t      *neighbours = NULL;
		size_t                          neighbour_count = 0;
		ncfg_observed_steerable_t      *steerable = NULL;
		size_t                          steerable_count = 0;

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
		/*
		 * Who is associated, on the same connection (10.591). Not a reason to
		 * call the daemon unanswering when it fails: the lists above were
		 * answered, and they are what converging needs. A prefix then has
		 * nothing new to expand against this pass, which is the cautious
		 * direction -- nothing is removed on the strength of it, because a
		 * held entry is kept by the planner whether or not it is associated.
		 */
		if (!associated_of(client, &associated, &associated_count, &steerable,
		        &steerable_count)) {
			associated = NULL;
			associated_count = 0;
		}
		neighbours = NULL;
		neighbour_count = 0;
		if (!neighbours_of(client, &neighbours, &neighbour_count)) {
			ncfg_supplicant_client_free(client);
			ncfg_hostapd_stations_free(denied, denied_count);
			ncfg_hostapd_stations_free(accepted, accepted_count);
			ncfg_hostapd_stations_free(associated, associated_count);
			free_neighbours(neighbours, neighbour_count);
			free_steerable(steerable, steerable_count);
			ncfg_error_set(err, err_size, "out of memory recording %s's neighbours",
			    backend->interface);
			return 0;
		}
		ncfg_supplicant_client_free(client);
		backend->answering.has = 1;
		backend->answering.value = 1;
		lists = calloc(1u, sizeof(*lists));
		if (!lists) {
			ncfg_hostapd_stations_free(denied, denied_count);
			ncfg_hostapd_stations_free(accepted, accepted_count);
			ncfg_hostapd_stations_free(associated, associated_count);
			free_neighbours(neighbours, neighbour_count);
			free_steerable(steerable, steerable_count);
			ncfg_error_set(err, err_size,
			    "out of memory recording what %s is admitting", backend->interface);
			return 0;
		}
		ncfg_hostapd_recorded_policy(run_dir, backend->interface, &lists->policy);
		lists->denied = denied;
		lists->denied_count = denied_count;
		lists->accepted = accepted;
		lists->accepted_count = accepted_count;
		lists->associated = associated;
		lists->associated_count = associated_count;
		lists->neighbours = neighbours;
		lists->neighbour_count = neighbour_count;
		lists->steerable = steerable;
		lists->steerable_count = steerable_count;
		if (!ncfg_hostapd_steered_read(run_dir, backend->interface, (int64_t)time(NULL),
		        &lists->steered, &lists->steered_count)) {
			ncfg_observed_access_control_free(lists);
			ncfg_error_set(err, err_size, "out of memory reading whom %s has steered",
			    backend->interface);
			return 0;
		}
		ncfg_observed_access_control_free(backend->access_control);
		backend->access_control = lists;
		ncfg_observed_access_point_free(backend->started_with);
		backend->started_with = started_with(run_dir, backend->interface);
	}
	return 1;
}
