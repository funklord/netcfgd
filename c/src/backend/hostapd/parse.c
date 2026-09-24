/*
 * parse.c -- what hostapd says back, read the way its own source says it writes.
 *
 * Both formats here were read out of hostapd 2.10's `hostapd/ctrl_iface.c` and
 * `src/ap/ctrl_iface_ap.c` rather than guessed from its documentation, and each
 * changed a plausible parser:
 *
 *   * **An empty reply is an answer, not a failure.** `hostapd_ctrl_iface_
 *     acl_show_mac` prints zero bytes for an empty list, and
 *     `hostapd_ctrl_iface_sta_mib` returns zero bytes for a null station -- so
 *     "denies nobody" and "the end of the walk" are both the empty string.
 *   * **Everything except a station's address is optional.**
 *     `hostapd_get_sta_info` writes nothing at all when the driver read fails.
 *
 * The round trip that would carry a reply here is the supplicant module's
 * `wpa_ctrl` client, which is not this build's; these are the halves that are
 * pure, and they are where being wrong is silent.
 */
#include "ncfg/hostapd.h"

#include "../backend_internal.h"
#include "ncfg/base.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int compare_addresses(const void *one, const void *two)
{
	return strcmp(*(char *const *)one, *(char *const *)two);
}

int ncfg_hostapd_parse_acl_show(const char *reply, char ***out, size_t *count_out, char *err,
    size_t err_size)
{
	char **found = NULL;
	size_t count = 0;
	size_t capacity = 0;
	size_t at;
	size_t kept;

	if (!out || !count_out) {
		ncfg_error_set(err, err_size, "an acl reply was parsed with nowhere to put it");
		return 0;
	}
	*out = NULL;
	*count_out = 0;
	while (reply != NULL && *reply != '\0') {
		const char *end = strchr(reply, '\n');
		size_t      length = end ? (size_t)(end - reply) : strlen(reply);
		char        word[64];
		char        address[18];
		size_t      word_length = 0;

		while (word_length < length && word_length < sizeof(word) - 1u &&
		    !isspace((unsigned char)reply[word_length])) {
			word[word_length] = reply[word_length];
			word_length++;
		}
		word[word_length] = '\0';
		reply = end ? end + 1u : NULL;
		/* **What is not an address is not a station.** `FAIL`, `UNKNOWN
		 * COMMAND` and a truncated line all reach here as text, and none of
		 * them may become an entry netcfgd then tries to delete. */
		if (word_length == 0u ||
		    !ncfg_station_address_normalize(word, address, sizeof(address), NULL, 0)) {
			continue;
		}
		if (count == capacity) {
			size_t wanted = capacity ? capacity * 2u : 8u;
			char **grown = realloc(found, wanted * sizeof(*grown));

			if (!grown) {
				ncfg_hostapd_stations_free(found, count);
				ncfg_error_set(err, err_size, "out of memory reading an acl reply");
				return 0;
			}
			found = grown;
			capacity = wanted;
		}
		found[count] = ncfg_backend_strdup(address);
		if (!found[count]) {
			ncfg_hostapd_stations_free(found, count);
			ncfg_error_set(err, err_size, "out of memory reading an acl reply");
			return 0;
		}
		count++;
	}

	/* Sorted and deduplicated, so a comparison against the document's stations
	 * -- which the compiler sorts and deduplicates (0039) -- is a comparison of
	 * two lists rather than of two sets pretending to be lists. */
	if (count > 1u) {
		qsort(found, count, sizeof(*found), compare_addresses);
	}
	kept = count ? 1u : 0u;
	for (at = 1u; at < count; at++) {
		if (strcmp(found[kept - 1u], found[at]) == 0) {
			free(found[at]);
			continue;
		}
		found[kept++] = found[at];
	}
	*out = found;
	*count_out = kept;
	return 1;
}

void ncfg_hostapd_stations_free(char **stations, size_t count)
{
	size_t at;

	if (!stations) {
		return;
	}
	for (at = 0u; at < count; at++) {
		free(stations[at]);
	}
	free(stations);
}

/* One `key=value` line's value as an integer, where it is one. Anything that is
 * not a number leaves the field absent, which is what the Rust's `parse().ok()`
 * does -- a field hostapd wrote in a form this does not understand is not a
 * reason to drop a station that is really there. */
static void take_number(ncfg_optint_t *field, const char *value)
{
	char      *end = NULL;
	long long  parsed;

	while (*value == ' ' || *value == '\t') {
		value++;
	}
	parsed = strtoll(value, &end, 10);
	if (end == value) {
		return;
	}
	while (end && (*end == ' ' || *end == '\t' || *end == '\r')) {
		end++;
	}
	if (end && *end != '\0') {
		return;
	}
	field->has = 1;
	field->value = parsed;
}

int ncfg_hostapd_parse_station(const char *reply, ncfg_hostapd_station_t *out)
{
	const char *walk = reply;
	const char *end;
	char        first[64];
	size_t      length;

	if (!out) {
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!reply) {
		return 0;
	}
	end = strchr(walk, '\n');
	length = end ? (size_t)(end - walk) : strlen(walk);
	/* The first token of the first line, which is what the Rust's `.trim()`
	 * amounts to here: a reply that arrived with a carriage return or padding
	 * still names the same station. */
	while (length > 0u && isspace((unsigned char)*walk)) {
		walk++;
		length--;
	}
	while (length > 0u && isspace((unsigned char)walk[length - 1u])) {
		length--;
	}
	if (length >= sizeof(first)) {
		return 0;
	}
	memcpy(first, walk, length);
	first[length] = '\0';
	/* `FAIL`, an empty reply and `UNKNOWN COMMAND` all mean "no more", and none
	 * of them is an error worth showing somebody. A first line that is not an
	 * address is not trusted into the list either. */
	if (!ncfg_station_address_normalize(first, out->address, sizeof(out->address), NULL, 0)) {
		return 0;
	}

	walk = end ? end + 1u : NULL;
	while (walk != NULL && *walk != '\0') {
		char        line[512];
		char       *split;
		const char *value;

		end = strchr(walk, '\n');
		length = end ? (size_t)(end - walk) : strlen(walk);
		if (length >= sizeof(line)) {
			length = sizeof(line) - 1u;
		}
		memcpy(line, walk, length);
		line[length] = '\0';
		walk = end ? end + 1u : NULL;

		split = strchr(line, '=');
		if (!split) {
			continue;
		}
		*split = '\0';
		value = split + 1u;
		if (strcmp(line, "flags") == 0) {
			/* The flag that separates a station that completed authentication
			 * from one part way through it. An unauthorized station is
			 * associated and cannot pass traffic, which is worth showing
			 * differently rather than not at all. */
			out->authorized = strstr(value, "[AUTHORIZED]") != NULL;
		} else if (strcmp(line, "signal") == 0) {
			take_number(&out->signal_dbm, value);
		} else if (strcmp(line, "connected_time") == 0) {
			take_number(&out->connected_seconds, value);
		} else if (strcmp(line, "inactive_msec") == 0) {
			take_number(&out->inactive_msec, value);
		} else if (strcmp(line, "rx_bytes") == 0) {
			take_number(&out->rx_bytes, value);
		} else if (strcmp(line, "tx_bytes") == 0) {
			take_number(&out->tx_bytes, value);
		}
	}
	return 1;
}
