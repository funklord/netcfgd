/*
 * common.c -- the small things every `ncfg` renderer needs.
 *
 * The three shared *rules* live here rather than at their call sites, and each
 * of them is here because it was at its call sites first: an access point's
 * name was spelled three ways across three clients, and "is this a radio" was
 * written as an `or` in one place and a fallback in another. A rule written
 * twice is a rule that is right once.
 */
#include "cli_internal.h"

#include <stdio.h>
#include <string.h>

const char *ncfg_cli_text(ncfg_proto_str_t text, char *out, size_t out_size)
{
	size_t length;

	if (!out || out_size == 0) {
		return "";
	}
	if (!text.bytes) {
		out[0] = '\0';
		return out;
	}
	length = text.length;
	if (length > out_size - 1) {
		length = out_size - 1;
	}
	memcpy(out, text.bytes, length);
	out[length] = '\0';
	return out;
}

const char *ncfg_cli_access_point_name(const char *name, const char *ssid, char *out,
    size_t out_size)
{
	if (!out || out_size == 0) {
		return "";
	}
	if (!name) {
		/* Not text: the hex is the only honest name there is, and it is kept
		 * rather than summarised -- two unprintable SSIDs are two rows. */
		(void)snprintf(out, out_size, "hex:%s", ssid ? ssid : "");
	} else if (name[0] == '\0') {
		(void)snprintf(out, out_size, "(hidden)");
	} else {
		(void)snprintf(out, out_size, "%s", name);
	}
	return out;
}

const char *ncfg_cli_access_point_security(int secured, int enterprise, int owe)
{
	if (enterprise) {
		return "enterprise";
	}
	if (secured) {
		return "secured";
	}
	/* **Encrypted and asking for nothing, which is not "open" (0227).**
	 * `secured` is false for both because neither needs a credential, and they
	 * are different networks to join: an open profile against an OWE access
	 * point does not associate. */
	if (owe) {
		return "owe";
	}
	return "open";
}

int ncfg_cli_is_radio(const char *kind, const char *name)
{
	if (kind && kind[0] != '\0') {
		return strcmp(kind, "wlan") == 0;
	}
	return name && strncmp(name, "wl", 2) == 0;
}

const char *ncfg_cli_duration(int64_t seconds, char *out, size_t out_size)
{
	int64_t hours;
	int64_t minutes;
	int64_t rest;

	if (!out || out_size == 0) {
		return "";
	}
	if (seconds < 0) {
		seconds = 0;
	}
	hours = seconds / 3600;
	minutes = (seconds % 3600) / 60;
	rest = seconds % 60;
	if (hours > 0) {
		(void)snprintf(out, out_size, "%lldh%02lldm", (long long)hours, (long long)minutes);
	} else if (minutes > 0) {
		(void)snprintf(out, out_size, "%lldm%02llds", (long long)minutes, (long long)rest);
	} else {
		(void)snprintf(out, out_size, "%llds", (long long)rest);
	}
	return out;
}

const char *ncfg_cli_bytes(int64_t count, char *out, size_t out_size)
{
	static const int64_t limits[] = { 1000000000, 1000000, 1000 };
	static const char *const suffixes[] = { "G", "M", "k" };
	size_t at;

	if (!out || out_size == 0) {
		return "";
	}
	if (count < 0) {
		count = 0;
	}
	for (at = 0; at < sizeof(limits) / sizeof(limits[0]); at++) {
		if (count >= limits[at]) {
			int64_t whole = count / limits[at];
			int64_t tenths = (count % limits[at]) * 10 / limits[at];

			(void)snprintf(out, out_size, "%lld.%lld%s", (long long)whole,
			    (long long)tenths, suffixes[at]);
			return out;
		}
	}
	(void)snprintf(out, out_size, "%lldB", (long long)count);
	return out;
}
