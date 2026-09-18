/*
 * multicall.c -- which of the three programs this image was called as.
 *
 * WHY THE NAME IS A STRING COMPARISON AND NOT A TABLE
 *   Three names, and two of them are the install. A table would be a list to
 *   keep in step with the install rules, the symlink in the Makefile and the
 *   packaging, for three entries that have not changed since 0024.
 *
 * WHAT THIS FILE MAY NOT DO
 *   Guess. A name that is neither is refused with both names said out loud,
 *   because the alternative -- defaulting to one of them -- starts a network
 *   configuration daemon for somebody who typed a client's name, on the one
 *   machine where that is the difference between a shell and no network.
 */
#include "main_internal.h"

#include "ncfg/portal.h"

#include <stdio.h>
#include <string.h>

const char *ncfg_main_basename(const char *path)
{
	const char *slash;

	if (!path) {
		return "";
	}
	slash = strrchr(path, '/');
	return slash ? slash + 1 : path;
}

ncfg_main_program_t ncfg_main_program_for(const char *argv0)
{
	const char *name = ncfg_main_basename(argv0);

	if (strcmp(name, NCFG_MAIN_CLIENT_NAME) == 0) {
		return NCFG_MAIN_PROGRAM_CLIENT;
	}
	if (strcmp(name, NCFG_MAIN_DAEMON_NAME) == 0) {
		return NCFG_MAIN_PROGRAM_DAEMON;
	}
	if (strcmp(name, NCFG_PORTAL_HELPER_NAME) == 0) {
		return NCFG_MAIN_PROGRAM_PROBE;
	}
	return NCFG_MAIN_PROGRAM_NONE;
}

void ncfg_main_legible_name(const char *name, char *out, size_t out_size)
{
	size_t kept = 0;

	if (!out || out_size == 0u) {
		return;
	}
	out[0] = '\0';
	if (!name) {
		return;
	}
	while (name[kept] != '\0' && kept < (size_t)NCFG_MAIN_NAME_KEEP && kept + 1u < out_size) {
		unsigned char byte = (unsigned char)name[kept];

		/* Printable ASCII and nothing else. A space is kept because a path may
		 * genuinely hold one; everything below it moves a cursor or worse, and
		 * everything above 0x7e is a multi-byte sequence this has no reason to
		 * reassemble. */
		out[kept] = (byte >= 0x20u && byte <= 0x7eu) ? (char)byte : '.';
		kept++;
	}
	out[kept] = '\0';
	if (name[kept] != '\0' && kept + 4u <= out_size) {
		/* There was more. Said, rather than left looking like the whole name:
		 * a truncated path that reads as complete is a person searching their
		 * filesystem for something that is not there. */
		out[kept] = '.';
		out[kept + 1u] = '.';
		out[kept + 2u] = '.';
		out[kept + 3u] = '\0';
	}
}

int ncfg_main_miscalled(const char *called_as)
{
	char legible[NCFG_MAIN_NAME_MAX];

	ncfg_main_legible_name(called_as, legible, sizeof(legible));
	/*
	 * No `netcfgd: ` prefix, and that is not an oversight: the sentence is
	 * about the image rather than about either program, and prefixing it with
	 * one of the two names would answer the question it exists to ask.
	 */
	(void)fprintf(stderr,
	    "this binary is `" NCFG_MAIN_DAEMON_NAME "` and `" NCFG_MAIN_CLIENT_NAME "`, and "
	    "picks by the name it is called as; it was called as `%s`\n", legible);
	(void)fprintf(stderr, "install it as `" NCFG_MAIN_DAEMON_NAME "` and symlink `"
	    NCFG_MAIN_CLIENT_NAME "` to it\n");
	return NCFG_MAIN_EXIT_MISCALLED;
}
