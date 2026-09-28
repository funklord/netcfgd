/*
 * log.c -- the library half of log.h: a diagnostic, on stderr, that never ends
 * the process.
 *
 * Nothing in this file exits, asserts, allocates or prints to stdout. A write
 * it cannot complete is dropped, because a log line nobody can receive is not a
 * reason to take a daemon down -- and because this is linked into a library,
 * where decision 0263 allows exactly one exception and it is `out.c`.
 */
#include "ncfg/log.h"

#include <errno.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * The level accepted, as a discriminant so it can live in an atomic.
 *
 * `NCFG_LOG_INFO` by default, which is what netcfgd printed before it had
 * levels at all: a change of shape must not also be a change of what an
 * operator sees on an ordinary machine.
 *
 * Atomic because a daemon has more than one thread and this is written once at
 * startup and read on every message. Relaxed ordering: a message that crosses
 * the change and is taken at the old level is not a fault, and a fence per log
 * line would be.
 */
static _Atomic unsigned char accepted_level = (unsigned char)NCFG_LOG_INFO;

/*
 * The subsystem path below which nothing is emitted, empty for everything.
 *
 * A plain buffer and not an atomic, deliberately: `log.h` says this is set at
 * startup before any thread exists, and an atomic here would assert a property
 * nothing maintains. The level above it is atomic because the `verbosity`
 * request really does write it while the daemon runs.
 */
static char accepted_subsystem[NCFG_LOG_SUBSYSTEM_MAX] = "";

const char *ncfg_log_label(ncfg_severity_t severity)
{
	switch (severity) {
	case NCFG_LOG_CRITICAL:
		return "Critical";
	case NCFG_LOG_ERROR:
		return "Error";
	case NCFG_LOG_WARNING:
		return "Warning";
	case NCFG_LOG_NOTE:
		return "!";
	case NCFG_LOG_DEBUG:
		return "Debug";
	case NCFG_LOG_INFO:
	case NCFG_LOG_VERBOSE:
	default:
		/* No label on purpose: the ordinary line is a sentence, and
		 * `Info:` in front of every one of them is furniture. */
		return NULL;
	}
}

const char *ncfg_log_name(ncfg_severity_t severity)
{
	switch (severity) {
	case NCFG_LOG_CRITICAL:
		return "critical";
	case NCFG_LOG_ERROR:
		return "error";
	case NCFG_LOG_WARNING:
		return "warning";
	case NCFG_LOG_NOTE:
		return "note";
	case NCFG_LOG_VERBOSE:
		return "verbose";
	case NCFG_LOG_DEBUG:
		return "debug";
	case NCFG_LOG_INFO:
	default:
		return "info";
	}
}

int ncfg_log_from_name(const char *text, ncfg_severity_t *severity)
{
	static const ncfg_severity_t levels[] = {
		NCFG_LOG_CRITICAL, NCFG_LOG_ERROR, NCFG_LOG_WARNING, NCFG_LOG_NOTE,
		NCFG_LOG_INFO, NCFG_LOG_VERBOSE, NCFG_LOG_DEBUG
	};
	size_t i;

	if (!text) {
		return 0;
	}
	for (i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
		if (strcmp(ncfg_log_name(levels[i]), text) == 0) {
			if (severity) {
				*severity = levels[i];
			}
			return 1;
		}
	}
	return 0;
}

void ncfg_log_accept(ncfg_severity_t level)
{
	atomic_store_explicit(&accepted_level, (unsigned char)level, memory_order_relaxed);
}

ncfg_severity_t ncfg_log_accepted(void)
{
	unsigned char held = atomic_load_explicit(&accepted_level, memory_order_relaxed);

	switch (held) {
	case (unsigned char)NCFG_LOG_CRITICAL:
		return NCFG_LOG_CRITICAL;
	case (unsigned char)NCFG_LOG_ERROR:
		return NCFG_LOG_ERROR;
	case (unsigned char)NCFG_LOG_WARNING:
		return NCFG_LOG_WARNING;
	case (unsigned char)NCFG_LOG_NOTE:
		return NCFG_LOG_NOTE;
	case (unsigned char)NCFG_LOG_VERBOSE:
		return NCFG_LOG_VERBOSE;
	case (unsigned char)NCFG_LOG_DEBUG:
		return NCFG_LOG_DEBUG;
	default:
		/* Including a byte nothing here stored, which cannot happen and
		 * is answered with the default rather than with a new level. */
		return NCFG_LOG_INFO;
	}
}

void ncfg_log_accept_from_env(void)
{
	const char *asked = getenv("NCFG_LOG");
	const char *only = getenv("NCFG_LOG_SUBSYSTEM");
	char word[32];
	size_t length;
	size_t start = 0;
	ncfg_severity_t level;

	/* Read before the level's own early return, or a filter would apply only
	 * when a level was asked for as well -- two settings where the operator
	 * set one. */
	if (only) {
		ncfg_log_accept_subsystem(only);
	}
	if (!asked) {
		return;
	}
	length = strlen(asked);
	while (start < length && (asked[start] == ' ' || asked[start] == '\t')) {
		start++;
	}
	while (length > start && (asked[length - 1] == ' ' || asked[length - 1] == '\t' ||
	    asked[length - 1] == '\n')) {
		length--;
	}
	length -= start;
	if (length + 1 > sizeof(word)) {
		/* Too long to be any level's name, and too long to quote back in
		 * full. Truncated for the message rather than dropped: a silent
		 * default is the fault this branch exists to refuse. */
		length = sizeof(word) - 1;
	}
	memcpy(word, asked + start, length);
	word[length] = '\0';
	if (ncfg_log_from_name(word, &level)) {
		ncfg_log_accept(level);
		return;
	}
	/* Said rather than ignored: a misspelt level that silently keeps the
	 * default is the whole family of faults this tree spent a day on. */
	ncfg_log_emitf("log", NCFG_LOG_WARNING,
	    "NCFG_LOG=`%s` is not a level, so `%s` still applies. Levels: "
	    "critical, error, warning, note, info, verbose, debug",
	    word, ncfg_log_name(ncfg_log_accepted()));
}

int ncfg_log_subsystem_matches(const char *subsystem, const char *filter)
{
	size_t length;

	if (!filter || filter[0] == '\0') {
		return 1;
	}
	if (!subsystem) {
		return 0;
	}
	length = strlen(filter);
	if (strncmp(subsystem, filter, length) != 0) {
		return 0;
	}
	/* The boundary, which is the whole function: `dhcp` is a prefix of
	 * `dhcpcd` as a string and is not an ancestor of it as a path. Accept only
	 * where the filter ends the path or ends a level of it. */
	return subsystem[length] == '\0' || subsystem[length] == '.';
}

void ncfg_log_accept_subsystem(const char *filter)
{
	if (!filter || filter[0] == '\0') {
		accepted_subsystem[0] = '\0';
		return;
	}
	(void)snprintf(accepted_subsystem, sizeof(accepted_subsystem), "%s", filter);
}

const char *ncfg_log_accepted_subsystem(void)
{
	return accepted_subsystem;
}

void ncfg_log_emit(const char *subsystem, ncfg_severity_t severity, const char *text)
{
	char line[NCFG_LOG_MAX];
	const char *label;
	int written;
	size_t length;
	size_t sent = 0;
	int attempts = 0;

	if ((int)severity > (int)ncfg_log_accepted()) {
		return;
	}
	/* After the level and before the rendering, which is the cheap order: a
	 * filtered-out line costs one `strncmp` and no `snprintf`. */
	if (!ncfg_log_subsystem_matches(subsystem, accepted_subsystem)) {
		return;
	}
	label = ncfg_log_label(severity);
	/* One `snprintf` and one `write`, not two of either: two writes would
	 * let another thread's line land between the prefix and the text, which
	 * is how interleaved logs are made. */
	if (label) {
		written = snprintf(line, sizeof(line), "netcfgd: [%s] %s: %s\n",
		    subsystem ? subsystem : "netcfgd", label, text ? text : "");
	} else {
		written = snprintf(line, sizeof(line), "netcfgd: [%s] %s\n",
		    subsystem ? subsystem : "netcfgd", text ? text : "");
	}
	if (written <= 0) {
		return;
	}
	length = (size_t)written;
	if (length >= sizeof(line)) {
		/* Truncated, and the newline went with the tail. Put it back: a
		 * log line that lost its newline joins the next one, and two
		 * messages read as one is worse than one message read short. */
		length = sizeof(line) - 1;
		line[length - 1] = '\n';
	}
	while (sent < length && attempts < 8) {
		ssize_t got = write(STDERR_FILENO, line + sent, length - sent);

		attempts++;
		if (got < 0) {
			if (errno == EINTR) {
				continue;
			}
			/* Nowhere to report this to, and nothing to do about it.
			 * A daemon whose journal went away is still doing its
			 * job. */
			return;
		}
		sent += (size_t)got;
	}
}

void ncfg_log_emitf(const char *subsystem, ncfg_severity_t severity, const char *format, ...)
{
	char text[NCFG_LOG_MAX];
	va_list args;
	int written;

	if ((int)severity > (int)ncfg_log_accepted()) {
		/* The arguments have already been evaluated -- C decides that at
		 * the call site and flog makes the same trade -- but the
		 * rendering is skipped, which is the half that is free to skip.
		 */
		return;
	}
	if (!format) {
		return;
	}
	va_start(args, format);
	written = vsnprintf(text, sizeof(text), format, args);
	va_end(args);
	if (written < 0) {
		return;
	}
	ncfg_log_emit(subsystem, severity, text);
}

void ncfg_log_aboutf(const char *subsystem, const char *about, ncfg_severity_t severity,
    const char *format, ...)
{
	char    path[NCFG_LOG_SUBSYSTEM_MAX];
	char    text[NCFG_LOG_MAX];
	va_list args;
	int     written;

	/*
	 * The path first, because the filter is asked about the composed path
	 * rather than about the root -- `NCFG_LOG_SUBSYSTEM=dhcp.wlp0s20f3` is the
	 * question this exists to make askable, and testing the root would answer
	 * a different one.
	 */
	if (!about || about[0] == '\0') {
		(void)snprintf(path, sizeof(path), "%s", subsystem ? subsystem : "netcfgd");
	} else {
		(void)snprintf(path, sizeof(path), "%s.%s", subsystem ? subsystem : "netcfgd",
		    about);
	}
	if ((int)severity > (int)ncfg_log_accepted() ||
	    !ncfg_log_subsystem_matches(path, accepted_subsystem)) {
		return;
	}
	if (!format) {
		return;
	}
	va_start(args, format);
	written = vsnprintf(text, sizeof(text), format, args);
	va_end(args);
	if (written < 0) {
		return;
	}
	ncfg_log_emit(path, severity, text);
}
