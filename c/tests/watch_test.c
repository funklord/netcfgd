/*
 * watch_test.c -- the event walk, and both mechanisms against one directory
 * this test made.
 *
 * WHAT IS WATCHED HERE, AND WHAT IS NOT
 *   A temporary directory of this test's own. Not `/etc/netcfgd`, not
 *   `conf.d/`: this suite runs on the machine netcfgd is configuring, and a
 *   watcher on its real configuration is a watcher on somebody's live network.
 *   Everything created below is removed by name at the end.
 *
 * WHY BOTH PATHS ARE EXERCISED AGAINST THE SAME ASSERTIONS
 *   The polling fallback only runs when something else has already gone wrong
 *   -- `fs.inotify.max_user_instances` exhausted, or a runtime that forbids
 *   inotify -- which makes it exactly the code nobody has ever seen work. So
 *   `ncfg_watch_open_polling` is public, and the checks below ask both
 *   mechanisms the same question.
 *
 * WHY THE WALK IS TESTED WITH BYTES
 *   The kernel will not produce a malformed event on demand, and the two
 *   failures that matter -- a walk that does not terminate, and one that reads
 *   past the end of the buffer -- are invisible in a passing daemon. A length
 *   field large enough to run off the end is written by hand below, and the
 *   buffers are allocated to their exact size so that a read one byte past the
 *   end is an ASan report rather than a byte of the rest of the allocation.
 *
 * WHY EVERY WAIT HAS A CEILING
 *   A watcher that gets the timeout wrong does not fail, it hangs, and a hung
 *   test reports nothing at all. Every wait below is tens of milliseconds and
 *   the walks are bounded by a counter.
 */
#include "ncfg/base.h"
#include "ncfg/watch.h"
#include "ncfg/wire.h"

#include "tempdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* A walk that will not run for ever even if the code under test would. */
#define WALK_CAP 1000u

static uint8_t *exact_copy(const void *bytes, size_t length)
{
	uint8_t *copy;

	if (!bytes || length == 0) {
		return NULL;
	}
	copy = malloc(length);
	if (!copy) {
		return NULL;
	}
	memcpy(copy, bytes, length);
	return copy;
}

/* One event as the kernel writes it: the header's four native fields, then the
 * name padded with NULs to a four-byte boundary. */
static size_t put_event(uint8_t *at, int wd, uint32_t mask, const char *name, uint32_t len)
{
	int32_t  written_wd = wd;
	uint32_t cookie = 0;

	memcpy(at, &written_wd, sizeof(written_wd));
	memcpy(at + 4, &mask, sizeof(mask));
	memcpy(at + 8, &cookie, sizeof(cookie));
	memcpy(at + 12, &len, sizeof(len));
	if (len > 0) {
		memset(at + NCFG_INOTIFY_EVENT_HDR_LEN, 0, len);
		if (name) {
			memcpy(at + NCFG_INOTIFY_EVENT_HDR_LEN, name, strlen(name));
		}
	}
	return NCFG_INOTIFY_EVENT_HDR_LEN + len;
}

/* How many events a buffer walks into, and whether it was refused. */
static size_t count_events(const void *bytes, size_t length, int *refused)
{
	ncfg_inotify_walk_t  walk;
	ncfg_inotify_event_t event;
	size_t               seen = 0;

	if (refused) {
		*refused = 0;
	}
	ncfg_inotify_walk_start(&walk, bytes, length);
	while (seen < WALK_CAP) {
		ncfg_wire_step_t step = ncfg_inotify_walk_next(&walk, &event, NULL, 0);

		if (step == NCFG_WIRE_OK) {
			seen++;
			continue;
		}
		if (step == NCFG_WIRE_BAD && refused) {
			*refused = 1;
		}
		break;
	}
	return seen;
}

/* Make a file, and say whether it worked. */
static int make_file(const char *path, const char *text)
{
	int made = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

	if (made < 0) {
		return 0;
	}
	if (text && write(made, text, strlen(text)) < 0) {
		(void)close(made);
		return 0;
	}
	(void)close(made);
	return 1;
}

int main(void)
{
	char root[256];
	char conf[400];
	char other[400];
	char missing[400];

	if (!tempdir_make("watch", root, sizeof(root))) {
		printf("watch_test: could not make a temporary directory\n");
		return 1;
	}
	(void)snprintf(conf, sizeof(conf), "%s/netcfgd.conf", root);
	(void)snprintf(other, sizeof(other), "%s/second.conf", root);
	(void)snprintf(missing, sizeof(missing), "%s/conf.d", root);

	/* Two events in one read, which is what a directory with two files
	 * written to it produces. */
	{
		uint8_t  buffer[128];
		uint8_t *exact;
		size_t   length = 0;
		ncfg_inotify_walk_t  walk;
		ncfg_inotify_event_t event;

		memset(buffer, 0, sizeof(buffer));
		length += put_event(buffer, 3, IN_CREATE, "netcfgd.conf", 16u);
		length += put_event(buffer + length, 3, IN_CLOSE_WRITE, "second.conf", 12u);
		exact = exact_copy(buffer, length);
		check(exact != NULL && count_events(exact, length, NULL) == 2u,
		    "two events in one read walk out as two");

		ncfg_inotify_walk_start(&walk, exact, length);
		check(ncfg_inotify_walk_next(&walk, &event, NULL, 0) == NCFG_WIRE_OK,
		    "the first one reads");
		check(event.wd == 3 && (event.mask & (uint32_t)IN_CREATE) != 0,
		    "with the watch it came from and what happened");
		check(event.has_name && strcmp(event.name, "netcfgd.conf") == 0,
		    "and the name ends at the first NUL, not at the padded length");
		check(ncfg_inotify_walk_next(&walk, &event, NULL, 0) == NCFG_WIRE_OK &&
		    strcmp(event.name, "second.conf") == 0,
		    "and the second event begins where the padding ended");
		check(ncfg_inotify_walk_next(&walk, &event, NULL, 0) == NCFG_WIRE_END,
		    "after which the buffer has ended cleanly");
		free(exact);
	}

	/* An event with no name at all, which is what `DELETE_SELF` on the
	 * watched directory looks like. */
	{
		uint8_t              buffer[NCFG_INOTIFY_EVENT_HDR_LEN];
		uint8_t             *exact;
		size_t               length;
		ncfg_inotify_walk_t  walk;
		ncfg_inotify_event_t event;

		length = put_event(buffer, 3, IN_DELETE_SELF, NULL, 0);
		exact = exact_copy(buffer, length);
		ncfg_inotify_walk_start(&walk, exact, length);
		check(ncfg_inotify_walk_next(&walk, &event, NULL, 0) == NCFG_WIRE_OK,
		    "an event with no name is still an event");
		check(!event.has_name, "and it carries no name");
		free(exact);
	}

	/*
	 * A name longer than one event can carry.
	 *
	 * `NAME_MAX` says the kernel cannot produce this, which is exactly why
	 * it is asserted: the arm that handles it is unreachable from a kernel
	 * and reachable from a buffer, and an event is still an event -- it is
	 * the *name* that is dropped rather than truncated, because a truncated
	 * name is a name, just somebody else's.
	 */
	{
		uint8_t             *buffer;
		size_t               length;
		ncfg_inotify_walk_t  walk;
		ncfg_inotify_event_t event;
		const uint32_t       claimed = NCFG_INOTIFY_NAME_MAX + 8u;

		length = NCFG_INOTIFY_EVENT_HDR_LEN + claimed;
		buffer = malloc(length);
		check(buffer != NULL, "a buffer for an over-long name is allocated");
		if (buffer) {
			memset(buffer, 0, length);
			(void)put_event(buffer, 3, IN_CREATE, NULL, claimed);
			memset(buffer + NCFG_INOTIFY_EVENT_HDR_LEN, 'x', claimed);
			ncfg_inotify_walk_start(&walk, buffer, length);
			check(ncfg_inotify_walk_next(&walk, &event, NULL, 0) == NCFG_WIRE_OK,
			    "an event with an impossible name is still an event");
			check(!event.has_name, "and the name is dropped rather than cut short");
			check(ncfg_inotify_walk_next(&walk, &event, NULL, 0) == NCFG_WIRE_END,
			    "with the walk ending after it, not inside it");
			free(buffer);
		}
	}

	/* The kernel's own "you missed something", which for a watcher that
	 * re-reads everything is an ordinary change. */
	{
		uint8_t              buffer[NCFG_INOTIFY_EVENT_HDR_LEN];
		ncfg_inotify_walk_t  walk;
		ncfg_inotify_event_t event;
		size_t               length;

		length = put_event(buffer, -1, (uint32_t)IN_Q_OVERFLOW, NULL, 0);
		ncfg_inotify_walk_start(&walk, buffer, length);
		check(ncfg_inotify_walk_next(&walk, &event, NULL, 0) == NCFG_WIRE_OK &&
		    ncfg_inotify_event_overflowed(&event),
		    "a queue overflow is reported as one");
		check(!ncfg_inotify_event_overflowed(NULL),
		    "and asking about no event at all is not an overflow");
	}

	/*
	 * A name length that runs past the end of the buffer.
	 *
	 * The walk must end rather than index out of it, and it must say the
	 * buffer was malformed rather than that it had finished -- one boolean
	 * cannot tell those apart, which is why this walk has three outcomes.
	 */
	{
		uint8_t  buffer[NCFG_INOTIFY_EVENT_HDR_LEN + 8u];
		uint8_t *exact;
		int      refused = 0;
		char     err[NCFG_ERROR_MAX];
		ncfg_inotify_walk_t  walk;
		ncfg_inotify_event_t event;

		memset(buffer, 0, sizeof(buffer));
		(void)put_event(buffer, 3, IN_CREATE, NULL, 8u);
		/* Claim far more name than is there. */
		{
			uint32_t lying = 0xfffffff0u;

			memcpy(buffer + 12, &lying, sizeof(lying));
		}
		exact = exact_copy(buffer, sizeof(buffer));
		check(count_events(exact, sizeof(buffer), &refused) == 0u,
		    "an event claiming more name than there is yields nothing");
		check(refused, "and is refused rather than read as the end of the buffer");

		err[0] = '\0';
		ncfg_inotify_walk_start(&walk, exact, sizeof(buffer));
		(void)ncfg_inotify_walk_next(&walk, &event, err, sizeof(err));
		check(err[0] != '\0', "with a sentence saying what was wrong");
		check(ncfg_inotify_walk_next(&walk, &event, NULL, 0) == NCFG_WIRE_END,
		    "and the walk is left exhausted, so a loop ignoring it still ends");
		free(exact);
	}

	/* A buffer too short to hold one header, and an empty one. */
	{
		uint8_t *exact = exact_copy("short", 5u);
		int      refused = 0;

		check(count_events(exact, 5u, &refused) == 0u && refused,
		    "a buffer shorter than one event header is refused");
		free(exact);
		check(count_events(NULL, 0, &refused) == 0u && !refused,
		    "and an empty read is the end of the buffer, not a refusal");
	}

	/* The mechanisms have names, because an operator debugging a reload that
	 * did not happen needs to know which one is in play. */
	{
		check(strcmp(ncfg_watch_mechanism_name(NCFG_WATCH_INOTIFY), "inotify") == 0,
		    "the kernel's mechanism is named");
		check(strcmp(ncfg_watch_mechanism_name(NCFG_WATCH_POLLING), "mtime polling") == 0,
		    "and so is the fallback");
	}

	/* The polling path, against a directory this test owns. */
	{
		ncfg_watch_t watch;
		const char  *paths[1];
		int          changed = 1;

		check(make_file(conf, "interface eth0 { }\n"), "a configuration file is made");
		paths[0] = root;
		check(ncfg_watch_open_polling(&watch, paths, 1u, NULL, 0),
		    "a polling watcher opens");
		check(ncfg_watch_mechanism(&watch) == NCFG_WATCH_POLLING,
		    "and says it is polling");
		check(ncfg_watch_wait(&watch, 20, &changed, NULL, 0) && changed == 0,
		    "with nothing happening, the wait is a tick rather than a change");

		check(make_file(other, "interface eth1 { }\n"), "a drop-in appears");
		check(ncfg_watch_wait(&watch, 20, &changed, NULL, 0) && changed == 1,
		    "which the fingerprint notices");
		check(ncfg_watch_wait(&watch, 20, &changed, NULL, 0) && changed == 0,
		    "and having noticed it once, does not report it again");

		check(unlink(other) == 0, "the drop-in is removed");
		check(ncfg_watch_wait(&watch, 20, &changed, NULL, 0) && changed == 1,
		    "which is a change too, because absence is part of the fingerprint");
		ncfg_watch_close(&watch);
		check(watch.paths == NULL && watch.marks.count == 0u,
		    "closing a watcher releases what it held");
		ncfg_watch_close(&watch);
	}

	/* The inotify path, asked the same question. */
	{
		ncfg_watch_t watch;
		const char  *paths[1];
		int          changed = 1;

		paths[0] = root;
		check(ncfg_watch_open(&watch, paths, 1u, NULL, 0), "a watcher opens");
		if (ncfg_watch_mechanism(&watch) == NCFG_WATCH_INOTIFY) {
			check(ncfg_watch_wait(&watch, 20, &changed, NULL, 0) && changed == 0,
			    "with nothing happening, inotify times out rather than reporting");
			check(make_file(other, "interface eth1 { }\n"),
			    "a drop-in appears under the watched directory");
			check(ncfg_watch_wait(&watch, 500, &changed, NULL, 0) && changed == 1,
			    "and the kernel says so");
			check(unlink(other) == 0, "the drop-in is removed");
			check(ncfg_watch_wait(&watch, 500, &changed, NULL, 0) && changed == 1,
			    "which is a change as well");
		} else {
			/* A machine whose inotify instances are exhausted, or a
			 * runtime that forbids them. Not a failure: it is the
			 * case the fallback exists for, and the polling checks
			 * above have already asked the same questions. */
			printf("%-58s %s\n", "inotify is unavailable here", "skipped");
		}
		ncfg_watch_close(&watch);
	}

	/* A directory that does not exist yet is still watched, and its
	 * appearance is a change -- which matters because `conf.d/` is created
	 * the first time somebody writes a drop-in. */
	{
		ncfg_watch_t watch;
		const char  *paths[2];
		int          changed = 1;

		paths[0] = root;
		paths[1] = missing;
		check(ncfg_watch_open_polling(&watch, paths, 2u, NULL, 0),
		    "a watcher over a directory that is not there opens");
		check(ncfg_watch_wait(&watch, 20, &changed, NULL, 0) && changed == 0,
		    "and reports nothing while it stays absent");
		check(mkdir(missing, 0700) == 0, "the drop-in directory is created");
		check(ncfg_watch_wait(&watch, 20, &changed, NULL, 0) && changed == 1,
		    "and its appearance is a change");
		ncfg_watch_close(&watch);
	}

	/* What a watcher refuses. */
	{
		ncfg_watch_t watch;
		const char  *paths[1];
		int          changed = 0;

		paths[0] = NULL;
		check(!ncfg_watch_open_polling(&watch, paths, 1u, NULL, 0),
		    "a directory that is nothing is refused");
		check(!ncfg_watch_open(NULL, paths, 0, NULL, 0),
		    "as is a watcher with nowhere to keep the watch");
		check(ncfg_watch_mechanism(NULL) == NCFG_WATCH_POLLING,
		    "and a watcher that is not there is not using the kernel's");

		check(ncfg_watch_open_polling(&watch, NULL, 0, NULL, 0),
		    "a watcher over no directories at all opens");
		check(ncfg_watch_wait(&watch, 1, &changed, NULL, 0) && changed == 0,
		    "and has nothing to report, for ever");
		check(!ncfg_watch_wait(&watch, 1, NULL, NULL, 0),
		    "a wait with nowhere to say so is refused");
		ncfg_watch_close(&watch);
	}

	/* Removed by name: what this test made, and only that. */
	if (rmdir(missing) != 0) {
		printf("watch_test: could not remove %s\n", missing);
		failures++;
	}
	if (unlink(conf) != 0) {
		printf("watch_test: could not remove %s\n", conf);
		failures++;
	}
	if (rmdir(root) != 0) {
		printf("watch_test: could not remove %s\n", root);
		failures++;
	}

	if (failures == 0) {
		printf("watch_test: all checks passed\n");
	} else {
		printf("watch_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
