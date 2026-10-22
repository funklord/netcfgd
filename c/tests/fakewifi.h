/*
 * fakewifi.h -- standing the repository's fake radios up, for a test.
 *
 * WHY THIS IS A HEADER AND NOT TWO COPIES
 *   `tests/live/fake_supplicant.py` and `fake_hostapd.py` are what let a test
 *   ask netcfgd about a radio with no radio and no root. Two test binaries now
 *   need them -- `daemon_wifi_test`, which asks what the daemon answers, and
 *   `socket_witness_test`, which writes `doc/schema/socket.json` from those
 *   answers -- and the machinery for starting one is a forked process, a bound
 *   socket and a kill that has to reach a process group. That is not a thing
 *   to have two of: the second copy is where the kill gets forgotten.
 *
 *   Header-only and `static`, which is `testdir.h`'s shape and for the same
 *   reason: one translation unit per binary uses it, so there is nothing to
 *   link and no object for a Makefile to track.
 *
 * WHAT A CALLER OWES
 *   `stop_fakes()` before it exits, on every path including the failing ones.
 *   Nothing here registers an `atexit`, because a test that has already called
 *   it would then kill a second time and wait on a pid it does not own.
 */
#ifndef NCFG_FAKEWIFI_H
#define NCFG_FAKEWIFI_H

#include "testdir.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ====================================================== the fakes, bounded */

#define FAKES_MAX 4

static pid_t fake_pid[FAKES_MAX];
static size_t fake_count;

static long long now_ms(void)
{
	struct timespec when;

	(void)clock_gettime(CLOCK_MONOTONIC, &when);
	return (long long)when.tv_sec * 1000 + when.tv_nsec / 1000000;
}

static void pause_briefly(void)
{
	struct timespec slice;

	slice.tv_sec = 0;
	slice.tv_nsec = 2000000;
	(void)nanosleep(&slice, NULL);
}

/*
 * Start one of the repository's fakes, and wait for the socket it binds.
 *
 * `timeout` is the outer bound and is not a courtesy: a test binary killed
 * part way through must not leave a python process holding a socket, and the
 * only thing that can promise that is something outside this process.
 * `setpgid` is the inner one, so the kill below reaches `timeout` and the
 * python it started rather than one of the two.
 *
 * Waited for rather than slept on: the socket appearing is the readiness
 * signal, which is what netcfgd itself waits for when it starts a supplicant.
 */
static int start_fake(const char *script, const char *const *argument, size_t argument_count,
    const char *socket_path, const char *log_path)
{
	const char *argv[16];
	size_t      at = 0;
	long long   deadline;
	pid_t       child;

	if (fake_count >= FAKES_MAX || argument_count + 6u > sizeof(argv) / sizeof(argv[0])) {
		return 0;
	}
	argv[at++] = "timeout";
	argv[at++] = "-k";
	argv[at++] = "2";
	argv[at++] = "60";
	argv[at++] = "python3";
	argv[at++] = script;
	for (; at < argument_count + 6u; at++) {
		argv[at] = argument[at - 6u];
	}
	argv[at] = NULL;
	child = fork();
	if (child < 0) {
		return 0;
	}
	if (child == 0) {
		int log = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		(void)setpgid(0, 0);
		if (log >= 0) {
			(void)dup2(log, STDOUT_FILENO);
			(void)dup2(log, STDERR_FILENO);
			(void)close(log);
		}
		/* A cast away from `const` because `execvp` predates it; nothing
		 * here writes through the pointers. */
		(void)execvp("timeout", (char *const *)(void *)argv);
		_exit(127);
	}
	(void)setpgid(child, child);
	fake_pid[fake_count++] = child;
	deadline = now_ms() + 5000;
	while (now_ms() < deadline) {
		if (testdir_exists(socket_path)) {
			return 1;
		}
		pause_briefly();
	}
	return 0;
}

/* By the pid this process recorded, and by nothing else. */
static void stop_fakes(void)
{
	size_t at;

	for (at = 0; at < fake_count; at++) {
		int status = 0;

		if (fake_pid[at] <= 0) {
			continue;
		}
		(void)kill(-fake_pid[at], SIGTERM);
		(void)kill(fake_pid[at], SIGTERM);
		(void)waitpid(fake_pid[at], &status, 0);
		fake_pid[at] = -1;
	}
	fake_count = 0;
}

/*
 * A unix address for `<dir>/<leaf>`, refusing one longer than an address holds.
 *
 * `snprintf` is right in the library and wrong here: a compiler reasoning about
 * a 320-byte path copied into a 108-byte `sun_path` is a warning per call site
 * rather than a fault. A fixture path that does not fit is a test that would
 * check nothing, so this stops instead.
 */
static void address_for(struct sockaddr_un *out, const char *dir, const char *leaf)
{
	size_t used = strlen(dir);
	size_t tail = strlen(leaf);

	if (used + 1u + tail >= sizeof(out->sun_path)) {
		printf("a fixture socket path is longer than a unix address\n");
		exit(1);
	}
	memset(out, 0, sizeof(*out));
	out->sun_family = AF_UNIX;
	memcpy(out->sun_path, dir, used);
	out->sun_path[used] = '/';
	memcpy(out->sun_path + used + 1u, leaf, tail + 1u);
}

/* Say something to a fake that is not a wpa_supplicant command: `DISABLE`,
 * `FAIL_NEXT_SCAN`, `FAIL_NEXT_JOIN`. Each is that fixture's way of producing
 * a state which needs an access point refusing this station, or a scan that
 * did not finish. */
static int tell_fake(const char *dir, const char *interface, const char *command)
{
	struct sockaddr_un mine;
	struct sockaddr_un theirs;
	char               reply[64];
	char               leaf[64];
	int                fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	int                said = 0;
	struct timeval     patience;

	if (fd < 0) {
		return 0;
	}
	(void)snprintf(leaf, sizeof(leaf), "telling-%ld", (long)getpid());
	address_for(&mine, dir, leaf);
	address_for(&theirs, dir, interface);
	patience.tv_sec = 2;
	patience.tv_usec = 0;
	(void)unlink(mine.sun_path);
	if (bind(fd, (const struct sockaddr *)&mine, sizeof(mine)) == 0 &&
	    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &patience, sizeof(patience)) == 0 &&
	    sendto(fd, command, strlen(command), 0, (const struct sockaddr *)&theirs,
	        sizeof(theirs)) >= 0) {
		said = recv(fd, reply, sizeof(reply), 0) > 0;
	}
	(void)close(fd);
	(void)unlink(mine.sun_path);
	return said;
}

/* ============================================== the directories they read */

static void make_directory(const char *path)
{
	if (mkdir(path, 0700) != 0 && testdir_mode(path) < 0) {
		printf("could not make the fixture directory %s\n", path);
		exit(1);
	}
}

/*
 * A radio the fake `/sys/class/net` reports, which `ncfg_radio_is_wireless`
 * answers from `phy80211` (0231).
 *
 * **The attribute is a file, where the kernel makes it a directory**, and the
 * difference is the cleanup rather than the check: `attribute_exists` asks
 * `stat`, which does not care, and `testdir.h`'s removal is two levels deep by
 * hand -- so a directory here is one this test makes and cannot take away, and
 * thirty-nine of them were left under `TMPDIR` before this was a file.
 */
static void make_radio(const char *class_net, const char *name, int wireless)
{
	char device[384];
	char attribute[448];

	(void)snprintf(device, sizeof(device), "%s/%s", class_net, name);
	make_directory(device);
	if (wireless) {
		(void)snprintf(attribute, sizeof(attribute), "%s/phy80211", device);
		(void)testdir_write(attribute, "", 0);
	}
}

#endif /* NCFG_FAKEWIFI_H */
