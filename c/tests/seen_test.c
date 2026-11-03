/*
 * seen_test.c -- the hosts this machine sees, written down for fuzznet
 * (project.md 10.666).
 *
 * A stand-in fuzznetd, forked: it accepts a counted number of connections,
 * writes each request line to a file and answers `ok`, or a refusal where the
 * test asks for one. HOW IT STOPS: it takes at most the connections it was
 * told to, and the test kills it by its recorded pid and waits for it.
 */
#include "ncfg/seen.h"

#include "testdir.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-62s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static pid_t server;

/* Listen at `path`, answer `answer` to at most `count` requests, logging each
 * request line to `log`. */
static void serve(const char *path, const char *log, const char *answer, int count)
{
	struct sockaddr_un address;
	int                listener = socket(AF_UNIX, SOCK_STREAM, 0);

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
	(void)unlink(path);
	if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
	    listen(listener, 8) != 0) {
		check(0, "the stand-in fuzznetd listens");
		return;
	}
	server = fork();
	if (server == 0) {
		int taken;

		alarm(30);
		for (taken = 0; taken < count; taken++) {
			char  line[1024];
			FILE *out;
			int   fd = accept(listener, NULL, NULL);
			ssize_t got;

			if (fd < 0) {
				_exit(1);
			}
			got = read(fd, line, sizeof(line) - 1u);
			line[got > 0 ? got : 0] = '\0';
			out = fopen(log, "a");
			if (out) {
				fputs(line, out);
				fclose(out);
			}
			(void)write(fd, answer, strlen(answer));
			close(fd);
		}
		_exit(0);
	}
	close(listener);
}

static void stop_serving(void)
{
	if (server > 0) {
		(void)kill(server, SIGKILL);
		(void)waitpid(server, NULL, 0);
		server = 0;
	}
}

static int lines_in(const char *path)
{
	FILE *in = fopen(path, "r");
	int   count = 0;
	int   c;

	if (!in) {
		return 0;
	}
	while ((c = fgetc(in)) != EOF) {
		count += c == '\n';
	}
	fclose(in);
	return count;
}

/* An observation: one access point with two stations, one DHCP server with a
 * lease to a third host. */
static char *stations[] = { (char *)"02:00:00:00:00:01", (char *)"aa:bb:cc:00:00:02" };
static ncfg_observed_access_control_t control;
static ncfg_observed_lease_t           lease;
static ncfg_observed_backend_t         backends[2];
static ncfg_observed_t                 observed;

static void an_observation(const char *hostname)
{
	memset(&control, 0, sizeof(control));
	control.associated = stations;
	control.associated_count = 2u;
	memset(&lease, 0, sizeof(lease));
	lease.address = (char *)"192.168.4.51";
	lease.mac = (char *)"02:00:00:00:00:03";
	lease.hostname = (char *)hostname;
	memset(backends, 0, sizeof(backends));
	backends[0].interface = (char *)"ap0";
	backends[0].access_control = &control;
	backends[1].interface = (char *)"lan0";
	backends[1].leases = &lease;
	backends[1].lease_count = 1u;
	memset(&observed, 0, sizeof(observed));
	observed.backends = backends;
	observed.backend_count = 2u;
}

static void the_key(void)
{
	char key[NCFG_SEEN_KEY_MAX + 1u];

	printf("\n-- the key\n");
	check(ncfg_seen_key("wlan0", "AA:BB:cc:00:00:01", key, sizeof(key)) &&
	          strcmp(key, "seen/wlan0/aa-bb-cc-00-00-01") == 0,
	    "an interface and a MAC, dashed and lowercase, as fuzznet's grammar takes");
	check(!ncfg_seen_key("eth@0", "02:00:00:00:00:01", key, sizeof(key)),
	    "an interface name outside the grammar is not written");
	check(!ncfg_seen_key("ifname-long-enough-to-overrun-the-sixty-four-byte-bound",
	          "02:00:00:00:00:01", key, sizeof(key)),
	    "  nor is a key past sixty-four bytes");
}

static void what_is_written_and_when(const char *run)
{
	char         socket_path[512];
	char         log[512];
	char        *said;
	ncfg_seen_t *seen;
	const uint64_t now = 1800000000u;

	printf("\n-- what is written, and when\n");
	(void)snprintf(socket_path, sizeof(socket_path), "%s/fz.sock", run);
	(void)snprintf(log, sizeof(log), "%s/requests", run);
	serve(socket_path, log, "ok\n", 6);
	seen = ncfg_seen_new(socket_path);
	an_observation("laptop one");

	check(ncfg_seen_record(seen, &observed, now) == 3u,
	    "two stations and a lease, three records");
	said = testdir_read(log, NULL);
	check(said && strstr(said, "add record seen/ap0/02-00-00-00-00-01 station\n") &&
	          strstr(said, "add record seen/ap0/aa-bb-cc-00-00-02 station\n"),
	    "  a station as `station`, by the access point's interface");
	check(said && strstr(said, "add record seen/lan0/02-00-00-00-00-03 "
	                           "lease%20192.168.4.51%20laptop%20one\n"),
	    "  a lease with its address and name, the spaces escaped as fuzznet's grammar wants");
	free(said);

	check(ncfg_seen_record(seen, &observed, now + 60u) == 0u,
	    "the same hosts a minute later are not written again");
	an_observation("laptop two");
	check(ncfg_seen_record(seen, &observed, now + 120u) == 1u,
	    "a lease whose name changed is written again, alone");
	check(ncfg_seen_record(seen, &observed, now + 120u + NCFG_SEEN_REFRESH_SECONDS) == 2u,
	    "and a day on, the two still seen are written again: seen is also still seen");
	check(lines_in(log) == 6, "  six requests reached fuzznetd in all");
	stop_serving();
	ncfg_seen_free(seen);
}

static void nobody_listening(const char *run)
{
	char         socket_path[512];
	char         log[512];
	ncfg_seen_t *seen;
	const uint64_t now = 1800000000u;

	printf("\n-- nobody listening, and a refusal\n");
	(void)snprintf(socket_path, sizeof(socket_path), "%s/absent.sock", run);
	seen = ncfg_seen_new(socket_path);
	an_observation("x");
	check(ncfg_seen_record(seen, &observed, now) == 0u,
	    "with no fuzznetd, nothing is written and nothing fails");

	(void)snprintf(log, sizeof(log), "%s/late", run);
	serve(socket_path, log, "ok\n", 3);
	check(ncfg_seen_record(seen, &observed, now + 30u) == 0u,
	    "  and it is not asked again within the minute");
	check(ncfg_seen_record(seen, &observed, now + 61u) == 3u,
	    "  but after it, and then everything is written");
	stop_serving();
	ncfg_seen_free(seen);

	(void)snprintf(socket_path, sizeof(socket_path), "%s/refuses.sock", run);
	(void)snprintf(log, sizeof(log), "%s/refused", run);
	serve(socket_path, log, "denied this month's records were let go here\n", 6);
	seen = ncfg_seen_new(socket_path);
	check(ncfg_seen_record(seen, &observed, now) == 0u,
	    "a refusal writes nothing");
	check(ncfg_seen_record(seen, &observed, now + 1u) == 0u && lines_in(log) == 6,
	    "  and is asked again next pass, since nothing was kept");
	stop_serving();
	ncfg_seen_free(seen);
}

/*
 * Through a node's store (0308, fuzznet sec 827): the record goes to whatever
 * socket the store's `face` file names, read at the write -- so a face that
 * appears after the recorder was made is found, and a store with no face is
 * the quiet absence rather than a write to fuzznetd's guessed default.
 */
static void through_the_store_s_face(const char *run)
{
	char         sock[600];
	char         log[600];
	char         store[600];
	char         face[700];
	char        *heard;
	ncfg_seen_t *seen;

	(void)snprintf(sock, sizeof(sock), "%s/face.sock", run);
	(void)snprintf(log, sizeof(log), "%s/face.log", run);
	(void)snprintf(store, sizeof(store), "%s/store", run);
	(void)snprintf(face, sizeof(face), "%s/face", store);
	testdir_mkdirp(store);
	/* A path nothing serves, which a store's face must override. */
	seen = ncfg_seen_new("/nonexistent/fuzznetd.sock");
	ncfg_seen_use_store(seen, store);
	an_observation("x");
	check(ncfg_seen_record(seen, &observed, 1000u) == 0u,
	    "a store no process serves writes nothing, and is not an error");

	serve(sock, log, "ok\n", 3);
	(void)testdir_write(face, sock, strlen(sock));
	check(ncfg_seen_record(seen, &observed, 1000u + NCFG_SEEN_RETRY_SECONDS + 1u) == 3u,
	    "once a face writes its socket into the store, the record goes there");
	stop_serving();
	heard = testdir_read(log, NULL);
	check(heard && strstr(heard, "add record seen/ap0/02-00-00-00-00-01 station\n"),
	    "  as the same line fuzznetd's own socket takes");
	free(heard);
	ncfg_seen_free(seen);
}

int main(void)
{
	const char *run = testdir_make("seen");

	the_key();
	what_is_written_and_when(run);
	nobody_listening(run);
	through_the_store_s_face(run);
	if (failures) {
		printf("\nseen_test: %d check(s) FAILED\n", failures);
		return 1;
	}
	printf("\nseen_test: all checks passed\n");
	return 0;
}
