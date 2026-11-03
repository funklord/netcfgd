/*
 * fuzznet_line_test.c -- the escape, and the bounded one-line conversation
 * (`client/ncfg_fuzznet.c`, 10.688), against a scripted socket.
 *
 * WHAT IS CHECKED
 *   The escape round-trips every byte, unescaping refuses a broken `%XX` and
 *   an output that does not fit, and a reply is read whole; a socket that
 *   never answers is given up on within the wait, and none there is said to
 *   be silent rather than refusing.
 *
 * HOW IT STOPS: the server child serves three connections and exits, under
 * `alarm(10)` either way; the scratch directory is mkdtemp's and the four
 * names written in it are removed by name.
 */
#include "ncfg_fuzznet.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* Three connections: an answer to the line, a reply split in two sends,
 * and one never answered (held until the client gives up). */
static void serve(int listener)
{
	int at;

	alarm(10);
	for (at = 0; at < 3; at++) {
		char    line[256];
		size_t  have = 0;
		ssize_t n;
		int     fd = accept(listener, NULL, NULL);

		if (fd < 0) {
			_exit(1);
		}
		/* To the newline, which the client may send apart from the line. */
		while (at < 2 && have + 1u < sizeof(line) && !memchr(line, '\n', have) &&
		    (n = recv(fd, line + have, sizeof(line) - 1u - have, 0)) > 0) {
			have += (size_t)n;
		}
		line[have] = '\0';
		if (at == 0) {
			char reply[300];

			(void)snprintf(reply, sizeof(reply), "ok you said %s", line);
			(void)send(fd, reply, strlen(reply), MSG_NOSIGNAL);
		} else if (at == 1) {
			(void)send(fd, "ok in ", 6u, MSG_NOSIGNAL);
			usleep(50000);
			(void)send(fd, "two\n", 4u, MSG_NOSIGNAL);
		} else {
			char drain[64];

			(void)recv(fd, drain, sizeof(drain), 0); /* until the client closes */
		}
		close(fd);
	}
	_exit(0);
}

static long ms_since(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) * 1000L + (now.tv_nsec - start->tv_nsec) / 1000000L;
}

int main(void)
{
	char               dir[] = "/tmp/ncfg-fzline.XXXXXX";
	char               path[128];
	char               gone[128];
	char               escaped[1024];
	char               back[512];
	char               all[256];
	char               reply[512];
	char               why[256];
	struct sockaddr_un address;
	struct timespec    start;
	int                listener;
	int                silent = 0;
	int                status = 0;
	long               n;
	pid_t              child;
	size_t             at;

	for (at = 0; at < sizeof(all); at++) {
		all[at] = (char)(at + 1u); /* every byte but NUL, which a C string cannot hold */
	}
	all[255] = '\0';
	n = ncfg_fuzznet_escape(all, escaped, sizeof(escaped))
	        ? ncfg_fuzznet_unescape(escaped, strlen(escaped), back, sizeof(back))
	        : -1;
	check(n == 255 && memcmp(back, all, 255u) == 0 && !strchr(escaped, ' ') &&
	        !strchr(escaped, ',') && strstr(escaped, "%25") && strstr(escaped, "%7f"),
	    "the escape round-trips every byte, and escapes space, comma, % and DEL");
	n = ncfg_fuzznet_unescape("a%2", 3u, back, sizeof(back));
	check(n == -1, "a truncated escape is refused");
	n = ncfg_fuzznet_unescape("a%zz", 4u, back, sizeof(back));
	check(n == -1, "  and one that is not hex");
	n = ncfg_fuzznet_unescape("%4A%4a", 6u, back, sizeof(back));
	check(n == 2 && back[0] == 'J' && back[1] == 'J', "  and either case of hex is read");
	n = ncfg_fuzznet_unescape("abcd", 4u, back, 3u);
	check(n == -1, "an output that does not fit is refused, not cut");
	check(!ncfg_fuzznet_escape("a b", escaped, 5u), "  and an escape that does not fit");

	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 1;
	}
	(void)snprintf(path, sizeof(path), "%s/s", dir);
	(void)snprintf(gone, sizeof(gone), "%s/none", dir);
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, path, strlen(path) + 1u);
	if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
	    listen(listener, 4) != 0) {
		perror("listen");
		return 1;
	}
	child = fork();
	if (child == 0) {
		serve(listener);
	}
	close(listener);

	check(ncfg_fuzznet_ask(path, "call status 0", reply, sizeof(reply), 1000, &silent, why,
	          sizeof(why)) &&
	        strcmp(reply, "ok you said call status 0") == 0 && !silent,
	    "a line is asked with its newline added, and the reply read back");
	check(ncfg_fuzznet_ask(path, "x\n", reply, sizeof(reply), 1000, &silent, why,
	          sizeof(why)) &&
	        strcmp(reply, "ok in two") == 0,
	    "  a reply in two pieces is read whole");
	clock_gettime(CLOCK_MONOTONIC, &start);
	check(!ncfg_fuzznet_ask(path, "y", reply, sizeof(reply), 200, &silent, why, sizeof(why)) &&
	        silent && ms_since(&start) < 2000,
	    "a socket that never answers is given up on within the wait");
	check(!ncfg_fuzznet_ask(gone, "y", reply, sizeof(reply), 200, &silent, why, sizeof(why)) &&
	        silent && strstr(why, "not at") != NULL,
	    "and none there is silence, said as such");

	/* Where the daemon is asked (10.689): its run directory's socket, until
	 * `<run>/node` names a store whose `face` names another. */
	{
		char  where[256];
		char  file[200];
		FILE *out;
		int   fell_back;
		int   faced;

		fell_back = ncfg_fuzznet_daemon_socket(dir, where, sizeof(where)) &&
		    strcmp(where + strlen(dir), "/fuzznet.sock") == 0;
		(void)snprintf(file, sizeof(file), "%s/node", dir);
		out = fopen(file, "w");
		if (out) {
			(void)fprintf(out, "key=00\nstore=%s\n", dir);
			(void)fclose(out);
		}
		(void)snprintf(file, sizeof(file), "%s/face", dir);
		out = fopen(file, "w");
		if (out) {
			(void)fprintf(out, "%s/elsewhere.sock\n", dir);
			(void)fclose(out);
		}
		faced = ncfg_fuzznet_daemon_socket(dir, where, sizeof(where)) &&
		    strcmp(where + strlen(dir), "/elsewhere.sock") == 0;
		check(fell_back && faced,
		    "the daemon's socket is the run directory's, or the one its store's face names");
		(void)snprintf(file, sizeof(file), "%s/node", dir);
		(void)unlink(file);
		(void)snprintf(file, sizeof(file), "%s/face", dir);
		(void)unlink(file);
	}

	(void)waitpid(child, &status, 0);
	check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "the server served all three");

	/* Another node's events from a cursor (10.703): fuzznet's `events`, its
	 * `NEXT FIRST ...` escaped inside the call's own `ok`, as
	 * `fzn_node_events_since` writes it -- these answers first carried an
	 * inner `ok` too, agreeing with a parser that expected one, which the
	 * live test caught. A quote in a subject is
	 * refused, since a subject is printed into `--json`; a page holding more
	 * than room is said as a gap. */
	{
		static char subjects[2][NCFG_FUZZNET_SUBJECT_TEXT];
		static const char *const answers[] = {
			"ok 7%203%20net-observed%20-%20net-drift%20-\n",
			"ok 8%203%20net-%22x%20-\n",
			"ok 9%203%20a%20-%20b%20-%20c%20-\n",
		};
		static const char host[] =
		    "abababababababababababababababababababababababababababababababab";
		size_t next = 0;
		size_t first = 0;
		size_t count = 0;
		int    fine;

		listener = socket(AF_UNIX, SOCK_STREAM, 0);
		(void)unlink(path);
		if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
		    listen(listener, 4) != 0) {
			perror("listen");
			return 1;
		}
		child = fork();
		if (child == 0) {
			size_t page;

			alarm(10);
			for (page = 0; page < sizeof(answers) / sizeof(answers[0]); page++) {
				char line[160];
				int  fd = accept(listener, NULL, NULL);

				if (fd < 0) {
					_exit(1);
				}
				(void)recv(fd, line, sizeof(line), 0);
				(void)send(fd, answers[page], strlen(answers[page]), MSG_NOSIGNAL);
				close(fd);
			}
			_exit(0);
		}
		close(listener);
		fine = ncfg_fuzznet_events_at(path, host, 5u, &next, &first, subjects, 2u, &count, why,
		    sizeof(why));
		check(fine && next == 7u && first == 3u && count == 2u &&
		        strcmp(subjects[0], "net-observed") == 0 && strcmp(subjects[1], "net-drift") == 0,
		    "another node's events read from a cursor, with where to ask from next");
		fine = ncfg_fuzznet_events_at(path, host, 7u, &next, &first, subjects, 2u, &count, why,
		    sizeof(why));
		check(!fine && strstr(why, "not one") != NULL,
		    "  a subject with a quote in it is refused, not printed");
		fine = ncfg_fuzznet_events_at(path, host, 8u, &next, &first, subjects, 2u, &count, why,
		    sizeof(why));
		check(fine && count == 2u && first == next && first > 8u,
		    "  and more than room is said as a gap, not dropped quietly");
		(void)waitpid(child, &status, 0);
	}

	/* The estate's members (10.692): `list peer` in two pages, a contact
	 * among them, which is no member and is left out. */
	{
		static char keys[4][NCFG_FUZZNET_KEY_TEXT];
		static const char *const pages[] = {
			"ok 3 0 "
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,contact\n",
			"ok 3 2 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n",
			"ok 3 0 "
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,contact\n",
			"ok 3 2 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n",
			"ok 1 0 not-a-key\n",
		};
		size_t count = 0;
		int    fine;

		listener = socket(AF_UNIX, SOCK_STREAM, 0);
		(void)unlink(path);
		if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
		    listen(listener, 4) != 0) {
			perror("listen");
			return 1;
		}
		child = fork();
		if (child == 0) {
			size_t page;

			alarm(10);
			for (page = 0; page < sizeof(pages) / sizeof(pages[0]); page++) {
				char line[64];
				int  fd = accept(listener, NULL, NULL);

				if (fd < 0) {
					_exit(1);
				}
				(void)recv(fd, line, sizeof(line), 0);
				(void)send(fd, pages[page], strlen(pages[page]), MSG_NOSIGNAL);
				close(fd);
			}
			_exit(0);
		}
		close(listener);
		fine = ncfg_fuzznet_members(path, keys, 4u, &count, why, sizeof(why));
		check(fine && count == 2u && keys[0][0] == 'a' && keys[1][0] == 'c' &&
		        strlen(keys[1]) == 64u,
		    "the members are every page's keys, and a contact is left out");
		fine = ncfg_fuzznet_members(path, keys, 1u, &count, why, sizeof(why));
		check(!fine && strstr(why, "more than") != NULL,
		    "  more of them than room is said, not a list cut short");
		fine = ncfg_fuzznet_members(path, keys, 4u, &count, why, sizeof(why));
		check(!fine && strstr(why, "not a key") != NULL,
		    "  and a peer that is not a key is refused");
		(void)waitpid(child, &status, 0);
	}
	(void)unlink(path);
	(void)rmdir(dir);
	if (failures) {
		printf("\nfuzznet_line_test: %d check(s) FAILED\n", failures);
		return 1;
	}
	printf("\nfuzznet_line_test: all checks passed\n");
	return 0;
}
