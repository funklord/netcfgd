/*
 * fuzznet_line_test.c -- the escape, and the bounded one-line conversation
 * (`src/host/fuzznet_line.c`, 10.688), against a scripted socket.
 *
 * WHAT IS CHECKED
 *   The escape round-trips every byte, unescaping refuses a broken `%XX` and
 *   an output that does not fit, and a reply is read whole; a socket that
 *   never answers is given up on within the wait, and none there is said to
 *   be silent rather than refusing.
 *
 * HOW IT STOPS: the server child serves three connections and exits, under
 * `alarm(10)` either way; the scratch directory is mkdtemp's and its two
 * names are removed by name.
 */
#include "ncfg/fuzznet_line.h"

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

	(void)waitpid(child, &status, 0);
	check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "the server served all three");
	(void)unlink(path);
	(void)rmdir(dir);
	if (failures) {
		printf("\nfuzznet_line_test: %d check(s) FAILED\n", failures);
		return 1;
	}
	printf("\nfuzznet_line_test: all checks passed\n");
	return 0;
}
