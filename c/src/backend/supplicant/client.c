/*
 * client.c -- the control socket itself.
 *
 * `wpa_supplicant` listens on a unix *datagram* socket, which has a
 * consequence worth stating up front: the client must bind an address of its
 * own, because a datagram socket has nowhere to send the reply otherwise. That
 * bound path is a file in the filesystem, so it has to be created somewhere
 * writable and removed afterwards -- and both of those are this file's problem
 * rather than the caller's.
 */
#include "ncfg/supplicant.h"

#include "supplicant_internal.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/*
 * What a client's own reply socket is called.
 *
 * A datagram client must bind an address to be replied to, and it binds it in
 * the control directory beside the sockets it talks to -- that being the
 * directory both ends are known to be able to write.
 */
#define REPLY_PREFIX "netcfgd-"

/* `IFNAMSIZ` less the terminator, written out rather than included:
 * `linux/if.h` and `net/if.h` redefine each other's structures and this file's
 * callers are entitled to either. */

struct ncfg_supplicant_client {
	int    fd;
	/* Our own bound path, removed when the client is freed. */
	char   local[sizeof(((struct sockaddr_un *)0)->sun_path)];
	/* The interface this socket belongs to, for diagnostics. */
	char   interface[NCFG_INTERFACE_NAME_MAX + 1u];
	/* How long to wait for a reply on this connection. */
	int    timeout_ms;
	/* Whether `ATTACH` succeeded, so the free knows to undo it. */
	int    attached;
};

/*
 * Distinguishes concurrent connections from one process.
 *
 * A counter rather than a clock, because two connections can be opened inside
 * one clock tick. Not atomic, and it does not need to be: nothing in this port
 * has more than one thread, and the Rust's atomic was for a `static` shared by
 * a library that might.
 */
static unsigned long next_serial;

static long long now_ms(void)
{
	struct timespec when;

	/* Monotonic, so a clock stepped by NTP in the middle of a twenty-second
	 * join does not make the wait end early or never. */
	if (clock_gettime(CLOCK_MONOTONIC, &when) != 0) {
		return 0;
	}
	return (long long)when.tv_sec * 1000 + when.tv_nsec / 1000000;
}


int ncfg_supplicant_ctrl_dir(char *out, size_t out_size, char *err, size_t err_size)
{
	const char *set;

	if (!out || out_size == 0u) {
		ncfg_error_set(err, err_size, "a control directory needs somewhere to be put");
		return 0;
	}
	out[0] = '\0';
	set = getenv(NCFG_SUPPLICANT_CTRL_DIR_ENV);
	/* An empty value is the variable not being set. A directory of "" would
	 * make every socket path relative to the working directory, which is a
	 * different machine's worth of answers. */
	if (!set || set[0] == '\0') {
		set = NCFG_SUPPLICANT_CTRL_DIR;
	}
	if (strlen(set) >= out_size) {
		ncfg_error_set(err, err_size, "%s is longer than a control directory may be",
		    NCFG_SUPPLICANT_CTRL_DIR_ENV);
		return 0;
	}
	(void)snprintf(out, out_size, "%s", set);
	return 1;
}

int ncfg_supplicant_is_reply_socket(const char *name)
{
	/* A prefix rather than a parse: the serial and the pid are this file's
	 * business, and a reader only needs to know the entry is ours. */
	return name && strncmp(name, REPLY_PREFIX, sizeof(REPLY_PREFIX) - 1u) == 0;
}

int ncfg_supplicant_nothing_is_listening(int error_number)
{
	return error_number == ENOENT || error_number == ECONNREFUSED;
}

/* Fill in a unix address, or 0 where the path is longer than one holds. */
static int address_for(struct sockaddr_un *out, const char *path)
{
	size_t length = strlen(path);

	if (length >= sizeof(out->sun_path)) {
		return 0;
	}
	memset(out, 0, sizeof(*out));
	out->sun_family = AF_UNIX;
	memcpy(out->sun_path, path, length + 1u);
	return 1;
}

static int set_deadline(int fd, int milliseconds)
{
	struct timeval when;

	when.tv_sec = milliseconds / 1000;
	when.tv_usec = (suseconds_t)((milliseconds % 1000) * 1000);
	return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &when, sizeof(when)) == 0;
}

ncfg_supplicant_client_t *ncfg_supplicant_connect(const char *dir, const char *interface,
    char *err, size_t err_size)
{
	return ncfg_supplicant_connect_within(dir, interface, NCFG_SUPPLICANT_REPLY_TIMEOUT_MS, err,
	    err_size);
}

ncfg_supplicant_client_t *ncfg_supplicant_connect_within(const char *dir, const char *interface,
    int timeout_ms, char *err, size_t err_size)
{
	ncfg_supplicant_client_t *client;
	struct sockaddr_un        address;
	char                      remote[sizeof(address.sun_path)];
	const char               *why;
	struct stat               about;
	int                       written;

	/* Shortening only: a longer value than the default is clamped, so this
	 * cannot be used to make a scan time out. A non-positive one is the
	 * caller asking for the default rather than for a socket that never
	 * waits, which is what a zero `SO_RCVTIMEO` means. */
	if (timeout_ms <= 0 || timeout_ms > NCFG_SUPPLICANT_REPLY_TIMEOUT_MS) {
		timeout_ms = NCFG_SUPPLICANT_REPLY_TIMEOUT_MS;
	}
	if (!dir || dir[0] == '\0') {
		ncfg_error_set(err, err_size, "a control socket needs a directory to be found in");
		return NULL;
	}
	why = ncfg_usable_name(interface);
	if (why) {
		ncfg_error_set(err, err_size, "`%s` is not an interface name: %s",
		    interface ? interface : "", why);
		return NULL;
	}
	written = snprintf(remote, sizeof(remote), "%s/%s", dir, interface);
	if (written < 0 || (size_t)written >= sizeof(remote)) {
		ncfg_error_set(err, err_size,
		    "the control socket for `%s` under %s is a longer path than a unix socket "
		    "may have",
		    interface, dir);
		return NULL;
	}
	if (stat(remote, &about) != 0) {
		ncfg_error_set(err, err_size,
		    "no control socket at %s: is wpa_supplicant running on %s?", remote,
		    interface);
		return NULL;
	}

	client = calloc(1u, sizeof(*client));
	if (!client) {
		ncfg_error_set(err, err_size, "no memory for a connection to %s", interface);
		return NULL;
	}
	client->fd = -1;
	client->timeout_ms = timeout_ms;
	(void)snprintf(client->interface, sizeof(client->interface), "%s", interface);

	/* The local path must be unique per process *and* per connection: two
	 * clients in one process binding the same name is an error, and a stale
	 * file from a crashed run would be too. */
	written = snprintf(client->local, sizeof(client->local), "%s/%s%ld-%lu", dir,
	    REPLY_PREFIX, (long)getpid(), next_serial++);
	if (written < 0 || (size_t)written >= sizeof(client->local)) {
		ncfg_error_set(err, err_size,
		    "a reply socket under %s would be a longer path than a unix socket may have",
		    dir);
		client->local[0] = '\0';
		ncfg_supplicant_client_free(client);
		return NULL;
	}
	(void)unlink(client->local);

	client->fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (client->fd < 0) {
		ncfg_error_set(err, err_size, "cannot make a socket to reach %s: %s", interface,
		    strerror(errno));
		client->local[0] = '\0';
		ncfg_supplicant_client_free(client);
		return NULL;
	}
	if (!address_for(&address, client->local) ||
	    bind(client->fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
		ncfg_error_set(err, err_size, "cannot create a reply socket at %s: %s",
		    client->local, strerror(errno));
		client->local[0] = '\0';
		ncfg_supplicant_client_free(client);
		return NULL;
	}
	if (!set_deadline(client->fd, timeout_ms)) {
		ncfg_error_set(err, err_size, "cannot put a deadline on the socket for %s: %s",
		    interface, strerror(errno));
		ncfg_supplicant_client_free(client);
		return NULL;
	}
	if (!address_for(&address, remote) ||
	    connect(client->fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
		ncfg_error_set(err, err_size, "cannot reach %s: %s", remote, strerror(errno));
		ncfg_supplicant_client_free(client);
		return NULL;
	}
	/* **The `PING` is inside the connect**, which is why the deadline is a
	 * parameter of it: a deadline applied to the returned client would never
	 * cover the one round trip a wedged daemon is most likely to eat. 0114. */
	if (!ncfg_supplicant_ping(client, err, err_size)) {
		ncfg_supplicant_client_free(client);
		return NULL;
	}
	return client;
}

void ncfg_supplicant_client_free(ncfg_supplicant_client_t *client)
{
	if (!client) {
		return;
	}
	/*
	 * **An attached connection is registered inside `wpa_supplicant`**, and
	 * removing the socket underneath it does not unregister anything. The
	 * supplicant finds out on the next event it tries to deliver, logs
	 *
	 *     CTRL_IFACE: Detach monitor that cannot receive messages: ...
	 *
	 * and drops it then. Harmless once; this connection is made and dropped
	 * for every `ncfg wifi scan` (0194), so without this each scan leaves a
	 * monitor for the supplicant to trip over.
	 *
	 * **Sent, not asked.** Waiting for `OK` would take this connection's
	 * whole deadline against a supplicant that has stopped answering, on a
	 * code path whose only job is to let go.
	 */
	if (client->fd >= 0) {
		if (client->attached) {
			(void)send(client->fd, "DETACH", 6u, MSG_NOSIGNAL);
		}
		(void)close(client->fd);
	}
	/* The bound path is a real file. Leaving it behind fills the control
	 * directory with dead sockets, and the next reader of that directory
	 * cannot tell which are live. */
	if (client->local[0] != '\0') {
		(void)unlink(client->local);
	}
	free(client);
}

int ncfg_supplicant_client_descriptor(const ncfg_supplicant_client_t *client)
{
	return client ? client->fd : -1;
}

int ncfg_supplicant_request_labelled(ncfg_supplicant_client_t *client, const char *command,
    const char *label, char *body, size_t body_size, int *kind, char *err, size_t err_size)
{
	char      buffer[NCFG_SUPPLICANT_REPLY_MAX + 1u];
	long long deadline;
	size_t    index;

	if (!client || !command || !body || body_size == 0u) {
		ncfg_error_set(err, err_size, "a control command needs a client and a reply buffer");
		return 0;
	}
	body[0] = '\0';
	/* A command containing a newline would be read as two, and the second
	 * would run without ever having been reviewed by whatever built the
	 * first. Everything reaching here is built by this module, so this is a
	 * backstop rather than the control -- but it is the kind of backstop that
	 * turns a future mistake into an error instead of an incident. */
	for (index = 0; command[index] != '\0'; index++) {
		if (command[index] == '\n' || command[index] == '\r') {
			ncfg_error_set(err, err_size,
			    "a control command cannot contain a newline");
			return 0;
		}
	}
	if (index == 0u) {
		ncfg_error_set(err, err_size, "a control command cannot be empty");
		return 0;
	}
	if (send(client->fd, command, index, MSG_NOSIGNAL) < 0) {
		ncfg_error_set(err, err_size, "cannot send `%s` to %s: %s", label,
		    client->interface, strerror(errno));
		return 0;
	}

	/* Events share this socket once anything has attached, and they arrive
	 * interleaved with replies. Reading one as the answer to a command is the
	 * classic bug in a `wpa_supplicant` client -- it produces a status display
	 * that occasionally reports the previous command's outcome. */
	deadline = now_ms() + client->timeout_ms;
	for (;;) {
		ssize_t read = recv(client->fd, buffer, NCFG_SUPPLICANT_REPLY_MAX, 0);

		if (read < 0 && errno == EINTR) {
			/*
			 * **0233's case, at the other socket netcfgd blocks in.** A
			 * signal arriving mid-`recv` means *call it again* and nothing
			 * else: netcfgd spawns a child every time it runs a hook or
			 * starts a client, so `SIGCHLD` lands here on an ordinary day,
			 * and the handlers this daemon installs carry no `SA_RESTART`
			 * deliberately -- `EINTR` is handled where it arrives.
			 *
			 * Found live rather than by reading: `ncfg wifi connect` on the
			 * machine this was written on failed with *the supplicant on
			 * wlp0s20f3 stopped answering: Interrupted system call*, which is
			 * the event read below saying the same thing (project.md 10.234).
			 *
			 * It cannot spin. Every one of these is a signal that really
			 * arrived, and what is left of the **same** deadline is what
			 * bounds the retry -- the socket carries `SO_RCVTIMEO` as well,
			 * so an interrupted wait resumes with its own ceiling rather than
			 * a fresh one.
			 */
			if (now_ms() < deadline) {
				continue;
			}
			ncfg_error_set(err, err_size,
			    "no reply to `%s` from %s within %dms; the waits were interrupted by "
			    "signals and the deadline is what ran out", label, client->interface,
			    client->timeout_ms);
			return 0;
		}
		if (read < 0) {
			ncfg_error_set(err, err_size, "no reply to `%s` from %s: %s", label,
			    client->interface, strerror(errno));
			return 0;
		}
		/*
		 * **A reply that fills the buffer is an error, not an answer.** A
		 * unix datagram is truncated silently, so an oversized
		 * `SCAN_RESULTS` would come back as a shorter list with the last row
		 * cut mid-field and nothing saying the list was incomplete -- and a
		 * network missing from a scan because it was truncated off the end
		 * looks exactly like a network that is not there. 0224.
		 */
		if ((size_t)read == NCFG_SUPPLICANT_REPLY_MAX) {
			ncfg_error_set(err, err_size,
			    "the reply to `%s` filled the %u-byte buffer and was probably cut "
			    "short; a truncated answer is not reported as an answer",
			    label, (unsigned)NCFG_SUPPLICANT_REPLY_MAX);
			return 0;
		}
		buffer[read] = '\0';
		if (ncfg_supplicant_is_event(buffer)) {
			if (now_ms() >= deadline) {
				ncfg_error_set(err, err_size, "no reply to `%s`, only events",
				    label);
				return 0;
			}
			continue;
		}
		if (strlen(buffer) >= body_size) {
			ncfg_error_set(err, err_size,
			    "the reply to `%s` is %zu bytes and there is room for %zu", label,
			    strlen(buffer), body_size - 1u);
			return 0;
		}
		(void)snprintf(body, body_size, "%s", buffer);
		{
			int answered = ncfg_supplicant_reply_parse(body);

			if (kind) {
				*kind = answered;
			}
		}
		return 1;
	}
}

int ncfg_supplicant_request(ncfg_supplicant_client_t *client, const char *command, char *body,
    size_t body_size, int *kind, char *err, size_t err_size)
{
	/* The label is the command, which is right for every command that is not
	 * a `SET_NETWORK` carrying a credential. Those go through
	 * `ncfg_supplicant_request_labelled` with the redacted line as the label,
	 * and `supplicant_internal.h` says why that is a separate entry point
	 * rather than a rule each call site keeps. */
	return ncfg_supplicant_request_labelled(client, command, command, body, body_size, kind,
	    err, err_size);
}

int ncfg_supplicant_ask(ncfg_supplicant_client_t *client, const char *command, char *body,
    size_t body_size, char *err, size_t err_size)
{
	int kind = NCFG_SUPPLICANT_REPLY_FAIL;

	if (!ncfg_supplicant_request(client, command, body, body_size, &kind, err, err_size)) {
		return 0;
	}
	if (kind == NCFG_SUPPLICANT_REPLY_FAIL) {
		ncfg_error_set(err, err_size, "wpa_supplicant refused `%s`", command);
		return 0;
	}
	return 1;
}

int ncfg_supplicant_command(ncfg_supplicant_client_t *client, const char *command, char *err,
    size_t err_size)
{
	char body[NCFG_SUPPLICANT_REPLY_MAX];
	int  kind = NCFG_SUPPLICANT_REPLY_FAIL;

	if (!ncfg_supplicant_request(client, command, body, sizeof(body), &kind, err, err_size)) {
		return 0;
	}
	if (kind != NCFG_SUPPLICANT_REPLY_OK) {
		ncfg_error_set(err, err_size, "`%s` answered %s rather than OK", command,
		    kind == NCFG_SUPPLICANT_REPLY_FAIL ? "FAIL" : body);
		return 0;
	}
	return 1;
}

int ncfg_supplicant_ping(ncfg_supplicant_client_t *client, char *err, size_t err_size)
{
	char body[NCFG_SUPPLICANT_REPLY_MAX];
	int  kind = NCFG_SUPPLICANT_REPLY_FAIL;

	if (!ncfg_supplicant_request(client, "PING", body, sizeof(body), &kind, err, err_size)) {
		return 0;
	}
	if (kind != NCFG_SUPPLICANT_REPLY_DATA || strcmp(body, "PONG") != 0) {
		ncfg_error_set(err, err_size, "PING answered %s rather than PONG",
		    kind == NCFG_SUPPLICANT_REPLY_FAIL ? "FAIL" : body);
		return 0;
	}
	return 1;
}

int ncfg_supplicant_attach(ncfg_supplicant_client_t *client, char *err, size_t err_size)
{
	if (!ncfg_supplicant_command(client, "ATTACH", err, err_size)) {
		return 0;
	}
	client->attached = 1;
	return 1;
}

int ncfg_supplicant_next_event(ncfg_supplicant_client_t *client, int timeout_ms,
    ncfg_supplicant_event_t *out, int *got, char *err, size_t err_size)
{
	char    buffer[NCFG_SUPPLICANT_REPLY_MAX + 1u];
	ssize_t read;

	if (!client || !out || !got) {
		ncfg_error_set(err, err_size, "an event needs a client and somewhere to be put");
		return 0;
	}
	*got = 0;
	/*
	 * **A timeout of zero is refused rather than clamped, because zero is the
	 * one value that means the opposite of what a caller would read it as.**
	 * `SO_RCVTIMEO` of `{0, 0}` is the kernel's "no deadline at all", so a
	 * caller asking for the shortest possible wait -- which is what the
	 * header's "a caller polling several interfaces wants a short one" invites
	 * -- would get `recv` blocking for ever. On the daemon's single thread
	 * that is not a slow path, it is a wedge, and it would present as a
	 * netcfgd that has stopped reconciling with nothing in the log.
	 *
	 * A negative used to be clamped to zero, which turned "I got the sign
	 * wrong" into the same wedge. Both are now a sentence at the call site,
	 * where the mistake is.
	 */
	if (timeout_ms < 1) {
		ncfg_error_set(err, err_size,
		    "an event needs a timeout of at least 1ms, not %d: zero is the kernel's "
		    "\"no deadline\" and would wait for ever", timeout_ms);
		return 0;
	}
	if (!set_deadline(client->fd, timeout_ms)) {
		ncfg_error_set(err, err_size, "cannot put a deadline on the socket for %s: %s",
		    client->interface, strerror(errno));
		return 0;
	}
	read = recv(client->fd, buffer, NCFG_SUPPLICANT_REPLY_MAX, 0);
	/*
	 * **The connection's own deadline is put back**, which the Rust does not
	 * do. There, a poll for an event leaves `SO_RCVTIMEO` at the poll's
	 * interval, so the next command on that connection silently takes a
	 * quarter-second deadline instead of the one the connect was given. No
	 * caller does both today; one that did would get a wedged supplicant
	 * reported as an unresponsive one for reasons nothing anywhere states.
	 */
	(void)set_deadline(client->fd, client->timeout_ms);
	if (read < 0) {
		/* The two a timeout arrives as, and the interruption that is not a
		 * timeout at all. Nothing arriving is the ordinary answer on a quiet
		 * radio and is not a failure; neither is a signal. */
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			/*
			 * **`EINTR` is answered as "nothing yet", which is 0233's own
			 * remedy.** That decision put it this way: it "is reported as
			 * nothing yet, the same answer a timeout gets, so the caller's
			 * existing loop simply asks again". The comment above listed the
			 * two spellings of a timeout and left the interruption out, which
			 * is how a signal came to be reported as a supplicant that had
			 * died -- measured on this machine, aborting an `ncfg wifi
			 * connect` mid-join (project.md 10.234).
			 */
			return 1;
		}
		ncfg_error_set(err, err_size, "the supplicant on %s stopped answering: %s",
		    client->interface, strerror(errno));
		return 0;
	}
	if ((size_t)read == NCFG_SUPPLICANT_REPLY_MAX) {
		ncfg_error_set(err, err_size,
		    "an event filled the %u-byte buffer and was probably cut short",
		    (unsigned)NCFG_SUPPLICANT_REPLY_MAX);
		return 0;
	}
	buffer[read] = '\0';
	/* Replies are skipped rather than returned. Nothing should be issuing
	 * commands on an attached connection, and if something does, its answer is
	 * not an event and must not be handed back as one. */
	*got = ncfg_supplicant_event_parse(buffer, out);
	return 1;
}

/* ---------------------------------------------------------------- the reaper */

/* Whether `name` is exactly `netcfgd-<pid>-<serial>`, and which pid it names. */
static int shaped_like_ours(const char *name, long *pid_out)
{
	const char *rest;
	const char *dash;
	long        pid = 0;
	size_t      index;

	if (!ncfg_supplicant_is_reply_socket(name)) {
		return 0;
	}
	rest = name + sizeof(REPLY_PREFIX) - 1u;
	dash = strchr(rest, '-');
	if (!dash || dash == rest || dash[1] == '\0') {
		return 0;
	}
	for (index = 0; rest[index] != '\0'; index++) {
		if (rest[index] == '-') {
			continue;
		}
		if (rest[index] < '0' || rest[index] > '9') {
			return 0;
		}
	}
	/* Exactly one separator: `netcfgd-0-1-2` did not come from here. */
	if (strchr(dash + 1, '-')) {
		return 0;
	}
	for (index = 0; rest + index < dash; index++) {
		pid = pid * 10 + (rest[index] - '0');
		if (pid > 0x7fffffff) {
			return 0;
		}
	}
	*pid_out = pid;
	return 1;
}

size_t ncfg_supplicant_reap_reply_sockets(const char *dir)
{
	DIR                 *open_dir;
	const struct dirent *found;
	size_t               removed = 0;
	long                 mine = (long)getpid();

	if (!dir) {
		return 0;
	}
	open_dir = opendir(dir);
	if (!open_dir) {
		return 0;
	}
	while ((found = readdir(open_dir)) != NULL) {
		char               path[sizeof(((struct sockaddr_un *)0)->sun_path)];
		struct stat        about;
		struct sockaddr_un address;
		long               pid = 0;
		int                probe;
		int                written;

		if (!shaped_like_ours(found->d_name, &pid) || pid == mine) {
			continue;
		}
		written = snprintf(path, sizeof(path), "%s/%s", dir, found->d_name);
		if (written < 0 || (size_t)written >= sizeof(path)) {
			continue;
		}
		/* `lstat`, so a symlink is never followed to whatever it points at:
		 * this removes what it finds, and a name shaped like ours pointing
		 * somewhere else is not ours to remove. */
		if (lstat(path, &about) != 0 || !S_ISSOCK(about.st_mode)) {
			continue;
		}
		if (!address_for(&address, path)) {
			continue;
		}
		probe = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (probe < 0) {
			continue;
		}
		/*
		 * **The kernel's own answer to "does anyone have this address open".**
		 * A successful connect means a live unconnected socket; `EPERM` is
		 * the kernel refusing to connect to one that is already connected
		 * elsewhere, which every live reply socket is. Only `ECONNREFUSED`
		 * means nobody has it bound, and that is the definition of a stale
		 * socket file rather than a guess at one -- which is what asking
		 * `/proc/<pid>` was, since a pid is a name that gets reused. 0224.
		 */
		if (connect(probe, (const struct sockaddr *)&address, sizeof(address)) == 0) {
			(void)close(probe);
			continue;
		}
		if (errno != ECONNREFUSED) {
			(void)close(probe);
			continue;
		}
		(void)close(probe);
		if (unlink(path) == 0) {
			removed++;
		}
	}
	(void)closedir(open_dir);
	return removed;
}

/* ----------------------------------------------------------------- the waits */

/* Capped so a supplicant that goes quiet is noticed at the deadline rather
 * than one poll interval after it. */
#define POLL_SLICE_MS 250

int ncfg_supplicant_wait_for_scan(ncfg_supplicant_client_t *client, int patience_ms, char *err,
    size_t err_size)
{
	long long deadline = now_ms() + patience_ms;

	for (;;) {
		ncfg_supplicant_event_t event;
		long long               left = deadline - now_ms();
		int                     got = 0;
		char                    name[64];

		if (left <= 0) {
			ncfg_error_set(err, err_size, "the scan did not finish within %ds",
			    patience_ms / 1000);
			return 0;
		}
		if (!ncfg_supplicant_next_event(client, left < POLL_SLICE_MS ? (int)left :
		    POLL_SLICE_MS, &event, &got, err, err_size)) {
			return 0;
		}
		if (!got) {
			continue;
		}
		(void)ncfg_supplicant_event_name(&event, name, sizeof(name));
		if (strcmp(name, "CTRL-EVENT-SCAN-RESULTS") == 0) {
			return 1;
		}
		if (strcmp(name, "CTRL-EVENT-SCAN-FAILED") == 0) {
			/* `ret=` is the driver's own errno, negated: -16 is EBUSY, a
			 * radio doing something else, and -100 is ENETDOWN. Passed
			 * through rather than translated, because the set is the
			 * kernel's and any translation here would be a partial one. */
			char code[64];

			if (ncfg_supplicant_event_field(&event, "ret", code, sizeof(code))) {
				ncfg_error_set(err, err_size,
				    "the supplicant could not scan (ret=%s)", code);
			} else {
				ncfg_error_set(err, err_size, "the supplicant could not scan");
			}
			return 0;
		}
	}
}

int ncfg_supplicant_wait_for_connect(ncfg_supplicant_client_t *client, int patience_ms,
    char *err, size_t err_size)
{
	long long deadline = now_ms() + patience_ms;

	for (;;) {
		ncfg_supplicant_event_t event;
		long long               left = deadline - now_ms();
		int                     got = 0;
		char                    name[64];
		char                    why[128];
		char                    count[64];

		if (left <= 0) {
			ncfg_error_set(err, err_size,
			    "it did not join within %ds, and the supplicant did not say why",
			    patience_ms / 1000);
			return 0;
		}
		if (!ncfg_supplicant_next_event(client, left < POLL_SLICE_MS ? (int)left :
		    POLL_SLICE_MS, &event, &got, err, err_size)) {
			return 0;
		}
		if (!got) {
			continue;
		}
		(void)ncfg_supplicant_event_name(&event, name, sizeof(name));
		if (strcmp(name, "CTRL-EVENT-CONNECTED") == 0) {
			return 1;
		}
		if (strcmp(name, "CTRL-EVENT-SSID-TEMP-DISABLED") == 0) {
			/* The supplicant has given up on this network for a while. Its
			 * `reason` is worth more than any sentence here -- `WRONG_KEY`
			 * and `CONN_FAILED` send a person to different places -- so it is
			 * passed through. */
			if (ncfg_supplicant_event_field(&event, "reason", why, sizeof(why))) {
				if (ncfg_supplicant_event_field(&event, "auth_failures", count,
				    sizeof(count))) {
					ncfg_error_set(err, err_size,
					    "the supplicant gave up after %s failed attempt(s): %s",
					    count, why);
				} else {
					ncfg_error_set(err, err_size,
					    "the supplicant gave up: %s", why);
				}
			} else {
				ncfg_error_set(err, err_size,
				    "the supplicant gave up on this network");
			}
			return 0;
		}
		if (strcmp(name, "CTRL-EVENT-AUTH-REJECT") == 0 ||
		    strcmp(name, "CTRL-EVENT-ASSOC-REJECT") == 0) {
			if (ncfg_supplicant_event_field(&event, "status_code", why, sizeof(why))) {
				ncfg_error_set(err, err_size,
				    "the access point refused this station, status %s", why);
			} else {
				ncfg_error_set(err, err_size,
				    "the access point refused this station");
			}
			return 0;
		}
		/* **A disconnect is not a failure.** `SELECT_NETWORK` leaves whatever
		 * the radio was on before it, so a disconnect is the ordinary first
		 * step of a join and treating it as the outcome would fail every
		 * successful switch between networks. */
	}
}
