/*
 * server.c -- the control socket: one thread per connection.
 *
 * No epoll, no async runtime: a blocking accept and a blocking read per
 * connection, with the seam that answers a request called under one lock. That
 * keeps the daemon's state effectively single-threaded and costs a thread per
 * client on a socket that will normally have one or two.
 *
 * **The thread per connection is the part with a reason.** A client that stops
 * reading blocks only itself; a readiness loop would need writes buffered per
 * connection as well as reads, which is a great deal of machinery for a socket
 * with two clients on it.
 *
 * WHERE THIS DIFFERS FROM THE RUST, AND WHY
 *   The Rust hands each request to a single-threaded event loop over an
 *   `mpsc` channel and gets a `Response` back on a reply channel. The C calls
 *   the answering seam directly, under a mutex. The property both buy is the
 *   same one -- only one thread is ever inside the daemon's state -- and the
 *   channel version in C would be a queue, a condition variable and a reply
 *   channel per request: three more things to get wrong for no further
 *   guarantee. What is given up is that the loop cannot do anything *else*
 *   while an answer is being computed, which the Rust's version can; nothing
 *   in this module needs that yet, and the reconcile loop that would is not
 *   ported.
 *
 *   **The socket write happens after the lock is released**, which is what
 *   keeps a slow client from stalling everybody: the answer is built into a
 *   buffer under the lock and sent outside it.
 *
 *   **`monitor` is special-cased here in both**, and that is not an accident
 *   of either design: it is the one request whose answer is the connection
 *   itself, and the seam that answers requests is handed no descriptor. See
 *   `serve_monitor`.
 */
#include "ncfg/daemon.h"

#include "ncfg/log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* One open connection. */
typedef struct {
	int                   in_use;
	int                   has_thread;
	pthread_t             thread;
	/* -1 once the connection thread has taken it back to close it, which is
	 * what lets `stop` tell a live descriptor from a number that may already
	 * have been reused. */
	int                   fd;
	struct ncfg_daemon_server *server;
} ncfg_daemon_slot_t;

struct ncfg_daemon_server {
	int                         listener;
	char                        path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	ncfg_arrival_t               arrival;
	const ncfg_control_t       *control;
	const ncfg_remote_policy_t *remote;
	ncfg_authz_roots_t          roots;
	ncfg_daemon_answer_fn       answer;
	ncfg_daemon_stream_fn       stream;
	void                       *context;
	pthread_mutex_t             lock;
	pthread_t                   acceptor;
	int                         acceptor_live;
	int                         stopping;
	ncfg_daemon_slot_t          slots[NCFG_DAEMON_MAX_CONNECTIONS];
};

/* ------------------------------------------------------------ the policy */

/*
 * Give the socket permissions that match what the policy promises.
 *
 * A policy naming a group is a lie if the socket stays root-only, because the
 * caller cannot connect to be told yes. So the mode follows the most
 * permissive tier, and where a tier names a group the socket is given to it.
 *
 * Where that cannot be done -- no such group, or this process is not root --
 * this says so loudly rather than leaving a root-only socket under a config
 * that claims otherwise. That combination produces a bug report about wifi not
 * working which takes an afternoon to trace.
 */
static void apply_policy_permissions(const char *path, const ncfg_principal_t *const *reach,
    size_t reach_count, const ncfg_authz_roots_t *roots)
{
	mode_t      mode = 0600;
	/* At most one per principal, and `reach` is three principals for the local
	 * socket and one for the remote. */
	const char *groups[3];
	size_t      group_count = 0;
	size_t      at;
	gid_t       gid;

	for (at = 0; at < reach_count; at++) {
		const ncfg_principal_t *one = reach[at];

		if (!one) {
			continue;
		}
		if (one->kind == NCFG_PRINCIPAL_ANY) {
			mode = 0666;
		} else if (one->kind != NCFG_PRINCIPAL_ROOT && mode != 0666) {
			mode = 0660;
		}
		if (one->kind == NCFG_PRINCIPAL_GROUP && one->name && one->name[0] &&
		    group_count < sizeof(groups) / sizeof(groups[0])) {
			/*
			 * Deduplicated over the whole set rather than against the first
			 * one, because the count is what a warning reads. The policy
			 * `debian/postinst` prints names the same group for `observe`
			 * and `wifi`, which is the ordinary desktop case -- and it
			 * produced "the control policy names 2 groups (netcfgd,
			 * netcfgd)", warning about others that do not exist. A
			 * diagnostic that fires on the recommended configuration is one
			 * people learn to scroll past.
			 */
			size_t seen;
			int    already = 0;

			for (seen = 0; seen < group_count; seen++) {
				if (strcmp(groups[seen], one->name) == 0) {
					already = 1;
				}
			}
			if (!already) {
				groups[group_count] = one->name;
				group_count++;
			}
		}
	}

	if (chmod(path, mode) != 0) {
		ncfg_log_emitf("control", NCFG_LOG_ERROR,
		    "could not set socket mode %o: %s", (unsigned)mode, strerror(errno));
	}
	if (group_count == 0) {
		return;
	}
	if (group_count > 1) {
		ncfg_log_emitf("control", NCFG_LOG_WARNING,
		    "the control policy names %lu groups; the socket can belong to one, so it "
		    "is given to `%s`. Members of the others will not be able to connect.",
		    (unsigned long)group_count, groups[0]);
	}
	if (!ncfg_peer_group_id(roots->group_file, groups[0], &gid)) {
		ncfg_log_emitf("control", NCFG_LOG_WARNING,
		    "the control policy names group `%s`, which does not exist in the group "
		    "file. Nobody outside root will be able to connect.",
		    groups[0]);
		return;
	}
	/* The owner is left alone: -1 means "unchanged", and a socket whose owner
	 * moved would be a second change nobody asked for. */
	if (chown(path, (uid_t)-1, gid) != 0) {
		ncfg_log_emitf("control", NCFG_LOG_WARNING,
		    "the control policy opens access to group `%s`, but the socket could not "
		    "be given to it: %s. Nobody outside root will be able to connect.",
		    groups[0], strerror(errno));
	}
}

/* ------------------------------------------------------------- the slots */

/*
 * Take a slot, or NULL where the cap is reached.
 *
 * A finished thread's slot is joined before it is handed out again, which is
 * where every connection thread is reaped: a detached thread would need no
 * join and would also give `stop` nothing to wait on, and a server that
 * returned with threads still reading from descriptors it had closed is the
 * defect this module must not have.
 */
static ncfg_daemon_slot_t *slot_take(ncfg_daemon_server_t *server)
{
	size_t at;

	pthread_mutex_lock(&server->lock);
	for (at = 0; at < NCFG_DAEMON_MAX_CONNECTIONS; at++) {
		ncfg_daemon_slot_t *slot = &server->slots[at];

		if (slot->in_use) {
			continue;
		}
		if (slot->has_thread) {
			/* Not in use means the thread cleared it as its last act under
			 * this lock and then returned, so this join does not wait on
			 * anything but the unwinding. */
			pthread_join(slot->thread, NULL);
			slot->has_thread = 0;
		}
		slot->in_use = 1;
		slot->fd = -1;
		slot->server = server;
		pthread_mutex_unlock(&server->lock);
		return slot;
	}
	pthread_mutex_unlock(&server->lock);
	return NULL;
}

static void slot_release(ncfg_daemon_server_t *server, ncfg_daemon_slot_t *slot)
{
	pthread_mutex_lock(&server->lock);
	slot->in_use = 0;
	pthread_mutex_unlock(&server->lock);
}

size_t ncfg_daemon_server_open(const ncfg_daemon_server_t *server)
{
	size_t open = 0;
	size_t at;

	if (!server) {
		return 0;
	}
	pthread_mutex_lock(&((ncfg_daemon_server_t *)server)->lock);
	for (at = 0; at < NCFG_DAEMON_MAX_CONNECTIONS; at++) {
		if (server->slots[at].in_use) {
			open++;
		}
	}
	pthread_mutex_unlock(&((ncfg_daemon_server_t *)server)->lock);
	return open;
}

const char *ncfg_daemon_server_path(const ncfg_daemon_server_t *server)
{
	return server ? server->path : NULL;
}

/* --------------------------------------------------------- a connection */

/* Build a refusal and send it. Failure to send is a client that went away,
 * which is ordinary and silent. */
static void send_error(int fd, const char *message)
{
	ncfg_buf_t line;
	char       err[NCFG_ERROR_MAX];

	ncfg_buf_init(&line, NCFG_PROTO_MAX_LINE);
	if (ncfg_daemon_error_encode(message, &line, err, sizeof(err))) {
		(void)ncfg_daemon_line_write(fd, &line, err, sizeof(err));
	}
	ncfg_buf_free(&line);
}

/*
 * `monitor`: the connection stops being a conversation and becomes a stream.
 *
 * WHY THIS IS HERE AND NOT BEHIND THE ANSWER SEAM
 *   That seam is handed a request and a buffer and no descriptor, so there is
 *   nothing it could give away. The Rust special-cases `monitor` in its server
 *   for the same reason, beside the loop the stream is handed to.
 *
 * WHAT IS HANDED OVER, AND WHY IT IS A COPY
 *   A `dup`, never this connection's own number. Two owners closing one
 *   descriptor is how a daemon comes to write one client's events into
 *   another client's socket -- the first close frees the number, the kernel
 *   hands it to the next `accept`, and the second close takes that one away.
 *   With a copy each side closes exactly what it opened, and the *socket*
 *   outlives this thread because the copy still refers to it.
 *
 * WHY THE THREAD THEN ENDS RATHER THAN PARKING ON THE CONNECTION
 *   Three reasons, and the first is the one that decides it. The seam puts the
 *   descriptor in non-blocking mode -- it must, since the loop writes events
 *   from the thread that reconciles -- and `O_NONBLOCK` belongs to the open
 *   file description, which a `dup` *shares*. A parked `recv` on this side
 *   would therefore return `EAGAIN` at once, for ever: a thread spinning at
 *   100% CPU for as long as somebody is watching events.
 *
 *   Second, a parked thread holds one of `NCFG_DAEMON_MAX_CONNECTIONS` slots
 *   for the life of the stream, and a monitor stream is measured in hours.
 *   Sixteen of them -- which is `NCFG_MAIN_SUBSCRIBERS_MAX` -- would be
 *   sixteen slots held by threads with nothing left to read.
 *
 *   Third, there is nothing worth learning from this side. End of stream on
 *   the read half is *not* proof the client has gone: a client may
 *   `shutdown(SHUT_WR)` once it has asked and go on reading events for hours.
 *   The one reliable signal that a subscriber is gone is a write that fails,
 *   and that belongs to whoever writes.
 *
 *   So the connection is handed over whole and this thread returns. The client
 *   keeps its socket, the slot is released, and anything the client sends
 *   afterwards is unread -- which is what the Rust does too, its thread
 *   forwarding events and never reading again.
 */
static int serve_monitor(ncfg_daemon_server_t *server, int fd)
{
	char err[NCFG_ERROR_MAX];
	int  copy;
	int  took;

	if (!server->stream) {
		/* Named rather than bare. A client told only `error` reads it as a
		 * request the daemon did not recognise, and `monitor` is a verb this
		 * daemon does speak -- it has nowhere to put the connection. */
		send_error(fd, "this daemon does not stream events: nothing in it takes a "
		    "subscribed connection, so `monitor` would subscribe to a stream that "
		    "can never carry anything");
		return 1;
	}
	copy = dup(fd);
	if (copy < 0) {
		char message[160];

		(void)snprintf(message, sizeof(message),
		    "this connection could not be handed over to be streamed to: %s",
		    strerror(errno));
		send_error(fd, message);
		return 1;
	}
	/* `dup` clears it, and a stream that survived an exec would be a
	 * descriptor a hook's child could write events into. */
	(void)fcntl(copy, F_SETFD, FD_CLOEXEC);
	err[0] = '\0';
	/* Under the lock, exactly as the answer seam is: the same implementation
	 * is on the other side of both, and a subscription arriving while a
	 * request is being answered would be a second thread inside it. */
	pthread_mutex_lock(&server->lock);
	took = server->stream(server->context, copy, err, sizeof(err));
	pthread_mutex_unlock(&server->lock);
	if (!took) {
		/* Still the server's, so the server closes it. A failed hand-over
		 * that had closed the copy *and* left the seam holding the number is
		 * the double close this whole arrangement exists to avoid. */
		(void)close(copy);
		send_error(fd, err[0] ? err : "this daemon could not take a subscription");
		/* **A refusal does not end the connection**, here as everywhere else:
		 * a client refused a stream is entitled to ask something smaller. */
		return 1;
	}
	return 0;
}

/*
 * One decoded request, answered.
 *
 * Returns 1 to go on serving this connection and 0 to end it. **A refusal does
 * not end it**: a refusal is an answer, and a client that asked for something
 * beyond its tier is entitled to ask for something else.
 */
static int serve_one(ncfg_daemon_server_t *server, int fd, const ncfg_peer_t *peer,
    const ncfg_proto_request_t *request)
{
	ncfg_buf_t line;
	char       err[NCFG_ERROR_MAX];
	int        built;

	/*
	 * **One gate call, not two.** Forgetting the content gate is invisible --
	 * every test of it calls it directly and passes whether or not the daemon
	 * does -- which is why there is one function to call and this is the only
	 * place that calls anything.
	 */
	if (!ncfg_authz_permitted(&server->roots, server->control, server->remote, server->arrival,
	        peer, request, err, sizeof(err))) {
		send_error(fd, err);
		return 1;
	}

	/*
	 * **After the gate and before anything else**, which is the order that
	 * matters: `monitor` needs the `observe` tier, and a connection handed to
	 * the event stream before that was asked would be a subscription nobody
	 * checked. Like `hello`, it never reaches the answer seam -- see
	 * `serve_monitor` for why it cannot.
	 */
	if (request->kind == NCFG_PROTO_REQ_MONITOR) {
		return serve_monitor(server, fd);
	}

	ncfg_buf_init(&line, NCFG_PROTO_MAX_LINE);
	err[0] = '\0';
	if (request->kind == NCFG_PROTO_REQ_HELLO) {
		/*
		 * **Answered here rather than through the seam**, because everything
		 * `hello` carries is this module's: the protocol version, the schema
		 * version and the tiers *this connection* satisfies. Handing it out
		 * would mean the seam asking "may I" a second way, and a second
		 * implementation of that question is precisely what 0092 exists to
		 * prevent -- a client told it holds a tier it does not puts a button
		 * on a screen that fails when pressed.
		 */
		ncfg_tier_t told[NCFG_TIER_COUNT];
		size_t      count = ncfg_authz_granted(&server->roots, server->control,
		    server->remote, server->arrival, peer, told);

		if (!ncfg_daemon_hello_encode(told, count, &line, err, sizeof(err))) {
			ncfg_buf_free(&line);
			send_error(fd, err);
			return 1;
		}
		if (!ncfg_daemon_line_write(fd, &line, err, sizeof(err))) {
			ncfg_buf_free(&line);
			return 0;
		}
		ncfg_buf_free(&line);
		return 1;
	}
	pthread_mutex_lock(&server->lock);
	built = server->answer
	    ? server->answer(server->context, request, peer, server->arrival, &line, err, sizeof(err))
	    : 0;
	pthread_mutex_unlock(&server->lock);
	if (!built) {
		/*
		 * **Said in the log as well as to the client**, which it was not.
		 * A refused request went back over the socket and left no trace here
		 * at all -- so a `wifi connect` that failed mid-join on the machine
		 * this was written on showed the operator a sentence and the daemon's
		 * own log three startup lines, with nothing to say a request had ever
		 * arrived (project.md 10.234). A daemon whose log cannot be read
		 * afterwards to find out what it was asked is one nobody can debug
		 * from the evidence.
		 *
		 * A note rather than an error: most of these are the client being
		 * told no -- a name that is not a name, a tier it does not hold --
		 * which is the control socket working, not the daemon failing.
		 */
		const char *what = ncfg_proto_request_name(request->kind);

		ncfg_log_emitf("control", NCFG_LOG_NOTE, "`%s` was refused: %s",
		    what ? what : "a request", err[0] ? err : "no reason given");
		ncfg_buf_free(&line);
		send_error(fd, err[0] ? err : "the daemon had no answer for that");
		return 1;
	}
	if (!ncfg_daemon_line_write(fd, &line, err, sizeof(err))) {
		/*
		 * A client that hung up mid-answer is ordinary and silent. A response
		 * that will not frame is a bug here, and one that presents to the
		 * operator as "the daemon closed the connection without answering" --
		 * indistinguishable from a crash, with nothing anywhere saying
		 * otherwise. It cost a probe to find once.
		 */
		if (ncfg_buf_failed(&line)) {
			ncfg_log_emitf("control", NCFG_LOG_ERROR,
			    "could not serialise a response, which is a bug: %s. The client was "
			    "told nothing.",
			    err);
		}
		ncfg_buf_free(&line);
		return 0;
	}
	ncfg_buf_free(&line);
	return 1;
}

/* Clear the first-request deadline. See `NCFG_DAEMON_FIRST_REQUEST_SECONDS`:
 * what it is for is a connection that never speaks, and one that has spoken is
 * a client, which is allowed to be quiet. */
static void clear_deadline(int fd)
{
	struct timeval none;

	none.tv_sec = 0;
	none.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &none, (socklen_t)sizeof(none));
}

static void *connection(void *argument)
{
	ncfg_daemon_slot_t  *slot = argument;
	ncfg_daemon_server_t *server = slot->server;
	int                  fd = slot->fd;
	ncfg_peer_t          peer;
	ncfg_proto_framer_t  framer;
	char                 err[NCFG_ERROR_MAX];
	struct timeval       deadline;
	int                  spoken = 0;
	int                  serving = 1;

	/*
	 * Read once, at accept time, rather than per request: the credentials
	 * belong to the connection, and re-reading them would only widen the
	 * window in which the peer's pid could be recycled.
	 */
	if (!ncfg_peer_credentials(fd, &server->roots, &peer, err, sizeof(err))) {
		goto done;
	}
	deadline.tv_sec = NCFG_DAEMON_FIRST_REQUEST_SECONDS;
	deadline.tv_usec = 0;
	/* Failing to set it is not a reason to refuse the connection: the
	 * consequence is one slot that can be held, which is the state every
	 * release before 0183 shipped. */
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, (socklen_t)sizeof(deadline));

	ncfg_proto_framer_init(&framer);
	while (serving) {
		char    chunk[4096];
		ssize_t got;

		for (;;) {
			const char              *text;
			size_t                   length;
			ncfg_proto_line_result_t found;
			ncfg_proto_message_t     message;

			found = ncfg_proto_framer_next(&framer, &text, &length, err, sizeof(err));
			if (found == NCFG_PROTO_LINE_INCOMPLETE) {
				break;
			}
			if (found == NCFG_PROTO_LINE_FAILED) {
				send_error(fd, err);
				serving = 0;
				break;
			}
			if (!spoken) {
				spoken = 1;
				clear_deadline(fd);
			}
			/*
			 * `ncfg_proto_request_read` and not the lenient reader: this is
			 * the surface that reads untrusted bytes, and it refuses a member
			 * the protocol does not define. The client half stays lenient, so
			 * an older client is not broken by a newer daemon's response.
			 */
			if (!ncfg_proto_request_read(text, length, &message, err, sizeof(err))) {
				send_error(fd, err);
				serving = 0;
				break;
			}
			serving = serve_one(server, fd, &peer, &message.u.request);
			ncfg_proto_message_free(&message);
			if (!serving) {
				break;
			}
		}
		if (!serving) {
			break;
		}
		got = recv(fd, chunk, sizeof(chunk), 0);
		if (got == 0) {
			/* A clean end of stream is a client disconnecting and is not an
			 * error. A partial line left behind is a message cut in half and
			 * must not be half-read. */
			if (!ncfg_proto_framer_finish(&framer, err, sizeof(err))) {
				send_error(fd, err);
			}
			break;
		}
		if (got < 0) {
			if (errno == EINTR) {
				continue;
			}
			/* `EAGAIN` here is the first-request deadline expiring, which is
			 * a connection that never said anything: it is closed, silently,
			 * because there is nobody to tell. */
			break;
		}
		if (!ncfg_proto_framer_add(&framer, chunk, (size_t)got, err, sizeof(err))) {
			send_error(fd, err);
			break;
		}
	}
	ncfg_proto_framer_free(&framer);

done:
	pthread_mutex_lock(&server->lock);
	slot->fd = -1;
	pthread_mutex_unlock(&server->lock);
	(void)close(fd);
	slot_release(server, slot);
	return NULL;
}

/* --------------------------------------------------------- the accept loop */

static void *acceptor(void *argument)
{
	ncfg_daemon_server_t *server = argument;

	for (;;) {
		ncfg_daemon_slot_t *slot;
		int                 fd = accept(server->listener, NULL, NULL);

		if (fd < 0) {
			if (errno == EINTR) {
				continue;
			}
			/* The listener was shut down, which is how `stop` gets here. */
			break;
		}
		(void)fcntl(fd, F_SETFD, FD_CLOEXEC);
		pthread_mutex_lock(&server->lock);
		if (server->stopping) {
			pthread_mutex_unlock(&server->lock);
			(void)close(fd);
			break;
		}
		pthread_mutex_unlock(&server->lock);

		slot = slot_take(server);
		if (!slot) {
			/*
			 * Refused with an answer rather than a dropped connection: the
			 * protocol has an error response and section 7 says to return
			 * one, so a client that hits the cap is told which wall it met
			 * instead of seeing an end of stream it has to guess about.
			 */
			char refusal[96];

			(void)snprintf(refusal, sizeof(refusal),
			    "too many connections, %d are open", NCFG_DAEMON_MAX_CONNECTIONS);
			send_error(fd, refusal);
			(void)close(fd);
			continue;
		}
		slot->fd = fd;
		if (pthread_create(&slot->thread, NULL, connection, slot) != 0) {
			(void)close(fd);
			slot->fd = -1;
			slot_release(server, slot);
			continue;
		}
		pthread_mutex_lock(&server->lock);
		slot->has_thread = 1;
		pthread_mutex_unlock(&server->lock);
	}
	return NULL;
}

/* ------------------------------------------------------------- bind, stop */

ncfg_daemon_server_t *ncfg_daemon_serve(const ncfg_daemon_serve_t *how, char *err, size_t err_size)
{
	ncfg_daemon_server_t *server;
	struct sockaddr_un    address;
	size_t                at;

	if (!how || !how->path || !how->path[0]) {
		ncfg_error_set(err, err_size,
		    "a socket to serve needs a path; there is deliberately no default here");
		return NULL;
	}
	if (!how->control) {
		ncfg_error_set(err, err_size,
		    "a socket to serve needs a control policy to judge its callers by");
		return NULL;
	}
	if (strlen(how->path) >= sizeof(address.sun_path)) {
		/*
		 * The path is not quoted whole, deliberately: `NCFG_ERROR_MAX` is 512
		 * bytes and a path that overflows `sun_path` can be most of that, so
		 * a message leading with it would be truncated before it said what
		 * was wrong. The first forty bytes are enough to recognise which path
		 * this is, and the numbers are what an operator acts on.
		 */
		ncfg_error_set(err, err_size,
		    "the socket path is %lu bytes and a unix socket takes at most %lu, so `%.40s...` "
		    "cannot be bound -- it is refused rather than silently shortened into a "
		    "different path",
		    (unsigned long)strlen(how->path), (unsigned long)sizeof(address.sun_path) - 1u,
		    how->path);
		return NULL;
	}
	server = calloc(1, sizeof(*server));
	if (!server) {
		ncfg_error_set(err, err_size, "there was no memory for the control socket");
		return NULL;
	}
	server->listener = -1;
	server->arrival = how->arrival;
	server->control = how->control;
	server->remote = how->remote;
	server->roots = how->roots.proc_root || how->roots.group_file || how->roots.passwd_file
	    ? how->roots
	    : ncfg_authz_roots_default();
	server->answer = how->answer;
	server->stream = how->stream;
	server->context = how->context;
	(void)snprintf(server->path, sizeof(server->path), "%s", how->path);
	for (at = 0; at < NCFG_DAEMON_MAX_CONNECTIONS; at++) {
		server->slots[at].fd = -1;
	}
	if (pthread_mutex_init(&server->lock, NULL) != 0) {
		ncfg_error_set(err, err_size, "the control socket's lock could not be made");
		free(server);
		return NULL;
	}

	server->listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server->listener < 0) {
		ncfg_error_set(err, err_size, "no socket could be made: %s", strerror(errno));
		goto failed;
	}
	(void)fcntl(server->listener, F_SETFD, FD_CLOEXEC);
	/*
	 * A stale socket from a previous run refuses to bind, and leaving the
	 * daemon unable to start because it did not shut down cleanly last time
	 * is a worse failure than removing a file nothing is listening on.
	 * Removed by the name the caller gave, never by a pattern.
	 */
	(void)unlink(server->path);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", server->path);
	if (bind(server->listener, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) < 0) {
		ncfg_error_set(err, err_size, "`%s` could not be bound: %s", server->path,
		    strerror(errno));
		goto failed;
	}
	if (listen(server->listener, NCFG_DAEMON_MAX_CONNECTIONS) < 0) {
		ncfg_error_set(err, err_size, "`%s` could not be listened on: %s", server->path,
		    strerror(errno));
		(void)unlink(server->path);
		goto failed;
	}
	apply_policy_permissions(server->path, how->reach, how->reach_count, &server->roots);

	if (pthread_create(&server->acceptor, NULL, acceptor, server) != 0) {
		ncfg_error_set(err, err_size, "the accept loop could not be started");
		(void)unlink(server->path);
		goto failed;
	}
	server->acceptor_live = 1;
	return server;

failed:
	if (server->listener >= 0) {
		(void)close(server->listener);
	}
	(void)pthread_mutex_destroy(&server->lock);
	free(server);
	return NULL;
}

void ncfg_daemon_server_stop(ncfg_daemon_server_t *server)
{
	size_t at;

	if (!server) {
		return;
	}
	pthread_mutex_lock(&server->lock);
	server->stopping = 1;
	pthread_mutex_unlock(&server->lock);
	/*
	 * `shutdown` before `close`, because `close` alone does not wake a thread
	 * already blocked in `accept` on the same descriptor -- and a server that
	 * returned leaving that thread blocked would leave it blocked for the
	 * life of the process, which is what "no process or socket left behind"
	 * rules out.
	 */
	if (server->listener >= 0) {
		(void)shutdown(server->listener, SHUT_RDWR);
	}
	if (server->acceptor_live) {
		pthread_join(server->acceptor, NULL);
		server->acceptor_live = 0;
	}
	/* Every live connection, woken the same way. The descriptor is read and
	 * shut down under the lock so it cannot be one the connection thread has
	 * already closed and the kernel has already reused. */
	pthread_mutex_lock(&server->lock);
	for (at = 0; at < NCFG_DAEMON_MAX_CONNECTIONS; at++) {
		if (server->slots[at].fd >= 0) {
			(void)shutdown(server->slots[at].fd, SHUT_RDWR);
		}
	}
	pthread_mutex_unlock(&server->lock);
	for (at = 0; at < NCFG_DAEMON_MAX_CONNECTIONS; at++) {
		int has;

		pthread_mutex_lock(&server->lock);
		has = server->slots[at].has_thread;
		pthread_mutex_unlock(&server->lock);
		if (has) {
			pthread_join(server->slots[at].thread, NULL);
			server->slots[at].has_thread = 0;
		}
	}
	if (server->listener >= 0) {
		(void)close(server->listener);
	}
	(void)unlink(server->path);
	(void)pthread_mutex_destroy(&server->lock);
	free(server);
}
