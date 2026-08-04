/*
 * ncfg_client.c -- the connection described in ncfg_client.h.
 */
#include "ncfg_client.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* The daemon's compiled-in default, and the one `ncfg` resolves to. Kept as a
 * literal rather than read from anywhere: it is part of the installed layout,
 * and a client that guessed differently would silently talk to nothing. */
#define NCFG_DEFAULT_RUN_DIR "/run/netcfgd"
#define NCFG_SOCKET_NAME     "netcfgd.sock"

/* A response is a line, and a status on a busy router is the largest of them:
 * every link, address, route and backend. A megabyte is far past that and is
 * still a bound -- without one, a peer that never sends a newline is a client
 * that grows until it is killed. */
#define NCFG_LINE_MAX (1024u * 1024u)

struct ncfg_client {
	int    fd;
	char   path[108]; /* sun_path is 108 on Linux, so a longer one cannot be
			   * connected to anyway and is refused when it is set */
	char  *buffer;    /* what has been read and not yet consumed */
	size_t length;
	size_t capacity;
};

static void set_error(char *err, size_t err_size, const char *format, ...)
{
	va_list args;

	if (!err || !err_size) {
		return;
	}
	va_start(args, format);
	vsnprintf(err, err_size, format, args);
	va_end(args);
}

const char *ncfg_client_default_socket(void)
{
	static char path[sizeof(((struct ncfg_client *)0)->path)];
	const char *run_dir = getenv("NCFG_RUN_DIR");

	if (!run_dir || !*run_dir) {
		run_dir = NCFG_DEFAULT_RUN_DIR;
	}
	int written = snprintf(path, sizeof(path), "%s/%s", run_dir, NCFG_SOCKET_NAME);
	if (written < 0 || (size_t)written >= sizeof(path)) {
		/* A run directory long enough to overflow sun_path cannot be
		 * connected to by anybody, so returning the default is more
		 * useful than returning a truncation that would fail obscurely. */
		snprintf(path, sizeof(path), "%s/%s", NCFG_DEFAULT_RUN_DIR, NCFG_SOCKET_NAME);
	}
	return path;
}

/*
 * A connected descriptor, or -1 with `err` said properly.
 *
 * Separate from ncfg_client_open because a monitor connects to the same daemon
 * for the same reasons and must fail with the same sentence -- two copies of
 * this would be two diagnostics for one problem, and the second one would be
 * the one that never got the path put into it.
 */
static int connect_socket(const char *socket_path, char *err, size_t err_size)
{
	struct sockaddr_un address;

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (strlen(socket_path) >= sizeof(address.sun_path)) {
		set_error(err, err_size, "the socket path is longer than a unix socket allows: %s",
			  socket_path);
		return -1;
	}
	strcpy(address.sun_path, socket_path);

	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		set_error(err, err_size, "cannot make a socket: %s", strerror(errno));
		return -1;
	}
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		/* The path is in the message on purpose. "Connection refused"
		 * alone sends the reader looking for a network problem, when the
		 * answer is nearly always that netcfgd is not running or that
		 * this client is looking in the wrong run directory. */
		set_error(err, err_size, "cannot reach netcfgd at %s: %s. Is the daemon running?",
			  socket_path, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

ncfg_client_t *ncfg_client_open(const char *socket_path, char *err, size_t err_size)
{
	if (err && err_size) {
		err[0] = '\0';
	}
	if (!socket_path || !*socket_path) {
		socket_path = ncfg_client_default_socket();
	}

	int fd = connect_socket(socket_path, err, err_size);
	if (fd < 0) {
		return NULL;
	}

	ncfg_client_t *client = calloc(1, sizeof(*client));
	if (!client) {
		set_error(err, err_size, "out of memory");
		close(fd);
		return NULL;
	}
	client->fd = fd;
	snprintf(client->path, sizeof(client->path), "%s", socket_path);
	return client;
}

void ncfg_client_close(ncfg_client_t *client)
{
	if (!client) {
		return;
	}
	if (client->fd >= 0) {
		close(client->fd);
	}
	free(client->buffer);
	free(client);
}

const char *ncfg_client_socket_path(const ncfg_client_t *client)
{
	return client ? client->path : "";
}

/* Everything, or a failure. `write` on a socket may write part of a buffer. */
static int write_all(int fd, const char *data, size_t length)
{
	while (length) {
		ssize_t wrote = write(fd, data, length);
		if (wrote < 0) {
			if (errno == EINTR) {
				continue;
			}
			return 0;
		}
		data += (size_t)wrote;
		length -= (size_t)wrote;
	}
	return 1;
}

/*
 * One line from the connection, without its newline.
 *
 * The buffer holds whatever arrived past the end of the line, because a daemon
 * that answered two requests quickly may have put both in one read -- and
 * throwing the second away would lose an answer somebody is waiting for.
 */
static char *read_line(ncfg_client_t *client, size_t *length_out, char *err, size_t err_size)
{
	for (;;) {
		/* Guarded on the length rather than trusting memchr with a null
		 * buffer and zero bytes: that is undefined behaviour even though
		 * every implementation returns NULL, and UBSan says so on the
		 * first read of every fresh connection -- which is how this was
		 * found, in the first headless run of the GUI against a real
		 * daemon. */
		char *newline = client->length ? memchr(client->buffer, '\n', client->length)
					       : NULL;
		if (newline) {
			size_t line_length = (size_t)(newline - client->buffer);
			char *line = malloc(line_length + 1u);
			if (!line) {
				set_error(err, err_size, "out of memory");
				return NULL;
			}
			memcpy(line, client->buffer, line_length);
			line[line_length] = '\0';

			size_t consumed = line_length + 1u;
			memmove(client->buffer, client->buffer + consumed,
				client->length - consumed);
			client->length -= consumed;
			*length_out = line_length;
			return line;
		}

		if (client->length >= NCFG_LINE_MAX) {
			set_error(err, err_size,
				  "netcfgd sent more than %u bytes with no end of line",
				  NCFG_LINE_MAX);
			return NULL;
		}
		if (client->length == client->capacity) {
			size_t next = client->capacity ? client->capacity * 2u : 8192u;
			char *grown = realloc(client->buffer, next);
			if (!grown) {
				set_error(err, err_size, "out of memory");
				return NULL;
			}
			client->buffer = grown;
			client->capacity = next;
		}
		ssize_t got = read(client->fd, client->buffer + client->length,
				   client->capacity - client->length);
		if (got < 0) {
			if (errno == EINTR) {
				continue;
			}
			set_error(err, err_size, "cannot read from netcfgd: %s", strerror(errno));
			return NULL;
		}
		if (got == 0) {
			set_error(err, err_size,
				  "netcfgd closed the connection without answering");
			return NULL;
		}
		client->length += (size_t)got;
	}
}

ncfg_json_doc_t *ncfg_client_request(ncfg_client_t *client, const char *request,
				     char *err, size_t err_size)
{
	if (err && err_size) {
		err[0] = '\0';
	}
	if (!client || !request) {
		set_error(err, err_size, "no client");
		return NULL;
	}
	if (strchr(request, '\n')) {
		/* The same refusal netcfgd-proto's codec.rs makes on its side: a
		 * message containing a newline would frame as two. Refusing here
		 * means a bug in a caller is a message rather than a daemon
		 * reading half a request as a whole one. */
		set_error(err, err_size, "a request may not contain a newline");
		return NULL;
	}

	size_t length = strlen(request);
	if (!write_all(client->fd, request, length) || !write_all(client->fd, "\n", 1)) {
		set_error(err, err_size, "cannot send to netcfgd: %s", strerror(errno));
		return NULL;
	}

	size_t line_length = 0;
	char *line = read_line(client, &line_length, err, err_size);
	if (!line) {
		return NULL;
	}

	char parse_error[NCFG_ERROR_MAX];
	ncfg_json_doc_t *doc = ncfg_json_parse(line, line_length, parse_error,
					       sizeof(parse_error));
	free(line);
	if (!doc) {
		set_error(err, err_size, "netcfgd sent something this cannot read: %s",
			  parse_error);
		return NULL;
	}
	return doc;
}

ncfg_json_doc_t *ncfg_client_hello(ncfg_client_t *client, char *err, size_t err_size)
{
	return ncfg_client_request(client, "{\"request\":\"hello\"}", err, err_size);
}

ncfg_json_doc_t *ncfg_client_status(ncfg_client_t *client, char *err, size_t err_size)
{
	return ncfg_client_request(client, "{\"request\":\"status\"}", err, err_size);
}

ncfg_json_doc_t *ncfg_client_plan(ncfg_client_t *client, char *err, size_t err_size)
{
	return ncfg_client_request(client, "{\"request\":\"plan\"}", err, err_size);
}

const char *ncfg_client_error_message(const ncfg_json_doc_t *doc, size_t *length_out)
{
	uint32_t root = ncfg_json_root(doc);

	if (length_out) {
		*length_out = 0;
	}
	if (!ncfg_json_string_equals(doc, ncfg_json_member(doc, root, "response"), "error")) {
		return NULL;
	}
	return ncfg_json_string(doc, ncfg_json_member(doc, root, "message"), length_out);
}

/* ------------------------------------------------------------------ models
 *
 * One parsed response, turned into the flat structs in the header.
 *
 * Two rules hold everywhere below, and everything else follows from them.
 *
 * A string in a model is a heap copy and is never NULL. An absent member, a
 * null and a number all become "". A model whose strings could be NULL would
 * put a null check in front of every label in every frontend, and the one
 * somebody forgot would be a crash in a screen nobody was looking at. The
 * reader keeps absent and null apart for good reasons (ncfg_json.h says which),
 * but nothing a screen does with a name differs between them, so the
 * distinction is spent here rather than passed on.
 *
 * A conversion that fails frees what it built and leaves the caller's struct
 * zeroed. Handing back a half-built list would mean the free walked an array
 * nobody finished filling, and "sometimes it is safe to free the out parameter"
 * is not a rule a caller can follow.
 */

static char *dup_text(const char *text, size_t length)
{
	char *copy = malloc(length + 1u);

	if (!copy) {
		return NULL;
	}
	if (length) {
		memcpy(copy, text, length);
	}
	copy[length] = '\0';
	return copy;
}

static char *dup_string(const char *text)
{
	return dup_text(text, strlen(text));
}

/*
 * One member as a C string, whether it is there or not.
 *
 * `name` may be NULL, for a list whose shape has no such field at all -- the
 * three note lists share one conversion and differ in exactly that way. NULL
 * comes back only for a failed allocation, which is why every caller checks it
 * and none of them checks for absence.
 */
static char *member_text(const ncfg_json_doc_t *doc, uint32_t object, const char *name)
{
	size_t length = 0;
	const char *text = NULL;

	if (name) {
		text = ncfg_json_string(doc, ncfg_json_member(doc, object, name), &length);
	}
	if (!text) {
		length = 0;
	}
	return dup_text(text ? text : "", length);
}

/*
 * Safe on a zeroed struct, and leaves one.
 *
 * Both halves are load-bearing: a conversion that ran out of memory calls this
 * on a list it half filled, a caller that never made a request calls it on a
 * struct it only declared, and a caller that frees twice gets nothing. A free
 * that needed to know which case it was in would be a rule somebody forgets on
 * an error path, which is the path nobody tests.
 */
void ncfg_links_free(ncfg_links_t *links)
{
	if (!links) {
		return;
	}
	for (size_t i = 0; i < links->count; i++) {
		free(links->items[i].name);
		free(links->items[i].kind);
		free(links->items[i].mac);
		free(links->items[i].addresses);
	}
	free(links->items);
	memset(links, 0, sizeof(*links));
}

static void notes_free(ncfg_note_t *notes, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		free(notes[i].message);
		free(notes[i].interface);
		free(notes[i].detail);
		free(notes[i].remedy);
		free(notes[i].consent);
		free(notes[i].field);
		free(notes[i].desired);
		free(notes[i].observed);
	}
	free(notes);
}

void ncfg_plan_free(ncfg_plan_t *plan)
{
	if (!plan) {
		return;
	}
	for (size_t i = 0; i < plan->action_count; i++) {
		free(plan->actions[i].op);
		free(plan->actions[i].interface);
		free(plan->actions[i].field);
		free(plan->actions[i].desired);
		free(plan->actions[i].observed);
	}
	free(plan->actions);
	notes_free(plan->warnings, plan->warning_count);
	notes_free(plan->refusals, plan->refusal_count);
	notes_free(plan->stranded, plan->stranded_count);
	memset(plan, 0, sizeof(*plan));
}

void ncfg_journal_free(ncfg_journal_t *journal)
{
	if (!journal) {
		return;
	}
	for (size_t i = 0; i < journal->count; i++) {
		free(journal->items[i].op);
		free(journal->items[i].interface);
		free(journal->items[i].outcome);
		free(journal->items[i].detail);
	}
	free(journal->items);
	memset(journal, 0, sizeof(*journal));
}

void ncfg_event_free(ncfg_event_t *event)
{
	if (!event) {
		return;
	}
	free(event->kind);
	free(event->interface);
	free(event->summary);
	free(event->raw);
	memset(event, 0, sizeof(*event));
}

/*
 * The addresses `status` reports for one interface, joined with ", ".
 *
 * The observation is one flat list keyed by interface rather than a field of
 * each link, so somebody has to do this join. Here rather than in a screen,
 * because otherwise both frontends do it and they disagree about the separator
 * -- which is the shape of mistake this whole layer exists to stop.
 *
 * Quadratic in links times addresses, deliberately. The largest host anyone has
 * pointed this at is a few dozen of each, so it is a few hundred comparisons
 * against a socket round trip, and a hash table here would be more code than
 * the rest of the conversion put together.
 */
static char *join_addresses(const ncfg_json_doc_t *doc, uint32_t addresses, const char *name)
{
	char *joined = dup_text("", 0);
	size_t length = 0;

	if (!joined) {
		return NULL;
	}
	uint32_t count = ncfg_json_count(doc, addresses);
	for (uint32_t i = 0; i < count; i++) {
		uint32_t entry = ncfg_json_at(doc, addresses, i);
		size_t address_length = 0;
		const char *address;

		uint32_t owner = ncfg_json_member(doc, entry, "interface");
		if (!ncfg_json_string_equals(doc, owner, name)) {
			continue;
		}
		address = ncfg_json_string(doc, ncfg_json_member(doc, entry, "address"),
					   &address_length);
		if (!address || !address_length) {
			continue;
		}
		char *grown = realloc(joined, length + (length ? 2u : 0u) + address_length + 1u);
		if (!grown) {
			free(joined);
			return NULL;
		}
		joined = grown;
		if (length) {
			memcpy(joined + length, ", ", 2u);
			length += 2u;
		}
		memcpy(joined + length, address, address_length);
		length += address_length;
		joined[length] = '\0';
	}
	return joined;
}

static int convert_links(const ncfg_json_doc_t *doc, ncfg_links_t *out, char *err, size_t err_size)
{
	uint32_t root = ncfg_json_root(doc);
	uint32_t links = ncfg_json_member(doc, root, "links");
	uint32_t addresses = ncfg_json_member(doc, root, "addresses");
	uint32_t count = ncfg_json_count(doc, links);

	if (!count) {
		/* A host with no links is a real answer, and calloc(0, n) is
		 * allowed to return NULL -- which the next line would read as
		 * being out of memory. */
		return 1;
	}
	out->items = calloc(count, sizeof(*out->items));
	if (!out->items) {
		set_error(err, err_size, "out of memory");
		return 0;
	}
	/* The count goes up before the strings go in, so that the free on the
	 * way out of a failure sees the whole array rather than the part that
	 * was finished. calloc zeroed the rest, and free(NULL) is nothing. */
	out->count = count;

	for (uint32_t i = 0; i < count; i++) {
		uint32_t link = ncfg_json_at(doc, links, i);
		ncfg_link_t *item = &out->items[i];

		item->name = member_text(doc, link, "name");
		/* An empty kind is what the kernel reports for a real NIC, and
		 * it is kept empty: `eth0` is a naming convention rather than a
		 * fact, and a word invented here would be one this layer had
		 * decided on behalf of every screen. */
		item->kind = member_text(doc, link, "kind");
		item->mac = member_text(doc, link, "mac");
		item->mtu = (int)ncfg_json_int(doc, ncfg_json_member(doc, link, "mtu"), 0);
		item->up = ncfg_json_bool(doc, ncfg_json_member(doc, link, "up"), 0);
		item->carrier = ncfg_json_bool(doc, ncfg_json_member(doc, link, "carrier"), 0);
		item->addresses = item->name ? join_addresses(doc, addresses, item->name) : NULL;
		if (!item->name || !item->kind || !item->mac || !item->addresses) {
			set_error(err, err_size, "out of memory");
			ncfg_links_free(out);
			return 0;
		}
	}
	return 1;
}

/*
 * The name of an op, whichever shape it arrived in.
 *
 * A plan's op is a tagged object -- {"op":"link.create","name":"br0"} -- and a
 * journal's is the bare name. One helper rather than two conversions, because
 * the two lists are the same actions before and after, and a screen that showed
 * one name in the plan and another in the journal would look broken in a way
 * nobody would attribute to this.
 *
 * Which is what it did, until 0083. The tag used to be serde's snake_case of
 * the variant while the journal carried netcfgd's short name, and they were not
 * the same word: `link_create` against `link.create`, and `bridge_vlan_add`
 * against `bridge.vlan.add`, where even replacing the first underscore gives
 * the wrong answer. The tags are now the names, so reading the tag is reading
 * the name and this helper is the whole of it. Nothing here tabulates the
 * forty-seven; that table belongs to netcfgd and a copy of it here would be a
 * copy that drifts.
 *
 * A daemon older than 0083 sends the old tags, and this reports them as it
 * finds them. `link_create` in an op column is wrong and readable; an empty
 * column, which is what insisting on the new spelling would give, is neither.
 */
static char *op_name(const ncfg_json_doc_t *doc, uint32_t op)
{
	size_t length = 0;
	const char *text;

	if (ncfg_json_type(doc, op) == NCFG_JSON_OBJECT) {
		return member_text(doc, op, "op");
	}
	text = ncfg_json_string(doc, op, &length);
	return dup_text(text ? text : "", length);
}

/*
 * The member names one note list uses, since all three read the same.
 *
 * `message` is the headline, `detail` the sentence behind it, and the two
 * remedies stay two: `remedy` is the change that makes the situation not arise,
 * `consent` the flag that proceeds anyway. NULL means this list has no such
 * field, which is how a warning -- two fields where the others have five or six
 * -- goes through the same loop as the rest.
 */
typedef struct {
	const char *message;
	const char *interface;
	const char *detail;
	const char *remedy;
	const char *consent;
} note_names_t;

static int convert_notes(const ncfg_json_doc_t *doc, uint32_t array, const note_names_t *names,
			 ncfg_note_t **items_out, size_t *count_out, char *err, size_t err_size)
{
	uint32_t count = ncfg_json_count(doc, array);

	if (!count) {
		return 1;
	}
	*items_out = calloc(count, sizeof(**items_out));
	if (!*items_out) {
		set_error(err, err_size, "out of memory");
		return 0;
	}
	*count_out = count;

	for (uint32_t i = 0; i < count; i++) {
		uint32_t entry = ncfg_json_at(doc, array, i);
		ncfg_note_t *note = &(*items_out)[i];

		/* A refusal carries the same `reason` object an action does, and
		 * NCFG_JSON_NONE reads through as absent -- so the three lists that
		 * have no reason take this path too and come out empty. */
		uint32_t reason = ncfg_json_member(doc, entry, "reason");

		note->message = member_text(doc, entry, names->message);
		note->interface = member_text(doc, entry, names->interface);
		note->detail = member_text(doc, entry, names->detail);
		note->remedy = member_text(doc, entry, names->remedy);
		note->consent = member_text(doc, entry, names->consent);
		note->field = member_text(doc, reason, "field");
		note->desired = member_text(doc, reason, "desired");
		note->observed = member_text(doc, reason, "observed");
		if (!note->message || !note->interface || !note->detail || !note->remedy ||
		    !note->consent || !note->field || !note->desired || !note->observed) {
			set_error(err, err_size, "out of memory");
			return 0;
		}
	}
	return 1;
}

static int convert_actions(const ncfg_json_doc_t *doc, ncfg_plan_t *out, char *err,
			   size_t err_size)
{
	uint32_t root = ncfg_json_root(doc);
	uint32_t actions = ncfg_json_member(doc, root, "actions");
	uint32_t count = ncfg_json_count(doc, actions);

	if (!count) {
		return 1;
	}
	out->actions = calloc(count, sizeof(*out->actions));
	if (!out->actions) {
		set_error(err, err_size, "out of memory");
		return 0;
	}
	out->action_count = count;

	for (uint32_t i = 0; i < count; i++) {
		uint32_t action = ncfg_json_at(doc, actions, i);
		uint32_t reason = ncfg_json_member(doc, action, "reason");
		uint32_t inverse = ncfg_json_member(doc, action, "inverse");
		ncfg_action_t *item = &out->actions[i];

		item->id = (long long)ncfg_json_int(doc, ncfg_json_member(doc, action, "id"), 0);
		item->op = op_name(doc, ncfg_json_member(doc, action, "op"));
		/* Every one of these comes out of `reason` and not out of the op:
		 * the op payload names its subject differently for each of forty
		 * variants (`name`, `iface`, `device`), while the reason carries
		 * the interface the planner attributed the action to -- and
		 * absent there means the action belongs to the host rather than
		 * to a device, which is exactly the header's "" case. */
		item->interface = member_text(doc, reason, "interface");
		item->field = member_text(doc, reason, "field");
		item->desired = member_text(doc, reason, "desired");
		item->observed = member_text(doc, reason, "observed");
		/* Absent and null both mean no inverse. netcfgd omits the field
		 * rather than writing null today, and a client that only knew one
		 * of the two spellings would quietly promise an undo it cannot
		 * do -- which is the one mistake a confirm window must not make. */
		item->reversible = inverse != NCFG_JSON_NONE &&
				   ncfg_json_type(doc, inverse) != NCFG_JSON_NULL;
		if (!item->op || !item->interface || !item->field || !item->desired ||
		    !item->observed) {
			set_error(err, err_size, "out of memory");
			return 0;
		}
	}
	return 1;
}

/*
 * A plan, in the four lists a screen draws.
 *
 * The three note lists are different shapes in the witness and one shape here,
 * and the mapping is a judgement worth writing down:
 *
 *   message     interface   detail        remedy         consent
 *   ---------------------------------------------------------------------
 *   warning   | message   | interface  | --          | --           | --
 *   refusal   | op        | interface  | guard       | --           | override_with
 *   stranded  | credential| interface  | irrevocable | remove_with  | consent_with
 *
 * The headline is the thing being talked about -- the op that was dropped, the
 * credential being left behind -- and the detail is the sentence the guard or
 * the credential carries about it.
 *
 * The two remedies stay separate because they are different answers, and `ncfg`
 * prints the config one first so that the flag does not read as the fix. An
 * earlier draft flattened them and kept `consent_with`, which is the wrong one
 * of the two to lose: it would have shown an operator how to consent to walking
 * away from a private key and not how to stop leaving it behind.
 *
 * A refusal's `reason` goes through convert_notes with the actions' names, so
 * a screen can say what the refused action would have been. Without it a
 * refusal is the one place this client is a black box, and constraint 7 is
 * about exactly that -- being told no is when a reason is most wanted.
 */
static int convert_plan(const ncfg_json_doc_t *doc, ncfg_plan_t *out, char *err, size_t err_size)
{
	static const note_names_t warning_names = { "message", "interface", NULL, NULL, NULL };
	static const note_names_t refusal_names = { "op", "interface", "guard", NULL,
						    "override_with" };
	static const note_names_t stranded_names = { "credential", "interface", "irrevocable",
						     "remove_with", "consent_with" };
	uint32_t root = ncfg_json_root(doc);

	if (!convert_actions(doc, out, err, err_size) ||
	    !convert_notes(doc, ncfg_json_member(doc, root, "warnings"), &warning_names,
			   &out->warnings, &out->warning_count, err, err_size) ||
	    !convert_notes(doc, ncfg_json_member(doc, root, "refusals"), &refusal_names,
			   &out->refusals, &out->refusal_count, err, err_size) ||
	    !convert_notes(doc, ncfg_json_member(doc, root, "stranded"), &stranded_names,
			   &out->stranded, &out->stranded_count, err, err_size)) {
		ncfg_plan_free(out);
		return 0;
	}
	return 1;
}

static int convert_journal(const ncfg_json_doc_t *doc, ncfg_journal_t *out, char *err,
			   size_t err_size)
{
	uint32_t root = ncfg_json_root(doc);
	uint32_t records = ncfg_json_member(doc, root, "records");
	uint32_t count = ncfg_json_count(doc, records);

	if (!count) {
		return 1;
	}
	out->items = calloc(count, sizeof(*out->items));
	if (!out->items) {
		set_error(err, err_size, "out of memory");
		return 0;
	}
	out->count = count;

	for (uint32_t i = 0; i < count; i++) {
		uint32_t record = ncfg_json_at(doc, records, i);
		ncfg_record_t *item = &out->items[i];

		item->id = (long long)ncfg_json_int(doc, ncfg_json_member(doc, record, "id"), 0);
		item->op = op_name(doc, ncfg_json_member(doc, record, "op"));
		item->interface = member_text(doc, record, "interface");
		item->outcome = member_text(doc, record, "outcome");
		/* `error` and not a word of this library's own: the daemon's
		 * sentence says what the kernel refused, and "failed" on its own
		 * has never helped anybody. */
		item->detail = member_text(doc, record, "error");
		if (!item->op || !item->interface || !item->outcome || !item->detail) {
			set_error(err, err_size, "out of memory");
			ncfg_journal_free(out);
			return 0;
		}
	}
	return 1;
}

/*
 * A refusal from the daemon, copied into `err`.
 *
 * Returns 1 when there was one. The message is counted rather than terminated,
 * so it goes through the formatter with a precision -- a refusal naming a path
 * with a NUL in it is not a thing netcfgd sends, but truncating at one silently
 * would be a message that stopped mid-sentence for no visible reason.
 */
static int took_refusal(const ncfg_json_doc_t *doc, char *err, size_t err_size)
{
	size_t length = 0;
	const char *message = ncfg_client_error_message(doc, &length);

	if (!message) {
		return 0;
	}
	set_error(err, err_size, "%.*s", (int)length, message);
	return 1;
}

int ncfg_client_links(ncfg_client_t *client, ncfg_links_t *out, char *err, size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	memset(out, 0, sizeof(*out));

	ncfg_json_doc_t *doc = ncfg_client_status(client, err, err_size);
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size) && convert_links(doc, out, err, err_size);
	ncfg_json_free(doc);
	return done;
}

int ncfg_client_plan_of(ncfg_client_t *client, ncfg_plan_t *out, char *err, size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	memset(out, 0, sizeof(*out));

	ncfg_json_doc_t *doc = ncfg_client_plan(client, err, err_size);
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size) && convert_plan(doc, out, err, err_size);
	ncfg_json_free(doc);
	return done;
}

int ncfg_client_apply(ncfg_client_t *client, unsigned confirm_seconds, ncfg_journal_t *out,
		      char *err, size_t err_size)
{
	char request[64];

	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	memset(out, 0, sizeof(*out));

	/* No window means the field is left out, not sent as zero: `confirm` is
	 * an option on the daemon's side and `"confirm":0` is a window of no
	 * seconds, which arms and expires. Two spellings of "no" where one of
	 * them reverts the change is not a thing to leave to a reader.
	 *
	 * allow_disruption and strand_credentials are never sent. They are
	 * consent, the header has no parameter for them, and a library that
	 * defaulted them to anything would be consenting on the operator's
	 * behalf to the two things netcfgd stops for. */
	if (confirm_seconds) {
		snprintf(request, sizeof(request), "{\"request\":\"apply\",\"confirm\":%u}",
			 confirm_seconds);
	} else {
		snprintf(request, sizeof(request), "{\"request\":\"apply\"}");
	}

	ncfg_json_doc_t *doc = ncfg_client_request(client, request, err, err_size);
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size) && convert_journal(doc, out, err, err_size);
	ncfg_json_free(doc);
	return done;
}

/*
 * A request whose whole answer is whether it worked.
 *
 * Anything that is neither `ok` nor `error` is a failure rather than a success
 * with an unread body: this is the second implementation of a pinned surface,
 * and quietly accepting a response it does not recognise is how a client comes
 * to report that a confirm landed when it did not.
 */
static int simple_request(ncfg_client_t *client, const char *request, char *err, size_t err_size)
{
	ncfg_json_doc_t *doc = ncfg_client_request(client, request, err, err_size);

	if (!doc) {
		return 0;
	}
	int done = 1;
	if (took_refusal(doc, err, err_size)) {
		done = 0;
	} else if (!ncfg_json_string_equals(doc, ncfg_json_member(doc, ncfg_json_root(doc),
								  "response"), "ok")) {
		set_error(err, err_size, "netcfgd answered %s with something other than ok",
			  request);
		done = 0;
	}
	ncfg_json_free(doc);
	return done;
}

int ncfg_client_confirm(ncfg_client_t *client, char *err, size_t err_size)
{
	return simple_request(client, "{\"request\":\"confirm\"}", err, err_size);
}

int ncfg_client_revert(ncfg_client_t *client, char *err, size_t err_size)
{
	return simple_request(client, "{\"request\":\"revert\"}", err, err_size);
}

/* ----------------------------------------------------------------- monitor */

struct ncfg_monitor {
	int    fd;
	char  *buffer; /* what has arrived and not yet been given out, partial
			* lines included */
	size_t length;
	size_t capacity;
};

ncfg_monitor_t *ncfg_monitor_open(const char *socket_path, char *err, size_t err_size)
{
	if (err && err_size) {
		err[0] = '\0';
	}
	if (!socket_path || !*socket_path) {
		socket_path = ncfg_client_default_socket();
	}

	int fd = connect_socket(socket_path, err, err_size);
	if (fd < 0) {
		return NULL;
	}

	/* The request goes out while the descriptor is still blocking, and
	 * nothing is ever written to it again. Twenty-two bytes into a socket
	 * nobody has written to cannot be a partial write worth spinning on,
	 * and doing it in this order means the non-blocking half of this file
	 * has no write path at all to get wrong. */
	static const char request[] = "{\"request\":\"monitor\"}\n";
	if (!write_all(fd, request, sizeof(request) - 1u)) {
		set_error(err, err_size, "cannot subscribe to netcfgd at %s: %s", socket_path,
			  strerror(errno));
		close(fd);
		return NULL;
	}

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		/* Without this the descriptor is a trap: the header promises
		 * ncfg_monitor_next never blocks, and a UI that called it from
		 * its event loop on a blocking descriptor would freeze the whole
		 * window the first time the daemon went quiet mid-line. */
		set_error(err, err_size, "cannot make the monitor stream non-blocking: %s",
			  strerror(errno));
		close(fd);
		return NULL;
	}

	ncfg_monitor_t *monitor = calloc(1, sizeof(*monitor));
	if (!monitor) {
		set_error(err, err_size, "out of memory");
		close(fd);
		return NULL;
	}
	monitor->fd = fd;
	return monitor;
}

void ncfg_monitor_close(ncfg_monitor_t *monitor)
{
	if (!monitor) {
		return;
	}
	if (monitor->fd >= 0) {
		close(monitor->fd);
	}
	free(monitor->buffer);
	free(monitor);
}

int ncfg_monitor_fd(const ncfg_monitor_t *monitor)
{
	return monitor ? monitor->fd : -1;
}

/*
 * One line from the stream, or NULL with `*waiting` set when none is complete.
 *
 * This is read_line again, and knowingly. The two differ in the one place that
 * matters: that one loops until a whole line exists and calls the end of the
 * connection a failure to answer, because a request without a response is
 * broken; this one returns "nothing yet" and treats a short read as the
 * ordinary case. Teaching one function both would put a mode flag on the
 * request path, and the failure that follows -- ncfg_client_request returning
 * successfully with no document because the daemon was merely slow -- is worse
 * than thirty duplicated lines.
 */
static char *monitor_line(ncfg_monitor_t *monitor, size_t *length_out, int *waiting, char *err,
			  size_t err_size)
{
	*waiting = 0;
	for (;;) {
		char *newline = monitor->length
					? memchr(monitor->buffer, '\n', monitor->length)
					: NULL;
		if (newline) {
			size_t line_length = (size_t)(newline - monitor->buffer);
			char *line = dup_text(monitor->buffer, line_length);
			if (!line) {
				set_error(err, err_size, "out of memory");
				return NULL;
			}
			size_t consumed = line_length + 1u;
			memmove(monitor->buffer, monitor->buffer + consumed,
				monitor->length - consumed);
			monitor->length -= consumed;
			*length_out = line_length;
			return line;
		}

		if (monitor->length >= NCFG_LINE_MAX) {
			set_error(err, err_size,
				  "netcfgd sent more than %u bytes of event with no end of line",
				  NCFG_LINE_MAX);
			return NULL;
		}
		if (monitor->length == monitor->capacity) {
			size_t next = monitor->capacity ? monitor->capacity * 2u : 8192u;
			char *grown = realloc(monitor->buffer, next);
			if (!grown) {
				set_error(err, err_size, "out of memory");
				return NULL;
			}
			monitor->buffer = grown;
			monitor->capacity = next;
		}
		ssize_t got = read(monitor->fd, monitor->buffer + monitor->length,
				   monitor->capacity - monitor->length);
		if (got < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* The ordinary answer. Whatever arrived stays in
				 * the buffer, so a line split across two wakeups
				 * is one line and not two halves thrown away. */
				*waiting = 1;
				return NULL;
			}
			set_error(err, err_size, "cannot read the monitor stream: %s",
				  strerror(errno));
			return NULL;
		}
		if (got == 0) {
			set_error(err, err_size, "netcfgd closed the monitor stream");
			return NULL;
		}
		monitor->length += (size_t)got;
	}
}

/*
 * One event, filled in from the line it arrived on.
 *
 * `summary` is the daemon's own sentence wherever the event has one, and is
 * composed here only for the kinds that carry none -- a confirm window's
 * seconds are a number, and a pane cannot draw a number without saying what it
 * counts. Where netcfgd has words, they are used verbatim: two vocabularies for
 * one event is how a bug report ends up describing something nobody can find in
 * the daemon's source.
 */
static int convert_event(const ncfg_json_doc_t *doc, const char *raw, size_t raw_length,
			 ncfg_event_t *out)
{
	uint32_t root = ncfg_json_root(doc);
	char composed[160];

	memset(out, 0, sizeof(*out));
	out->kind = member_text(doc, root, "event");
	if (!out->kind) {
		return 0;
	}
	out->interface = member_text(doc, root, "interface");
	out->raw = dup_text(raw, raw_length);

	if (ncfg_json_type(doc, ncfg_json_member(doc, root, "summary")) == NCFG_JSON_STRING) {
		out->summary = member_text(doc, root, "summary");
	} else if (strcmp(out->kind, "reloaded") == 0) {
		uint32_t diagnostics = ncfg_json_member(doc, root, "diagnostics");
		if (ncfg_json_type(doc, diagnostics) == NCFG_JSON_STRING) {
			out->summary = member_text(doc, root, "diagnostics");
		} else {
			out->summary = dup_string(
				ncfg_json_bool(doc, ncfg_json_member(doc, root, "ok"), 0)
					? "the configuration was reloaded"
					: "the configuration did not compile");
		}
	} else if (strcmp(out->kind, "confirm_armed") == 0) {
		snprintf(composed, sizeof(composed), "a confirm window is open for %lld seconds",
			 (long long)ncfg_json_int(doc, ncfg_json_member(doc, root, "seconds"), 0));
		out->summary = dup_string(composed);
	} else if (strcmp(out->kind, "confirm_resolved") == 0) {
		out->summary = dup_string(
			ncfg_json_bool(doc, ncfg_json_member(doc, root, "confirmed"), 0)
				? "the change was confirmed"
				: "the change was reverted");
	} else {
		/* A kind this build has never heard of still becomes an event
		 * with its line in `raw`, rather than being dropped. An event
		 * netcfgd grew after this client was compiled should look
		 * unfamiliar in a pane, not invisible. */
		out->summary = dup_text("", 0);
	}

	if (!out->interface || !out->raw || !out->summary) {
		ncfg_event_free(out);
		return 0;
	}
	return 1;
}

int ncfg_monitor_next(ncfg_monitor_t *monitor, ncfg_event_t *out, char *err, size_t err_size)
{
	if (err && err_size) {
		err[0] = '\0';
	}
	if (!monitor || !out) {
		set_error(err, err_size, "no monitor");
		return -1;
	}
	memset(out, 0, sizeof(*out));

	size_t line_length = 0;
	int waiting = 0;
	char *line = monitor_line(monitor, &line_length, &waiting, err, err_size);
	if (!line) {
		return waiting ? 0 : -1;
	}

	char parse_error[NCFG_ERROR_MAX];
	ncfg_json_doc_t *doc = ncfg_json_parse(line, line_length, parse_error,
					       sizeof(parse_error));
	if (!doc) {
		/* Not skipped. A stream that sends a line this cannot read is one
		 * this cannot follow, and carrying on would mean a pane that
		 * looks live while it has stopped understanding the daemon. */
		set_error(err, err_size, "netcfgd sent an event this cannot read: %s",
			  parse_error);
		free(line);
		return -1;
	}

	int result = 1;
	if (took_refusal(doc, err, err_size)) {
		/* The daemon says yes to `monitor` by saying nothing at all and
		 * streaming, so its no arrives here rather than at open time:
		 * the tier check happens before the subscription and a refusal
		 * is the only line that connection will ever carry. */
		result = -1;
	} else if (!convert_event(doc, line, line_length, out)) {
		set_error(err, err_size, "out of memory");
		result = -1;
	}
	ncfg_json_free(doc);
	free(line);
	return result;
}

size_t ncfg_client_quote(const char *text, char *out, size_t out_size)
{
	if (!text || !out || out_size < 3u) {
		return 0;
	}
	size_t at = 0;
	out[at++] = '"';

	for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
		char escape[7];
		size_t span;

		switch (*p) {
		case '"':  memcpy(escape, "\\\"", 2); span = 2; break;
		case '\\': memcpy(escape, "\\\\", 2); span = 2; break;
		case '\b': memcpy(escape, "\\b", 2);  span = 2; break;
		case '\f': memcpy(escape, "\\f", 2);  span = 2; break;
		case '\n': memcpy(escape, "\\n", 2);  span = 2; break;
		case '\r': memcpy(escape, "\\r", 2);  span = 2; break;
		case '\t': memcpy(escape, "\\t", 2);  span = 2; break;
		default:
			if (*p < 0x20u) {
				/* The remaining control characters, which JSON
				 * has no short escape for. */
				span = (size_t)snprintf(escape, sizeof(escape), "\\u%04x", *p);
			} else {
				escape[0] = (char)*p;
				span = 1;
			}
			break;
		}
		if (at + span + 2u > out_size) {
			return 0;
		}
		memcpy(out + at, escape, span);
		at += span;
	}
	out[at++] = '"';
	out[at] = '\0';
	return at;
}
