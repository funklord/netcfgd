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
		int failed = errno;

		/* The path is in the message on purpose. "Connection refused"
		 * alone sends the reader looking for a network problem, when the
		 * answer is nearly always that netcfgd is not running or that
		 * this client is looking in the wrong run directory.
		 *
		 * EACCES is the one that is *not* that, and asking "is the daemon
		 * running?" for it is actively wrong: the daemon is running and
		 * refusing, and the reader is sent to systemctl and the journal
		 * for a problem that is in a config file. The socket's mode
		 * follows `global { control { ... } }`, every tier of which
		 * defaults to root, so this is what a desktop client meets on a
		 * default install (0118). Section 2.1 already makes the daemon
		 * complain about the same mismatch from its side and calls it a
		 * lie that costs an afternoon to diagnose; this is that afternoon
		 * from the client's side.
		 */
		if (failed == EACCES || failed == EPERM) {
			set_error(err, err_size,
			      "not allowed to talk to netcfgd at %s: %s. The socket's mode "
			      "follows `global { control { ... } }`, and every tier "
			      "defaults to root -- so this is a permission policy rather "
			      "than a daemon that is not running",
			      socket_path, strerror(failed));
		} else {
			set_error(err, err_size,
			      "cannot reach netcfgd at %s: %s. Is the daemon running?",
			      socket_path, strerror(failed));
		}
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
/*
 * Kind first, name second, and never name only: the kernel's word is a fact
 * where it exists, and the `wl` prefix is a convention that happens to hold on
 * every machine anybody has run this on -- the same reason `eth0` is not proof
 * of an ethernet.
 *
 * This said exactly that and then wrote an *or*, which reaches the name even
 * when the kernel has spoken. An empty kind is a real NIC, as the parser above
 * says; a non-empty one is the kernel naming a virtual device, so `bridge` or
 * `vlan` is an answer rather than a gap to fall through. A VLAN on a radio is
 * called `wlan0.10` and was reported wireless by the name alone.
 *
 * `ncfg tui` asks the identical question in Rust. The two are checked against
 * each other by the conformance target rather than trusted to stay in step --
 * which keeps them identical and cannot say they are correct, both having been
 * written from each other. Each side pins the intent in its own tests.
 */
int ncfg_link_is_wireless(const char *kind, const char *name)
{
	if (kind && *kind) {
		return !strcmp(kind, "wlan");
	}
	return name && !strncmp(name, "wl", 2);
}

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

/*
 * Does a default route leave through `name`, in the main table?
 *
 * Table 254 only. A default route in another table is reached through a policy
 * rule and says nothing about where this machine's ordinary traffic goes, so
 * counting it would tell a tray icon that a host with one rule and no uplink
 * was connected.
 *
 * Ownership is deliberately not consulted. A route netcfgd did not install
 * still carries packets, and an icon that went grey because another daemon put
 * the route there would be reporting on netcfgd rather than on the machine.
 */
static int link_has_default_route(const ncfg_json_doc_t *doc, uint32_t routes, const char *name)
{
	uint32_t count = ncfg_json_count(doc, routes);
	for (uint32_t i = 0; i < count; i++) {
		uint32_t entry = ncfg_json_at(doc, routes, i);
		uint32_t owner = ncfg_json_member(doc, entry, "interface");
		uint32_t where = ncfg_json_member(doc, entry, "destination");
		if (!ncfg_json_string_equals(doc, owner, name)) {
			continue;
		}
		if (!ncfg_json_string_equals(doc, where, "default")) {
			continue;
		}
		if (ncfg_json_int(doc, ncfg_json_member(doc, entry, "table"), 0) != 254) {
			continue;
		}
		return 1;
	}
	return 0;
}

static int convert_links(const ncfg_json_doc_t *doc, ncfg_links_t *out, char *err, size_t err_size)
{
	uint32_t root = ncfg_json_root(doc);
	uint32_t links = ncfg_json_member(doc, root, "links");
	uint32_t addresses = ncfg_json_member(doc, root, "addresses");
	uint32_t routes = ncfg_json_member(doc, root, "routes");
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
		item->default_route =
		    item->name ? link_has_default_route(doc, routes, item->name) : 0;
		// **The daemon's answer where there is one.** netcfgd reads
		// /sys/class/net/<name>/wireless and puts it on the wire; guessing
		// from the name was all a client could do before, and it disagrees
		// with the daemon on any interface whose name does not begin `wl` --
		// a renamed adapter, or a radio a test invented. `gui_wifi.sh` found
		// it that way: netcfgd managed the radio, and the GUI's own interface
		// list was empty, so every wireless button was dead with no
		// explanation. The heuristic stays as the fallback for a daemon older
		// than the field, which is the only case that can still need it.
		const uint32_t wireless = ncfg_json_member(doc, link, "wireless");
		item->wireless = wireless == NCFG_JSON_NONE
		    ? ncfg_link_is_wireless(item->kind, item->name)
		    : ncfg_json_bool(doc, wireless, 0);
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

int ncfg_client_confirm_default(ncfg_client_t *client, unsigned *out, char *err, size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	*out = 0;

	ncfg_json_doc_t *doc =
	    ncfg_client_request(client, "{\"request\":\"show\"}", err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	/* Absent is the ordinary case and not a failure: most machines name no
	 * default, and the caller's own is right for them. */
	uint32_t globals = ncfg_json_member(doc, ncfg_json_root(doc), "globals");
	uint32_t seconds = ncfg_json_member(doc, globals, "confirm_default");
	long long value = ncfg_json_int(doc, seconds, 0);
	if (value > 0 && value <= 86400) {
		*out = (unsigned)value;
	}
	ncfg_json_free(doc);
	return 1;
}

int ncfg_client_tiers(ncfg_client_t *client, ncfg_tiers_t *out, char *err, size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	memset(out, 0, sizeof(*out));

	ncfg_json_doc_t *doc = ncfg_client_hello(client, err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	/* Absent means a daemon older than this field, and nothing granted is the
	 * wrong answer for that -- it would grey out every button against a daemon
	 * that would have answered. Everything granted is the wrong answer too.
	 * So: absent is reported as success with nothing set, and the caller that
	 * cares says which it wants. The GUI treats "could not tell" as permitted,
	 * because the daemon refusing is a sentence the operator can read and a
	 * disabled button is not. */
	uint32_t tiers = ncfg_json_member(doc, ncfg_json_root(doc), "tiers");
	for (uint32_t i = 0; i < ncfg_json_count(doc, tiers); i++) {
		size_t length = 0;
		const char *name = ncfg_json_string(doc, ncfg_json_at(doc, tiers, i), &length);
		if (!name) {
			continue;
		}
		if (length == 7u && !memcmp(name, "observe", 7)) {
			out->observe = 1;
		} else if (length == 4u && !memcmp(name, "wifi", 4)) {
			out->wifi = 1;
		} else if (length == 5u && !memcmp(name, "admin", 5)) {
			out->admin = 1;
		}
	}
	ncfg_json_free(doc);
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

void ncfg_scan_free(ncfg_scan_t *scan)
{
	if (!scan) {
		return;
	}
	for (size_t i = 0; i < scan->count; i++) {
		free(scan->items[i].bssid);
		free(scan->items[i].ssid);
		free(scan->items[i].name);
		free(scan->items[i].configured);
		free(scan->items[i].display);
	}
	free(scan->items);
	free(scan->interface);
	memset(scan, 0, sizeof(*scan));
}

void ncfg_wifi_status_free(ncfg_wifi_status_t *status)
{
	if (!status) {
		return;
	}
	free(status->interface);
	free(status->state);
	free(status->ssid);
	free(status->name);
	free(status->bssid);
	free(status->network);
	memset(status, 0, sizeof(*status));
}

/*
 * `{"request":"verb","interface":"name"}`, with the name quoted.
 *
 * Returns 0 if it would not fit, which every caller turns into a refusal. A
 * truncated request is not a smaller request; it is a different one, and this
 * one names an interface.
 */
static int wifi_request(char *out, size_t out_size, const char *verb, const char *interface)
{
	int head = snprintf(out, out_size, "{\"request\":\"%s\",\"interface\":", verb);

	if (head < 0 || (size_t)head >= out_size) {
		return 0;
	}
	size_t at = (size_t)head;
	size_t span = ncfg_client_quote(interface, out + at, out_size - at);
	if (!span) {
		return 0;
	}
	at += span;
	if (at + 2 > out_size) {
		return 0;
	}
	out[at++] = '}';
	out[at] = '\0';
	return 1;
}

/*
 * The one string a screen shows for an access point's name.
 *
 * Three cases because the daemon sends three, and the two that are not "a
 * name" are the ones every client was getting wrong: a hidden network drew as
 * a blank cell, and an unprintable SSID drew as a word naming the *condition*,
 * which made two such networks one row. The hex is kept, prefixed so nobody
 * reads it as the name.
 */
char *ncfg_access_point_display(int named, const char *name, const char *ssid)
{
	if (!named) {
		size_t span = strlen("hex:") + strlen(ssid) + 1u;
		char *text = malloc(span);
		if (text) {
			snprintf(text, span, "hex:%s", ssid);
		}
		return text;
	}
	if (!*name) {
		return dup_string("(hidden)");
	}
	return dup_string(name);
}

void ncfg_saved_networks_free(ncfg_saved_networks_t *networks)
{
	if (!networks) {
		return;
	}
	for (size_t i = 0; i < networks->count; i++) {
		free(networks->items[i].id);
		free(networks->items[i].name);
		free(networks->items[i].ssid);
		free(networks->items[i].security);
		free(networks->items[i].credential);
	}
	free(networks->items);
	networks->items = NULL;
	networks->count = 0;
}

int ncfg_client_saved_networks(ncfg_client_t *client, ncfg_saved_networks_t *out, char *err,
    size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	out->items = NULL;
	out->count = 0;

	ncfg_json_doc_t *doc = ncfg_client_request(client, "{\"request\":\"show\"}", err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	uint32_t networks = ncfg_json_member(doc, ncfg_json_root(doc), "networks");
	uint32_t count = ncfg_json_count(doc, networks);
	if (!count) {
		/* A document that configures no wireless network is ordinary --
		 * a wired machine has none -- and calloc(0, n) may return NULL,
		 * which the next line would read as being out of memory. */
		ncfg_json_free(doc);
		return 1;
	}
	out->items = calloc(count, sizeof(*out->items));
	if (!out->items) {
		set_error(err, err_size, "out of memory");
		ncfg_json_free(doc);
		return 0;
	}
	out->count = count;

	for (uint32_t i = 0; i < count; i++) {
		uint32_t entry = ncfg_json_at(doc, networks, i);
		ncfg_saved_network_t *item = &out->items[i];

		item->id = member_text(doc, entry, "id");
		item->ssid = member_text(doc, entry, "ssid");
		/* The document holds the SSID as hex and an id beside it. An id
		 * derived from text is that text, so it doubles as the name --
		 * but only when it is genuinely the SSID rather than a label
		 * somebody chose, which is why the name is left empty and the
		 * hex kept: `ncfg_access_point_display` is the one place that
		 * decides how these are spelled. */
		item->name = member_text(doc, entry, "id");
		uint32_t security = ncfg_json_member(doc, entry, "security");
		item->security = member_text(doc, security, "type");
		/* Whichever of the three a network of this kind refers to. An open or
		 * OWE network names none of them and the field stays empty, which is
		 * the honest answer rather than a dash a screen has to interpret. */
		item->credential = NULL;
		{
			static const char *const keys[] = { "passphrase", "password", "private_key" };
			for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
				uint32_t held = ncfg_json_member(doc, security, keys[k]);
				char *named = member_text(doc, held, "name");
				if (named && *named) {
					item->credential = named;
					break;
				}
				free(named);
			}
			if (!item->credential) {
				item->credential = dup_string("");
			}
		}
		item->priority =
		    (int)ncfg_json_int(doc, ncfg_json_member(doc, entry, "priority"), 0);
		item->autoconnect =
		    ncfg_json_bool(doc, ncfg_json_member(doc, entry, "autoconnect"), 0);
		item->hidden = ncfg_json_bool(doc, ncfg_json_member(doc, entry, "hidden"), 0);
	}
	ncfg_json_free(doc);
	return 1;
}

void ncfg_dns_free(ncfg_dns_t *dns)
{
	if (!dns) {
		return;
	}
	free(dns->mode);
	for (size_t i = 0; i < dns->server_count; i++) {
		free(dns->servers[i]);
	}
	free(dns->servers);
	for (size_t i = 0; i < dns->search_count; i++) {
		free(dns->search[i]);
	}
	free(dns->search);
	dns->mode = NULL;
	dns->servers = NULL;
	dns->search = NULL;
	dns->server_count = 0;
	dns->search_count = 0;
	dns->managing = 0;
}

/*
 * One array of strings out of a JSON list, or NULL for an empty one.
 *
 * `*count` is set before the strings go in, so a caller freeing after a partial
 * failure walks the whole array rather than the finished part of it -- the same
 * order `convert_links` takes, and for the same reason.
 */
static char **string_list(const ncfg_json_doc_t *doc, uint32_t array, size_t *count)
{
	*count = 0;
	uint32_t total = ncfg_json_count(doc, array);
	if (!total) {
		return NULL;
	}
	char **items = calloc(total, sizeof(*items));
	if (!items) {
		return NULL;
	}
	*count = total;
	for (uint32_t i = 0; i < total; i++) {
		size_t length = 0;
		const char *text = ncfg_json_string(doc, ncfg_json_at(doc, array, i), &length);
		items[i] = text ? dup_text(text, length) : dup_string("");
	}
	return items;
}

int ncfg_client_dns(ncfg_client_t *client, ncfg_dns_t *out, char *err, size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	memset(out, 0, sizeof(*out));

	ncfg_json_doc_t *doc = ncfg_client_request(client, "{\"request\":\"show\"}", err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	uint32_t globals = ncfg_json_member(doc, ncfg_json_root(doc), "globals");
	uint32_t dns = ncfg_json_member(doc, globals, "dns");
	out->mode = member_text(doc, dns, "mode");
	out->servers = string_list(doc, ncfg_json_member(doc, dns, "servers"), &out->server_count);
	out->search = string_list(doc, ncfg_json_member(doc, dns, "search"), &out->search_count);
	ncfg_json_free(doc);

	/* The observed half, from a second request: the document says what was
	 * asked for and the status says what is. A mode that is not `none` with
	 * nothing observed is a configuration that has not taken effect, which
	 * is a different thing to report than either one alone. */
	doc = ncfg_client_request(client, "{\"request\":\"status\"}", err, err_size);
	if (doc) {
		if (!took_refusal(doc, err, err_size)) {
			uint32_t observed = ncfg_json_member(doc, ncfg_json_root(doc), "dns");
			out->managing = ncfg_json_count(doc, observed) > 0;
		}
		ncfg_json_free(doc);
	}
	return 1;
}

void ncfg_profiles_free(ncfg_profiles_t *profiles)
{
	if (!profiles) {
		return;
	}
	for (size_t i = 0; i < profiles->count; i++) {
		free(profiles->items[i].name);
	}
	free(profiles->items);
	free(profiles->chosen);
	profiles->items = NULL;
	profiles->count = 0;
	profiles->chosen = NULL;
}

int ncfg_client_profiles(ncfg_client_t *client, ncfg_profiles_t *out, char *err,
                         size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	out->items = NULL;
	out->count = 0;
	out->chosen = NULL;

	ncfg_json_doc_t *doc =
	    ncfg_client_request(client, "{\"request\":\"profile_list\"}", err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	/* Absent rather than empty when no profile is chosen, which is the
	 * default state and not an error. `member_text` gives NULL for a missing
	 * or null member, which is exactly the distinction wanted here. */
	out->chosen = member_text(doc, ncfg_json_root(doc), "chosen");

	uint32_t profiles = ncfg_json_member(doc, ncfg_json_root(doc), "profiles");
	uint32_t count = ncfg_json_count(doc, profiles);
	if (!count) {
		/* A machine with no profiles is an ordinary answer -- and
		 * calloc(0, n) may return NULL, which the next line would read as
		 * being out of memory. */
		ncfg_json_free(doc);
		return 1;
	}
	out->items = calloc(count, sizeof(*out->items));
	if (!out->items) {
		set_error(err, err_size, "out of memory");
		ncfg_json_free(doc);
		return 0;
	}
	out->count = count;

	for (uint32_t i = 0; i < count; i++) {
		uint32_t entry = ncfg_json_at(doc, profiles, i);
		out->items[i].name = member_text(doc, entry, "name");
		out->items[i].shipped =
		    ncfg_json_bool(doc, ncfg_json_member(doc, entry, "shipped"), 0);
	}
	ncfg_json_free(doc);
	return 1;
}

/* One selector word, appended only when the member is there. Building the
 * phrase this way rather than with a format string per combination is what
 * keeps eight optional selectors from becoming eight nested conditionals. */
static void append_selector(char *out, size_t size, const char *word, char *value)
{
	if (value && value[0]) {
		size_t used = strlen(out);
		if (used < size) {
			(void)snprintf(out + used, size - used, "%s%s %s",
			    used ? " " : "", word, value);
		}
	}
	free(value);
}

void ncfg_rules_free(ncfg_rules_t *rules)
{
	if (!rules) {
		return;
	}
	for (size_t i = 0; i < rules->count; i++) {
		free(rules->items[i].id);
		free(rules->items[i].family);
		free(rules->items[i].selector);
		free(rules->items[i].action);
		free(rules->items[i].table);
	}
	free(rules->items);
	rules->items = NULL;
	rules->count = 0;
}

int ncfg_client_rules(ncfg_client_t *client, ncfg_rules_t *out, char *err, size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	out->items = NULL;
	out->count = 0;

	ncfg_json_doc_t *doc = ncfg_client_request(client, "{\"request\":\"show\"}", err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	uint32_t rules = ncfg_json_member(doc, ncfg_json_root(doc), "rules");
	uint32_t count = ncfg_json_count(doc, rules);
	if (!count) {
		ncfg_json_free(doc);
		return 1;
	}
	out->items = calloc(count, sizeof(*out->items));
	if (!out->items) {
		set_error(err, err_size, "out of memory");
		ncfg_json_free(doc);
		return 0;
	}
	out->count = count;

	for (uint32_t i = 0; i < count; i++) {
		uint32_t entry = ncfg_json_at(doc, rules, i);
		out->items[i].id = member_text(doc, entry, "id");
		out->items[i].priority =
		    (int)ncfg_json_int(doc, ncfg_json_member(doc, entry, "priority"), 0);
		out->items[i].family = member_text(doc, entry, "family");
		out->items[i].action = member_text(doc, entry, "action");
		out->items[i].table = member_text(doc, entry, "table");

		char phrase[256];
		phrase[0] = '\0';
		append_selector(phrase, sizeof(phrase), "from", member_text(doc, entry, "from"));
		append_selector(phrase, sizeof(phrase), "to", member_text(doc, entry, "to"));
		append_selector(phrase, sizeof(phrase), "iif", member_text(doc, entry, "iif"));
		append_selector(phrase, sizeof(phrase), "oif", member_text(doc, entry, "oif"));
		out->items[i].selector = dup_string(phrase);
	}
	ncfg_json_free(doc);
	return 1;
}

void ncfg_bluetooths_free(ncfg_bluetooths_t *devices)
{
	if (!devices) {
		return;
	}
	for (size_t i = 0; i < devices->count; i++) {
		free(devices->items[i].id);
		free(devices->items[i].address);
		free(devices->items[i].profile);
	}
	free(devices->items);
	devices->items = NULL;
	devices->count = 0;
}

int ncfg_client_bluetooth(ncfg_client_t *client, ncfg_bluetooths_t *out, char *err,
                          size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	out->items = NULL;
	out->count = 0;

	ncfg_json_doc_t *doc = ncfg_client_request(client, "{\"request\":\"show\"}", err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	uint32_t devices = ncfg_json_member(doc, ncfg_json_root(doc), "bluetooth");
	uint32_t count = ncfg_json_count(doc, devices);
	if (!count) {
		ncfg_json_free(doc);
		return 1;
	}
	out->items = calloc(count, sizeof(*out->items));
	if (!out->items) {
		set_error(err, err_size, "out of memory");
		ncfg_json_free(doc);
		return 0;
	}
	out->count = count;

	for (uint32_t i = 0; i < count; i++) {
		uint32_t entry = ncfg_json_at(doc, devices, i);
		out->items[i].id = member_text(doc, entry, "id");
		out->items[i].address = member_text(doc, entry, "address");
		out->items[i].profile = member_text(doc, entry, "profile");
		out->items[i].autoconnect =
		    ncfg_json_bool(doc, ncfg_json_member(doc, entry, "autoconnect"), 0);
	}
	ncfg_json_free(doc);
	return 1;
}

/* A principal as the configuration spells it.
 *
 * The wire form is either a bare string -- "root", "any" -- or a one-member
 * object, {"group":"netdev"}. Rendered back to the configuration's own
 * spelling rather than to something this file invents, so that what a table
 * shows is what an operator would type.
 */
static char *principal_text(const ncfg_json_doc_t *doc, uint32_t object, const char *name)
{
	uint32_t member = ncfg_json_member(doc, object, name);
	size_t length = 0;
	const char *text = ncfg_json_string(doc, member, &length);

	if (text) {
		return dup_text(text, length);
	}
	for (size_t i = 0; i < 2; i++) {
		const char *kind = i ? "group" : "user";
		uint32_t inner = ncfg_json_member(doc, member, kind);
		const char *who = ncfg_json_string(doc, inner, &length);
		if (who) {
			char rendered[160];
			(void)snprintf(rendered, sizeof(rendered), "%s:%.*s", kind, (int)length,
			    who);
			return dup_string(rendered);
		}
	}
	return dup_string("");
}

void ncfg_globals_free(ncfg_globals_t *globals)
{
	if (!globals) {
		return;
	}
	free(globals->networking);
	free(globals->profile);
	free(globals->hostname);
	free(globals->on_drift);
	free(globals->control_observe);
	free(globals->control_wifi);
	free(globals->control_admin);
	memset(globals, 0, sizeof(*globals));
}

int ncfg_client_globals(ncfg_client_t *client, ncfg_globals_t *out, char *err, size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	memset(out, 0, sizeof(*out));

	ncfg_json_doc_t *doc = ncfg_client_request(client, "{\"request\":\"show\"}", err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	uint32_t globals = ncfg_json_member(doc, ncfg_json_root(doc), "globals");
	out->networking = member_text(doc, globals, "networking");
	if (!out->networking[0]) {
		/* Absent means the default, and the default is on. A blank cell
		 * would read as "netcfgd does not know", which is a different
		 * thing from "this machine does networking". */
		free(out->networking);
		out->networking = dup_string("on");
	}
	out->profile = member_text(doc, globals, "profile");
	out->on_drift = member_text(doc, globals, "on_drift_default");
	out->confirm = (int)ncfg_json_int(doc, ncfg_json_member(doc, globals, "confirm_default"), 0);

	/* Either the string "none"/"from_dhcp" or {"static":"name"}, which is the
	 * same shape a principal takes and is read the same way. */
	uint32_t hostname = ncfg_json_member(doc, globals, "hostname_policy");
	size_t length = 0;
	const char *policy = ncfg_json_string(doc, hostname, &length);
	if (policy) {
		out->hostname = dup_text(policy, length);
	} else {
		out->hostname = member_text(doc, hostname, "static");
	}

	uint32_t control = ncfg_json_member(doc, globals, "control");
	out->control_observe = principal_text(doc, control, "observe");
	out->control_wifi = principal_text(doc, control, "wifi");
	out->control_admin = principal_text(doc, control, "admin");

	uint32_t remote = ncfg_json_member(doc, globals, "remote");
	out->remote_observe = ncfg_json_bool(doc, ncfg_json_member(doc, remote, "observe"), 0);
	out->remote_wifi = ncfg_json_bool(doc, ncfg_json_member(doc, remote, "wifi"), 0);
	out->remote_admin = ncfg_json_bool(doc, ncfg_json_member(doc, remote, "admin"), 0);

	ncfg_json_free(doc);
	return 1;
}

void ncfg_hooks_free(ncfg_hooks_t *hooks)
{
	if (!hooks) {
		return;
	}
	for (size_t i = 0; i < hooks->count; i++) {
		free(hooks->items[i].interface);
		free(hooks->items[i].phase);
		free(hooks->items[i].path);
		free(hooks->items[i].run_as);
	}
	free(hooks->items);
	hooks->items = NULL;
	hooks->count = 0;
}

int ncfg_client_hooks(ncfg_client_t *client, ncfg_hooks_t *out, char *err, size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	out->items = NULL;
	out->count = 0;

	ncfg_json_doc_t *doc = ncfg_client_request(client, "{\"request\":\"show\"}", err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	uint32_t interfaces = ncfg_json_member(doc, ncfg_json_root(doc), "interfaces");
	uint32_t interface_count = ncfg_json_count(doc, interfaces);

	/* Counted first, because the rows are spread across interfaces and one
	 * allocation is easier to reason about than a growing array. */
	size_t total = 0;
	for (uint32_t i = 0; i < interface_count; i++) {
		uint32_t hooks = ncfg_json_member(doc, ncfg_json_at(doc, interfaces, i), "hooks");
		total += ncfg_json_count(doc, hooks);
	}
	if (!total) {
		ncfg_json_free(doc);
		return 1;
	}
	out->items = calloc(total, sizeof(*out->items));
	if (!out->items) {
		set_error(err, err_size, "out of memory");
		ncfg_json_free(doc);
		return 0;
	}
	out->count = total;

	size_t row = 0;
	for (uint32_t i = 0; i < interface_count; i++) {
		uint32_t interface = ncfg_json_at(doc, interfaces, i);
		char *name = member_text(doc, interface, "name");
		uint32_t hooks = ncfg_json_member(doc, interface, "hooks");
		uint32_t count = ncfg_json_count(doc, hooks);
		for (uint32_t j = 0; j < count && row < total; j++, row++) {
			uint32_t entry = ncfg_json_at(doc, hooks, j);
			out->items[row].interface = dup_string(name ? name : "");
			out->items[row].phase = member_text(doc, entry, "phase");
			out->items[row].path = member_text(doc, entry, "path");
			out->items[row].run_as = member_text(doc, entry, "run_as");
			out->items[row].timeout =
			    (int)ncfg_json_int(doc, ncfg_json_member(doc, entry, "timeout"), 0);
		}
		free(name);
	}
	ncfg_json_free(doc);
	return 1;
}

void ncfg_modems_free(ncfg_modems_t *modems)
{
	if (!modems) {
		return;
	}
	for (size_t i = 0; i < modems->count; i++) {
		free(modems->items[i].device);
		for (size_t j = 0; j < modems->items[i].sim_count; j++) {
			free(modems->items[i].sim[j]);
		}
		free(modems->items[i].sim);
		free(modems->items[i].selected);
		free(modems->items[i].apn);
	}
	free(modems->items);
	modems->items = NULL;
	modems->count = 0;
}

int ncfg_client_modems(ncfg_client_t *client, ncfg_modems_t *out, char *err,
                       size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	out->items = NULL;
	out->count = 0;

	ncfg_json_doc_t *doc =
	    ncfg_client_request(client, "{\"request\":\"modem_list\"}", err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	uint32_t modems = ncfg_json_member(doc, ncfg_json_root(doc), "modems");
	uint32_t count = ncfg_json_count(doc, modems);
	if (!count) {
		/* A machine with no modem is the ordinary case, not an error --
		 * and calloc(0, n) may return NULL, which the next line would
		 * read as being out of memory. */
		ncfg_json_free(doc);
		return 1;
	}
	out->items = calloc(count, sizeof(*out->items));
	if (!out->items) {
		set_error(err, err_size, "out of memory");
		ncfg_json_free(doc);
		return 0;
	}
	out->count = count;

	for (uint32_t i = 0; i < count; i++) {
		uint32_t entry = ncfg_json_at(doc, modems, i);
		out->items[i].device = member_text(doc, entry, "device");
		out->items[i].selected = member_text(doc, entry, "selected");
		out->items[i].apn = member_text(doc, entry, "apn");
		out->items[i].cycle_pending =
		    ncfg_json_bool(doc, ncfg_json_member(doc, entry, "cycle_pending"), 0);

		uint32_t sim = ncfg_json_member(doc, entry, "sim");
		uint32_t sources = ncfg_json_count(doc, sim);
		if (!sources) {
			/* A modem block with no source listed is an ordinary
			 * configuration: an APN, and the SIM left alone. */
			continue;
		}
		out->items[i].sim = calloc(sources, sizeof(*out->items[i].sim));
		if (!out->items[i].sim) {
			set_error(err, err_size, "out of memory");
			ncfg_json_free(doc);
			ncfg_modems_free(out);
			return 0;
		}
		out->items[i].sim_count = sources;
		for (uint32_t j = 0; j < sources; j++) {
			size_t length = 0;
			const char *text =
			    ncfg_json_string(doc, ncfg_json_at(doc, sim, j), &length);
			out->items[i].sim[j] = dup_text(text ? text : "", text ? length : 0);
		}
	}
	ncfg_json_free(doc);
	return 1;
}

void ncfg_probes_free(ncfg_probes_t *probes)
{
	if (!probes) {
		return;
	}
	for (size_t i = 0; i < probes->count; i++) {
		free(probes->items[i].name);
		free(probes->items[i].directory);
		free(probes->items[i].text);
	}
	free(probes->items);
	probes->items = NULL;
	probes->count = 0;
}

int ncfg_client_probes(ncfg_client_t *client, ncfg_probes_t *out, char *err, size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	out->items = NULL;
	out->count = 0;

	ncfg_json_doc_t *doc =
	    ncfg_client_request(client, "{\"request\":\"probe_list\"}", err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	uint32_t probes = ncfg_json_member(doc, ncfg_json_root(doc), "probes");
	uint32_t count = ncfg_json_count(doc, probes);
	if (!count) {
		/* A machine with no scripts is an ordinary answer -- and calloc(0, n)
		 * may return NULL, which the next line would read as being out of
		 * memory. */
		ncfg_json_free(doc);
		return 1;
	}
	out->items = calloc(count, sizeof(*out->items));
	if (!out->items) {
		set_error(err, err_size, "out of memory");
		ncfg_json_free(doc);
		return 0;
	}
	out->count = count;

	for (uint32_t i = 0; i < count; i++) {
		uint32_t entry = ncfg_json_at(doc, probes, i);
		out->items[i].name = member_text(doc, entry, "name");
		out->items[i].directory = member_text(doc, entry, "directory");
		out->items[i].text = member_text(doc, entry, "text");
		out->items[i].editable =
		    ncfg_json_bool(doc, ncfg_json_member(doc, entry, "editable"), 0);
	}
	ncfg_json_free(doc);
	return 1;
}

void ncfg_radios_free(ncfg_radios_t *radios)
{
	if (!radios) {
		return;
	}
	for (size_t i = 0; i < radios->count; i++) {
		free(radios->items[i].interface);
	}
	free(radios->items);
	memset(radios, 0, sizeof(*radios));
}

int ncfg_client_radios(ncfg_client_t *client, ncfg_radios_t *out, char *err, size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no output");
		return 0;
	}
	memset(out, 0, sizeof(*out));

	ncfg_json_doc_t *doc = ncfg_client_request(client, "{\"request\":\"radios\"}", err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	uint32_t root = ncfg_json_root(doc);
	uint32_t list = ncfg_json_member(doc, root, "radios");
	uint32_t count = ncfg_json_count(doc, list);
	if (!count) {
		/* A machine with no radio is a real answer, and calloc(0) may return
		 * NULL without failing -- which the free path would then read as an
		 * allocation that went wrong. Same trap convert_links() documents. */
		ncfg_json_free(doc);
		return 1;
	}

	out->items = calloc(count, sizeof(*out->items));
	if (!out->items) {
		set_error(err, err_size, "out of memory");
		ncfg_json_free(doc);
		return 0;
	}
	out->count = count;
	for (uint32_t i = 0; i < count; i++) {
		uint32_t entry = ncfg_json_at(doc, list, i);
		out->items[i].interface = member_text(doc, entry, "interface");
		out->items[i].activated =
		    ncfg_json_bool(doc, ncfg_json_member(doc, entry, "activated"), 0);
		out->items[i].supplicant =
		    ncfg_json_bool(doc, ncfg_json_member(doc, entry, "supplicant"), 0);
		if (!out->items[i].interface) {
			set_error(err, err_size, "out of memory");
			ncfg_radios_free(out);
			ncfg_json_free(doc);
			return 0;
		}
	}
	ncfg_json_free(doc);
	return 1;
}

int ncfg_client_radio_set(ncfg_client_t *client, const char *interface, int activate, char *err,
              size_t err_size)
{
	if (!interface) {
		set_error(err, err_size, "a radio needs a name");
		return 0;
	}

	char request[512];
	int head = snprintf(request, sizeof(request), "{\"request\":\"radio_set\",\"interface\":");
	if (head < 0 || (size_t)head >= sizeof(request)) {
		return 0;
	}
	size_t at = (size_t)head;
	if (!ncfg_client_quote(interface, request + at, sizeof(request) - at)) {
		set_error(err, err_size, "that interface name does not fit in one request");
		return 0;
	}
	at += strlen(request + at);
	int span = snprintf(request + at, sizeof(request) - at, ",\"activate\":%s}",
	            activate ? "true" : "false");
	if (span < 0 || (size_t)span >= sizeof(request) - at) {
		set_error(err, err_size, "that interface name does not fit in one request");
		return 0;
	}

	ncfg_json_doc_t *doc = ncfg_client_request(client, request, err, err_size);
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size);
	ncfg_json_free(doc);
	return done;
}

static int convert_scan(const ncfg_json_doc_t *doc, ncfg_scan_t *out, char *err, size_t err_size)
{
	uint32_t root = ncfg_json_root(doc);
	uint32_t points = ncfg_json_member(doc, root, "access_points");
	uint32_t count = ncfg_json_count(doc, points);

	out->interface = member_text(doc, root, "interface");
	if (!out->interface) {
		set_error(err, err_size, "out of memory");
		return 0;
	}
	if (!count) {
		/* A radio that found nothing is a real answer, and the same
		 * calloc(0) trap convert_links() documents applies here. */
		return 1;
	}
	out->items = calloc(count, sizeof(*out->items));
	if (!out->items) {
		set_error(err, err_size, "out of memory");
		ncfg_scan_free(out);
		return 0;
	}
	out->count = count;

	for (uint32_t i = 0; i < count; i++) {
		uint32_t entry = ncfg_json_at(doc, points, i);
		ncfg_access_point_t *item = &out->items[i];

		item->bssid = member_text(doc, entry, "bssid");
		item->ssid = member_text(doc, entry, "ssid");
		item->name = member_text(doc, entry, "name");
		/* Asked separately from the text, because absent and empty are
		 * different networks: the daemon omits `name` when the SSID is
		 * not valid UTF-8, and a hidden network broadcasts an SSID that
		 * genuinely is empty. member_text() flattens both to "", so the
		 * distinction has to come from the member itself. */
		item->named = ncfg_json_member(doc, entry, "name") != NCFG_JSON_NONE;
		item->display = ncfg_access_point_display(item->named, item->name, item->ssid);
		item->configured = member_text(doc, entry, "configured");
		item->frequency = (int)ncfg_json_int(doc, ncfg_json_member(doc, entry, "frequency"), 0);
		item->signal = (int)ncfg_json_int(doc, ncfg_json_member(doc, entry, "signal"), 0);
		item->secured = ncfg_json_bool(doc, ncfg_json_member(doc, entry, "secured"), 0);
		/* Defaults to 0, which is what a daemon older than the field sends:
		 * an absent member reads as "not enterprise", so a client asks for a
		 * passphrase exactly as it did before rather than showing nothing. */
		item->enterprise =
		    ncfg_json_bool(doc, ncfg_json_member(doc, entry, "enterprise"), 0);
		if (!item->bssid || !item->ssid || !item->name || !item->configured
		    || !item->display) {
			set_error(err, err_size, "out of memory");
			ncfg_scan_free(out);
			return 0;
		}
	}
	return 1;
}

static int convert_wifi_status(const ncfg_json_doc_t *doc, ncfg_wifi_status_t *out, char *err,
                   size_t err_size)
{
	uint32_t root = ncfg_json_root(doc);

	out->interface = member_text(doc, root, "interface");
	out->state = member_text(doc, root, "state");
	out->ssid = member_text(doc, root, "ssid");
	out->name = member_text(doc, root, "name");
	out->bssid = member_text(doc, root, "bssid");
	out->network = member_text(doc, root, "network");
	if (!out->interface || !out->state || !out->ssid || !out->name || !out->bssid
	    || !out->network) {
		set_error(err, err_size, "out of memory");
		ncfg_wifi_status_free(out);
		return 0;
	}
	return 1;
}

/*
 * Append `,"key":"value"` with the value quoted, or nothing when it is NULL.
 *
 * Returns 0 if it would not fit, which the caller turns into a refusal rather
 * than a shorter request: a truncated request is a different request, and one
 * of these members is a passphrase.
 */
static int append_member(char *out, size_t out_size, size_t *at, const char *key,
             const char *value)
{
	if (!value) {
		return 1;
	}
	int head = snprintf(out + *at, out_size - *at, ",\"%s\":", key);
	if (head < 0 || (size_t)head >= out_size - *at) {
		return 0;
	}
	*at += (size_t)head;
	size_t span = ncfg_client_quote(value, out + *at, out_size - *at);
	if (!span) {
		return 0;
	}
	*at += span;
	return 1;
}

/*
 * Wipe a buffer that held a secret.
 *
 * Through a volatile pointer so the compiler cannot decide the writes are dead
 * -- which it may, and does, for a plain memset to a local about to go out of
 * scope. This is the one request in this library that carries a passphrase, so
 * it is the one place worth the care.
 */
static void wipe(char *buffer, size_t size)
{
	volatile char *p = (volatile char *)buffer;

	while (size--) {
		*p++ = '\0';
	}
}

int ncfg_client_wifi_add(ncfg_client_t *client, const ncfg_network_t *network, char *err,
             size_t err_size)
{
	if (!network || !network->ssid) {
		set_error(err, err_size, "a network needs an ssid, as lowercase hex");
		return 0;
	}

	char request[2048];
	int head = snprintf(request, sizeof(request), "{\"request\":\"wifi_add\",\"ssid\":");
	if (head < 0 || (size_t)head >= sizeof(request)) {
		return 0;
	}
	size_t at = (size_t)head;

	int built = ncfg_client_quote(network->ssid, request + at, sizeof(request) - at) > 0;
	if (built) {
		at += strlen(request + at);
	}
	built = built && append_member(request, sizeof(request), &at, "id", network->id)
	    && append_member(request, sizeof(request), &at, "passphrase", network->passphrase)
	    && append_member(request, sizeof(request), &at, "proto", network->proto);

	if (built && network->hidden) {
		int span = snprintf(request + at, sizeof(request) - at, ",\"hidden\":true");
		built = span >= 0 && (size_t)span < sizeof(request) - at;
		if (built) {
			at += (size_t)span;
		}
	}
	if (built && network->priority >= 0) {
		int span = snprintf(request + at, sizeof(request) - at, ",\"priority\":%d",
		            network->priority);
		built = span >= 0 && (size_t)span < sizeof(request) - at;
		if (built) {
			at += (size_t)span;
		}
	}
	if (built && network->eap) {
		const ncfg_eap_t *eap = network->eap;
		/* Required by the daemon, and refused here so the message names the
		 * missing field rather than arriving as a round trip that says the
		 * request would not deserialise. */
		if (!eap->method || !eap->identity) {
			wipe(request, sizeof(request));
			set_error(err, err_size,
			      "an enterprise network needs a method and an identity");
			return 0;
		}
		int span = snprintf(request + at, sizeof(request) - at, ",\"eap\":{");
		built = span >= 0 && (size_t)span < sizeof(request) - at;
		if (built) {
			at += (size_t)span;
		}
		/* `method` opens the object, so it is written without the leading
		 * comma append_member() adds and the rest follow it. */
		built = built
		    && snprintf(request + at, sizeof(request) - at, "\"method\":") > 0;
		if (built) {
			at += strlen(request + at);
			built = ncfg_client_quote(eap->method, request + at,
			                  sizeof(request) - at) > 0;
		}
		if (built) {
			at += strlen(request + at);
		}
		built = built
		    && append_member(request, sizeof(request), &at, "identity", eap->identity)
		    && append_member(request, sizeof(request), &at, "anonymous_identity",
		               eap->anonymous_identity)
		    && append_member(request, sizeof(request), &at, "phase2", eap->phase2)
		    && append_member(request, sizeof(request), &at, "ca_cert", eap->ca_cert)
		    && append_member(request, sizeof(request), &at, "client_cert",
		               eap->client_cert);
		if (built && at + 1 < sizeof(request)) {
			request[at++] = '}';
		} else {
			built = 0;
		}
	}
	if (!built || at + 2 > sizeof(request)) {
		wipe(request, sizeof(request));
		set_error(err, err_size, "that network does not fit in one request");
		return 0;
	}
	request[at++] = '}';
	request[at] = '\0';

	ncfg_json_doc_t *doc = ncfg_client_request(client, request, err, err_size);
	/* Before anything else, including the error path: the passphrase has been
	 * written to the socket and has no further business in this process. */
	wipe(request, sizeof(request));
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size);
	ncfg_json_free(doc);
	return done;
}

/*
 * The buffer this needs is sized rather than fixed, which is the one way it
 * differs from every other request here.
 *
 * A certificate is the value this exists for and a PEM is kilobytes, so the
 * 2048-byte stack buffer the other requests use would refuse exactly the case
 * worth having. Worst case for JSON escaping is six bytes out per byte in
 * (\u00XX for a control character), plus the fixed text and the name.
 */
/*
 * Both writers are one function: the requests differ only in their verb, and
 * two copies of this would drift in the quoting, which is the half that has to
 * be right.
 */
static int put_named_text(ncfg_client_t *client, const char *verb, const char *name,
    const char *text, int replace, char *err, size_t err_size)
{
	if (!name || !text) {
		set_error(err, err_size, "a drop-in needs a name and some text");
		return 0;
	}
	if (!*text) {
		/* Refused here as well as at the daemon: an empty drop-in is a file
		 * that configures nothing, and the round trip would not say which
		 * name was empty. Removing one is its own verb. */
		set_error(err, err_size, "an empty drop-in is a file that configures nothing");
		return 0;
	}

	const size_t need = 64 + strlen(verb) + strlen(name) * 6 + strlen(text) * 6;
	char *request = malloc(need);
	if (!request) {
		set_error(err, err_size, "that drop-in does not fit in memory");
		return 0;
	}

	int head = snprintf(request, need, "{\"request\":\"%s\",\"name\":", verb);
	int built = head > 0 && (size_t)head < need;
	size_t at = built ? (size_t)head : 0;
	if (built) {
		built = ncfg_client_quote(name, request + at, need - at) > 0;
	}
	if (built) {
		at += strlen(request + at);
		built = append_member(request, need, &at, "text", text);
	}
	if (built && replace) {
		int span = snprintf(request + at, need - at, ",\"replace\":true");
		built = span >= 0 && (size_t)span < need - at;
		if (built) {
			at += (size_t)span;
		}
	}
	if (!built || at + 2 > need) {
		free(request);
		set_error(err, err_size, "that drop-in does not fit in one request");
		return 0;
	}
	request[at++] = '}';
	request[at] = '\0';

	ncfg_json_doc_t *doc = ncfg_client_request(client, request, err, err_size);
	free(request);
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size);
	ncfg_json_free(doc);
	return done;
}

int ncfg_client_config_put(ncfg_client_t *client, const char *name, const char *text, int replace,
    char *err, size_t err_size)
{
	return put_named_text(client, "config_put", name, text, replace, err, err_size);
}

void ncfg_secrets_free(ncfg_secrets_t *secrets)
{
	if (!secrets) {
		return;
	}
	for (size_t i = 0; i < secrets->count; i++) {
		free(secrets->items[i].name);
		free(secrets->items[i].used_by);
	}
	free(secrets->items);
	secrets->items = NULL;
	secrets->count = 0;
}

int ncfg_client_secrets(ncfg_client_t *client, ncfg_secrets_t *out, char *err, size_t err_size)
{
	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	out->items = NULL;
	out->count = 0;

	ncfg_json_doc_t *doc =
	    ncfg_client_request(client, "{\"request\":\"secret_list\"}", err, err_size);
	if (!doc) {
		return 0;
	}
	if (took_refusal(doc, err, err_size)) {
		ncfg_json_free(doc);
		return 0;
	}

	uint32_t secrets = ncfg_json_member(doc, ncfg_json_root(doc), "secrets");
	uint32_t count = ncfg_json_count(doc, secrets);
	if (!count) {
		ncfg_json_free(doc);
		return 1;
	}
	out->items = calloc(count, sizeof(*out->items));
	if (!out->items) {
		set_error(err, err_size, "out of memory");
		ncfg_json_free(doc);
		return 0;
	}
	out->count = count;

	for (uint32_t i = 0; i < count; i++) {
		uint32_t entry = ncfg_json_at(doc, secrets, i);
		out->items[i].name = member_text(doc, entry, "name");
		out->items[i].stored = ncfg_json_bool(doc, ncfg_json_member(doc, entry, "stored"), 0);

		/* Joined here rather than in the view: the seam puts the models
		 * below the widgets, and "which blocks use this" is a model. */
		char joined[512];
		joined[0] = '\0';
		uint32_t used = ncfg_json_member(doc, entry, "used_by");
		uint32_t users = ncfg_json_count(doc, used);
		for (uint32_t j = 0; j < users; j++) {
			size_t length = 0;
			const char *text = ncfg_json_string(doc, ncfg_json_at(doc, used, j), &length);
			size_t at = strlen(joined);
			if (!text || at >= sizeof(joined)) {
				continue;
			}
			(void)snprintf(joined + at, sizeof(joined) - at, "%s%.*s", at ? ", " : "",
			    (int)length, text);
		}
		out->items[i].used_by = dup_string(joined);
	}
	ncfg_json_free(doc);
	return 1;
}

int ncfg_client_profile_save(ncfg_client_t *client, const char *name, int replace, char *err,
                             size_t err_size)
{
	if (!name || !name[0]) {
		set_error(err, err_size, "a profile needs a name to be saved as");
		return 0;
	}

	char stack[512];
	char *request = stack;
	size_t need = 96 + strlen(name) * 6;

	if (need > sizeof(stack)) {
		request = malloc(need);
		if (!request) {
			set_error(err, err_size, "that name does not fit in memory");
			return 0;
		}
	} else {
		need = sizeof(stack);
	}

	int head = snprintf(request, need, "{\"request\":\"profile_save\",\"name\":");
	int built = head > 0 && (size_t)head < need;
	size_t at = built ? (size_t)head : 0;
	if (built) {
		built = ncfg_client_quote(name, request + at, need - at) > 0;
	}
	if (built) {
		at += strlen(request + at);
		int tail = snprintf(request + at, need - at, "%s}",
		    replace ? ",\"replace\":true" : "");
		built = tail > 0 && (size_t)tail < need - at;
	}
	if (!built) {
		if (request != stack) {
			free(request);
		}
		set_error(err, err_size, "that name does not fit in one request");
		return 0;
	}

	ncfg_json_doc_t *doc = ncfg_client_request(client, request, err, err_size);
	if (request != stack) {
		free(request);
	}
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size);
	ncfg_json_free(doc);
	return done;
}

int ncfg_client_profile_set(ncfg_client_t *client, const char *name, char *err, size_t err_size)
{
	/* NULL is "stop using a profile", which is a real state rather than a
	 * missing argument -- so it is sent as the request with no name, not
	 * refused here. */
	char stack[512];
	char *request = stack;
	size_t need = sizeof(stack);

	if (!name) {
		snprintf(stack, sizeof(stack), "{\"request\":\"profile_set\"}");
	} else {
		need = 64 + strlen(name) * 6;
		if (need > sizeof(stack)) {
			request = malloc(need);
			if (!request) {
				set_error(err, err_size, "that name does not fit in memory");
				return 0;
			}
		} else {
			need = sizeof(stack);
		}

		int head = snprintf(request, need, "{\"request\":\"profile_set\",\"name\":");
		int built = head > 0 && (size_t)head < need;
		size_t at = built ? (size_t)head : 0;
		if (built) {
			built = ncfg_client_quote(name, request + at, need - at) > 0;
		}
		if (built) {
			at += strlen(request + at);
		}
		if (!built || at + 2 > need) {
			if (request != stack) {
				free(request);
			}
			set_error(err, err_size, "that name does not fit in one request");
			return 0;
		}
		request[at++] = '}';
		request[at] = '\0';
	}

	ncfg_json_doc_t *doc = ncfg_client_request(client, request, err, err_size);
	if (request != stack) {
		free(request);
	}
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size);
	ncfg_json_free(doc);
	return done;
}

int ncfg_client_probe_put(ncfg_client_t *client, const char *name, const char *text, int replace,
    char *err, size_t err_size)
{
	return put_named_text(client, "probe_put", name, text, replace, err, err_size);
}

int ncfg_client_secret_put(ncfg_client_t *client, const char *name, const char *value,
               int replace, char *err, size_t err_size)
{
	if (!name || !value) {
		set_error(err, err_size, "a secret needs a name and a value");
		return 0;
	}
	if (!*value) {
		/* Refused here rather than at the daemon, which refuses it too: an
		 * empty secret fails at the moment it is used rather than now, and
		 * the round trip would not say which file was empty. */
		set_error(err, err_size, "an empty secret is one that fails when it is used");
		return 0;
	}

	const size_t name_len = strlen(name);
	const size_t value_len = strlen(value);
	/* 64 covers the fixed text and the `replace` member with room over. */
	const size_t need = 64 + name_len * 6 + value_len * 6;
	char *request = malloc(need);
	if (!request) {
		set_error(err, err_size, "that secret does not fit in memory");
		return 0;
	}

	int head = snprintf(request, need, "{\"request\":\"secret_put\",\"name\":");
	int built = head > 0 && (size_t)head < need;
	size_t at = built ? (size_t)head : 0;
	if (built) {
		built = ncfg_client_quote(name, request + at, need - at) > 0;
	}
	if (built) {
		at += strlen(request + at);
		built = append_member(request, need, &at, "value", value);
	}
	if (built && replace) {
		int span = snprintf(request + at, need - at, ",\"replace\":true");
		built = span >= 0 && (size_t)span < need - at;
		if (built) {
			at += (size_t)span;
		}
	}
	if (!built || at + 2 > need) {
		wipe(request, need);
		free(request);
		set_error(err, err_size, "that secret does not fit in one request");
		return 0;
	}
	request[at++] = '}';
	request[at] = '\0';

	ncfg_json_doc_t *doc = ncfg_client_request(client, request, err, err_size);
	/* Before anything else, including the error path: the value has been
	 * written to the socket and has no further business in this process. */
	wipe(request, need);
	free(request);
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size);
	ncfg_json_free(doc);
	return done;
}

int ncfg_client_wifi_scan(ncfg_client_t *client, const char *interface, ncfg_scan_t *out,
              char *err, size_t err_size)
{
	if (!out || !interface) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	memset(out, 0, sizeof(*out));

	char request[512];
	if (!wifi_request(request, sizeof(request), "wifi_scan", interface)) {
		set_error(err, err_size, "interface name is too long to ask about");
		return 0;
	}
	ncfg_json_doc_t *doc = ncfg_client_request(client, request, err, err_size);
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size) && convert_scan(doc, out, err, err_size);
	ncfg_json_free(doc);
	return done;
}

int ncfg_client_wifi_status(ncfg_client_t *client, const char *interface,
                ncfg_wifi_status_t *out, char *err, size_t err_size)
{
	if (!out || !interface) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	memset(out, 0, sizeof(*out));

	char request[512];
	if (!wifi_request(request, sizeof(request), "wifi_status", interface)) {
		set_error(err, err_size, "interface name is too long to ask about");
		return 0;
	}
	ncfg_json_doc_t *doc = ncfg_client_request(client, request, err, err_size);
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size) && convert_wifi_status(doc, out, err, err_size);
	ncfg_json_free(doc);
	return done;
}

int ncfg_client_wifi_connect(ncfg_client_t *client, const char *interface, const char *network,
                 char *err, size_t err_size)
{
	if (!interface || !network) {
		set_error(err, err_size, "no network to join");
		return 0;
	}

	char request[768];
	int head = snprintf(request, sizeof(request), "{\"request\":\"wifi_connect\",\"interface\":");
	if (head < 0 || (size_t)head >= sizeof(request)) {
		return 0;
	}
	size_t at = (size_t)head;
	size_t span = ncfg_client_quote(interface, request + at, sizeof(request) - at);
	if (!span) {
		set_error(err, err_size, "interface name is too long to ask about");
		return 0;
	}
	at += span;
	int mid = snprintf(request + at, sizeof(request) - at, ",\"network\":");
	if (mid < 0 || (size_t)mid >= sizeof(request) - at) {
		return 0;
	}
	at += (size_t)mid;
	/* The network's id, quoted for the same reason the interface is: it comes
	 * from a `network` block whose label an operator chose, and 0069 lets that
	 * be any string the config language accepts. */
	span = ncfg_client_quote(network, request + at, sizeof(request) - at);
	if (!span) {
		set_error(err, err_size, "network name is too long to ask about");
		return 0;
	}
	at += span;
	if (at + 2 > sizeof(request)) {
		return 0;
	}
	request[at++] = '}';
	request[at] = '\0';

	ncfg_json_doc_t *doc = ncfg_client_request(client, request, err, err_size);
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size);
	ncfg_json_free(doc);
	return done;
}

int ncfg_client_wifi_disconnect(ncfg_client_t *client, const char *interface, char *err,
                size_t err_size)
{
	if (!interface) {
		set_error(err, err_size, "no interface to leave");
		return 0;
	}

	char request[512];
	if (!wifi_request(request, sizeof(request), "wifi_disconnect", interface)) {
		set_error(err, err_size, "interface name is too long to ask about");
		return 0;
	}
	ncfg_json_doc_t *doc = ncfg_client_request(client, request, err, err_size);
	if (!doc) {
		return 0;
	}
	int done = !took_refusal(doc, err, err_size);
	ncfg_json_free(doc);
	return done;
}

/*
 * `"name":["a","b"]`, appended, or nothing at all for an empty list.
 *
 * Absent rather than `[]` because the daemon defaults both to empty and an
 * empty array says the same thing at more length -- and because a request that
 * carries consent keys on every apply makes "did the operator agree to
 * something" invisible in a packet capture and in the daemon's log.
 *
 * Returns 0 if it would not fit, which the caller turns into a refusal rather
 * than a truncated request: half a consent list is consent to the wrong things.
 */
static int append_consent(char *out, size_t out_size, size_t *at, const char *name,
              const char *const *values, size_t count)
{
	if (!count) {
		return 1;
	}
	int written = snprintf(out + *at, out_size - *at, ",\"%s\":[", name);
	if (written < 0 || (size_t)written >= out_size - *at) {
		return 0;
	}
	*at += (size_t)written;

	for (size_t i = 0; i < count; i++) {
		if (i) {
			if (*at + 1 >= out_size) {
				return 0;
			}
			out[(*at)++] = ',';
		}
		/* Quoted, never interpolated. An interface name is not guaranteed
		 * to be a bare word, and a name with a quote in it would produce a
		 * request that consents to something else. */
		size_t span = ncfg_client_quote(values[i], out + *at, out_size - *at);
		if (!span) {
			return 0;
		}
		*at += span;
	}
	if (*at + 2 >= out_size) {
		return 0;
	}
	out[(*at)++] = ']';
	out[*at] = '\0';
	return 1;
}

int ncfg_client_apply(ncfg_client_t *client, unsigned confirm_seconds,
              const ncfg_consent_t *consent, ncfg_journal_t *out, char *err,
              size_t err_size)
{
	/* Not NCFG_LINE_MAX: that bounds what may be *read* from a socket, and a
	 * megabyte of it on the stack is a way to fall off the end of one. An
	 * interface name is at most 15 characters, so this holds several hundred
	 * of them -- past any machine's interface count, and still a bound. */
	char request[8192];
	size_t at = 0;

	if (!out) {
		set_error(err, err_size, "no result to fill in");
		return 0;
	}
	memset(out, 0, sizeof(*out));

	/* No window means the field is left out, not sent as zero: `confirm` is
	 * an option on the daemon's side and `"confirm":0` is a window of no
	 * seconds, which arms and expires. Two spellings of "no" where one of
	 * them reverts the change is not a thing to leave to a reader. */
	int written = confirm_seconds
	              ? snprintf(request, sizeof(request),
	                 "{\"request\":\"apply\",\"confirm\":%u", confirm_seconds)
	              : snprintf(request, sizeof(request), "{\"request\":\"apply\"");
	if (written < 0 || (size_t)written >= sizeof(request)) {
		set_error(err, err_size, "cannot build the request");
		return 0;
	}
	at = (size_t)written;

	/* Two lists and never one flag: they consent to different things, and
	 * 0087's neighbour argument applies here too -- an operator who accepted
	 * an outage on one interface has not agreed to leave a key on another. */
	if (consent
	    && (!append_consent(request, sizeof(request), &at, "allow_disruption", consent->disrupt,
	            consent->disrupt_count)
	    || !append_consent(request, sizeof(request), &at, "strand_credentials",
	               consent->strand, consent->strand_count))) {
		set_error(err, err_size, "that is more consent than one request can carry");
		return 0;
	}
	if (at + 2 > sizeof(request)) {
		set_error(err, err_size, "cannot build the request");
		return 0;
	}
	request[at++] = '}';
	request[at] = '\0';

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
