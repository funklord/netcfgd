/*
 * profile.c -- `ncfg profile`: which configuration profile the machine runs.
 *
 * 0151: a profile is a directory of drop-ins layered on `conf.d`, and it is
 * switched by hand. This is the hand.
 *
 * SETTING ONE IS AN ORDINARY CONFIGURATION WRITE
 *   Not a mode the daemon remembers: it puts `global { profile = "<name>" }`
 *   in a drop-in, through the daemon like every other write since 0127. So the
 *   state is in the configuration where it can be read, diffed and committed,
 *   `ncfg plan` shows what changing it would do before it does it, and there is
 *   nothing for a reboot to forget.
 *
 * WHY A CLIENT ASKS THE DAEMON WHAT PROFILES THERE ARE
 *   Listing the local `/etc/netcfgd/profile` would show *this* laptop while
 *   configuring a remote machine, and would then offer to switch that machine
 *   to a profile it does not have. The daemon's `chosen` comes from the
 *   document it compiled, so it is what is in effect rather than what a file
 *   asked for.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   `--json` is answered rather than accepted and ignored, at all five
 *   subcommands. `list` prints the socket's own `profiles` payload; the other
 *   four print `chosen`, which is that payload's word for the same fact, so a
 *   script reads one member name whichever it ran.
 *
 *   `ncfg profile set` writes its selection through `ncfg_profile_set`, which
 *   is `config.h`'s one spelling of `global { profile = "..." }` and validates
 *   the name against the rule that covers both halves of what a profile name
 *   is -- a directory *and* a value in the configuration language. The Rust
 *   composes that line in the CLI and checks only for `/`, a leading dot and
 *   emptiness, so a name carrying a quote reaches a quoted string. 0263 has the
 *   entry, including the one line of output it costs.
 */
#include "subcommand_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* An owned copy, or NULL for none and for out of memory alike -- every caller
 * here treats both as "no profile", which is what they mean. */
static char *dup_text(const char *text)
{
	char  *copy;
	size_t length;

	if (!text) {
		return NULL;
	}
	length = strlen(text) + 1u;
	copy = malloc(length);
	if (copy) {
		memcpy(copy, text, length);
	}
	return copy;
}

/*
 * What netcfgd has, and what it is running.
 *
 * `answered` is the whole of the branch: everything else falls back to the
 * local directories and the local compile, which is the machine being
 * configured before netcfgd runs on it.
 */
typedef struct {
	ncfg_profile_entry_t *entries;
	size_t                count;
	char                 *chosen;
	int                   answered;
} listing_t;

static void listing_free(listing_t *listing)
{
	ncfg_profile_entries_free(listing->entries, listing->count);
	free(listing->chosen);
	listing->entries = NULL;
	listing->count = 0;
	listing->chosen = NULL;
	listing->answered = 0;
}

/*
 * What the daemon says it has and what it is running, when one is listening.
 *
 * Anything other than a profile list -- no daemon, a refusal, an answer of
 * another kind -- is "it did not answer", which is the Rust's `_ => None` and
 * is what makes this a fallback rather than a failure.
 */
static int ask_daemon(const ncfg_cli_options_t *options, listing_t *out)
{
	char                 socket_path[NCFG_CLI_PATH_MAX];
	char                 ignored[NCFG_ERROR_MAX];
	ncfg_proto_request_t request;
	ncfg_proto_message_t message;
	size_t               which;

	memset(out, 0, sizeof(*out));
	if (!ncfg_cli_daemon_socket(options, socket_path, sizeof(socket_path)) ||
	    !ncfg_cli_daemon_listening(socket_path)) {
		return 0;
	}
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_PROFILE_LIST;
	if (!ncfg_cli_ask(socket_path, &request, &message, ignored, sizeof(ignored))) {
		return 0;
	}
	if (message.kind != NCFG_PROTO_MESSAGE_RESPONSE ||
	    message.u.response.kind != NCFG_PROTO_RESP_PROFILES) {
		ncfg_proto_message_free(&message);
		return 0;
	}
	out->count = message.u.response.u.profiles.count;
	if (out->count > 0) {
		out->entries = calloc(out->count, sizeof(*out->entries));
		if (!out->entries) {
			out->count = 0;
			ncfg_proto_message_free(&message);
			return 0;
		}
	}
	for (which = 0; which < out->count; which++) {
		char name[NCFG_CLI_TEXT_MAX];

		out->entries[which].name = dup_text(ncfg_cli_text(
		    message.u.response.u.profiles.items[which].name, name, sizeof(name)));
		out->entries[which].shipped =
		    message.u.response.u.profiles.items[which].shipped ? 1 : 0;
	}
	if (ncfg_proto_str_present(message.u.response.u.profiles.chosen)) {
		char name[NCFG_CLI_TEXT_MAX];

		out->chosen = dup_text(ncfg_cli_text(message.u.response.u.profiles.chosen, name,
		    sizeof(name)));
	}
	ncfg_proto_message_free(&message);
	out->answered = 1;
	return 1;
}

/*
 * The profiles this machine has, from both layers.
 *
 * Shipped ones and the operator's, and which is which: an operator editing
 * what looks like their own file and finding it replaced on upgrade is the
 * confusion that column exists to prevent.
 */
static int profile_dirs(const ncfg_cli_options_t *options, listing_t *out, char *err,
    size_t err_size)
{
	char config_dir[NCFG_CLI_PATH_MAX];
	char factory_dir[NCFG_CLI_PATH_MAX];

	if (ask_daemon(options, out)) {
		return 1;
	}
	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
	    sizeof(factory_dir));
	return ncfg_profile_list(config_dir, factory_dir, &out->entries, &out->count, err,
	    err_size);
}

/* The profile in effect, or NULL where none is chosen. The caller frees it. */
static int active(const ncfg_cli_options_t *options, char **chosen_out, char *err,
    size_t err_size)
{
	listing_t        said;
	ncfg_document_t *document;

	*chosen_out = NULL;
	if (ask_daemon(options, &said)) {
		*chosen_out = said.chosen;
		said.chosen = NULL;
		listing_free(&said);
		return 1;
	}
	listing_free(&said);
	document = ncfg_cli_compile_to_read(options, err, err_size);
	if (!document) {
		return 0;
	}
	*chosen_out = dup_text(document->globals.profile);
	ncfg_document_free(document);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The subcommands
 * ------------------------------------------------------------------------ */

/*
 * `chosen`, which is the socket's own word for this fact and is the same word
 * in all four subcommands that have it.
 *
 * **Absent where none is chosen, never null and never a name.** The socket's
 * `profiles` response skips `chosen` when nothing is selected, and the text
 * form here is careful for the same reason 0151 gives: an absent selection and
 * the shipped do-nothing profile are different states, so a document that said
 * `"none"` would be the one sentence this verb refuses to print, spelled as
 * JSON. `{}` is therefore the honest answer for a machine with no profile, and
 * it is what `unset` prints as well -- the two agree by construction.
 */
static void member_chosen(ncfg_json_writer_t *writer, const char *chosen)
{
	if (chosen) {
		ncfg_json_write_member_string(writer, "chosen", chosen);
	}
}

/* One object, finished and printed, for the subcommands whose answer is which
 * profile the machine is on and which route the answer took. */
static int say_chosen(const char *chosen, const int *daemon, const char *path, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;
	ncfg_buf_t         out;
	int                ok;

	ncfg_buf_init(&out, 0);
	ncfg_json_write_init(&writer, &out);
	ncfg_json_write_object_begin(&writer);
	member_chosen(&writer, chosen);
	if (daemon) {
		ncfg_json_write_member_bool(&writer, "daemon", *daemon);
	}
	if (path) {
		ncfg_json_write_member_string(&writer, "path", path);
	}
	ncfg_json_write_object_end(&writer);
	ok = ncfg_cli_say_json(&writer, "the chosen profile", err, err_size);
	ncfg_buf_free(&out);
	return ok;
}

static int get(const ncfg_cli_options_t *options, char *err, size_t err_size)
{
	char *chosen = NULL;
	int   ok;

	if (!active(options, &chosen, err, err_size)) {
		return 0;
	}
	if (options->json) {
		ok = say_chosen(chosen, NULL, NULL, err, err_size);
		free(chosen);
		return ok;
	}
	/* **Not a profile called "none".** 0151: an absent selection and the
	 * shipped do-nothing profile are different states, and printing one name
	 * for both would make every diagnostic ambiguous. */
	ncfg_out_line(chosen ? chosen : "no profile chosen");
	free(chosen);
	return 1;
}

/*
 * The socket's `profiles` payload, member for member.
 *
 * `doc/schema/socket.json` carries
 * `{"profiles":[{"name","shipped"}],"chosen":"office"}`, and this is that with
 * the `"response"` tag left off -- the same rule `json.c` follows for the five
 * answers it renders, applied to the one this verb computes locally when no
 * daemon answers. The `*` the table puts against the chosen row is `chosen`
 * here, which is why the mark does not need a member of its own.
 *
 * The list is written even when it is empty, because the protocol always sends
 * it: "this machine has no profiles" is a list of none, not an absence, and
 * the table says it in words for the same reason.
 */
static int say_profiles(const listing_t *found, const char *chosen, char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	ncfg_buf_t         out;
	size_t             which;
	int                ok;

	ncfg_buf_init(&out, 0);
	ncfg_json_write_init(&writer, &out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_key(&writer, "profiles");
	ncfg_json_write_array_begin(&writer);
	for (which = 0; which < found->count; which++) {
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "name",
		    found->entries[which].name ? found->entries[which].name : "");
		ncfg_json_write_member_bool(&writer, "shipped", found->entries[which].shipped);
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	member_chosen(&writer, chosen);
	ncfg_json_write_object_end(&writer);
	ok = ncfg_cli_say_json(&writer, "the profile list", err, err_size);
	ncfg_buf_free(&out);
	return ok;
}

static int list(const ncfg_cli_options_t *options, char *err, size_t err_size)
{
	listing_t found;
	char     *chosen = NULL;
	char      ignored[NCFG_ERROR_MAX];
	size_t    which;

	/* A configuration that does not compile still has profiles on disk, and
	 * the listing is more use than the refusal would be -- so the mark is what
	 * is lost rather than the list. */
	(void)active(options, &chosen, ignored, sizeof(ignored));
	if (!profile_dirs(options, &found, err, err_size)) {
		listing_free(&found);
		free(chosen);
		return 0;
	}
	if (options->json) {
		int ok = say_profiles(&found, chosen, err, err_size);

		listing_free(&found);
		free(chosen);
		return ok;
	}
	if (found.count == 0) {
		ncfg_out_line("no profiles; a profile is a directory under `profile/`");
		listing_free(&found);
		free(chosen);
		return 1;
	}
	for (which = 0; which < found.count; which++) {
		const char *name = found.entries[which].name ? found.entries[which].name : "";
		const char *mark = (chosen && strcmp(chosen, name) == 0) ? "*" : " ";

		ncfg_out_writef("%s %s  (%s)\n", mark, name,
		    found.entries[which].shipped ? "shipped" : "yours");
	}
	listing_free(&found);
	free(chosen);
	return 1;
}

/*
 * Write what the machine is running into a profile, and select it.
 *
 * **The only door into a profile directory.** 0151: nothing else writes there
 * -- not a settings edit, not the gui, not the shim, not the daemon -- because
 * a profile may be carefully crafted and none of that is recoverable from the
 * running state once something has helpfully rewritten it.
 *
 * **The daemon first, which this alone did not do.** Every other write verb
 * takes the socket when one is listening and the directory only when none is --
 * 0127's collapse, because `/etc/netcfgd` is root's and a client is not root.
 * `save` wrote locally unconditionally, so an unprivileged operator with
 * netcfgd running got "Permission denied" for a request the daemon already
 * serves and already authorizes at the `admin` tier.
 */
static int save(const char **rest, size_t count, const ncfg_cli_options_t *options, char *err,
    size_t err_size)
{
	char             socket_path[NCFG_CLI_PATH_MAX];
	char             config_dir[NCFG_CLI_PATH_MAX];
	char             factory_dir[NCFG_CLI_PATH_MAX];
	char             said[NCFG_ERROR_MAX];
	ncfg_document_t *running;
	char            *path = NULL;
	int              denied = 0;
	int              wrote;

	if (count == 0) {
		ncfg_error_set(err, err_size, "`ncfg profile save` needs a name to save as");
		return 0;
	}
	if (!ncfg_cli_daemon_socket(options, socket_path, sizeof(socket_path))) {
		ncfg_error_set(err, err_size,
		    "the run directory makes a socket path too long to connect to");
		return 0;
	}
	if (ncfg_cli_daemon_listening(socket_path)) {
		ncfg_proto_request_t request;

		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_PROFILE_SAVE;
		request.u.profile_save.name = ncfg_proto_str(rest[0]);
		request.u.profile_save.replace = (unsigned char)(options->replace ? 1 : 0);
		if (!ncfg_cli_ask_ok(socket_path, &request, err, err_size)) {
			return 0;
		}
		/* No path: netcfgd chose where it went, and 0127's rule is that
		 * handing one back invites a client to keep it. The document leaves
		 * `path` out for that reason rather than for want of one. */
		if (options->json) {
			int daemon = 1;

			return say_chosen(rest[0], &daemon, NULL, err, err_size);
		}
		ncfg_out_writef("netcfgd saved `%s` and is running it\n", rest[0]);
		return 1;
	}

	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
	    sizeof(factory_dir));

	/* What is running, before anything moves -- compiled the same way
	 * `ncfg_profile_save` compiles the result it compares against, or the two
	 * would differ on their hook paths alone. */
	running = ncfg_cli_compile_to_read(options, err, err_size);
	if (!running) {
		return 0;
	}
	/* The remedy in this caller's vocabulary: `ncfg` has a flag to name, and a
	 * message naming a gui's button would be useless here. */
	wrote = ncfg_profile_save(config_dir, factory_dir, rest[0], options->replace, running,
	    "`--replace`", &path, &denied, said, sizeof(said));
	ncfg_document_free(running);
	if (!wrote) {
		ncfg_cli_refused_locally(denied, said, socket_path, err, err_size);
		return 0;
	}
	if (options->json) {
		int daemon = 0;
		int ok = say_chosen(rest[0], &daemon, path, err, err_size);

		free(path);
		return ok;
	}
	ncfg_out_writef("wrote %s\n", path ? path : "");
	ncfg_out_writef("`%s` is now the profile in use\n", rest[0]);
	free(path);
	return 1;
}

/* Whether the machine has a profile of this name, and what it does have. */
static int is_known(const listing_t *found, const char *name)
{
	size_t which;

	for (which = 0; which < found->count; which++) {
		if (found->entries[which].name && strcmp(found->entries[which].name, name) == 0) {
			return 1;
		}
	}
	return 0;
}

static int set(const char **rest, size_t count, const ncfg_cli_options_t *options, char *err,
    size_t err_size)
{
	char        socket_path[NCFG_CLI_PATH_MAX];
	char        config_dir[NCFG_CLI_PATH_MAX];
	char        factory_dir[NCFG_CLI_PATH_MAX];
	char        said[NCFG_ERROR_MAX];
	listing_t   found;
	const char *name;
	int         daemon = 0;
	int         denied = 0;

	if (count == 0) {
		ncfg_error_set(err, err_size,
		    "`ncfg profile set` needs a name; `ncfg profile list` shows them");
		return 0;
	}
	name = rest[0];
	/* Refused here as well as by the compiler, because the round trip would
	 * not say which part of the name was the problem. */
	if (name[0] == '\0' || strchr(name, '/') != NULL || name[0] == '.') {
		ncfg_error_set(err, err_size,
		    "`%s` cannot be a profile name: a plain name, since netcfgd chooses the "
		    "directory it is read from", name);
		return 0;
	}

	/*
	 * **A name with no directory is refused rather than written.** Writing it
	 * would produce a machine whose configuration names a profile that does
	 * not exist, and the failure would surface later as a profile that changes
	 * nothing -- which reads as netcfgd ignoring the operator.
	 */
	if (!profile_dirs(options, &found, err, err_size)) {
		listing_free(&found);
		return 0;
	}
	if (!is_known(&found, name)) {
		ncfg_buf_t known;
		size_t     which;

		ncfg_buf_init(&known, 0);
		for (which = 0; which < found.count; which++) {
			if (which > 0) {
				ncfg_buf_add_text(&known, ", ");
			}
			ncfg_buf_add_text(&known,
			    found.entries[which].name ? found.entries[which].name : "");
		}
		if (found.count == 0) {
			ncfg_error_set(err, err_size, "no profile called `%s`", name);
		} else {
			ncfg_error_set(err, err_size, "no profile called `%s`; this machine has %s",
			    name, ncfg_buf_text(&known));
		}
		ncfg_buf_free(&known);
		listing_free(&found);
		return 0;
	}
	listing_free(&found);

	if (!ncfg_cli_daemon_socket(options, socket_path, sizeof(socket_path))) {
		ncfg_error_set(err, err_size,
		    "the run directory makes a socket path too long to connect to");
		return 0;
	}
	if (ncfg_cli_daemon_listening(socket_path)) {
		ncfg_proto_request_t request;

		/* **Through `profile_set` when a daemon is listening**, which is the
		 * verb the gui uses -- so the two clients take one path and the
		 * daemon's own checks run for both. */
		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_PROFILE_SET;
		request.u.name = ncfg_proto_str(name);
		if (!ncfg_cli_ask_ok(socket_path, &request, err, err_size)) {
			return 0;
		}
		daemon = 1;
	} else {
		(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
		(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
		    sizeof(factory_dir));
		char *written = NULL;

		if (!ncfg_profile_set(config_dir, factory_dir, name, &written, &denied, said,
		    sizeof(said))) {
			ncfg_cli_refused_locally(denied, said, socket_path, err, err_size);
			return 0;
		}
		if (!options->json) {
			/*
			 * **The file, before the note about how it got there.** `save`
			 * says which file it wrote and so does `config put`; this said
			 * only that a daemon was not listening, which leaves an operator
			 * looking for the drop-in by hand. The order is the Rust's.
			 *
			 * The `--json` object does not gain a `path`: 0263 pins it as
			 * `chosen` beside `daemon`, with `path` on `save` alone.
			 */
			ncfg_out_writef("wrote %s\n", written ? written : "");
			ncfg_out_writef("nothing is listening on %s, so this was written "
			    "directly\n", socket_path);
		}
		free(written);
	}
	/*
	 * **The advice is not in the document.** `ncfg plan` and `ncfg apply
	 * --confirm-within` are what a person should do next, and they are the
	 * same two commands whatever the answer is -- a member repeating them on
	 * every switch would be text addressed to somebody who is not reading, on
	 * a stream that promised one value. This is `ncfg plan --json`'s own rule
	 * for the two notes under a plan.
	 */
	if (options->json) {
		return say_chosen(name, &daemon, NULL, err, err_size);
	}
	ncfg_out_writef("profile is now `%s`\n", name);
	/* Said because a profile switch is the change most likely to need it: it is
	 * large, deliberate, and cannot be undone from the far end of a link it
	 * just took down. */
	ncfg_out_line("`ncfg plan` shows what that changes; `ncfg apply --confirm-within 60` "
	    "keeps a way back");
	return 1;
}

static int unset(const ncfg_cli_options_t *options, char *err, size_t err_size)
{
	ncfg_cli_wrote_t wrote = { 0, 0, NULL, NULL };
	int              ok;

	if (!ncfg_cli_remove_named(NCFG_PROFILE_DROP_IN, "a chosen profile", options, &wrote, err,
	    err_size)) {
		ncfg_cli_wrote_free(&wrote);
		return 0;
	}
	/*
	 * **`chosen` is absent, which is the whole answer.** The sentence exists
	 * to say that the state afterwards is the default and not a profile called
	 * `none`; the document says the same thing by not having the member, and a
	 * `ncfg profile get --json` straight afterwards prints the same object.
	 */
	if (options->json) {
		ok = say_chosen(NULL, &wrote.daemon, NULL, err, err_size);
		ncfg_cli_wrote_free(&wrote);
		return ok;
	}
	ncfg_cli_wrote_free(&wrote);
	ncfg_out_line("no profile is chosen now, which is the default rather than a profile "
	    "called `none`");
	return 1;
}

int ncfg_cli_profile(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size)
{
	if (count == 0) {
		ncfg_error_set(err, err_size,
		    "`ncfg profile` takes `get`, `set`, `save`, `unset` or `list`");
		return 0;
	}
	if (strcmp(positional[0], "get") == 0) {
		return get(options, err, err_size);
	}
	if (strcmp(positional[0], "list") == 0) {
		return list(options, err, err_size);
	}
	if (strcmp(positional[0], "save") == 0) {
		return save(positional + 1, count - 1, options, err, err_size);
	}
	if (strcmp(positional[0], "set") == 0) {
		return set(positional + 1, count - 1, options, err, err_size);
	}
	if (strcmp(positional[0], "unset") == 0) {
		return unset(options, err, err_size);
	}
	ncfg_error_set(err, err_size,
	    "unknown profile subcommand `%.*s`; it is `get`, `set`, `save`, `unset` or `list`",
	    (int)NCFG_CLI_TEXT_MAX, positional[0]);
	return 0;
}
