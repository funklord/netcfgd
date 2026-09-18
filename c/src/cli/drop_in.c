/*
 * drop_in.c -- `ncfg config`: putting configuration where netcfgd will read it.
 *
 * THE GENERAL CASE OF WHAT `ncfg wifi add` DOES FOR ONE BLOCK
 *   0127 makes netcfgd the only writer of `/etc/netcfgd`, so a client with
 *   configuration to contribute sends the text and netcfgd decides where it
 *   goes. This is the command that does that, and until it existed the
 *   mechanism was reachable only by a program somebody wrote themselves.
 *
 * WHY A NAME AND A FILE ARE DIFFERENT THINGS
 *   The file is read *here*, by whoever ran the command, with their own
 *   permissions -- so it may be anywhere they can read, including their home
 *   directory or standard input. What crosses the socket is the **text**, and
 *   the name is what netcfgd files it under. A request carrying a path would
 *   be a request to read a file as root, which is a different and much larger
 *   permission than "add this to the configuration".
 *
 * WHAT IT DOES NOT CHECK
 *   Whether the configuration compiles, and whether the caller may send what
 *   is in it. Both are netcfgd's: the daemon compiles the whole directory with
 *   this file in it, which is the only way to know that a drop-in does not
 *   collide with one already there, and it classifies the text against the
 *   same table it uses for every other caller. On the local route
 *   `ncfg_config_install_drop_in` does the same compile for the same reason.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   * **A removal that removed nothing puts the profile back.** 0263's list
 *     has the whole of it; the short version is that the Rust folds the
 *     profile into `conf.d` before every settings write and undoes the fold
 *     only when the write *fails*. `ncfg config rm` of a name that is not
 *     there neither fails nor writes, so it kept the fold: a command that
 *     changed nothing took the machine off its profile.
 *   * **The fold is announced once the write stands**, rather than before it
 *     is attempted. The Rust prints "the `office` profile was folded into your
 *     configuration" and then, on a refusal, "nothing was written, so the
 *     `office` profile is chosen again" -- two sentences describing a state the
 *     machine passed through and left. Saying nothing about a fold that was
 *     undone is the same fact with less to read.
 *   * **The text is bounded** at `NCFG_CONFIG_FILE_MAX`. `read_to_string` on a
 *     path a caller named will read `/dev/zero` until the machine stops, and
 *     0263's buffer rule is that text with no ceiling is text somebody else
 *     chooses the size of.
 *   * **`--json` is answered rather than accepted and ignored.** The Rust
 *     prints its sentences here whatever the flag says. `subcommand_internal.h`
 *     holds the rule the six writing verbs share; this file also holds the two
 *     pieces they share to obey it, because the two write helpers below are
 *     already here.
 */
#include "subcommand_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * What the six writing verbs share to answer `--json`
 * ------------------------------------------------------------------------ */

void ncfg_cli_wrote_free(ncfg_cli_wrote_t *wrote)
{
	if (!wrote) {
		return;
	}
	free(wrote->path);
	free(wrote->folded);
	wrote->path = NULL;
	wrote->folded = NULL;
	wrote->daemon = 0;
	wrote->removed = 0;
}

int ncfg_cli_say_json(const ncfg_json_writer_t *writer, const char *what, char *err,
    size_t err_size)
{
	if (!ncfg_json_write_done(writer)) {
		const char *why = ncfg_json_write_failure(writer);

		/*
		 * `run.c`'s sentence with one clause added, and the clause is the
		 * difference between a verb that renders and a verb that writes.
		 *
		 * **What stopped is the rendering, not the command.** These six have
		 * already written the file by the time the answer is composed, so a
		 * reader told only "could not be written as JSON" concludes the
		 * credential was not stored and writes it again somewhere else. A
		 * name that is not valid UTF-8 is what is actually met here -- it
		 * comes straight off `argv` -- and 0263's rule is that it fails the
		 * command rather than being repaired, because every repair puts a
		 * value in front of somebody that nobody typed.
		 */
		ncfg_error_set(err, err_size,
		    "%s could not be written as JSON: %s.\nwhat stopped is the rendering and "
		    "not the command, which has already done what it was asked -- and nothing "
		    "is printed rather than a document with a value in it that nobody typed. "
		    "The same command without `--json` renders the answer as text",
		    what, why ? why : "it did not fit");
		return 0;
	}
	ncfg_out_line(ncfg_buf_text(writer->buf));
	return 1;
}

/* ------------------------------------------------------------------------ *
 * A person changed a setting, so the machine comes off its profile
 * ------------------------------------------------------------------------ */

/*
 * Fold the chosen profile into `conf.d` and stop claiming to be on it.
 *
 * The local half of the daemon's rule of the same name (0151), for a machine
 * being configured before netcfgd runs on it. What is running does not move --
 * `ncfg_profile_adopt` proves that by compiling before and after -- and only
 * the label changes.
 *
 * `*folded_out` receives the profile's name, which the caller frees, or NULL
 * where none was chosen. Writing the selection drop-in itself is not a
 * settings write and takes no profile off.
 */
static int take_off_profile(const char *config_dir, const char *factory_dir, const char *name,
    char **folded_out, char *err, size_t err_size)
{
	*folded_out = NULL;
	if (strcmp(name, NCFG_PROFILE_DROP_IN) == 0) {
		return 1;
	}
	return ncfg_profile_adopt(config_dir, factory_dir, folded_out, err, err_size);
}

/* What the fold is announced as, once the write it was made for stands. */
static void say_folded(const char *folded)
{
	if (folded) {
		ncfg_out_writef("the `%s` profile was folded into your configuration and no "
		    "profile is chosen now; what is running has not changed\n", folded);
	}
}

/*
 * Put the selection back, because the write it was made for did not happen.
 *
 * The fold has to come first -- folding afterwards would have to preserve a
 * document in which the profile still overrides the new edit, so it would land
 * late and the edit would never take effect -- which means the only way to keep
 * "a write that did not happen moved nothing" true is to undo it.
 *
 * A failed undo is appended to the refusal rather than swallowed: the machine
 * is then genuinely off its profile and the operator has to know.
 */
static void put_profile_back(const char *config_dir, const char *folded, char *err,
    size_t err_size)
{
	char undo[NCFG_ERROR_MAX];
	char refusal[NCFG_ERROR_MAX];

	if (!folded) {
		return;
	}
	if (ncfg_profile_restore(config_dir, folded, undo, sizeof(undo))) {
		return;
	}
	(void)snprintf(refusal, sizeof(refusal), "%s", err ? err : "");
	ncfg_error_set(err, err_size, "%s\n(and the `%s` profile could not be put back: %s)",
	    refusal, folded, undo);
}

/* ------------------------------------------------------------------------ *
 * Storing and removing
 * ------------------------------------------------------------------------ */

int ncfg_cli_put_text(const char *name, const char *text, int replace, const char *subject,
    const ncfg_cli_options_t *options, ncfg_cli_wrote_t *wrote, char *err, size_t err_size)
{
	char  socket_path[NCFG_CLI_PATH_MAX];
	char  config_dir[NCFG_CLI_PATH_MAX];
	char  factory_dir[NCFG_CLI_PATH_MAX];
	char  said[NCFG_ERROR_MAX];
	char *folded = NULL;
	char *path = NULL;
	int   denied = 0;

	if (wrote) {
		memset(wrote, 0, sizeof(*wrote));
	}

	/*
	 * **The daemon first, and the local write only when none is listening**,
	 * which is the order `ncfg wifi add` and `ncfg secret set` have taken
	 * since 0127 and for the same reason: `/etc/netcfgd` is root's and a
	 * client is not root. The local path is for a machine being configured
	 * before netcfgd runs on it.
	 */
	if (!ncfg_cli_daemon_socket(options, socket_path, sizeof(socket_path))) {
		ncfg_error_set(err, err_size,
		    "the run directory makes a socket path too long to connect to");
		return 0;
	}
	if (ncfg_cli_daemon_listening(socket_path)) {
		ncfg_proto_request_t request;

		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_CONFIG_PUT;
		request.u.put.name = ncfg_proto_str(name);
		request.u.put.text = ncfg_proto_str(text);
		request.u.put.replace = (unsigned char)(replace ? 1 : 0);
		if (!ncfg_cli_ask_ok(socket_path, &request, err, err_size)) {
			return 0;
		}
		if (wrote) {
			wrote->daemon = 1;
		}
		if (!options->json) {
			ncfg_out_writef("netcfgd stored %s and re-read its configuration\n",
			    subject);
		}
		return 1;
	}

	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
	    sizeof(factory_dir));

	if (!take_off_profile(config_dir, factory_dir, name, &folded, err, err_size)) {
		return 0;
	}
	if (!ncfg_config_install_drop_in(config_dir, factory_dir, name, text, replace, &path,
	    &denied, said, sizeof(said))) {
		ncfg_cli_refused_locally(denied, said, socket_path, err, err_size);
		put_profile_back(config_dir, folded, err, err_size);
		free(folded);
		return 0;
	}
	if (!options->json) {
		say_folded(folded);
		ncfg_out_writef("wrote %s\n", path ? path : "");
		ncfg_out_writef("nothing is listening on %s, so this was written directly\n",
		    socket_path);
	}
	if (wrote) {
		wrote->folded = folded;
		wrote->path = path;
	} else {
		free(folded);
		free(path);
	}
	return 1;
}

int ncfg_cli_remove_named(const char *name, const char *subject,
    const ncfg_cli_options_t *options, ncfg_cli_wrote_t *wrote, char *err, size_t err_size)
{
	char  socket_path[NCFG_CLI_PATH_MAX];
	char  config_dir[NCFG_CLI_PATH_MAX];
	char  factory_dir[NCFG_CLI_PATH_MAX];
	char  said[NCFG_ERROR_MAX];
	char *folded = NULL;
	int   removed = 0;
	int   denied = 0;

	if (wrote) {
		memset(wrote, 0, sizeof(*wrote));
	}

	if (!ncfg_cli_daemon_socket(options, socket_path, sizeof(socket_path))) {
		ncfg_error_set(err, err_size,
		    "the run directory makes a socket path too long to connect to");
		return 0;
	}
	if (ncfg_cli_daemon_listening(socket_path)) {
		ncfg_proto_request_t request;

		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_CONFIG_DELETE;
		request.u.name = ncfg_proto_str(name);
		if (!ncfg_cli_ask_ok(socket_path, &request, err, err_size)) {
			return 0;
		}
		if (wrote) {
			wrote->daemon = 1;
		}
		/* Said plainly, because an absent file is success and somebody who
		 * mistyped the name would otherwise read that as "removed". */
		if (!options->json) {
			ncfg_out_writef("netcfgd no longer has %s\n", subject);
		}
		return 1;
	}

	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
	    sizeof(factory_dir));

	if (!take_off_profile(config_dir, factory_dir, name, &folded, err, err_size)) {
		return 0;
	}
	/*
	 * **Which sentence depends on whether anything was there**, and the Rust
	 * said the second one either way: a drop-in it had just removed was
	 * reported as "is not in", so an operator read a successful removal as a
	 * failed one and went looking for a file that had gone.
	 */
	if (!ncfg_config_remove_drop_in(config_dir, factory_dir, name, &removed, &denied, said,
	    sizeof(said))) {
		ncfg_cli_refused_locally(denied, said, socket_path, err, err_size);
		put_profile_back(config_dir, folded, err, err_size);
		free(folded);
		return 0;
	}
	if (!removed) {
		/* **Nothing was there, so nothing was changed, so the machine is
		 * still on its profile.** The Rust kept the fold here: a `rm` of a
		 * name that was never written took the selection away and folded the
		 * profile into `conf.d`, for a command that did nothing. */
		put_profile_back(config_dir, folded, err, err_size);
		free(folded);
		if (!options->json) {
			ncfg_out_writef("%s is not in %s\n", subject, config_dir);
		}
		return 1;
	}
	if (!options->json) {
		say_folded(folded);
		/* The same words the daemon path uses, because it is the same event
		 * and an operator should not have to tell which route it took. */
		ncfg_out_writef("netcfgd no longer has %s\n", subject);
	}
	if (wrote) {
		wrote->removed = 1;
		wrote->folded = folded;
	} else {
		free(folded);
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * `ncfg config put|rm`
 * ------------------------------------------------------------------------ */

/*
 * What a `config put` or `config rm` did, as one object.
 *
 * `name` because that is what netcfgd files a drop-in under and the only
 * handle a script has on it afterwards; `daemon` because the two routes are a
 * real difference -- one has already re-read the configuration and the other
 * wrote a file that something will read later -- and it replaces the "nothing
 * is listening on ... so this was written directly" sentence rather than
 * dropping it. `path` is written only where this process wrote a file, which
 * is 0127 in a member: the daemon chose where its copy went and handing that
 * back invites a client to keep it.
 *
 * `removed` is the `rm` half and is **absent on the daemon route**, because an
 * absent file is success there and the answer cannot tell "removed" from "was
 * never there". The text says so in words -- "netcfgd no longer has ...", said
 * plainly for exactly that reason -- and a `false` here would be a claim
 * nobody made.
 */
static int say_drop_in(const char *name, const ncfg_cli_wrote_t *wrote, int is_removal,
    char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	ncfg_buf_t         out;
	int                ok;

	ncfg_buf_init(&out, 0);
	ncfg_json_write_init(&writer, &out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "name", name);
	ncfg_json_write_member_bool(&writer, "daemon", wrote->daemon);
	if (wrote->path) {
		ncfg_json_write_member_string(&writer, "path", wrote->path);
	}
	if (is_removal && !wrote->daemon) {
		ncfg_json_write_member_bool(&writer, "removed", wrote->removed);
	}
	/* The fold is a second thing that happened to the machine, and the text
	 * says it; absent where none was made. */
	if (wrote->folded) {
		ncfg_json_write_member_string(&writer, "folded", wrote->folded);
	}
	ncfg_json_write_object_end(&writer);
	ok = ncfg_cli_say_json(&writer, is_removal ? "what was removed" : "what was stored", err,
	    err_size);
	ncfg_buf_free(&out);
	return ok;
}

/*
 * Read the text a `put` is to send, into `out`.
 *
 * A path, or standard input when the path is `-` or absent. Standard input is
 * the form that matters for the audience this is for: a fleet tool generating
 * configuration has it in a pipe, not in a file it wants to leave lying around.
 *
 * Bounded, unlike the Rust -- see the header. The refusal names the ceiling
 * rather than truncating, because half a drop-in that parses is worse than
 * none.
 */
static int text_from(const char *source, ncfg_buf_t *out, char *err, size_t err_size)
{
	int   from_stdin = !source || strcmp(source, "-") == 0;
	FILE *stream = from_stdin ? stdin : fopen(source, "rb");

	ncfg_buf_init(out, NCFG_CONFIG_FILE_MAX);
	if (!stream) {
		ncfg_error_set(err, err_size, "could not read %s", source);
		return 0;
	}
	for (;;) {
		char   chunk[4096];
		size_t got = fread(chunk, 1u, sizeof(chunk), stream);

		if (got > 0) {
			ncfg_buf_add(out, chunk, got);
		}
		if (got < sizeof(chunk)) {
			break;
		}
		if (ncfg_buf_failed(out)) {
			break;
		}
	}
	if (ferror(stream)) {
		ncfg_error_set(err, err_size, "could not read %s",
		    from_stdin ? "standard input" : source);
		if (!from_stdin) {
			(void)fclose(stream);
		}
		return 0;
	}
	if (!from_stdin) {
		(void)fclose(stream);
	}
	if (ncfg_buf_failed(out)) {
		ncfg_error_set(err, err_size,
		    "%s is larger than %u bytes, which is more configuration than netcfgd "
		    "will take in one drop-in",
		    from_stdin ? "what arrived on standard input" : source,
		    (unsigned)NCFG_CONFIG_FILE_MAX);
		return 0;
	}
	return 1;
}

/* Whether there is anything in it but whitespace. */
static int blank(const char *text)
{
	size_t at;

	for (at = 0; text[at] != '\0'; at++) {
		unsigned char one = (unsigned char)text[at];

		if (one != ' ' && one != '\t' && one != '\n' && one != '\r' && one != '\f' &&
		    one != '\v') {
			return 0;
		}
	}
	return 1;
}

static int put(const char **rest, size_t count, const ncfg_cli_options_t *options, char *err,
    size_t err_size)
{
	ncfg_buf_t       text;
	ncfg_cli_wrote_t wrote = { 0, 0, NULL, NULL };
	char             subject[NCFG_CLI_TEXT_MAX];
	int              ok;

	if (count == 0) {
		ncfg_error_set(err, err_size,
		    "`ncfg config put` needs a name: what netcfgd files it under, as in "
		    "`ncfg config put site site.conf`. The name is not a path");
		return 0;
	}
	if (count > 2) {
		ncfg_error_set(err, err_size,
		    "`ncfg config put` takes a name and at most one file, and got %zu "
		    "arguments", count);
		return 0;
	}
	if (!text_from(count > 1 ? rest[1] : NULL, &text, err, err_size)) {
		ncfg_buf_free(&text);
		return 0;
	}
	if (blank(ncfg_buf_text(&text))) {
		ncfg_error_set(err, err_size,
		    "nothing was given for `%s`, and an empty drop-in is a file that "
		    "configures nothing. Use `ncfg config rm %s` to take one away", rest[0],
		    rest[0]);
		ncfg_buf_free(&text);
		return 0;
	}
	(void)snprintf(subject, sizeof(subject), "`%.*s`", (int)NCFG_CLI_TEXT_MAX - 3, rest[0]);
	ok = ncfg_cli_put_text(rest[0], ncfg_buf_text(&text), options->replace, subject, options,
	    &wrote, err, err_size);
	ncfg_buf_free(&text);
	if (ok && options->json) {
		ok = say_drop_in(rest[0], &wrote, 0, err, err_size);
	}
	ncfg_cli_wrote_free(&wrote);
	return ok;
}

static int remove_one(const char **rest, size_t count, const ncfg_cli_options_t *options,
    char *err, size_t err_size)
{
	ncfg_cli_wrote_t wrote = { 0, 0, NULL, NULL };
	char             subject[NCFG_CLI_SENTENCE_MAX];
	int              ok;

	if (count == 0) {
		ncfg_error_set(err, err_size,
		    "`ncfg config rm` needs the name a drop-in was put under");
		return 0;
	}
	(void)snprintf(subject, sizeof(subject), "a drop-in called `%.*s`",
	    (int)NCFG_CLI_TEXT_MAX, rest[0]);
	ok = ncfg_cli_remove_named(rest[0], subject, options, &wrote, err, err_size);
	if (ok && options->json) {
		ok = say_drop_in(rest[0], &wrote, 1, err, err_size);
	}
	ncfg_cli_wrote_free(&wrote);
	return ok;
}

int ncfg_cli_config(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size)
{
	if (count == 0) {
		ncfg_error_set(err, err_size, "`ncfg config` takes `put` or `rm`");
		return 0;
	}
	if (strcmp(positional[0], "put") == 0) {
		return put(positional + 1, count - 1, options, err, err_size);
	}
	if (strcmp(positional[0], "rm") == 0) {
		return remove_one(positional + 1, count - 1, options, err, err_size);
	}
	ncfg_error_set(err, err_size, "unknown config subcommand `%.*s`; it is `put` or `rm`",
	    (int)NCFG_CLI_TEXT_MAX, positional[0]);
	return 0;
}
