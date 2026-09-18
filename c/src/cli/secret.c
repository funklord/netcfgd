/*
 * secret.c -- `ncfg secret set NAME`: store a credential the config refers to.
 *
 * WHAT THIS IS FOR, AND WHAT IT IS NOT
 *   The config never holds secret material: section 2's rule is that a
 *   document carries a `ncfg_secret_ref_t` and nothing else, so
 *   `password = "@secret:vpn"` needs a file at `<config-dir>/secrets/vpn` for
 *   the `file` provider to find. Writing that file needed an editor, a `chmod`
 *   and the discipline to remember both -- and the compiler's diagnostic for a
 *   missing one used to tell the reader to run this command, which did not
 *   exist. Decision 0075 is the answer.
 *
 *   It is deliberately *only* the write. `ncfg wifi add` writes a config block
 *   and a secret together because a network is both; a WireGuard key or a DSL
 *   password belongs to a block the operator is editing anyway, so this stores
 *   the credential and says which blocks refer to it.
 *
 * THE TWO THINGS IT DOES THAT AN EDITOR DOES NOT
 *   The value never appears on a command line, in a prompt, or in a shell
 *   history -- and the file is 0600 from the moment it exists, because a
 *   `chmod` afterwards is a window.
 *
 * WHICH HOOK SINK, AND WHY
 *   `report` compiles the configuration to answer one question -- does
 *   anything refer to this name -- and throws the document away. That is a
 *   compile to **read**, so it goes through `ncfg_cli_compile_to_read` and the
 *   unwritten sink. The refusing sink would answer "nothing refers to it" on
 *   any machine with a hook in its configuration, which is an invitation to
 *   delete a credential something needs (0258). The Rust's production path
 *   here is right -- it uses the recording sink -- and the `NoHooks` in its
 *   own tests is a fixture with no hooks in it.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   `--json` is answered rather than accepted and ignored. The object is the
 *   socket's `secrets` element for this name -- `name` and `used_by`, spelled
 *   as `doc/schema/socket.json` spells them -- with the path and whether
 *   something was overwritten beside it, because the text says both and a flag
 *   that said less than the table would be the thing the flag exists to avoid.
 *   **`used_by` is absent where the configuration could not be compiled**,
 *   never `[]`: the text says nothing there, and an empty list would be this
 *   command claiming that nothing refers to a name it was unable to look for.
 *
 *   One entry in 0263: a local write that fails carries the "and there was no
 *   daemon to ask" half whichever way it failed, because `ncfg_secret_store_put`
 *   is the one door into the store and does not report `denied` -- and
 *   inferring it from the words of a message is what `config.h` says not to do.
 *   Every refusal this can still meet at that point is the filesystem refusing
 *   the write: the name, the value and the existing file have all been checked
 *   already.
 */
#include "subcommand_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/log.h"
#include "ncfg/secrets.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

/* Standard input, by number, because that is what the terminal calls want. */
#define NCFG_CLI_STDIN 0

/*
 * The most a secret may be.
 *
 * A passphrase is a line and a stored certificate is a PEM; neither is a
 * payload. The Rust reads until end of file with no ceiling, which is a
 * process reading somebody's redirect -- `ncfg secret set x < /dev/zero`
 * allocates until the machine stops. The refusal names the bound.
 */
#define NCFG_CLI_SECRET_MAX (64u * 1024u)

/*
 * The signals blocked for exactly as long as echo is off.
 *
 * `^C` at the prompt then arrives after the restore rather than instead of it,
 * which is the difference between an aborted command and a shell with echo
 * off. The same four `netcfgd_sys::signals` blocks, and that module exists
 * because this happened.
 */
static const int blocked_signals[] = { SIGTERM, SIGHUP, SIGINT, SIGQUIT };

int ncfg_cli_read_secret(const char *prompt, char **out, char *err, size_t err_size)
{
	struct termios before;
	struct termios quiet;
	sigset_t       blocked;
	sigset_t       previous;
	ncfg_buf_t     value;
	int            interactive = isatty(NCFG_CLI_STDIN) == 1;
	int            echo_off = 0;
	int            signals_off = 0;
	size_t         which;
	size_t         length;
	char          *bytes;

	*out = NULL;
	if (interactive) {
		sigemptyset(&blocked);
		for (which = 0; which < sizeof(blocked_signals) / sizeof(blocked_signals[0]);
		    which++) {
			(void)sigaddset(&blocked, blocked_signals[which]);
		}
		signals_off = sigprocmask(SIG_BLOCK, &blocked, &previous) == 0;

		if (tcgetattr(NCFG_CLI_STDIN, &before) != 0) {
			if (signals_off) {
				(void)sigprocmask(SIG_SETMASK, &previous, NULL);
			}
			ncfg_error_set(err, err_size, "could not turn echo off");
			return 0;
		}
		quiet = before;
		/* Only `ECHO` is cleared. The line discipline keeps `ICANON`, so the
		 * read below is still a line. `TCSAFLUSH` rather than `TCSANOW`: it
		 * discards input that arrived before the prompt took effect, which
		 * would otherwise be echoed and become part of the passphrase. */
		quiet.c_lflag &= ~(tcflag_t)ECHO;
		if (tcsetattr(NCFG_CLI_STDIN, TCSAFLUSH, &quiet) != 0) {
			if (signals_off) {
				(void)sigprocmask(SIG_SETMASK, &previous, NULL);
			}
			ncfg_error_set(err, err_size, "could not turn echo off");
			return 0;
		}
		echo_off = 1;
		/* On standard error, so that a shell function wrapping this command
		 * can still capture its output, and flushed by hand because a prompt
		 * with no newline would otherwise appear after the answer. */
		(void)fprintf(stderr, "%s: ", prompt);
		(void)fflush(stderr);
	}

	/*
	 * **A terminal gives one line; a redirect gives a file.** Stopping at the
	 * first newline is right for somebody typing a passphrase and silently
	 * wrong for the workflow this command's own help prints:
	 *
	 *     ncfg secret set corp-ca < /etc/ssl/certs/corp.pem
	 *
	 * stored the twenty-seven bytes `-----BEGIN CERTIFICATE-----` and nothing
	 * else. The resolver then materialised that stub for wpa_supplicant, which
	 * rejected it, and the only symptom was an association failing with
	 * nothing from netcfgd -- measured, not reasoned. The reader half was
	 * already right: it takes the whole file and strips one trailing newline,
	 * so a hand-placed PEM always worked and only the writer could not produce
	 * one.
	 */
	ncfg_buf_init(&value, NCFG_CLI_SECRET_MAX);
	for (;;) {
		int one = fgetc(stdin);

		if (one == EOF) {
			break;
		}
		ncfg_buf_add_char(&value, (char)one);
		if (ncfg_buf_failed(&value)) {
			break;
		}
		if (interactive && one == '\n') {
			break;
		}
	}
	if (echo_off) {
		(void)tcsetattr(NCFG_CLI_STDIN, TCSAFLUSH, &before);
	}
	if (signals_off) {
		/* Unblocked after the restore, never before: the reverse would reopen
		 * the window this closes. */
		(void)sigprocmask(SIG_SETMASK, &previous, NULL);
	}
	if (interactive) {
		/* The newline the operator typed was not echoed either. */
		(void)fprintf(stderr, "\n");
	}
	if (ncfg_buf_failed(&value)) {
		ncfg_buf_free(&value);
		ncfg_error_set(err, err_size,
		    "that is more than %u bytes, which is more than a credential is",
		    (unsigned)NCFG_CLI_SECRET_MAX);
		return 0;
	}
	length = value.length;
	if (length == 0) {
		ncfg_buf_free(&value);
		ncfg_error_set(err, err_size, "nothing was given for the %s", prompt);
		return 0;
	}
	bytes = malloc(length + 1u);
	if (!bytes) {
		ncfg_buf_free(&value);
		ncfg_error_set(err, err_size, "out of memory reading a credential");
		return 0;
	}
	memcpy(bytes, ncfg_buf_text(&value), length + 1u);
	ncfg_buf_free(&value);

	/*
	 * The line terminator, and nothing else. A secret may legitimately begin
	 * or end with a space, and trimming one that does would store something
	 * that never associates and looks right in every diagnostic.
	 */
	if (length > 0 && bytes[length - 1u] == '\n') {
		bytes[--length] = '\0';
	}
	if (length > 0 && bytes[length - 1u] == '\r') {
		bytes[--length] = '\0';
	}
	*out = bytes;
	return 1;
}

/* The bytes, gone, before the allocator can hand them to somebody else. */
static void forget(char *value)
{
	if (value) {
		memset(value, 0, strlen(value));
		free(value);
	}
}

/* Where the `file` provider will look for this one. */
static int secret_path(const char *config_dir, const char *name, char *out, size_t out_size)
{
	int wrote = snprintf(out, out_size, "%s/secrets/%s", config_dir, name);

	return wrote > 0 && (size_t)wrote < out_size;
}

/*
 * What was written, and whether anything refers to it.
 *
 * The second half is the useful part: a secret whose name does not match the
 * reference in the document is a file that will be read by nothing, and the
 * failure arrives later as "no such secret" from a backend. Saying so here
 * turns a typo into a sentence rather than into an afternoon.
 *
 * **Never the value, never its length.** `secrets.h` keeps that rule
 * everywhere and a convenience command is not the place to break it.
 *
 * The document is compiled to answer "does anything use this?", and a
 * configuration that does not compile is not an error *here*: the secret is
 * written either way, and an operator storing a credential before writing the
 * block that names it is the ordinary order to do things in.
 */
/*
 * What was stored, and what refers to it, as one object.
 *
 * **Never the value and never its length**, which is `secrets.h`'s rule and is
 * the reason this file exists in the shape it does; a document is a worse place
 * to break it than a sentence, because a script writes what it reads to a log.
 * The members are the name, where the `file` provider will look, whether
 * something was overwritten, and which blocks refer to the name.
 *
 * `name` and `used_by` are `doc/schema/socket.json`'s spellings for exactly
 * these two facts, taken rather than invented. `stored` is that element's third
 * member and is **not** written: on this verb it would be the constant `true`,
 * since the file has just been written, and a member that cannot carry a fact
 * is noise in every document a caller ever reads.
 *
 * `used_by` is written as an empty list where the configuration compiled and
 * named nothing, and left out entirely where it could not be compiled -- the
 * two are different answers and the text distinguishes them too, by printing
 * the note in one case and saying nothing in the other.
 */
static int say_secret(const char *name, const char *path, int replacing, int daemon, int looked,
    char *const *users, size_t count, char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	ncfg_buf_t         out;
	size_t             which;
	int                ok;

	ncfg_buf_init(&out, 0);
	ncfg_json_write_init(&writer, &out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "name", name);
	ncfg_json_write_member_string(&writer, "path", path);
	ncfg_json_write_member_bool(&writer, "replaced", replacing);
	ncfg_json_write_member_bool(&writer, "daemon", daemon);
	if (looked) {
		ncfg_json_write_key(&writer, "used_by");
		ncfg_json_write_array_begin(&writer);
		for (which = 0; which < count; which++) {
			ncfg_json_write_string(&writer, users[which] ? users[which] : "");
		}
		ncfg_json_write_array_end(&writer);
	}
	ncfg_json_write_object_end(&writer);
	ok = ncfg_cli_say_json(&writer, "the stored credential", err, err_size);
	ncfg_buf_free(&out);
	return ok;
}

static int report(const char *path, const char *name, int replacing, int daemon,
    const ncfg_cli_options_t *options, char *err, size_t err_size)
{
	char              ignored[NCFG_ERROR_MAX];
	ncfg_document_t  *document;
	char            **users = NULL;
	size_t            count = 0;
	size_t            which;
	int               looked = 0;
	ncfg_buf_t        listed;

	if (!options->json) {
		ncfg_out_writef("%s %s (0600)\n", replacing ? "replaced" : "stored", path);
	}

	document = ncfg_cli_compile_to_read(options, ignored, sizeof(ignored));
	if (document) {
		looked = ncfg_secret_referring_to(document, name, &users, &count, ignored,
		    sizeof(ignored));
		ncfg_document_free(document);
	}
	if (options->json) {
		int ok = say_secret(name, path, replacing, daemon, looked, users, count, err,
		    err_size);

		if (looked) {
			ncfg_secret_names_free(users, count);
		}
		return ok;
	}
	if (!looked) {
		return 1;
	}
	if (count == 0) {
		ncfg_out_writef("note: nothing in the configuration refers to `@secret:%s` yet\n",
		    name);
		ncfg_secret_names_free(users, count);
		return 1;
	}
	ncfg_buf_init(&listed, 0);
	for (which = 0; which < count; which++) {
		if (which > 0) {
			ncfg_buf_add_text(&listed, ", ");
		}
		ncfg_buf_add_text(&listed, users[which]);
	}
	ncfg_out_writef("used by: %s\n", ncfg_buf_text(&listed));
	ncfg_buf_free(&listed);
	ncfg_secret_names_free(users, count);
	return 1;
}

static int set(const char **rest, size_t count, const ncfg_cli_options_t *options, char *err,
    size_t err_size)
{
	char        config_dir[NCFG_CLI_PATH_MAX];
	char        socket_path[NCFG_CLI_PATH_MAX];
	char        path[NCFG_CLI_PATH_MAX];
	char        prompt[NCFG_CLI_TEXT_MAX];
	char        said[NCFG_ERROR_MAX];
	struct stat about;
	const char *name;
	char       *value = NULL;
	int         replacing;
	int         stored;

	if (count == 0) {
		ncfg_error_set(err, err_size,
		    "`ncfg secret set` needs a name: the one the config refers to, as in "
		    "`password = \"@secret:vpn\"` -- so `ncfg secret set vpn`");
		return 0;
	}
	if (count > 1) {
		ncfg_error_set(err, err_size,
		    "`ncfg secret set` takes one name, and got `%.*s` as well. The value is "
		    "never an argument -- it is typed at the prompt, or read from standard "
		    "input", (int)NCFG_CLI_TEXT_MAX, rest[1]);
		return 0;
	}
	name = rest[0];
	if (!ncfg_secret_name_usable(name, err, err_size)) {
		return 0;
	}

	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	if (!secret_path(config_dir, name, path, sizeof(path))) {
		ncfg_error_set(err, err_size,
		    "%s makes a path too long to store a credential in", config_dir);
		return 0;
	}
	/*
	 * Refused rather than replaced, unless the operator says. `set` reads as
	 * "overwrite" and for most things it could be -- but one of the
	 * credentials this stores is a WireGuard private key, which decision 0042
	 * calls the one thing on a machine that nobody can get back. A flag is
	 * cheap; that is not.
	 */
	replacing = stat(path, &about) == 0;
	if (replacing && !options->replace) {
		ncfg_error_set(err, err_size,
		    "%s already exists. Pass --replace to overwrite it -- and note that a "
		    "private key nobody has a copy of cannot be got back "
		    "(doc/decision/0042)", path);
		return 0;
	}

	/*
	 * Last, because it is the only step that stops and waits for a person: a
	 * refusal that was going to happen anyway should not happen after the
	 * secret has been typed. The same order `wifi add` takes, for the same
	 * reason.
	 */
	(void)snprintf(prompt, sizeof(prompt), "value for `%.*s`", (int)NCFG_CLI_TEXT_MAX - 16,
	    name);
	if (!ncfg_cli_read_secret(prompt, &value, err, err_size)) {
		return 0;
	}
	if (value[0] == '\0') {
		forget(value);
		ncfg_error_set(err, err_size,
		    "nothing was given for `%s`, and an empty secret is a secret that fails "
		    "at the moment it is used rather than now", name);
		return 0;
	}

	/*
	 * **The daemon first**, for 0127's reason and by the same rule `wifi add`
	 * follows: `/etc/netcfgd/secrets` is root's, a client is not root, and the
	 * channel carries what the client cannot write. The local write stays for
	 * the case the daemon cannot serve -- a machine being configured before
	 * netcfgd runs on it.
	 */
	if (!ncfg_cli_daemon_socket(options, socket_path, sizeof(socket_path))) {
		forget(value);
		ncfg_error_set(err, err_size,
		    "the run directory makes a socket path too long to connect to");
		return 0;
	}
	if (ncfg_cli_daemon_listening(socket_path)) {
		ncfg_proto_request_t request;

		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_SECRET_PUT;
		request.u.secret_put.name = ncfg_proto_str(name);
		request.u.secret_put.value = ncfg_proto_str(value);
		request.u.secret_put.replace = (unsigned char)(options->replace ? 1 : 0);
		stored = ncfg_cli_ask_ok(socket_path, &request, err, err_size);
		forget(value);
		if (!stored) {
			return 0;
		}
		return report(path, name, replacing, 1, options, err, err_size);
	}

	stored = ncfg_secret_store_put(config_dir, name, value, options->replace, NULL, said,
	    sizeof(said));
	forget(value);
	if (!stored) {
		/* The second half is 0127's: there was no daemon to ask, and
		 * `/etc/netcfgd/secrets` is root's. Told only that permission was
		 * denied, a reader goes looking for a mode to change when starting
		 * netcfgd would have done it for them. */
		ncfg_cli_refused_locally(1, said, socket_path, err, err_size);
		return 0;
	}
	return report(path, name, replacing, 0, options, err, err_size);
}

/*
 * `ncfg secret SUBCOMMAND`.
 *
 * One subcommand, and the shape is deliberate: `set` writes a file that the
 * `file` provider reads, and there is no `get` -- the whole point of a secret
 * reference is that the value travels to the backend that needs it and nowhere
 * else. Decision 0075.
 */
int ncfg_cli_secret(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size)
{
	if (count == 0) {
		ncfg_error_set(err, err_size, "`ncfg secret` needs a subcommand: set");
		return 0;
	}
	if (strcmp(positional[0], "set") == 0) {
		return set(positional + 1, count - 1, options, err, err_size);
	}
	if (strcmp(positional[0], "get") == 0 || strcmp(positional[0], "show") == 0 ||
	    strcmp(positional[0], "print") == 0) {
		ncfg_error_set(err, err_size,
		    "there is no `ncfg secret %s`, and that is the point: a secret goes to "
		    "the backend that needs it and nowhere else (project.md section 2). The "
		    "file is readable by root if you must -- and if it is a WireGuard key, "
		    "the kernel has it too", positional[0]);
		return 0;
	}
	ncfg_error_set(err, err_size, "unknown `ncfg secret` subcommand `%.*s`; there is one: set",
	    (int)NCFG_CLI_TEXT_MAX, positional[0]);
	return 0;
}
