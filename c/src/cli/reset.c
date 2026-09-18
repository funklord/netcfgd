/*
 * reset.c -- `ncfg reset`: discard the writable configuration layer.
 *
 * Design section 10.4's verb, and `netcfgd-cli`'s own `lib.rs` rather than one
 * of the four write modules -- which is why 0263 listed it separately and why
 * it is a file of its own here.
 *
 * WHY IT DOES NOT GO THROUGH THE DAEMON
 *   It is a configuration edit, not a runtime operation, so it works on files.
 *   That is also what gates it: the configuration directory is root's, and
 *   anybody who can delete these files can edit them. The daemon notices by
 *   inotify, the same way it notices any other edit. **Nothing in this file
 *   opens a socket, compiles a plan or applies anything**, and that is a
 *   property worth stating rather than inferring -- this is the most
 *   destructive verb the program has.
 *
 * WHAT IT REMOVES, AND WHY THE LIST IS THE LOADER'S
 *   `ncfg_config_writable_files` is the same enumeration the loader reads by.
 *   A reset that removed a different set from the one that gets loaded would
 *   leave files behind that still configure the machine, which is the one
 *   failure that would make this verb worse than useless. Files pulled in by
 *   `include` are not in it: an include may point anywhere, and deleting a
 *   path because something mentioned it is not a thing a reset should do.
 *
 * WHAT IT LEAVES, WHICH IS THE PART PEOPLE ARE SURPRISED BY
 *   The factory layer, which is the whole point. The profile directories,
 *   which are snapshots rather than the machine's current configuration -- the
 *   `90-profile` drop-in that *selects* one is in `conf.d` and does go. And
 *   the credentials, which nothing here removes because a private key nobody
 *   has a copy of cannot be got back (0042) -- so this says how many are left
 *   rather than leaving an operator to discover a directory of passphrases
 *   that nothing refers to any more.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   Each is argued at the code. In short: the two directories are compared
 *   after resolving them rather than as text; an argument is refused rather
 *   than ignored; "removed" is printed after the file is gone rather than
 *   before the loop that removes it; the credentials that outlive the reset
 *   are counted; and `--json` is answered rather than accepted and ignored.
 *
 * WHAT `--json` PRINTS, AND THE ONE THING IT MUST NOT SAY
 *   One object, at the end, built from what happened rather than from what was
 *   about to. **`removed` is written only from the paths `unlink` returned 0
 *   for**, and `would_remove` -- the prediction -- is written only on a run
 *   that attempted nothing. The two never appear together, because one is a
 *   record and the other is a guess, and a document that carried both would be
 *   asking a reader to tell them apart by name. project.md section 10.175 is the
 *   whole reason: the Rust prints the word `removed` over the list before the
 *   loop, and a script believes a document in a way nobody believes a sentence.
 *
 *   A run that stops part way prints **no document at all** -- the verb answers
 *   0 and the sentence carries which file stopped it and how many of how many
 *   had gone, which is `say_json`'s rule for a render that failed and is right
 *   here for the same reason: half an answer is the one that gets parsed.
 */
#include "subcommand_internal.h"

#include "ncfg/base.h"
#include "ncfg/config.h"
#include "ncfg/log.h"
#include "ncfg/secrets.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Whether two directory names are the same directory.
 *
 * **Resolved rather than compared as text.** Resetting into the factory
 * directory would delete the thing being reset to, and the Rust's guard
 * compares two `PathBuf`s -- which is component-wise, so a trailing slash is
 * seen through and nothing else is. A symlinked `/etc/netcfgd`, a directory
 * named with a `.` in the middle, or a bind mount of one onto the other all
 * walk straight past it. Measured against the shipped binary with a symlink:
 * it removed the factory layer and then reported those same two files as the
 * ones that remain. The comment on that guard says what it is for -- a
 * misconfigured unit file, "which is exactly when nobody is watching".
 *
 * Where a name does not resolve it is compared as it stands, which is right
 * for the only case that produces: a directory that is not there has no files
 * to delete and none to protect.
 */
static int same_directory(const char *one, const char *other)
{
	char *left = realpath(one, NULL);
	char *right = realpath(other, NULL);
	int   same = strcmp(left ? left : one, right ? right : other) == 0;

	free(left);
	free(right);
	return same;
}

/*
 * How many credentials the store holds, or -1 where it cannot be listed.
 *
 * Asked through `ncfg_secret_list` rather than by reading the directory here:
 * that is the one place that knows what the store's contents are, and a second
 * enumeration of one directory is how a count comes to disagree with the
 * listing an operator checks it against. The document is NULL because the
 * question is only "what is stored" -- what refers to it is about to stop
 * existing.
 */
static long stored_credentials(const char *config_dir)
{
	ncfg_secret_entry_t *entries = NULL;
	size_t               count = 0;
	size_t               at;
	long                 stored = 0;
	char                 ignored[NCFG_ERROR_MAX];

	if (!ncfg_secret_list(config_dir, NULL, &entries, &count, ignored, sizeof(ignored))) {
		return -1;
	}
	for (at = 0; at < count; at++) {
		if (entries[at].stored) {
			stored++;
		}
	}
	ncfg_secret_entries_free(entries, count);
	return stored;
}

/* What remains after this, said before it happens rather than discovered by
 * the next apply tearing everything down. */
static void say_what_is_left(const char *config_dir, const char *factory_dir, size_t factory,
    long credentials)
{
	ncfg_out_line("");
	if (factory == 0) {
		/*
		 * The case that surprises people: no factory layer means reset does
		 * not restore anything, it empties the machine's configuration.
		 * **And the next reconcile is as soon as this matters** -- a machine
		 * whose `on_drift` is `reconcile` does not wait to be asked, which is
		 * the half the Rust's wording leaves out.
		 */
		ncfg_out_writef("note: %s holds no factory config, so this leaves netcfgd with "
		    "no configuration at all. The next reconcile or apply would remove every "
		    "address, route and link netcfgd installed.\n", factory_dir);
	} else {
		ncfg_out_writef("%zu file%s remain%s, from %s\n", factory, factory == 1u ? "" : "s",
		    factory == 1u ? "s" : "", factory_dir);
	}
	if (credentials > 0) {
		/*
		 * **Not removed, and said rather than left to be found.** A stored
		 * credential nothing refers to is the fault a credential listing
		 * exists to surface, and emptying the configuration is exactly how one
		 * is created -- but removing a private key on this command's own
		 * initiative is unrecoverable in the way 0042 describes, and nobody
		 * asked for it.
		 */
		ncfg_out_writef("%ld credential%s stay%s in %s/secrets, which nothing will refer "
		    "to afterwards. `ncfg secret set` wrote them and removing one is `rm`\n",
		    credentials, credentials == 1 ? "" : "s", credentials == 1 ? "s" : "",
		    config_dir);
	}
}

/*
 * The document, written from what happened.
 *
 * `attempted` says which of the two lists this is: 0 means nothing was tried,
 * so the paths are a prediction and go under `would_remove`; 1 means the loop
 * ran and `done` of them came back from `unlink` successfully, so exactly those
 * go under `removed`. **There is no call shape that writes a path under
 * `removed` without a successful `unlink` behind it**, which is the property
 * project.md section 10.175 costs a machine's configuration when it is missing.
 *
 * `credentials_remaining` is absent where the store could not be listed, not
 * zero: the text prints nothing in that case for the same reason, and a `0`
 * would be this command reporting an emptiness it never looked at.
 */
static int say_reset(const char *config_dir, const char *factory_dir, char *const *doomed,
    size_t doomed_count, int attempted, size_t done, size_t factory_count, long credentials,
    char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	ncfg_buf_t         out;
	size_t             at;
	size_t             listed = attempted ? done : doomed_count;
	int                ok;

	ncfg_buf_init(&out, 0);
	ncfg_json_write_init(&writer, &out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "config_dir", config_dir);
	ncfg_json_write_member_string(&writer, "factory_dir", factory_dir);
	ncfg_json_write_key(&writer, attempted ? "removed" : "would_remove");
	ncfg_json_write_array_begin(&writer);
	for (at = 0; at < listed; at++) {
		ncfg_json_write_string(&writer, doomed[at] ? doomed[at] : "");
	}
	ncfg_json_write_array_end(&writer);
	/* How much of a factory layer is left, which is the difference between a
	 * machine being restored and one being emptied. Zero is the case the text
	 * spends a paragraph on. */
	ncfg_json_write_member_int(&writer, "factory_remaining", (int64_t)factory_count);
	if (credentials >= 0) {
		ncfg_json_write_member_int(&writer, "credentials_remaining", (int64_t)credentials);
	}
	ncfg_json_write_object_end(&writer);
	ok = ncfg_cli_say_json(&writer, "what the reset did", err, err_size);
	ncfg_buf_free(&out);
	return ok;
}

int ncfg_cli_reset(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size)
{
	char    config_dir[NCFG_CLI_PATH_MAX];
	char    factory_dir[NCFG_CLI_PATH_MAX];
	char  **doomed = NULL;
	char  **factory = NULL;
	size_t  doomed_count = 0;
	size_t  factory_count = 0;
	size_t  at;
	size_t  removed = 0;
	long    credentials;
	int     ok = 1;

	/*
	 * **Refused rather than ignored.** The Rust's dispatch drops every
	 * positional argument here, so `ncfg reset office --yes` -- somebody
	 * reaching for `profile unset`, or mistyping a verb that does take a name
	 * -- empties the machine's configuration and says nothing about the word
	 * it did not understand. This verb is the wrong one to be relaxed about an
	 * argument nobody can act on.
	 */
	if (count > 0) {
		ncfg_error_set(err, err_size,
		    "`ncfg reset` takes no arguments and got `%.*s`. It removes the whole "
		    "writable configuration layer; there is nothing to name",
		    (int)NCFG_CLI_TEXT_MAX, positional[0]);
		return 0;
	}
	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
	    sizeof(factory_dir));

	if (same_directory(config_dir, factory_dir)) {
		ncfg_error_set(err, err_size,
		    "the config directory and the factory directory are both %s; reset would "
		    "delete the defaults it is meant to fall back to", config_dir);
		return 0;
	}
	if (!ncfg_config_writable_files(config_dir, &doomed, &doomed_count, err, err_size)) {
		return 0;
	}
	if (!ncfg_config_writable_files(factory_dir, &factory, &factory_count, err, err_size)) {
		ncfg_config_paths_free(doomed, doomed_count);
		return 0;
	}
	credentials = stored_credentials(config_dir);
	if (doomed_count == 0) {
		if (options->json) {
			/* An empty `would_remove` rather than an empty `removed`: nothing
			 * was attempted, and the two lists mean different things. */
			ok = say_reset(config_dir, factory_dir, doomed, 0u, 0, 0u, factory_count,
			    credentials, err, err_size);
		} else {
			ncfg_out_writef("nothing to reset: %s holds no config\n", config_dir);
		}
		ncfg_config_paths_free(doomed, doomed_count);
		ncfg_config_paths_free(factory, factory_count);
		return ok;
	}

	/*
	 * **"would remove" in both modes, because at this point nothing has
	 * been.** The Rust prints "removed" for every path *before* the loop that
	 * removes them, so a reset that fails on its second file has already told
	 * the operator that all of them are gone -- and the one that stopped it is
	 * named in a sentence underneath a list saying otherwise. What each file
	 * actually became is said below, as it happens.
	 */
	if (!options->json) {
		for (at = 0; at < doomed_count; at++) {
			ncfg_out_writef("would remove %s\n", doomed[at]);
		}
		say_what_is_left(config_dir, factory_dir, factory_count, credentials);
	}

	if (!options->yes) {
		if (options->json) {
			ok = say_reset(config_dir, factory_dir, doomed, doomed_count, 0, 0u,
			    factory_count, credentials, err, err_size);
		} else {
			ncfg_out_line("");
			ncfg_out_line("nothing was removed; add --yes to do it");
		}
		ncfg_config_paths_free(doomed, doomed_count);
		ncfg_config_paths_free(factory, factory_count);
		return ok;
	}

	if (!options->json) {
		ncfg_out_line("");
	}
	for (at = 0; at < doomed_count; at++) {
		if (unlink(doomed[at]) != 0) {
			/*
			 * **Stopped, and the count said.** Carrying on would remove more
			 * of a configuration that is now a mixture of the old one and
			 * nothing; stopping leaves a mixture too, so what matters is that
			 * the operator is told exactly where it stopped rather than left
			 * to diff the directory against a list that claimed success.
			 */
			ncfg_error_set(err, err_size,
			    "%s: %s. %zu of %zu file(s) were removed before this, and the rest "
			    "are still there", doomed[at], strerror(errno), removed,
			    doomed_count);
			ok = 0;
			break;
		}
		removed++;
		if (!options->json) {
			ncfg_out_writef("removed %s\n", doomed[at]);
		}
	}
	/*
	 * **Only on a run that finished.** A reset that stopped part way has
	 * already set `err`, and printing a document beside it would be a value on
	 * stdout for a command that exits non-zero -- the sentence carries the
	 * count, which is the half a reader needs and the half the Rust's list
	 * contradicted.
	 */
	if (ok && options->json) {
		ok = say_reset(config_dir, factory_dir, doomed, doomed_count, 1, removed,
		    factory_count, credentials, err, err_size);
	}
	ncfg_config_paths_free(doomed, doomed_count);
	ncfg_config_paths_free(factory, factory_count);
	return ok;
}
