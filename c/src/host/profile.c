/*
 * profile.c -- listing profiles, choosing one, and taking the machine off one.
 *
 * Decision 0151: a profile is a directory of drop-ins and it is switched by
 * hand. There is no new syntax and no second mechanism -- a profile is read
 * the way `conf.d` is read and layered the way the factory and runtime
 * directories already layer, so everything the drop-in model gives
 * (precedence, `override`, deleting by deleting) applies unchanged.
 *
 * WHAT IS HERE AND WHAT IS NEXT DOOR
 *   The reading half is `config_load.c` and the writing half is
 *   `config_write.c`; this is the mechanism on top of them, and
 *   `profile_save.c` is the one operation that needs the renderer.
 *
 * EVERY COMPILE HERE IS A COMPILE TO READ
 *   The fold compiles the configuration before and after in order to *compare*
 *   the two, and throws both documents away. `ncfg_config_compile_for_reading`
 *   carries the unwritten hook sink for that reason; the refusing sink would
 *   make the proof fail on any machine with a hook, which is a fold refused
 *   for a reason that has nothing to do with the fold.
 */
#include "config_internal.h"
#include "host_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

const char *const ncfg_config_folded_prefixes[NCFG_FOLDED_PREFIX_COUNT] = {
	"05-profile-", "zz-profile-"
};

/* ------------------------------------------------------------------------ *
 * Listing
 * ------------------------------------------------------------------------ */

void ncfg_profile_entries_free(ncfg_profile_entry_t *entries, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		free(entries[i].name);
	}
	free(entries);
}

static int entries_add(ncfg_profile_entry_t **entries, size_t *count, size_t *capacity,
    const char *name, int shipped)
{
	char *copy;
	size_t i;

	for (i = 0; i < *count; i++) {
		if (strcmp((*entries)[i].name, name) == 0) {
			return 1;
		}
	}
	if (*count == *capacity) {
		size_t                want = *capacity ? *capacity * 2u : 8u;
		ncfg_profile_entry_t *grown = realloc(*entries, want * sizeof(*grown));

		if (!grown) {
			return 0;
		}
		*entries = grown;
		*capacity = want;
	}
	copy = malloc(strlen(name) + 1u);
	if (!copy) {
		return 0;
	}
	memcpy(copy, name, strlen(name) + 1u);
	(*entries)[*count].name = copy;
	(*entries)[*count].shipped = shipped;
	(*count)++;
	return 1;
}

static int by_profile_name(const void *one, const void *other)
{
	const ncfg_profile_entry_t *a = one;
	const ncfg_profile_entry_t *b = other;

	return strcmp(a->name, b->name);
}

int ncfg_profile_list(const char *config_dir, const char *factory_dir,
    ncfg_profile_entry_t **out, size_t *count_out, char *err, size_t err_size)
{
	ncfg_profile_entry_t *found = NULL;
	size_t                count = 0;
	size_t                capacity = 0;
	size_t                which;

	*out = NULL;
	*count_out = 0;
	/* The operator's first, so a name in both reads as theirs -- which is what
	 * it effectively is, since their files layer over the shipped ones. */
	for (which = 0; which < 2u; which++) {
		const char          *root = which == 0u ? config_dir : factory_dir;
		char                *directory = ncfg_host_join(root, "profile", err, err_size);
		DIR                 *open_dir;
		const struct dirent *entry;

		if (!directory) {
			ncfg_profile_entries_free(found, count);
			return 0;
		}
		open_dir = opendir(directory);
		if (!open_dir) {
			free(directory);
			continue;
		}
		while ((entry = readdir(open_dir)) != NULL) {
			char       *path;
			struct stat about;

			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
				continue;
			}
			path = ncfg_host_join(directory, entry->d_name, err, err_size);
			if (!path) {
				(void)closedir(open_dir);
				free(directory);
				ncfg_profile_entries_free(found, count);
				return 0;
			}
			if (stat(path, &about) == 0 && S_ISDIR(about.st_mode) &&
			    !entries_add(&found, &count, &capacity, entry->d_name, which != 0u)) {
				free(path);
				(void)closedir(open_dir);
				free(directory);
				ncfg_profile_entries_free(found, count);
				ncfg_error_set(err, err_size, "out of memory listing profiles");
				return 0;
			}
			free(path);
		}
		(void)closedir(open_dir);
		free(directory);
	}
	if (count > 1u) {
		qsort(found, count, sizeof(*found), by_profile_name);
	}
	*out = found;
	*count_out = count;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Choosing
 * ------------------------------------------------------------------------ */

int ncfg_profile_name_usable(const char *name, char *err, size_t err_size)
{
	return ncfg_config_name_usable(name, "a profile name", err, err_size);
}

int ncfg_profile_set(const char *config_dir, const char *factory_dir, const char *name,
    char **path_out, int *denied, char *err, size_t err_size)
{
	char *text;
	int   ok;

	if (path_out) {
		*path_out = NULL;
	}
	if (denied) {
		*denied = 0;
	}
	/* Before the name reaches a quoted string, which is the whole of the
	 * injection this closes. */
	if (!ncfg_profile_name_usable(name, err, err_size)) {
		return 0;
	}
	text = ncfg_config_profile_block(name, err, err_size);
	if (!text) {
		return 0;
	}
	/*
	 * Through the install rather than a bare write, because the install
	 * verifies **with the chosen profile folded in**: a profile whose drop-in
	 * does not compile was accepted once, and every command after it failed
	 * on the config until somebody thought to run `profile unset`.
	 */
	ok = ncfg_config_install_drop_in(config_dir, factory_dir, NCFG_PROFILE_DROP_IN, text, 1,
	    path_out, denied, err, err_size);
	free(text);
	return ok;
}

int ncfg_profile_unset(const char *config_dir, const char *factory_dir, int *removed, int *denied,
    char *err, size_t err_size)
{
	return ncfg_config_remove_drop_in(config_dir, factory_dir, NCFG_PROFILE_DROP_IN, removed,
	    denied, err, err_size);
}

int ncfg_profile_restore(const char *config_dir, const char *name, char *err, size_t err_size)
{
	char *selection;
	char *text;
	size_t i;
	int   ok;

	if (!ncfg_profile_name_usable(name, err, err_size)) {
		return 0;
	}
	for (i = 0; i < NCFG_FOLDED_PREFIX_COUNT; i++) {
		char folded_name[256];
		char *folded;

		(void)snprintf(folded_name, sizeof(folded_name), "%s%s",
		    ncfg_config_folded_prefixes[i], name);
		folded = ncfg_config_drop_in_path(config_dir, folded_name, err, err_size);
		if (!folded) {
			return 0;
		}
		if (unlink(folded) != 0 && errno != ENOENT) {
			ncfg_error_set(err, err_size, "could not remove %s: %s", folded,
			    strerror(errno));
			free(folded);
			return 0;
		}
		free(folded);
	}
	selection = ncfg_config_drop_in_path(config_dir, NCFG_PROFILE_DROP_IN, err, err_size);
	if (!selection) {
		return 0;
	}
	text = ncfg_config_profile_block(name, err, err_size);
	if (!text) {
		free(selection);
		return 0;
	}
	ok = ncfg_config_write_atomically(selection, text, strlen(text), 0644u, NULL, err,
	    err_size);
	free(text);
	free(selection);
	return ok;
}

/* ------------------------------------------------------------------------ *
 * The folded files
 * ------------------------------------------------------------------------ */

static int is_folded(const char *name)
{
	size_t i;

	for (i = 0; i < NCFG_FOLDED_PREFIX_COUNT; i++) {
		const char *prefix = ncfg_config_folded_prefixes[i];

		if (strncmp(name, prefix, strlen(prefix)) == 0) {
			return 1;
		}
	}
	return 0;
}

void ncfg_config_taken_free(ncfg_config_taken_t *taken, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		free(taken[i].path);
		free(taken[i].text);
	}
	free(taken);
}

int ncfg_config_take_folded(const char *config_dir, ncfg_config_taken_t **out, size_t *count_out,
    char *err, size_t err_size)
{
	ncfg_config_taken_t *taken = NULL;
	size_t               count = 0;
	char                *conf_d;
	DIR                 *open_dir;
	const struct dirent *entry;

	*out = NULL;
	*count_out = 0;
	conf_d = ncfg_host_join(config_dir, "conf.d", err, err_size);
	if (!conf_d) {
		return 0;
	}
	open_dir = opendir(conf_d);
	if (!open_dir) {
		free(conf_d);
		return 1;
	}
	while ((entry = readdir(open_dir)) != NULL) {
		ncfg_config_taken_t *grown;
		char                *path;
		char                *text;
		size_t               length;

		if (!is_folded(entry->d_name)) {
			continue;
		}
		path = ncfg_host_join(conf_d, entry->d_name, err, err_size);
		if (!path) {
			break;
		}
		text = ncfg_host_read_file(path, &length, NCFG_CONFIG_FILE_MAX);
		if (!text) {
			ncfg_error_set(err, err_size, "could not read %s: %s", path,
			    strerror(errno));
			free(path);
			(void)closedir(open_dir);
			free(conf_d);
			ncfg_config_taken_free(taken, count);
			return 0;
		}
		grown = realloc(taken, (count + 1u) * sizeof(*grown));
		if (!grown) {
			free(path);
			free(text);
			break;
		}
		taken = grown;
		taken[count].path = path;
		taken[count].text = text;
		taken[count].length = length;
		count++;
		if (unlink(path) != 0) {
			ncfg_error_set(err, err_size, "could not remove %s: %s", path,
			    strerror(errno));
			(void)closedir(open_dir);
			free(conf_d);
			ncfg_config_taken_free(taken, count);
			return 0;
		}
	}
	(void)closedir(open_dir);
	free(conf_d);
	*out = taken;
	*count_out = count;
	return 1;
}

void ncfg_config_restore_folded(const ncfg_config_taken_t *taken, size_t count)
{
	char   quiet[NCFG_ERROR_MAX];
	size_t i;

	for (i = 0; i < count; i++) {
		(void)ncfg_config_write_atomically(taken[i].path, taken[i].text, taken[i].length,
		    0644u, NULL, quiet, sizeof(quiet));
	}
}

/* ------------------------------------------------------------------------ *
 * The fold
 * ------------------------------------------------------------------------ */

/*
 * The profile's files, in the order the loader read them, as one text.
 *
 * One file rather than several: it is generated, it is removed as a unit by
 * `ncfg profile save`, and a person reading `conf.d` should see one thing that
 * arrived together rather than a scatter they have to reassemble.
 */
static char *folded_text(const ncfg_config_sources_t *with_profile,
    const ncfg_config_sources_t *base, const char *name, char *err, size_t err_size)
{
	ncfg_buf_t text;
	size_t     i;

	ncfg_buf_init(&text, NCFG_CONFIG_FILE_MAX);
	ncfg_buf_addf(&text,
	    "# Generated by netcfgd: the `%s` profile, folded in when a setting\n"
	    "# was changed by hand. The machine is on no profile now (0151); this\n"
	    "# file is what it was running, so nothing moved. Edit it freely, or\n"
	    "# `ncfg profile save %s` to put it back and select it again.\n",
	    name, name);
	for (i = 0; i < with_profile->count; i++) {
		const char *source = with_profile->at[i].name;
		size_t      j;
		int         in_base = 0;

		for (j = 0; j < base->count; j++) {
			if (strcmp(base->at[j].name, source) == 0) {
				in_base = 1;
				break;
			}
		}
		if (in_base) {
			continue;
		}
		ncfg_buf_addf(&text, "\n# from %s\n", source);
		ncfg_buf_add(&text, with_profile->at[i].text, with_profile->at[i].length);
	}
	if (ncfg_buf_failed(&text)) {
		ncfg_buf_free(&text);
		ncfg_error_set(err, err_size, "the `%s` profile is too large to fold in", name);
		return NULL;
	}
	{
		char *out = ncfg_buf_take(&text, NULL);

		ncfg_buf_free(&text);
		if (!out) {
			ncfg_error_set(err, err_size, "out of memory folding the `%s` profile",
			    name);
		}
		return out;
	}
}

int ncfg_profile_fold_for_write(const char *config_dir, const char *factory_dir,
    const char *name, char **folded_out, char *err, size_t err_size)
{
	if (folded_out) {
		*folded_out = NULL;
	}
	if (!name || !folded_out) {
		ncfg_error_set(err, err_size,
		    "a fold needs the name being written and somewhere to put the answer");
		return 0;
	}
	/* Writing the selection itself is not a settings change: `ncfg profile
	 * set` would otherwise take the machine off the profile it has just
	 * chosen, one line after choosing it. */
	if (strcmp(name, NCFG_PROFILE_DROP_IN) == 0) {
		return 1;
	}
	return ncfg_profile_adopt(config_dir, factory_dir, folded_out, err, err_size);
}

void ncfg_profile_put_back(const char *config_dir, const char *folded, char *err,
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

int ncfg_profile_adopt(const char *config_dir, const char *factory_dir, char **folded_out,
    char *err, size_t err_size)
{
	ncfg_config_sources_t before_sources = { 0 };
	ncfg_config_sources_t base = { 0 };
	ncfg_document_t      *before;
	char                  quiet[NCFG_ERROR_MAX];
	char                  refusal[NCFG_ERROR_MAX];
	char                 *name = NULL;
	char                 *folded = NULL;
	char                 *selection = NULL;
	char                 *kept = NULL;
	char                 *conf_d = NULL;
	size_t                kept_length = 0;
	size_t                i;
	int                   done = 0;

	*folded_out = NULL;
	refusal[0] = '\0';
	if (!ncfg_config_load_with_profile(factory_dir, config_dir, &before_sources, err,
	    err_size)) {
		ncfg_config_sources_free(&before_sources);
		return 0;
	}
	/* The unwritten sink: this document is compared and thrown away. */
	before = ncfg_config_compile_for_reading(&before_sources, quiet, sizeof(quiet));
	if (!before || !before->globals.profile) {
		/*
		 * It does not compile, so there is nothing to preserve and nothing
		 * to prove; or nothing is chosen, which is the common case and is
		 * not an error. Either way leave it alone and let the caller report
		 * what it finds.
		 */
		ncfg_document_free(before);
		ncfg_config_sources_free(&before_sources);
		return 1;
	}
	name = malloc(strlen(before->globals.profile) + 1u);
	if (!name) {
		ncfg_document_free(before);
		ncfg_config_sources_free(&before_sources);
		ncfg_error_set(err, err_size, "out of memory");
		return 0;
	}
	memcpy(name, before->globals.profile, strlen(before->globals.profile) + 1u);

	if (!ncfg_config_load_layered(factory_dir, config_dir, &base, err, err_size)) {
		goto done;
	}
	folded = folded_text(&before_sources, &base, name, err, err_size);
	if (!folded) {
		goto done;
	}
	selection = ncfg_config_drop_in_path(config_dir, NCFG_PROFILE_DROP_IN, err, err_size);
	if (!selection) {
		goto done;
	}
	/* A selection written somewhere else is not netcfgd's to move. Editing
	 * somebody's own file to take them off a profile is exactly the helpful
	 * rewrite 0151 forbids, so the machine stays on it and the edit is an
	 * ordinary edit. */
	kept = ncfg_host_read_file(selection, &kept_length, NCFG_CONFIG_FILE_MAX);
	if (!kept) {
		done = 1;
		goto done;
	}
	conf_d = ncfg_host_join(config_dir, "conf.d", err, err_size);
	if (!conf_d || !ncfg_host_make_directory(conf_d, (mode_t)0755, err, err_size)) {
		goto done;
	}

	/*
	 * **Verified through the real loader, not through a model of it.** The
	 * first attempt built a candidate in memory and appended the folded file
	 * last, which is not where it sorts on disk -- so it proved a layering
	 * that would never happen and passed a fold that changed the machine's
	 * MTU. Ordering is the loader's to decide; ask it rather than reimplement
	 * it. That means writing first and undoing when the answer is wrong.
	 */
	for (i = 0; i < NCFG_FOLDED_PREFIX_COUNT; i++) {
		ncfg_config_sources_t after_sources = { 0 };
		ncfg_document_t      *after = NULL;
		char                  folded_name[256];
		char                 *written;
		int                   agrees = 0;
		int                   compiled_after = 0;

		(void)snprintf(folded_name, sizeof(folded_name), "%s%s",
		    ncfg_config_folded_prefixes[i], name);
		written = ncfg_config_drop_in_path(config_dir, folded_name, err, err_size);
		if (!written) {
			goto done;
		}
		if (!ncfg_config_write_atomically(written, folded, strlen(folded), 0644u, NULL,
		    err, err_size)) {
			free(written);
			goto done;
		}
		if (unlink(selection) != 0) {
			ncfg_error_set(err, err_size, "could not remove %s: %s", selection,
			    strerror(errno));
			(void)unlink(written);
			free(written);
			goto done;
		}
		if (ncfg_config_load_with_profile(factory_dir, config_dir, &after_sources, quiet,
		    sizeof(quiet))) {
			after = ncfg_config_compile_for_reading(&after_sources, quiet,
			    sizeof(quiet));
		}
		/* Equal but for the selection, which is the one thing this is meant
		 * to change. Comparing the whole document would fail every time and
		 * prove nothing; comparing nothing would prove nothing either. */
		compiled_after = after != NULL;
		agrees = after && ncfg_config_documents_agree(before, NULL, after, NULL, 0u);
		ncfg_document_free(after);
		ncfg_config_sources_free(&after_sources);
		if (agrees) {
			free(written);
			*folded_out = name;
			name = NULL;
			done = 1;
			goto done;
		}
		(void)snprintf(refusal, sizeof(refusal), compiled_after
		    ? "folding the `%s` profile into `conf.d` would change what this machine is "
		      "running, at either position tried, so nothing was changed. "
		      "`ncfg profile unset` takes the profile off without folding it in, if "
		      "that is what you want"
		    : "folding the `%s` profile into the configuration would not compile, so "
		      "nothing was changed",
		    name);
		(void)ncfg_config_write_atomically(selection, kept, kept_length, 0644u, NULL,
		    quiet, sizeof(quiet));
		(void)unlink(written);
		free(written);
	}
	ncfg_error_set(err, err_size, "%s", refusal[0] ? refusal
	    : "the profile could not be folded in");

done:
	free(conf_d);
	free(kept);
	free(selection);
	free(folded);
	ncfg_document_free(before);
	free(name);
	ncfg_config_sources_free(&base);
	ncfg_config_sources_free(&before_sources);
	return done;
}
