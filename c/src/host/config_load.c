/*
 * config_load.c -- which files are the configuration, in which order.
 *
 * `crates/netcfgd-host/src/config.rs`'s reading half. The compiler opens no
 * files, which is what keeps the whole front end testable from strings; this
 * is the module that knows a directory layout, and it is deliberately the only
 * one.
 *
 * THE THREE STATES OF A PATH, WHICH `stat` ALONE CANNOT KEEP APART
 *   Not there, there, and cannot tell. Rust's `Path::is_file` answers `false`
 *   for a file it cannot examine, and the whole of `present` below is that one
 *   fact: a `netcfgd.conf` that is a symlink loop, a dangling link onto an
 *   unmounted disk, or a path on a filesystem returning EIO all read as *no
 *   configuration at all* -- and an empty configuration is a legitimate,
 *   meaningful state. Measured before the fix, with `netcfgd.conf` made a
 *   symlink to itself: `ncfg apply` compiled an empty document, printed
 *   `ok addr.del read0`, took the address off the interface, and exited 0.
 *
 * EVERY COMPILE HERE IS A COMPILE TO READ
 *   Which profile is selected, what one drop-in asks for on its own, whether
 *   the profile chose again. All three throw the document away, so all three
 *   go through `ncfg_config_compile_for_reading`, which has the unwritten hook
 *   sink built in rather than taking one. See `config.h`.
 */
#include "config_internal.h"
#include "host_internal.h"

#include "ncfg/base.h"
#include "ncfg/hooks.h"
#include "ncfg/parse.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* ------------------------------------------------------------------------ *
 * The source set
 * ------------------------------------------------------------------------ */

void ncfg_config_sources_free(ncfg_config_sources_t *sources)
{
	size_t i;

	if (!sources) {
		return;
	}
	for (i = 0; i < sources->count; i++) {
		free(sources->at[i].name);
		free(sources->at[i].text);
	}
	free(sources->at);
	sources->at = NULL;
	sources->count = 0;
	sources->capacity = 0;
}

/* Takes ownership of `text` whatever happens, so that a caller cannot leak it
 * on the failure path by forgetting which half of the call owns it. */
static int sources_add(ncfg_config_sources_t *out, const char *name, char *text, size_t length,
    char *err, size_t err_size)
{
	char *name_copy;

	if (out->count == out->capacity) {
		size_t              want = out->capacity ? out->capacity * 2u : 8u;
		ncfg_config_file_t *grown = realloc(out->at, want * sizeof(*grown));

		if (!grown) {
			free(text);
			ncfg_error_set(err, err_size, "out of memory reading the configuration");
			return 0;
		}
		out->at = grown;
		out->capacity = want;
	}
	name_copy = malloc(strlen(name) + 1u);
	if (!name_copy) {
		free(text);
		ncfg_error_set(err, err_size, "out of memory reading the configuration");
		return 0;
	}
	memcpy(name_copy, name, strlen(name) + 1u);
	out->at[out->count].name = name_copy;
	out->at[out->count].text = text;
	out->at[out->count].length = length;
	out->count++;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Paths
 * ------------------------------------------------------------------------ */

const char *ncfg_config_resolve_dir(const char *explicit_dir, char *out, size_t out_size)
{
	const char *from_environment;

	if (explicit_dir && explicit_dir[0]) {
		(void)snprintf(out, out_size, "%s", explicit_dir);
		return out;
	}
	from_environment = getenv(NCFG_CONFIG_DIR_ENV);
	(void)snprintf(out, out_size, "%s",
	    from_environment && from_environment[0] ? from_environment : NCFG_CONFIG_DIR_DEFAULT);
	return out;
}

const char *ncfg_config_resolve_factory_dir(const char *explicit_dir, char *out, size_t out_size)
{
	const char *from_environment;

	if (explicit_dir && explicit_dir[0]) {
		(void)snprintf(out, out_size, "%s", explicit_dir);
		return out;
	}
	from_environment = getenv(NCFG_FACTORY_DIR_ENV);
	(void)snprintf(out, out_size, "%s",
	    from_environment && from_environment[0] ? from_environment : NCFG_FACTORY_DIR_DEFAULT);
	return out;
}

char *ncfg_config_drop_in_path(const char *config_dir, const char *name, char *err,
    size_t err_size)
{
	char *directory = ncfg_host_join(config_dir, "conf.d", err, err_size);
	char *leaf;
	char *path;
	size_t size;

	if (!directory) {
		return NULL;
	}
	size = strlen(name) + sizeof(".conf");
	leaf = malloc(size);
	if (!leaf) {
		free(directory);
		ncfg_error_set(err, err_size, "out of memory building a path");
		return NULL;
	}
	(void)snprintf(leaf, size, "%s.conf", name);
	path = ncfg_host_join(directory, leaf, err, err_size);
	free(directory);
	free(leaf);
	return path;
}

const char *ncfg_config_file_stem(const char *path, char *out, size_t out_size)
{
	const char *slash = strrchr(path, '/');
	const char *leaf = slash ? slash + 1 : path;
	char       *dot;

	(void)snprintf(out, out_size, "%s", leaf);
	dot = strrchr(out, '.');
	if (dot && dot != out) {
		*dot = '\0';
	}
	return out;
}

/* Whether a name ends in `.conf`, ignoring case, which is the Rust's
 * `eq_ignore_ascii_case` on the extension. */
static int is_conf(const char *name)
{
	size_t length = strlen(name);
	const char *at;
	static const char suffix[] = ".conf";
	size_t i;

	if (length < sizeof(suffix) - 1u) {
		return 0;
	}
	at = name + (length - (sizeof(suffix) - 1u));
	for (i = 0; i < sizeof(suffix) - 1u; i++) {
		char one = at[i];

		if (one >= 'A' && one <= 'Z') {
			one = (char)(one - 'A' + 'a');
		}
		if (one != suffix[i]) {
			return 0;
		}
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Is it there?
 * ------------------------------------------------------------------------ */

/*
 * 1 for there, 0 for not there, -1 for cannot tell, with a sentence.
 *
 * The link itself first: `stat` follows one, so a dangling symlink would
 * answer `ENOENT` and be indistinguishable from an absent file. The operator
 * wrote a link -- to a config on a disk that is not mounted, most likely -- so
 * the honest answer is that it points at nothing, not that they configured
 * nothing.
 */
static int present(const char *path, char *err, size_t err_size)
{
	struct stat about;

	if (lstat(path, &about) != 0) {
		if (errno == ENOENT) {
			return 0;
		}
		ncfg_error_set(err, err_size, "%s: %s", path, strerror(errno));
		return -1;
	}
	/* It is there. Resolving it has to work as well, or what is there cannot
	 * be read and saying "no configuration" would be a guess. */
	if (stat(path, &about) != 0) {
		ncfg_error_set(err, err_size,
		    "%s: %s -- it is there but cannot be read, which is not the same as a "
		    "machine with no configuration",
		    path, strerror(errno));
		return -1;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Includes
 * ------------------------------------------------------------------------ */

/*
 * The path in `include "..."`, if this line is one.
 *
 * Written into `out` and returned, or NULL. A line that merely starts with the
 * word -- `included = true`, or a comment -- is not one.
 */
static const char *include_target(const char *line, char *out, size_t out_size)
{
	const char *at = line;
	const char *end;
	size_t      length;

	while (*at == ' ' || *at == '\t') {
		at++;
	}
	if (strncmp(at, "include", 7u) != 0) {
		return NULL;
	}
	at += 7u;
	while (*at == ' ' || *at == '\t') {
		at++;
	}
	if (*at != '"') {
		return NULL;
	}
	at++;
	end = strchr(at, '"');
	if (!end) {
		return NULL;
	}
	length = (size_t)(end - at);
	if (length + 1u > out_size) {
		return NULL;
	}
	memcpy(out, at, length);
	out[length] = '\0';
	return out;
}

/*
 * Identity by canonical path, so `a.conf`, `./a.conf` and a symlink to it are
 * one file rather than three. A path that will not canonicalise is kept as
 * written -- the read below then reports the real reason, which is a better
 * error than anything this could invent.
 */
static char *identity_of(const char *path)
{
	char  resolved[PATH_MAX];
	char *copy;
	const char *use = realpath(path, resolved) ? resolved : path;

	copy = malloc(strlen(use) + 1u);
	if (copy) {
		memcpy(copy, use, strlen(use) + 1u);
	}
	return copy;
}

/*
 * One file, following any `include` it contains.
 *
 * `open` is the chain of files currently being expanded, and it is what stops
 * `include` recursing for ever. A file that includes itself, or two that
 * include each other, recursed until the stack overflowed -- which is not a
 * diagnostic, it is the daemon dying, and `reload` is a socket request so it
 * could be asked for from outside.
 *
 * A stack of what is open rather than a set of everything seen, because the
 * two differ on a shape that is legal: `a` including `b` and `c`, both of
 * which include `d`, is a diamond and not a cycle. A seen-set would silently
 * drop the second `d` and change what the config means.
 */
static int add_file_within(ncfg_config_sources_t *out, const char *path, char **open,
    size_t *open_count, size_t *open_capacity, char *err, size_t err_size)
{
	struct stat about;
	char       *identity;
	char       *text;
	char       *body;
	size_t      body_length = 0;
	size_t      body_capacity;
	size_t      length = 0;
	size_t      i;
	const char *line;
	int         ok = 1;

	identity = identity_of(path);
	if (!identity) {
		ncfg_error_set(err, err_size, "out of memory reading %s", path);
		return 0;
	}
	for (i = 0; i < *open_count; i++) {
		if (strcmp(open[i], identity) != 0) {
			continue;
		}
		/* The chain is what makes it actionable: which file, reached how. */
		{
			char chain[NCFG_ERROR_MAX];
			size_t at = 0;
			size_t j;

			chain[0] = '\0';
			for (j = 0; j < *open_count && at < sizeof(chain); j++) {
				int put = snprintf(chain + at, sizeof(chain) - at, "%s -> ",
				    open[j]);

				if (put < 0) {
					break;
				}
				at += (size_t)put;
			}
			if (at < sizeof(chain)) {
				(void)snprintf(chain + at, sizeof(chain) - at, "%s", identity);
			}
			ncfg_error_set(err, err_size, "include cycle: %s", chain);
		}
		free(identity);
		return 0;
	}

	/*
	 * **A regular file, and nothing else.** A read runs to the end of the
	 * file and a character device has none: `include "/dev/zero"` allocated
	 * until memory ran out -- measured, a whole gigabyte under a cap -- in a
	 * daemon whose resident budget this project gates on at under five
	 * megabytes. A fifo is the same shape and blocks instead.
	 *
	 * A file type rather than a size limit, because the type is the honest
	 * question: a configuration include is a file somebody wrote.
	 */
	if (stat(path, &about) != 0) {
		ncfg_error_set(err, err_size, "%s: %s", path, strerror(errno));
		free(identity);
		return 0;
	}
	if (!S_ISREG(about.st_mode)) {
		ncfg_error_set(err, err_size,
		    "%s: not a regular file, so it cannot be included -- a device or a fifo has "
		    "no end to read to",
		    path);
		free(identity);
		return 0;
	}
	text = ncfg_host_read_file(path, &length, NCFG_CONFIG_FILE_MAX);
	if (!text) {
		ncfg_error_set(err, err_size, "%s: %s", path, strerror(errno));
		free(identity);
		return 0;
	}

	/*
	 * **A bound on the recursion, which is a divergence.** The Rust grows
	 * this stack without limit and relies on the cycle check alone, so a
	 * chain of distinct files -- `a` includes `b` includes `c`, ten thousand
	 * times -- still recurses until the stack overflows. That is the same
	 * fault the cycle check exists for, arriving by a shape it does not
	 * catch, and `reload` is a socket request. The number is the parser's
	 * own nesting bound, because the question is the same one.
	 */
	if (*open_count == *open_capacity) {
		ncfg_error_set(err, err_size,
		    "%s: includes are nested more than %d deep, which is past what a "
		    "configuration nests by hand",
		    path, (int)*open_capacity);
		free(text);
		free(identity);
		return 0;
	}
	open[*open_count] = identity;
	(*open_count)++;

	body_capacity = length + 2u;
	body = malloc(body_capacity);
	if (!body) {
		free(text);
		(*open_count)--;
		free(identity);
		ncfg_error_set(err, err_size, "out of memory reading %s", path);
		return 0;
	}
	body[0] = '\0';

	/*
	 * Includes are resolved by pulling the included file in ahead of the one
	 * that names it, and stripping the statement. The compiler refuses an
	 * unresolved include by name rather than ignoring it, so anything missed
	 * here is reported rather than lost.
	 */
	line = text;
	while (ok) {
		const char *stop = strchr(line, '\n');
		size_t      line_length = stop ? (size_t)(stop - line) : strlen(line);
		char        one[PATH_MAX];
		char        target[PATH_MAX];

		if (!stop && line_length == 0u) {
			break;
		}
		if (line_length + 1u <= sizeof(one)) {
			memcpy(one, line, line_length);
			one[line_length] = '\0';
			if (include_target(one, target, sizeof(target))) {
				char *resolved;

				if (target[0] == '/') {
					resolved = malloc(strlen(target) + 1u);
					if (resolved) {
						memcpy(resolved, target, strlen(target) + 1u);
					}
				} else {
					const char *slash = strrchr(path, '/');
					char       *directory = slash
					    ? strndup(path, (size_t)(slash - path))
					    : strdup(".");

					resolved = directory ? ncfg_host_join(directory, target,
					    err, err_size) : NULL;
					free(directory);
				}
				if (!resolved) {
					ncfg_error_set(err, err_size, "out of memory resolving "
					    "an include in %s", path);
					ok = 0;
				} else {
					ok = add_file_within(out, resolved, open, open_count,
					    open_capacity, err, err_size);
					free(resolved);
				}
				goto next;
			}
		}
		memcpy(body + body_length, line, line_length);
		body_length += line_length;
		body[body_length++] = '\n';
		body[body_length] = '\0';
	next:
		if (!stop) {
			break;
		}
		line = stop + 1;
	}
	free(text);

	/* Popped on the error path as well as the ordinary one. Nothing depends
	 * on it today -- the failure propagates out of the load and the stack is
	 * dropped with it -- but a function that pushes on one path and pops on
	 * some of them is the shape somebody later reuses and gets wrong. */
	(*open_count)--;
	free(identity);
	if (!ok) {
		free(body);
		return 0;
	}
	return sources_add(out, path, body, body_length, err, err_size);
}

static int add_file(ncfg_config_sources_t *out, const char *path, char *err, size_t err_size)
{
	/* One entry per file currently being expanded. The parser bounds how
	 * deeply one file may nest blocks; nothing bounded nesting *across*
	 * files, which is the same defect one directory up. */
	char  *open[NCFG_MAX_NESTING_DEPTH];
	size_t count = 0;
	size_t capacity = NCFG_MAX_NESTING_DEPTH;

	return add_file_within(out, path, open, &count, &capacity, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * A directory of drop-ins
 * ------------------------------------------------------------------------ */

/*
 * Every `.conf` in one directory, in lexical filename order.
 *
 * Its own function because **a profile directory is a `conf.d`**: the files sit
 * in it directly. The first version of the profile loader called the whole
 * directory reader on it, which looks for `netcfgd.conf` and a nested `conf.d`
 * -- so it found nothing, silently, and the profile appeared to be empty.
 */
static int add_drop_ins(ncfg_config_sources_t *out, const char *dir, char *err, size_t err_size)
{
	DIR                 *open_dir = opendir(dir);
	const struct dirent *found;
	char               **paths = NULL;
	size_t               count = 0;
	size_t               capacity = 0;
	size_t               i;
	int                  ok = 1;

	if (!open_dir) {
		ncfg_error_set(err, err_size, "%s: %s", dir, strerror(errno));
		return 0;
	}
	while ((found = readdir(open_dir)) != NULL) {
		char *path;

		if (!is_conf(found->d_name)) {
			continue;
		}
		path = ncfg_host_join(dir, found->d_name, err, err_size);
		if (!path || !ncfg_host_strings_add(&paths, &count, &capacity, path)) {
			free(path);
			ncfg_error_set(err, err_size, "out of memory listing %s", dir);
			ok = 0;
			break;
		}
		free(path);
	}
	(void)closedir(open_dir);
	/* Lexical order, so `10-foo.conf` precedes `20-bar.conf` and the
	 * precedence an operator sees matches the one they named. */
	ncfg_host_strings_sort_unique(paths, &count);
	for (i = 0; ok && i < count; i++) {
		ok = add_file(out, paths[i], err, err_size);
	}
	ncfg_host_strings_free(paths, count);
	return ok;
}

/* One directory's files: `netcfgd.conf`, then `conf.d`. */
static int extend(ncfg_config_sources_t *out, const char *dir, char *err, size_t err_size)
{
	char *main_file = ncfg_host_join(dir, "netcfgd.conf", err, err_size);
	char *drop_in_dir;
	int   there;
	int   ok = 1;

	if (!main_file) {
		return 0;
	}
	there = present(main_file, err, err_size);
	if (there < 0) {
		free(main_file);
		return 0;
	}
	if (there && !add_file(out, main_file, err, err_size)) {
		free(main_file);
		return 0;
	}
	free(main_file);

	drop_in_dir = ncfg_host_join(dir, "conf.d", err, err_size);
	if (!drop_in_dir) {
		return 0;
	}
	there = present(drop_in_dir, err, err_size);
	if (there < 0) {
		ok = 0;
	} else if (there) {
		ok = add_drop_ins(out, drop_in_dir, err, err_size);
	}
	free(drop_in_dir);
	return ok;
}

int ncfg_config_load(const char *dir, ncfg_config_sources_t *out, char *err, size_t err_size)
{
	if (!dir || !out) {
		ncfg_error_set(err, err_size, "a configuration was asked for with no directory");
		return 0;
	}
	return extend(out, dir, err, err_size);
}

int ncfg_config_load_layered(const char *factory_dir, const char *config_dir,
    ncfg_config_sources_t *out, char *err, size_t err_size)
{
	if (!factory_dir || !config_dir || !out) {
		ncfg_error_set(err, err_size, "a configuration was asked for with no directory");
		return 0;
	}
	if (!ncfg_config_load(factory_dir, out, err, err_size)) {
		return 0;
	}
	/* The same directory twice would load every file twice and make each
	 * block merge with itself. Harmless today -- merging a block with an
	 * identical copy is a no-op -- but it would double every `members` list,
	 * so it is refused rather than relied upon. */
	if (strcmp(factory_dir, config_dir) == 0) {
		return 1;
	}
	return extend(out, config_dir, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * Compiling what was loaded
 * ------------------------------------------------------------------------ */

/* Append one diagnostic, respecting `NCFG_DIAGS_MAX` the way `merge.c` does:
 * past the bound the total goes on rising and nothing more is kept. */
static void add_diag(ncfg_lower_diags_t *diags, const char *source, ncfg_span_t span,
    const char *message)
{
	char *copy;

	if (!diags) {
		return;
	}
	diags->total++;
	if (diags->count >= NCFG_DIAGS_MAX) {
		return;
	}
	if (diags->count == diags->capacity) {
		size_t             want = diags->capacity ? diags->capacity * 2u : 8u;
		ncfg_lower_diag_t *grown;

		if (want > NCFG_DIAGS_MAX) {
			want = NCFG_DIAGS_MAX;
		}
		grown = realloc(diags->at, want * sizeof(*grown));
		if (!grown) {
			return;
		}
		diags->at = grown;
		diags->capacity = want;
	}
	copy = malloc(strlen(message) + 1u);
	if (!copy) {
		return;
	}
	memcpy(copy, message, strlen(message) + 1u);
	diags->at[diags->count].source = source;
	diags->at[diags->count].span = span;
	diags->at[diags->count].message = copy;
	diags->count++;
}

ncfg_document_t *ncfg_config_compile(const ncfg_config_sources_t *sources,
    const ncfg_hook_sink_t *hooks, ncfg_lower_diags_t *diags, char *err, size_t err_size)
{
	return ncfg_config_compile_with_provenance(sources, hooks, NULL, diags, err, err_size);
}

ncfg_document_t *ncfg_config_compile_with_provenance(const ncfg_config_sources_t *sources,
    const ncfg_hook_sink_t *hooks, ncfg_provenance_t *provenance, ncfg_lower_diags_t *diags,
    char *err, size_t err_size)
{
	ncfg_ast_file_t **trees;
	ncfg_source_t    *parsed;
	ncfg_document_t  *document = NULL;
	size_t            i;
	int               failed = 0;
	int               said = 0;

	if (!sources || !hooks) {
		ncfg_error_set(err, err_size, "a compile was asked for with nothing to compile");
		return NULL;
	}
	if (sources->count == 0u) {
		/*
		 * **An empty configuration is a legitimate state**: a machine with no
		 * `/etc/netcfgd` is an ordinary machine, and it compiles to an empty
		 * document, which plans to do nothing. `ncfg_merge` refuses a set of
		 * no files with "nothing to merge", which is right for the caller it
		 * guards against -- one that passed nothing by mistake -- and wrong
		 * for the one caller that can legitimately have none, which is this
		 * one. So the empty document is made here rather than asked for
		 * there. Canonicalised and validated, so that it is the same shape a
		 * compile of one empty file would have produced.
		 */
		ncfg_document_t *empty = ncfg_document_new(err, err_size);

		if (!empty) {
			return NULL;
		}
		ncfg_document_canonicalize(empty);
		if (!ncfg_document_validate(empty, err, err_size)) {
			ncfg_document_free(empty);
			return NULL;
		}
		return empty;
	}
	trees = calloc(sources->count, sizeof(*trees));
	parsed = calloc(sources->count, sizeof(*parsed));
	if (!trees || !parsed) {
		free(trees);
		free(parsed);
		ncfg_error_set(err, err_size, "out of memory compiling the configuration");
		return NULL;
	}

	/* Every file is parsed before anything is reported, so that a set with
	 * two bad files names both rather than the first. */
	for (i = 0; i < sources->count; i++) {
		ncfg_diags_t parse_diags = { 0 };
		char         one[NCFG_ERROR_MAX];

		if (ncfg_parse(sources->at[i].text, sources->at[i].length, &trees[i], &parse_diags,
		    one, sizeof(one))) {
			ncfg_diags_free(&parse_diags);
			parsed[i].name = sources->at[i].name;
			parsed[i].file = trees[i];
			continue;
		}
		failed = 1;
		if (parse_diags.count == 0u) {
			ncfg_span_t nowhere = { 0, 0, 1, 1 };

			add_diag(diags, sources->at[i].name, nowhere, one);
		} else {
			size_t j;

			for (j = 0; j < parse_diags.count; j++) {
				add_diag(diags, sources->at[i].name, parse_diags.at[j].span,
				    parse_diags.at[j].message);
			}
		}
		/* The first failure's sentence, not the last: `err` is what a caller
		 * with no diagnostics prints, and the first is the one the reader
		 * should go and look at. */
		if (!said) {
			ncfg_error_set(err, err_size, "%s: %s", sources->at[i].name,
			    parse_diags.count ? parse_diags.at[0].message : one);
			said = 1;
		}
		ncfg_diags_free(&parse_diags);
	}

	if (!failed) {
		document = ncfg_compile_with_provenance(parsed, sources->count, hooks, provenance,
		    diags, err, err_size);
	}
	for (i = 0; i < sources->count; i++) {
		ncfg_ast_file_free(trees[i]);
	}
	free(trees);
	free(parsed);
	return document;
}

ncfg_document_t *ncfg_config_compile_for_reading(const ncfg_config_sources_t *sources, char *err,
    size_t err_size)
{
	ncfg_lower_diags_t diags = { 0 };
	ncfg_document_t   *document;

	/*
	 * **The unwritten sink, because this compiles in order to read.** The
	 * refusing one refuses every hook, and on a machine with one hook
	 * anywhere in its configuration that turned every question here into a
	 * failure: a drop-in refused, a profile silently not loaded.
	 */
	document = ncfg_config_compile(sources, ncfg_hook_sink_unwritten(), &diags, err, err_size);
	if (!document && diags.count > 0u) {
		char line[NCFG_ERROR_MAX];

		ncfg_lower_diag_render(&diags.at[0], line, sizeof(line));
		ncfg_error_set(err, err_size, "%s", line);
	}
	ncfg_lower_diags_free(&diags);
	return document;
}

/* ------------------------------------------------------------------------ *
 * The profile layer
 * ------------------------------------------------------------------------ */

char *ncfg_config_profile_block(const char *name, char *err, size_t err_size)
{
	static const char shape[] = "global {\n\tprofile = \"%s\"\n}\n";
	size_t            size = sizeof(shape) + strlen(name);
	char             *text = malloc(size);

	if (!text) {
		ncfg_error_set(err, err_size, "out of memory writing a profile selection");
		return NULL;
	}
	(void)snprintf(text, size, shape, name);
	return text;
}

/*
 * What the profile drop-in by itself asks for.
 *
 * Compiled alone, deliberately: the whole point is to learn what this one file
 * says without anything else being able to answer for it, so that the two can
 * then be compared. Returns an allocated name, or NULL where the file is not
 * there, does not compile, or selects nothing -- none of which is an error.
 */
static char *profile_drop_in_asks(const ncfg_config_sources_t *sources)
{
	ncfg_config_sources_t alone = { 0 };
	ncfg_document_t      *document;
	char                  err[NCFG_ERROR_MAX];
	char                  stem[256];
	char                 *asked = NULL;
	size_t                i;

	for (i = sources->count; i > 0u; i--) {
		const ncfg_config_file_t *file = &sources->at[i - 1u];
		char                     *text;

		if (strcmp(ncfg_config_file_stem(file->name, stem, sizeof(stem)),
		    NCFG_PROFILE_DROP_IN) != 0) {
			continue;
		}
		text = malloc(file->length + 1u);
		if (!text) {
			return NULL;
		}
		memcpy(text, file->text, file->length);
		text[file->length] = '\0';
		if (!sources_add(&alone, file->name, text, file->length, err, sizeof(err))) {
			ncfg_config_sources_free(&alone);
			return NULL;
		}
		break;
	}
	if (alone.count == 0u) {
		return NULL;
	}
	document = ncfg_config_compile_for_reading(&alone, err, sizeof(err));
	if (document && document->globals.profile) {
		asked = malloc(strlen(document->globals.profile) + 1u);
		if (asked) {
			memcpy(asked, document->globals.profile,
			    strlen(document->globals.profile) + 1u);
		}
	}
	ncfg_document_free(document);
	ncfg_config_sources_free(&alone);
	return asked;
}

/*
 * The refusal when something has taken the selection away.
 *
 * It names the likely culprit, because the reader's next question is which
 * file did it and the loader is the only thing holding the whole list.
 */
static void shadowed_profile(const ncfg_config_sources_t *sources, const char *asked,
    const char *selected, char *err, size_t err_size)
{
	const char *culprit = NULL;
	char        now[128];
	char        blame[NCFG_ERROR_MAX];
	size_t      i;

	for (i = sources->count; i > 0u; i--) {
		const ncfg_config_file_t *file = &sources->at[i - 1u];

		if (strstr(file->text, "override") && strstr(file->text, "global")) {
			culprit = file->name;
			break;
		}
	}
	if (selected) {
		(void)snprintf(now, sizeof(now), "the profile `%s`", selected);
	} else {
		(void)snprintf(now, sizeof(now), "no profile at all");
	}
	if (culprit) {
		(void)snprintf(blame, sizeof(blame), "`%s` writes `override global`", culprit);
	} else {
		(void)snprintf(blame, sizeof(blame),
		    "no file in the set writes `override global`, so look for whichever one "
		    "writes `global` last");
	}
	ncfg_error_set(err, err_size,
	    "`%s` selects the profile `%s`, but the configuration as a whole selects %s. A "
	    "profile changes only when somebody asks -- `ncfg profile set` or "
	    "`ncfg profile unset` -- so this is refused rather than applied (0151). %s; "
	    "`override global` replaces the whole block, taking the profile with it. Write "
	    "`global` instead and the two merge (0147).",
	    NCFG_PROFILE_DROP_IN, asked, now, blame);
}

int ncfg_config_load_with_profile(const char *factory_dir, const char *config_dir,
    ncfg_config_sources_t *out, char *err, size_t err_size)
{
	ncfg_document_t *document;
	char            *selected = NULL;
	char            *asked;
	char             quiet[NCFG_ERROR_MAX];
	const char      *roots[2];
	size_t           root_count;
	size_t           i;
	int              ok = 1;

	if (!ncfg_config_load_layered(factory_dir, config_dir, out, err, err_size)) {
		return 0;
	}

	/*
	 * **The unwritten hook sink, because this is a question and not an
	 * application.** The refusing sink was here, so on any machine with a
	 * hook this compile failed, the function returned before adding the
	 * profile directory, and `ncfg profile set` wrote a selection that was
	 * never read again -- silently, on this and every later load.
	 *
	 * A base that does not compile chooses nothing, and there is nothing
	 * here to check: the caller compiles it properly next and reports
	 * diagnostics that point at the line. Answering a syntax error with
	 * "your profile was taken away" would send the reader somewhere the
	 * fault is not.
	 */
	document = ncfg_config_compile_for_reading(out, quiet, sizeof(quiet));
	if (!document) {
		return 1;
	}
	if (document->globals.profile) {
		selected = malloc(strlen(document->globals.profile) + 1u);
		if (!selected) {
			ncfg_document_free(document);
			ncfg_error_set(err, err_size, "out of memory reading the configuration");
			return 0;
		}
		memcpy(selected, document->globals.profile,
		    strlen(document->globals.profile) + 1u);
	}
	ncfg_document_free(document);

	/*
	 * What one file asked for, against what every file together says. 0151
	 * requires them to agree: nothing but `ncfg profile` moves the
	 * selection, so a disagreement is some other config change having taken
	 * it away -- which is the automatic switch to no profile that record
	 * forbids.
	 */
	asked = profile_drop_in_asks(out);
	if (asked && (!selected || strcmp(selected, asked) != 0)) {
		shadowed_profile(out, asked, selected, err, err_size);
		free(asked);
		free(selected);
		return 0;
	}
	free(asked);
	if (!selected) {
		return 1;
	}

	/*
	 * The same guard `load_layered` makes, one directory down and for the
	 * same reason: one directory read twice defines every block twice, which
	 * is an error rather than a no-op. Missing it made a profile fail to
	 * compile and report itself as a loop, which is a confusing way to say
	 * "read once".
	 */
	roots[0] = factory_dir;
	root_count = 1u;
	if (strcmp(factory_dir, config_dir) != 0) {
		roots[1] = config_dir;
		root_count = 2u;
	}
	for (i = 0; ok && i < root_count; i++) {
		char *profile_root = ncfg_host_join(roots[i], "profile", err, err_size);
		char *dir = profile_root ? ncfg_host_join(profile_root, selected, err, err_size)
		    : NULL;
		int   there;

		free(profile_root);
		if (!dir) {
			ok = 0;
			break;
		}
		/* `present` rather than a bare `stat`, for its reason: a profile
		 * directory that cannot be examined is not a profile that is
		 * empty. */
		there = present(dir, err, err_size);
		if (there < 0) {
			ok = 0;
		} else if (there) {
			ok = add_drop_ins(out, dir, err, err_size);
		}
		free(dir);
	}
	if (!ok) {
		free(selected);
		return 0;
	}

	/*
	 * The refusal above, checked rather than assumed. A profile directory
	 * that sets `profile` would otherwise be silently ignored -- the base's
	 * answer already won -- and silently ignored is how somebody spends an
	 * afternoon wondering why their profile does not switch.
	 *
	 * Only when it compiles and says something else: a combined
	 * configuration that does not compile is the caller's to report, with
	 * diagnostics that point at the line. The unwritten sink again, and for
	 * the third time in one function it is the same reason -- this document
	 * is read and thrown away.
	 */
	document = ncfg_config_compile_for_reading(out, quiet, sizeof(quiet));
	if (document && (!document->globals.profile ||
	    strcmp(document->globals.profile, selected) != 0)) {
		ncfg_error_set(err, err_size,
		    "the `%s` profile sets `profile` itself, which would make the loader choose "
		    "again; remove it", selected);
		ok = 0;
	}
	ncfg_document_free(document);
	free(selected);
	return ok;
}

/* ------------------------------------------------------------------------ *
 * What a reset would remove
 * ------------------------------------------------------------------------ */

void ncfg_config_paths_free(char **paths, size_t count)
{
	ncfg_host_strings_free(paths, count);
}

int ncfg_config_writable_files(const char *config_dir, char ***out, size_t *count_out, char *err,
    size_t err_size)
{
	char       **found = NULL;
	size_t       count = 0;
	size_t       capacity = 0;
	char        *main_file;
	char        *drop_in_dir;
	struct stat  about;
	DIR         *open_dir;
	const struct dirent *entry;
	size_t       first_drop_in;

	*out = NULL;
	*count_out = 0;
	main_file = ncfg_host_join(config_dir, "netcfgd.conf", err, err_size);
	if (!main_file) {
		return 0;
	}
	if (stat(main_file, &about) == 0 && S_ISREG(about.st_mode) &&
	    !ncfg_host_strings_add(&found, &count, &capacity, main_file)) {
		free(main_file);
		ncfg_error_set(err, err_size, "out of memory listing %s", config_dir);
		return 0;
	}
	free(main_file);
	first_drop_in = count;

	drop_in_dir = ncfg_host_join(config_dir, "conf.d", err, err_size);
	if (!drop_in_dir) {
		ncfg_host_strings_free(found, count);
		return 0;
	}
	open_dir = opendir(drop_in_dir);
	if (!open_dir) {
		free(drop_in_dir);
		*out = found;
		*count_out = count;
		return 1;
	}
	while ((entry = readdir(open_dir)) != NULL) {
		char *path;

		if (!is_conf(entry->d_name)) {
			continue;
		}
		path = ncfg_host_join(drop_in_dir, entry->d_name, err, err_size);
		if (!path) {
			(void)closedir(open_dir);
			free(drop_in_dir);
			ncfg_host_strings_free(found, count);
			return 0;
		}
		if (stat(path, &about) != 0 || !S_ISREG(about.st_mode)) {
			free(path);
			continue;
		}
		if (!ncfg_host_strings_add(&found, &count, &capacity, path)) {
			ncfg_error_set(err, err_size, "out of memory listing %s", drop_in_dir);
			free(path);
			(void)closedir(open_dir);
			free(drop_in_dir);
			ncfg_host_strings_free(found, count);
			return 0;
		}
		free(path);
	}
	(void)closedir(open_dir);
	free(drop_in_dir);
	/* Only the drop-ins are sorted: `netcfgd.conf` is read first whatever it
	 * sorts as, and this list has to be the loader's order rather than a
	 * plain sort of the same names. */
	{
		size_t drop_in_count = count - first_drop_in;

		ncfg_host_strings_sort_unique(found + first_drop_in, &drop_in_count);
		count = first_drop_in + drop_in_count;
	}
	*out = found;
	*count_out = count;
	return 1;
}
