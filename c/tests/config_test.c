/*
 * config_test.c -- the configuration directory, the drop-ins, and the profile.
 *
 * WHAT THESE CASES ARE FOR
 *   Nearly every one of them is `crates/netcfgd-host/src/config.rs`'s own,
 *   carried across with the defect it names, because the case is the expensive
 *   half to rediscover. Four groups:
 *
 *   * **Three states of a path, not two.** A config that is there and cannot
 *     be read is not a machine with no config. Measured before the fix, with
 *     `netcfgd.conf` made a symlink to itself: `ncfg apply` compiled an empty
 *     document, printed `ok addr.del read0`, took the address off the
 *     interface and exited 0. The symlink loop is used here because it needs
 *     no privilege and no mount -- root gets `ELOOP` exactly as anybody does,
 *     where a mode would be walked straight through.
 *   * **`include` is bounded.** A file that includes itself overflowed the
 *     stack rather than producing a diagnostic, and `reload` is a socket
 *     request. A diamond is not a cycle and must still expand.
 *   * **The two defects of project.md's `UnwrittenHooks` section**, which are
 *     the reason this module has two named cases rather than an assertion
 *     somewhere: a drop-in installed on a machine that already has a hook, and
 *     a profile still loaded on a machine that has one. Each is paired with a
 *     control showing the refusing sink really does refuse that same
 *     configuration, so neither can pass vacuously.
 *   * **Nothing is left behind by a refusal.** A drop-in that would stop the
 *     configuration compiling is not kept, a replace that would is put back,
 *     and a fold that would change what the machine runs is undone.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY
 *   The real daemon is running on this machine with its real configuration in
 *   `/etc/netcfgd` and its real credentials in `/etc/netcfgd/secrets`. Every
 *   path here is under one `mkdtemp` directory and is passed explicitly;
 *   nothing falls back to a default, and the defaults are checked by reading
 *   the constants rather than by writing to them.
 */
#include "ncfg/base.h"
#include "ncfg/config.h"
#include "ncfg/document.h"
#include "ncfg/hooks.h"
#include "ncfg/lower.h"
#include "ncfg/state.h"

#include "testdir.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* ------------------------------------------------------------------------ *
 * A tree to work in
 * ------------------------------------------------------------------------ */

/*
 * `<dir>/<leaf>` in one of a few rotating buffers.
 *
 * Rotating rather than one static, because half the cases below join twice in
 * one expression -- `install(config(dir), factory(dir))` -- and a single
 * buffer would quietly make the two arguments the same string.
 */
static const char *in(const char *dir, const char *leaf)
{
	static char   buffers[8][512];
	static size_t next;
	char         *out = buffers[next];

	next = (next + 1u) % 8u;
	(void)snprintf(out, sizeof(buffers[0]), "%s/%s", dir, leaf);
	return out;
}

/* `mkdir -p` of every directory in `path`, which is a directory itself. */
static void make_dirs(const char *path)
{
	char  work[512];
	char *at;

	(void)snprintf(work, sizeof(work), "%s", path);
	for (at = work + 1; *at; at++) {
		if (*at != '/') {
			continue;
		}
		*at = '\0';
		(void)mkdir(work, 0755);
		*at = '/';
	}
	(void)mkdir(work, 0755);
}

typedef struct {
	const char *path;
	const char *text;
} file_t;

/* A directory tree, built from `relative path -> contents`, which is the
 * Rust's `tree` helper. */
static const char *tree(const char *root, const char *tag, const file_t *files, size_t count)
{
	const char *base = in(root, tag);
	static char kept[512];
	size_t      i;

	(void)snprintf(kept, sizeof(kept), "%s", base);
	make_dirs(kept);
	for (i = 0; i < count; i++) {
		char  full[640];
		char *slash;

		(void)snprintf(full, sizeof(full), "%s/%s", kept, files[i].path);
		slash = strrchr(full, '/');
		if (slash) {
			*slash = '\0';
			make_dirs(full);
			*slash = '/';
		}
		if (!testdir_write(full, files[i].text, strlen(files[i].text))) {
			printf("could not write the fixture %s\n", full);
			exit(1);
		}
	}
	return kept;
}

/*
 * Remove everything under `path`.
 *
 * **Not `testdir_remove`**, which walks three levels: a profile tree is four
 * deep -- `<root>/<case>/profile/office/00.conf` -- and a cleanup that stopped
 * short would leave the directory behind rather than say so. The guard is that
 * function's own and is the reason a wildcard is defensible at all: the
 * *directory* is one this process created with `mkdtemp` under `TMPDIR`, and
 * nothing outside it is touched, which is checked on every call rather than
 * assumed once at the top.
 */
static void remove_tree(const char *path)
{
	DIR                 *open_dir;
	const struct dirent *found;
	size_t               root_length = strlen(testdir_path);

	if (!path || !testdir_path[0] || strncmp(path, testdir_path, root_length) != 0 ||
	    (path[root_length] != '\0' && path[root_length] != '/')) {
		printf("refusing to remove `%s`, which is not under the directory this test made\n",
		    path ? path : "");
		return;
	}
	open_dir = opendir(path);
	if (!open_dir) {
		(void)unlink(path);
		return;
	}
	while ((found = readdir(open_dir)) != NULL) {
		char        child[1024];
		struct stat about;

		if (strcmp(found->d_name, ".") == 0 || strcmp(found->d_name, "..") == 0) {
			continue;
		}
		(void)snprintf(child, sizeof(child), "%s/%s", path, found->d_name);
		if (lstat(child, &about) != 0) {
			continue;
		}
		if (S_ISDIR(about.st_mode)) {
			remove_tree(child);
			continue;
		}
		(void)unlink(child);
	}
	(void)closedir(open_dir);
	(void)rmdir(path);
}

/* ------------------------------------------------------------------------ *
 * Looking at what a load found
 * ------------------------------------------------------------------------ */

/* Whether any source's name ends with `leaf`. */
static int loaded(const ncfg_config_sources_t *sources, const char *leaf)
{
	size_t i;

	for (i = 0; i < sources->count; i++) {
		size_t name = strlen(sources->at[i].name);
		size_t want = strlen(leaf);

		if (name >= want && strcmp(sources->at[i].name + (name - want), leaf) == 0) {
			return 1;
		}
	}
	return 0;
}

/* The document a set of sources compiles to, for reading. NULL is a
 * legitimate answer and the caller says which it expected. */
static ncfg_document_t *compiled(const ncfg_config_sources_t *sources)
{
	char err[NCFG_ERROR_MAX];

	return ncfg_config_compile(sources, ncfg_hook_sink_unwritten(), NULL, err, sizeof(err));
}

/* The MTU of the one device named `name`, or -1. */
static long device_mtu(const ncfg_document_t *document, const char *name)
{
	size_t i;

	for (i = 0; document && i < document->device_count; i++) {
		if (strcmp(document->devices[i].name, name) == 0) {
			return document->devices[i].mtu.has ? (long)document->devices[i].mtu.value
			    : -1;
		}
	}
	return -1;
}

/* ------------------------------------------------------------------------ *
 * Three states of a path
 * ------------------------------------------------------------------------ */

static void the_states_of_a_path(const char *root)
{
	ncfg_config_sources_t sources = { 0 };
	char                  err[NCFG_ERROR_MAX];
	const char           *base;

	base = tree(root, "unreadable", NULL, 0);
	(void)symlink("netcfgd.conf", in(base, "netcfgd.conf"));
	check(!ncfg_config_load(base, &sources, err, sizeof(err)),
	    "a config that cannot be examined is not read as an empty one");
	check(strstr(err, "netcfgd.conf") != NULL, "  it names the path");
	check(strstr(err, "Too many levels") != NULL || strstr(err, "symbolic") != NULL,
	    "  and carries the kernel's own reason");
	check(strstr(err, "no configuration") != NULL,
	    "  and says which two states it is keeping apart");
	ncfg_config_sources_free(&sources);

	{
		const file_t files[] = { { "netcfgd.conf", "interface eth0 { }\n" } };

		base = tree(root, "unreadable-drop-in", files, 1u);
		(void)symlink("conf.d", in(base, "conf.d"));
		check(!ncfg_config_load(base, &sources, err, sizeof(err)) &&
		    strstr(err, "conf.d") != NULL,
		    "a conf.d that cannot be examined is refused by name");
		ncfg_config_sources_free(&sources);
	}

	base = tree(root, "dangling", NULL, 0);
	(void)symlink(in(base, "elsewhere.conf"), in(base, "netcfgd.conf"));
	check(!ncfg_config_load(base, &sources, err, sizeof(err)) &&
	    strstr(err, "netcfgd.conf") != NULL,
	    "a link that points at nothing is reported rather than treated as absent");
	ncfg_config_sources_free(&sources);

	/* The control, and the state this must go on allowing: a machine with no
	 * `/etc/netcfgd` at all is an ordinary machine. */
	base = tree(root, "absent", NULL, 0);
	check(ncfg_config_load(in(base, "nothing-here"), &sources, err, sizeof(err)) &&
	    sources.count == 0u, "a config that is simply absent is still not an error");
	ncfg_config_sources_free(&sources);
	check(ncfg_config_load(base, &sources, err, sizeof(err)) && sources.count == 0u,
	    "and an empty directory is a valid state");
	{
		/* The claim the doc comment makes about that state, checked rather
		 * than asserted: an empty config compiles to an empty document, which
		 * plans to do nothing. */
		ncfg_document_t *nothing = compiled(&sources);

		check(nothing && nothing->interface_count == 0u && nothing->device_count == 0u,
		    "  which compiles to an empty document rather than to a refusal");
		ncfg_document_free(nothing);
	}
	ncfg_config_sources_free(&sources);
}

/* ------------------------------------------------------------------------ *
 * include
 * ------------------------------------------------------------------------ */

static void includes(const char *root)
{
	ncfg_config_sources_t sources = { 0 };
	char                  err[NCFG_ERROR_MAX];
	const char           *base;

	{
		const file_t files[] = { { "netcfgd.conf", "include \"netcfgd.conf\"\n" } };

		base = tree(root, "self-include", files, 1u);
		check(!ncfg_config_load(base, &sources, err, sizeof(err)) &&
		    strstr(err, "include cycle") != NULL,
		    "a file that includes itself is refused rather than recursed into");
		ncfg_config_sources_free(&sources);
	}
	{
		const file_t files[] = {
			{ "netcfgd.conf", "include \"other.conf\"\n" },
			{ "other.conf", "include \"netcfgd.conf\"\n" }
		};

		base = tree(root, "mutual-include", files, 2u);
		check(!ncfg_config_load(base, &sources, err, sizeof(err)) &&
		    strstr(err, "include cycle") != NULL && strstr(err, "other.conf") != NULL,
		    "two files including each other are refused, naming the chain");
		ncfg_config_sources_free(&sources);
	}
	{
		/* A diamond is not a cycle, and refusing one would be a regression: a
		 * set of everything seen would drop the second `d` and quietly change
		 * what the config means. */
		const file_t files[] = {
			{ "netcfgd.conf", "include \"b.conf\"\ninclude \"c.conf\"\n" },
			{ "b.conf", "include \"d.conf\"\n" },
			{ "c.conf", "include \"d.conf\"\n" },
			{ "d.conf", "# nothing to declare\n" }
		};

		base = tree(root, "diamond-include", files, 4u);
		check(ncfg_config_load(base, &sources, err, sizeof(err)),
		    "a diamond include is not a cycle");
		check(sources.count == 5u, "  and d.conf is expanded both times");
		ncfg_config_sources_free(&sources);
	}
	{
		/* A line that merely starts with the word is not an include, and a
		 * real one is pulled in ahead of the file that names it. */
		const file_t files[] = {
			{ "netcfgd.conf", "include \"extra.conf\"\n" },
			{ "extra.conf", "device eth0 { mtu = 1500 }\n" },
			{ "conf.d/10-not.conf", "# include \"nothing.conf\"\n" }
		};

		base = tree(root, "include-lines", files, 3u);
		check(ncfg_config_load(base, &sources, err, sizeof(err)) && sources.count == 3u,
		    "an include line is recognised and a commented one is not");
		check(sources.count == 3u && strstr(sources.at[0].name, "extra.conf") != NULL,
		    "  and the included file is read first");
		check(sources.count == 3u && strstr(sources.at[1].text, "include") == NULL,
		    "  with the statement taken out of the file that named it");
		ncfg_config_sources_free(&sources);
	}
	{
		/* A device has no end to read to, and reading one is how `include`
		 * came to allocate a gigabyte in a daemon budgeted at five
		 * megabytes. */
		const file_t files[] = { { "netcfgd.conf", "include \"/dev/zero\"\n" } };

		base = tree(root, "include-device", files, 1u);
		check(!ncfg_config_load(base, &sources, err, sizeof(err)) &&
		    strstr(err, "not a regular file") != NULL,
		    "a device cannot be included, and the refusal says why");
		ncfg_config_sources_free(&sources);
	}
}

/* ------------------------------------------------------------------------ *
 * Layering
 * ------------------------------------------------------------------------ */

static void layering(const char *root)
{
	ncfg_config_sources_t sources = { 0 };
	char                  err[NCFG_ERROR_MAX];

	{
		const file_t factory_files[] = { { "netcfgd.conf",
			"device eth0 { mtu = 1500 }\n" } };
		const file_t runtime_files[] = { { "conf.d/10-local.conf",
			"override device eth0 { mtu = 9000 }\n" } };
		const char  *factory = tree(root, "f1", factory_files, 1u);
		char         factory_kept[512];
		const char  *runtime;

		(void)snprintf(factory_kept, sizeof(factory_kept), "%s", factory);
		runtime = tree(root, "r1", runtime_files, 1u);
		check(ncfg_config_load_layered(factory_kept, runtime, &sources, err, sizeof(err)) &&
		    sources.count == 2u, "the runtime layer is read last");
		check(sources.count == 2u && strstr(sources.at[0].name, "netcfgd.conf") != NULL &&
		    strstr(sources.at[1].name, "10-local.conf") != NULL, "  in that order");
		ncfg_config_sources_free(&sources);
	}
	{
		const file_t files[] = { { "netcfgd.conf", "device eth0 { mtu = 1500 }\n" } };
		const char  *present = tree(root, "f2", files, 1u);
		char         kept[512];

		(void)snprintf(kept, sizeof(kept), "%s", present);
		check(ncfg_config_load_layered(in(kept, "nothing-here"), kept, &sources, err,
		    sizeof(err)) && sources.count == 1u, "a missing factory layer is not an error");
		ncfg_config_sources_free(&sources);
		check(ncfg_config_load_layered(kept, in(kept, "nothing-here"), &sources, err,
		    sizeof(err)) && sources.count == 1u, "and neither is a missing runtime layer");
		ncfg_config_sources_free(&sources);
		/* Reading it twice would make every block collide with a copy of
		 * itself, which is an "already defined" error against one file named
		 * as both positions. */
		check(ncfg_config_load_layered(kept, kept, &sources, err, sizeof(err)) &&
		    sources.count == 1u, "one directory named twice is read once");
		ncfg_config_sources_free(&sources);
	}
	{
		/* Two enumerations that drifted apart would leave files behind that
		 * still configure the machine after a reset said it had cleared it. */
		const file_t files[] = {
			{ "netcfgd.conf", "" },
			{ "conf.d/10-a.conf", "" },
			{ "conf.d/20-b.conf", "" },
			/* Neither is config and neither is removed: a disabled drop-in
			 * and a secret are both things that live in this tree. */
			{ "conf.d/10-a.conf.disabled", "" },
			{ "secrets/home", "hunter2" }
		};
		const char *base = tree(root, "f4", files, 5u);
		char      **paths = NULL;
		size_t      count = 0;
		char        kept[512];
		size_t      i;
		int         same = 1;

		(void)snprintf(kept, sizeof(kept), "%s", base);
		check(ncfg_config_writable_files(kept, &paths, &count, err, sizeof(err)) &&
		    count == 3u, "a reset removes three files here");
		check(ncfg_config_load(kept, &sources, err, sizeof(err)) && sources.count == count,
		    "  and the loader reads exactly that many");
		for (i = 0; i < count && i < sources.count; i++) {
			if (strcmp(paths[i], sources.at[i].name) != 0) {
				same = 0;
			}
		}
		check(same, "  the same files, in the same order");
		ncfg_config_paths_free(paths, count);
		ncfg_config_sources_free(&sources);
	}
}

/* ------------------------------------------------------------------------ *
 * Profiles
 * ------------------------------------------------------------------------ */

static void profiles(const char *root)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *document;
	char                  err[NCFG_ERROR_MAX];

	{
		/* A machine with hand-written configuration and no selection reads
		 * exactly its own files. 0151: spelling that state as a profile
		 * called `none` would make it confusable with the shipped `offline`
		 * one in every diagnostic that mentioned either. */
		const file_t files[] = { { "conf.d/10-base.conf",
			"device eth0 { mtu = 1500 }\n" } };
		const char  *base = tree(root, "p0", files, 1u);

		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)) &&
		    sources.count == 1u, "no profile chosen reads only the base");
		ncfg_config_sources_free(&sources);
	}
	{
		const file_t files[] = {
			{ "conf.d/10-base.conf", "global { profile = \"office\" }\n" },
			{ "profile/office/10-office.conf", "device eth0 { mtu = 9000 }\n" },
			/* A profile that was not chosen is not read, which is the point
			 * of choosing. */
			{ "profile/home/10-home.conf", "device eth0 { mtu = 1400 }\n" }
		};
		const char *base = tree(root, "p1", files, 3u);

		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)) &&
		    sources.count == 2u && loaded(&sources, "10-office.conf"),
		    "a chosen profile is layered on the base");
		document = compiled(&sources);
		check(device_mtu(document, "eth0") == 9000, "  and the profile won");
		ncfg_document_free(document);
		ncfg_config_sources_free(&sources);
	}
	{
		/* The operator's copy of a shipped profile layers over it, which is
		 * the factory-and-runtime rule one directory down rather than a
		 * second mechanism. */
		const file_t factory_files[] = {
			{ "conf.d/10-base.conf", "global { profile = \"offline\" }\n" },
			{ "profile/offline/10-off.conf", "device eth0 { mtu = 1280 }\n" }
		};
		const file_t runtime_files[] = { { "profile/offline/20-mine.conf",
			"override device eth0 { mtu = 1500 }\n" } };
		const char  *factory = tree(root, "p2f", factory_files, 2u);
		char         factory_kept[512];
		const char  *runtime;

		(void)snprintf(factory_kept, sizeof(factory_kept), "%s", factory);
		runtime = tree(root, "p2r", runtime_files, 1u);
		check(ncfg_config_load_with_profile(factory_kept, runtime, &sources, err,
		    sizeof(err)), "a profile layers factory then runtime");
		document = compiled(&sources);
		check(device_mtu(document, "eth0") == 1500,
		    "  the operator's copy layered over the shipped one");
		ncfg_document_free(document);
		ncfg_config_sources_free(&sources);
	}
	{
		/* Following it would mean loading until the answer stopped changing,
		 * and ignoring it silently is how somebody spends an afternoon
		 * wondering why their profile does not switch. */
		const file_t files[] = {
			{ "conf.d/10-base.conf", "global { profile = \"office\" }\n" },
			{ "profile/office/10-office.conf",
			    "override global { profile = \"home\" }\n" }
		};
		const char *base = tree(root, "p3", files, 2u);

		check(!ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)) &&
		    strstr(err, "office") != NULL && strstr(err, "choose again") != NULL,
		    "a profile that names a profile is refused rather than ignored");
		ncfg_config_sources_free(&sources);
	}
	{
		/* The loader returning an error here would replace a diagnostic
		 * pointing at the offending line with one that does not. */
		const file_t files[] = { { "conf.d/10-base.conf", "interface { mtu = }\n" } };
		const char  *base = tree(root, "p4", files, 1u);

		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)),
		    "a base that does not compile is not the loader's error");
		document = compiled(&sources);
		check(document == NULL, "  and the compiler is the one that complains");
		ncfg_document_free(document);
		ncfg_config_sources_free(&sources);
	}
	{
		/* The directive of 0151, mechanically: a hand edit that writes
		 * `override global` replaces the whole block and takes the selection
		 * with it, which is a switch to no profile that nobody asked for. */
		const file_t files[] = {
			{ "conf.d/90-profile.conf", "global { profile = \"office\" }\n" },
			{ "conf.d/99-mine.conf",
			    "override global { dns { search = \"example.invalid\" } }\n" },
			{ "profile/office/10-office.conf", "device eth0 { mtu = 9000 }\n" }
		};
		const char *base = tree(root, "pg1", files, 3u);

		check(!ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)),
		    "a hand edit cannot take the profile away");
		check(strstr(err, "99-mine.conf") != NULL, "  it names the culprit");
		check(strstr(err, "office") != NULL, "  and what was asked for");
		check(strstr(err, "ncfg profile set") != NULL, "  and who may");
		ncfg_config_sources_free(&sources);
	}
	{
		/* The other half, and the one that makes the guard worth having
		 * rather than merely strict: `ncfg control set` and the gui's dns tab
		 * emit their own sub-block, so they must go on working next to a
		 * chosen profile. */
		const file_t files[] = {
			{ "conf.d/90-profile.conf", "global { profile = \"office\" }\n" },
			{ "conf.d/99-mine.conf",
			    "global { dns { search = \"example.invalid\" } }\n" },
			{ "profile/office/10-office.conf", "device eth0 { mtu = 9000 }\n" }
		};
		const char *base = tree(root, "pg2", files, 3u);

		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)),
		    "a merging write leaves the profile alone");
		document = compiled(&sources);
		check(document && document->globals.profile &&
		    strcmp(document->globals.profile, "office") == 0, "  the selection holds");
		check(device_mtu(document, "eth0") == 9000, "  and the profile was read");
		ncfg_document_free(document);
		ncfg_config_sources_free(&sources);
	}
	{
		/* The guard reads the drop-in `ncfg profile` owns and only that one.
		 * A profile chosen by hand in some other file is nobody's to check
		 * against, and a guard that fired here would forbid editing the
		 * configuration by hand. */
		const file_t files[] = {
			{ "conf.d/10-base.conf", "global { profile = \"office\" }\n" },
			{ "profile/office/10-office.conf", "device eth0 { mtu = 9000 }\n" }
		};
		const char *base = tree(root, "pg3", files, 2u);

		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)) &&
		    sources.count == 2u, "a profile chosen in another file is not guarded");
		ncfg_config_sources_free(&sources);
	}
	{
		const file_t factory_files[] = { { "profile/offline/00.conf", "" } };
		const file_t runtime_files[] = {
			{ "profile/offline/00.conf", "" },
			{ "profile/office/00.conf", "" }
		};
		const char           *factory = tree(root, "pl-f", factory_files, 1u);
		char                  factory_kept[512];
		const char           *config;
		ncfg_profile_entry_t *entries = NULL;
		size_t                count = 0;

		(void)snprintf(factory_kept, sizeof(factory_kept), "%s", factory);
		config = tree(root, "pl-c", runtime_files, 2u);
		check(ncfg_profile_list(config, factory_kept, &entries, &count, err, sizeof(err)) &&
		    count == 2u, "the profiles of both layers are listed once each");
		check(count == 2u && strcmp(entries[0].name, "office") == 0 &&
		    strcmp(entries[1].name, "offline") == 0, "  in name order");
		check(count == 2u && !entries[0].shipped && !entries[1].shipped,
		    "  and a name in both layers is the operator's");
		ncfg_profile_entries_free(entries, count);
	}
}

/* ------------------------------------------------------------------------ *
 * The two defects of the `UnwrittenHooks` section
 * ------------------------------------------------------------------------ */

#define A_HOOKED_BASE \
	"interface eth0 {\n\tconfig = \"dhcp\"\n\tpost_up {\n#!/bin/sh\nlogger up\n\t}\n}\n"

static void a_machine_that_has_a_hook(const char *root)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *document;
	char                  err[NCFG_ERROR_MAX];

	{
		/*
		 * **The defect this replaces refused everything.** `install_drop_in`
		 * verifies by compiling, it compiled with a sink whose entire
		 * behaviour is to refuse a hook, and the failure was reported as
		 * "that would stop the configuration compiling" -- about a
		 * configuration the same daemon loads on every reload. So on any
		 * machine with one hook, every editor in the window and every
		 * `ncfg config put` was refused, and the message blamed the file
		 * being written rather than the check doing the writing.
		 */
		const file_t files[] = { { "etc/netcfgd.conf", A_HOOKED_BASE } };
		const char  *dir = tree(root, "hooked", files, 1u);
		char         config[512];
		char         factory[512];
		char        *path = NULL;

		(void)snprintf(config, sizeof(config), "%s/etc", dir);
		(void)snprintf(factory, sizeof(factory), "%s/factory", dir);

		/* The control, so this cannot pass vacuously: the refusing sink
		 * really does refuse this very configuration, which is what the
		 * verification compile used to be handed. */
		check(ncfg_config_load(config, &sources, err, sizeof(err)),
		    "a machine with a hook in its configuration loads");
		document = ncfg_config_compile(&sources, ncfg_hook_sink_refusing(), NULL, err,
		    sizeof(err));
		check(document == NULL && strstr(err, "cannot accept hooks") != NULL,
		    "  and the refusing sink refuses it, which is what the check used to use");
		ncfg_document_free(document);

		/*
		 * **And no sink at all is a different refusal, which it did not used
		 * to be.** Both said "a compile was asked for with nothing to
		 * compile", so a caller holding five good source files and no sink was
		 * told its sources were the problem. The sentence names what is
		 * missing now, and the count is in it so that the sources are visibly
		 * *not* the complaint.
		 */
		err[0] = '\0';
		document = ncfg_config_compile(&sources, NULL, NULL, err, sizeof(err));
		check(document == NULL && strstr(err, "somewhere to put the hooks") != NULL,
		    "  and a compile with no sink says that is what it is missing");
		check(strstr(err, "nothing to compile") == NULL,
		    "  rather than blaming the sources it was given");
		ncfg_document_free(document);
		ncfg_config_sources_free(&sources);

		check(ncfg_config_install_drop_in(config, factory, "another",
		    "interface eth1 {\n\tconfig = \"dhcp\"\n}\n", 0, &path, NULL, err,
		    sizeof(err)), "a drop-in is installed on a machine that has a hook");
		check(path && testdir_exists(path), "  and the file is there");
		free(path);

		/* And a drop-in that carries one itself, which is what the window
		 * writes when somebody adds a hook to an interface. */
		check(ncfg_config_install_drop_in(config, factory, "hooked",
		    "interface eth2 {\n\tconfig = \"dhcp\"\n\ton drift {\n#!/bin/sh\n"
		    "logger drifted\n\t}\n}\n", 0, NULL, NULL, err, sizeof(err)),
		    "a drop-in carrying a hook of its own is installed too");
	}
	{
		/*
		 * The other half of the same fault, and the quieter one:
		 * `load_with_profile` compiles the base to find out which profile is
		 * selected, and returned early when that compile failed. With a hook
		 * in the base it always failed, so the profile directory was never
		 * added -- `ncfg profile set` wrote a selection, reported success,
		 * and the profile's drop-ins were not read on this or any later load.
		 */
		const file_t files[] = {
			{ "netcfgd.conf", "device eth0 { mtu = 1500 }\n" A_HOOKED_BASE },
			{ "conf.d/00-profile.conf", "global { profile = \"office\" }\n" },
			{ "profile/office/10-office.conf",
			    "override device eth0 { mtu = 9000 }\n" }
		};
		const char *base = tree(root, "hooked-profile", files, 3u);

		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)),
		    "a machine with a hook still loads its profile");
		check(loaded(&sources, "10-office.conf"),
		    "  the selected profile's directory was read");
		document = compiled(&sources);
		check(device_mtu(document, "eth0") == 9000, "  and it is what the machine runs");
		ncfg_document_free(document);

		/* The control again: with the refusing sink this configuration does
		 * not compile, which is exactly what made the loader give up before
		 * it got to the profile. */
		document = ncfg_config_compile(&sources, ncfg_hook_sink_refusing(), NULL, err,
		    sizeof(err));
		check(document == NULL, "  and the refusing sink would still refuse it");
		ncfg_document_free(document);
		ncfg_config_sources_free(&sources);
	}
}

/* ------------------------------------------------------------------------ *
 * Writing a drop-in
 * ------------------------------------------------------------------------ */

static void drop_ins(const char *root)
{
	char        err[NCFG_ERROR_MAX];
	const char *dir;

	{
		const file_t files[] = { { "etc/netcfgd.conf",
			"interface eth0 {\n\tconfig = \"dhcp\"\n}\n" } };
		char        config[512];
		char        factory[512];
		char       *path = NULL;
		char       *text;

		dir = tree(root, "drop-in", files, 1u);
		(void)snprintf(config, sizeof(config), "%s/etc", dir);
		(void)snprintf(factory, sizeof(factory), "%s/factory", dir);

		check(ncfg_config_install_drop_in(config, factory, "ordinary",
		    "interface eth1 {\n\tconfig = \"dhcp\"\n}\n", 0, &path, NULL, err,
		    sizeof(err)) && path && testdir_exists(path),
		    "a drop-in that compiles is kept");
		free(path);

		/* The pair, and the second half is the reason the function exists: a
		 * file that parses on its own can still stop the *configuration*
		 * compiling, and a machine whose configuration stopped compiling is
		 * one where the next reload changes nothing and says why in a log
		 * nobody is reading. */
		check(!ncfg_config_install_drop_in(config, factory, "clashing",
		    "interface eth0 {\n\tconfig = \"dhcp\"\n}\n", 0, NULL, NULL, err,
		    sizeof(err)), "a drop-in that would break the configuration is not kept");
		check(strstr(err, "already defined") != NULL,
		    "  the refusal carries the compiler's own diagnostic");
		check(!testdir_exists(in(config, "conf.d/clashing.conf")),
		    "  and the refused drop-in was not left behind");

		{
			const char *bad[] = { "../escape", "sub/dir", ".hidden", "" };
			size_t      i;
			int         all = 1;

			for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
				if (ncfg_config_install_drop_in(config, factory, bad[i], "", 0,
				    NULL, NULL, err, sizeof(err))) {
					all = 0;
				}
			}
			check(all, "a name that is a path is refused");
		}

		/* Replacing is asked for, and a refused replace leaves the
		 * original. */
		check(!ncfg_config_install_drop_in(config, factory, "ordinary",
		    "interface eth1 {\n\tconfig = \"dhcp\"\n}\n", 0, NULL, NULL, err,
		    sizeof(err)) && strstr(err, "already exists") != NULL,
		    "an existing drop-in is kept unless replacing was asked for");
		check(ncfg_config_install_drop_in(config, factory, "ordinary",
		    "interface eth2 {\n\tconfig = \"dhcp\"\n}\n", 1, NULL, NULL, err,
		    sizeof(err)), "and replaced when it is");
		text = testdir_read(in(config, "conf.d/ordinary.conf"), NULL);
		check(text && strstr(text, "eth2") != NULL, "  with the new contents");
		free(text);

		/* The case the restore exists for: refusing after the write means the
		 * file on disk is briefly the new one, and leaving it there would be
		 * a rejected change that took effect anyway. */
		check(!ncfg_config_install_drop_in(config, factory, "ordinary",
		    "interface eth0 {\n\tconfig = \"dhcp\"\n}\n", 1, NULL, NULL, err,
		    sizeof(err)), "a replace that would not compile is refused");
		text = testdir_read(in(config, "conf.d/ordinary.conf"), NULL);
		check(text && strstr(text, "eth2") != NULL, "  and what was there is put back");
		free(text);
	}
	{
		const file_t files[] = { { "etc/conf.d/keep.conf", "" } };
		char         config[512];
		char         factory[512];
		int          removed = 1;

		dir = tree(root, "remove", files, 1u);
		(void)snprintf(config, sizeof(config), "%s/etc", dir);
		(void)snprintf(factory, sizeof(factory), "%s/factory", dir);

		/* **False, not just success.** It returned the same thing for a
		 * drop-in it had removed and for one that was never there, so
		 * `ncfg config rm` printed "is not in" on the success path and told
		 * an operator their removal had not happened. */
		check(ncfg_config_remove_drop_in(config, factory, "never-existed", &removed, NULL,
		    err, sizeof(err)) && removed == 0,
		    "removing nothing is success, and says nothing was there");
		check(ncfg_config_install_drop_in(config, factory, "thing",
		    "interface eth1 {\n\tconfig = \"dhcp\"\n}\n", 0, NULL, NULL, err,
		    sizeof(err)), "a drop-in is installed");
		check(ncfg_config_remove_drop_in(config, factory, "thing", &removed, NULL, err,
		    sizeof(err)) && removed == 1, "  and removing it says it was there");
		check(!testdir_exists(in(config, "conf.d/thing.conf")), "  and it is gone");

		/* Removing a file can break the configuration as surely as adding
		 * one: `override` on a block nothing defines is an error. */
		check(ncfg_config_install_drop_in(config, factory, "base",
		    "interface eth3 {\n\tconfig = \"dhcp\"\n}\n", 0, NULL, NULL, err,
		    sizeof(err)) &&
		    ncfg_config_install_drop_in(config, factory, "later",
		    "override interface eth3 {\n\tconfig = \"slaac\"\n}\n", 0, NULL, NULL, err,
		    sizeof(err)), "a drop-in another file overrides is installed");
		check(!ncfg_config_remove_drop_in(config, factory, "base", NULL, NULL, err,
		    sizeof(err)) && strstr(err, "put back") != NULL,
		    "a removal that would break the configuration is refused");
		check(testdir_exists(in(config, "conf.d/base.conf")), "  with the file put back");
	}
}

/* ------------------------------------------------------------------------ *
 * Writing, atomically and otherwise
 * ------------------------------------------------------------------------ */

static void writing(const char *root)
{
	char                 err[NCFG_ERROR_MAX];
	const char          *dir = tree(root, "writes", NULL, 0);
	char                 base[512];
	char                 path[640];
	char                *text;
	DIR                 *open_dir;
	const struct dirent *found;
	int                  leftovers = 0;
	int                  denied = 1;

	(void)snprintf(base, sizeof(base), "%s", dir);
	(void)snprintf(path, sizeof(path), "%s/thing.conf", base);

	/* netcfgd's own inotify watch is the reader that must never see half a
	 * file, which is why this property outlived the writer it was written
	 * for. */
	check(ncfg_config_write_atomically(path, "first\n", 6u, 0644u, &denied, err,
	    sizeof(err)) && !denied, "writing is atomic and asks for no fallback");
	check(ncfg_config_write_atomically(path, "second\n", 7u, 0644u, NULL, err, sizeof(err)),
	    "and writing again replaces it");
	text = testdir_read(path, NULL);
	check(text && strcmp(text, "second\n") == 0, "  with the second contents");
	free(text);
	open_dir = opendir(base);
	while (open_dir && (found = readdir(open_dir)) != NULL) {
		if (found->d_name[0] == '.' && strcmp(found->d_name, ".") != 0 &&
		    strcmp(found->d_name, "..") != 0) {
			leftovers++;
		}
	}
	if (open_dir) {
		(void)closedir(open_dir);
	}
	check(leftovers == 0, "  and no temporary is left behind");

	/*
	 * 0161's fallback, exercised directly.
	 *
	 * **The mechanism it exists for cannot be made here.** It engages when a
	 * sandbox grants a file without granting its directory, which is a
	 * read-only mount; a `chmod` does not reproduce it for root, who has
	 * `CAP_DAC_OVERRIDE` and walks straight through a mode. 0161 records a
	 * first end-to-end check that passed under `unshare -rn` against a
	 * `chmod`'d directory and passed just as happily with the fix reverted.
	 * So the fallback is called for what it is rather than provoked into
	 * being called, and the three things it promises are checked.
	 */
	check(ncfg_config_write_in_place(path, "third\n", 6u, 0600u, EROFS, err, sizeof(err)),
	    "the in-place fallback writes a file that is already there");
	text = testdir_read(path, NULL);
	check(text && strcmp(text, "third\n") == 0, "  with the new contents");
	free(text);
	check(testdir_mode(path) == 0600, "  and the mode it was given, which no open applies");

	check(!ncfg_config_write_in_place(in(base, "not-there.conf"), "x\n", 2u, 0644u, EROFS,
	    err, sizeof(err)), "it will not create a file that is not there");
	check(strstr(err, "would not take a temporary file") != NULL &&
	    strstr(err, "not there to be written in place") != NULL,
	    "  and says both halves, so the staging refusal is not spoken over");
	check(strstr(err, "ProtectSystem") != NULL,
	    "  naming the mount for a read-only filesystem, as a mechanism not a verdict");

	(void)symlink("thing.conf", in(base, "linked.conf"));
	check(!ncfg_config_write_in_place(in(base, "linked.conf"), "x\n", 2u, 0644u, EACCES, err,
	    sizeof(err)) && strstr(err, "symlink") != NULL,
	    "it will not follow a symlink, which would edit whatever owns the target");
	text = testdir_read(path, NULL);
	check(text && strcmp(text, "third\n") == 0, "  and the target is untouched");
	free(text);
	check(strstr(err, "ProtectSystem") == NULL,
	    "  and a permission refusal does not get the sentence about mounts");
}

/* ------------------------------------------------------------------------ *
 * Choosing, folding and saving
 * ------------------------------------------------------------------------ */

static void the_fold(const char *root)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *document;
	char                  err[NCFG_ERROR_MAX];

	{
		/* The check ran through the unprofiled loader, so `ncfg profile set`
		 * wrote the selection, compiled a configuration that excluded the
		 * very profile it had just chosen, and reported success. */
		const file_t files[] = {
			{ "netcfgd.conf", "device e0 { kind = \"dummy\" }\n" },
			{ "profile/broken/00.conf", "this is not config\n" },
			{ "profile/fine/00.conf", "override device e0 { mtu = 1400 }\n" }
		};
		const char *config = tree(root, "profile-broken", files, 3u);
		char        config_kept[512];
		const char *factory;

		(void)snprintf(config_kept, sizeof(config_kept), "%s", config);
		factory = tree(root, "profile-broken-factory", NULL, 0);
		check(!ncfg_profile_set(config_kept, factory, "broken", NULL, NULL, err, sizeof(err)),
		    "a profile whose drop-in does not compile is not chosen");
		check(!testdir_exists(in(config_kept, "conf.d/" NCFG_PROFILE_DROP_IN ".conf")),
		    "  and the refused selection was not left behind");
		check(ncfg_profile_set(config_kept, factory, "fine", NULL, NULL, err, sizeof(err)),
		    "a profile that compiles is selectable");

		{
			/* A profile name is written into the language, so it is checked
			 * like one. It was checked only as a directory name and then
			 * interpolated unescaped into `global { profile = "..." }`; a
			 * name carrying a quote and a newline closes the string and
			 * appends whatever follows, which compiles. Reproduced against
			 * the shipped binary: the next reload took an injected
			 * `hostname`, and a `hooks` block in the same position is shell
			 * that runs as root. */
			static const char escape[] =
			    "evil\"\n}\nglobal {\n\thostname = \"PWNED\"\n}\nglobal {\n"
			    "\tprofile = \"evil";
			const char *bad[] = { "", "has/slash", ".hidden", "..", "up/../out",
				"quote\"inside", "back\\slash", "newline\nafter" };
			const char *good[] = { "office", "home-2", "site.a", "a_b" };
			size_t      i;
			int         all = 1;

			check(!ncfg_profile_name_usable(escape, err, sizeof(err)),
			    "a profile name cannot carry configuration");
			for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
				if (ncfg_profile_name_usable(bad[i], err, sizeof(err))) {
					all = 0;
				}
			}
			check(all, "  nor a separator, a dot, a quote or a newline");
			for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
				if (!ncfg_profile_name_usable(good[i], err, sizeof(err))) {
					all = 0;
				}
			}
			check(all, "  and an ordinary name is still a name");
			check(strstr(err, "secret") == NULL,
			    "  with a refusal that does not talk about secrets");
		}
	}
	{
		/* The other half of 0151's directive: a settings edit takes the
		 * machine off its profile, and the configuration it is running does
		 * not move. */
		const file_t files[] = {
			{ "netcfgd.conf", "device eth0 { mtu = 1500 }\n" },
			{ "conf.d/90-profile.conf", "global { profile = \"office\" }\n" },
			{ "profile/office/10-office.conf",
			    "override device eth0 { mtu = 9000 }\n" }
		};
		const char *base = tree(root, "pa1", files, 3u);
		char       *folded = NULL;

		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)),
		    "a machine on a profile loads it");
		document = compiled(&sources);
		check(document && document->globals.profile &&
		    strcmp(document->globals.profile, "office") == 0 &&
		    device_mtu(document, "eth0") == 9000, "  and runs what it says");
		ncfg_document_free(document);
		ncfg_config_sources_free(&sources);

		check(ncfg_profile_adopt(base, base, &folded, err, sizeof(err)) && folded &&
		    strcmp(folded, "office") == 0,
		    "folding a profile in changes the label and nothing else");
		free(folded);
		check(!testdir_exists(in(base, "conf.d/90-profile.conf")),
		    "  the selection is gone");
		check(testdir_exists(in(base, "conf.d/05-profile-office.conf")),
		    "  kept, and early enough that the next edit wins");
		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)),
		    "  and the machine still loads");
		document = compiled(&sources);
		check(document && document->globals.profile == NULL, "  on no profile now");
		check(device_mtu(document, "eth0") == 9000, "  and running exactly what it was");
		ncfg_document_free(document);
		ncfg_config_sources_free(&sources);

		/*
		 * The undo, for a settings write that was then refused. A rejected
		 * edit must not move the selection: nothing was changed, so nothing
		 * should have moved -- and the fold has to come first, because
		 * folding afterwards would have to preserve a document in which the
		 * profile still overrides the new edit.
		 */
		check(ncfg_profile_restore(base, "office", err, sizeof(err)),
		    "a fold is undone when the write it was made for did not happen");
		check(!testdir_exists(in(base, "conf.d/05-profile-office.conf")),
		    "  the folded file is gone");
		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)),
		    "  and the machine loads");
		document = compiled(&sources);
		check(document && document->globals.profile &&
		    strcmp(document->globals.profile, "office") == 0 &&
		    device_mtu(document, "eth0") == 9000, "  back on its profile, running the same");
		ncfg_document_free(document);
		ncfg_config_sources_free(&sources);

		{
			int removed = 0;

			check(ncfg_profile_unset(base, base, &removed, NULL, err, sizeof(err)) &&
			    removed, "unsetting takes the selection off and says it was there");
			check(ncfg_profile_unset(base, base, &removed, NULL, err, sizeof(err)) &&
			    !removed, "  and unsetting again is success that says nothing was");
			check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)),
			    "  the machine loads");
			document = compiled(&sources);
			check(document && document->globals.profile == NULL &&
			    device_mtu(document, "eth0") == 1500,
			    "  on no profile, and without the profile's overrides -- which is "
			    "what unset means and fold does not");
			ncfg_document_free(document);
			ncfg_config_sources_free(&sources);
		}
	}
	{
		const file_t files[] = { { "netcfgd.conf", "device eth0 { mtu = 1500 }\n" } };
		const char  *base = tree(root, "pa2", files, 1u);
		char        *folded = (char *)1;

		check(ncfg_profile_adopt(base, base, &folded, err, sizeof(err)) && folded == NULL,
		    "folding with no profile chosen does nothing, and is not an error");
	}
	{
		/* The late position, used only when the early one would change
		 * things. A drop-in between the two means the profile really did
		 * depend on being read last, so the fold has to go last too. */
		const file_t files[] = {
			{ "netcfgd.conf", "device eth0 { mtu = 1500 }\n" },
			{ "conf.d/50-middle.conf", "override device eth0 { mtu = 1280 }\n" },
			{ "conf.d/90-profile.conf", "global { profile = \"office\" }\n" },
			{ "profile/office/10-office.conf",
			    "override device eth0 { mtu = 9000 }\n" }
		};
		const char *base = tree(root, "pa4", files, 4u);
		char       *folded = NULL;

		check(ncfg_profile_adopt(base, base, &folded, err, sizeof(err)) && folded &&
		    strcmp(folded, "office") == 0, "a fold falls back to the late position");
		free(folded);
		check(testdir_exists(in(base, "conf.d/zz-profile-office.conf")),
		    "  late, because early would have lost to 50-middle");
		check(!testdir_exists(in(base, "conf.d/05-profile-office.conf")),
		    "  and the early position was undone");
		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)),
		    "  and the machine still loads");
		document = compiled(&sources);
		check(device_mtu(document, "eth0") == 9000, "  unchanged either way");
		ncfg_document_free(document);
		ncfg_config_sources_free(&sources);
	}
	{
		/* The proof, exercised. A drop-in sorting after both positions takes
		 * precedence the profile used to have, so the fold would change what
		 * the machine runs -- and is refused with nothing written. */
		const file_t files[] = {
			{ "netcfgd.conf", "device eth0 { mtu = 1500 }\n" },
			{ "conf.d/90-profile.conf", "global { profile = \"office\" }\n" },
			{ "conf.d/zzz-late.conf", "override device eth0 { mtu = 1280 }\n" },
			{ "profile/office/10-office.conf",
			    "override device eth0 { mtu = 9000 }\n" }
		};
		const char *base = tree(root, "pa3", files, 4u);
		char       *folded = NULL;
		size_t      i;
		int         left = 0;

		check(!ncfg_profile_adopt(base, base, &folded, err, sizeof(err)) &&
		    strstr(err, "would change what") != NULL,
		    "a fold that would change the configuration is refused");
		check(folded == NULL, "  and names nothing as folded");
		check(testdir_exists(in(base, "conf.d/90-profile.conf")),
		    "  the selection is back where it was");
		for (i = 0; i < 2u; i++) {
			const char *prefix = i == 0u ? "conf.d/05-profile-office.conf"
			    : "conf.d/zz-profile-office.conf";

			if (testdir_exists(in(base, prefix))) {
				left = 1;
			}
		}
		check(!left, "  and neither position was left behind");
	}
}

static void saving(const char *root)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *running;
	char                  err[NCFG_ERROR_MAX];

	{
		const file_t files[] = {
			{ "netcfgd.conf",
			    "device eth0 { mtu = 1500 }\ninterface eth0 { config = \"dhcp\" }\n" },
			{ "conf.d/10-mine.conf", "override device eth0 { mtu = 9000 }\n" }
		};
		const char *base = tree(root, "save", files, 2u);
		char       *path = NULL;

		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)),
		    "a machine on no profile loads");
		running = compiled(&sources);
		ncfg_config_sources_free(&sources);
		check(running != NULL, "  and compiles");

		check(ncfg_profile_save(base, base, "office", 0, running, "pass --replace", &path,
		    NULL, err, sizeof(err)), "what the machine is running is saved as a profile");
		check(path && testdir_exists(path), "  the snapshot is on disk");
		free(path);
		check(testdir_exists(in(base, "conf.d/" NCFG_PROFILE_DROP_IN ".conf")),
		    "  and the machine is on it, because saying what it means and not "
		    "selecting it would surprise");

		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)),
		    "  the machine still loads");
		{
			ncfg_document_t *after = compiled(&sources);

			check(after && after->globals.profile &&
			    strcmp(after->globals.profile, "office") == 0 &&
			    device_mtu(after, "eth0") == 9000,
			    "  and runs exactly what it was, under the new label");
			ncfg_document_free(after);
		}
		ncfg_config_sources_free(&sources);

		/* An existing profile is somebody's work, and guessing here is the
		 * failure this exists to prevent. The remedy is the caller's words:
		 * `ncfg` has a flag to name and a gui has a button. */
		check(!ncfg_profile_save(base, base, "office", 0, running, "pass --replace", NULL,
		    NULL, err, sizeof(err)) && strstr(err, "pass --replace") != NULL,
		    "an existing profile is refused, in the caller's own words");
		check(ncfg_profile_save(base, base, "office", 1, running, "pass --replace", NULL,
		    NULL, err, sizeof(err)), "and replaced when that is asked for");

		make_dirs(in(base, "profile/by-hand"));
		check(!ncfg_profile_save(base, base, "by-hand", 1, running, "pass --replace", NULL,
		    NULL, err, sizeof(err)) && strstr(err, "written by hand") != NULL,
		    "a profile netcfgd did not write is not saved over even with replace");
		ncfg_document_free(running);
	}
	{
		/*
		 * A save that cannot be rendered puts everything back, and the
		 * selection is the part that was missed: the cleanup removed the
		 * snapshot, the directory and the fold, and left the drop-in where it
		 * was written -- so a save that reported "nothing was kept" had
		 * changed which profile the machine selects.
		 *
		 * A hook is what cannot be rendered, which `render.h` names first
		 * among its refusals.
		 */
		const file_t files[] = {
			{ "netcfgd.conf", A_HOOKED_BASE },
			{ "conf.d/90-profile.conf", "global { profile = \"first\" }\n" },
			{ "profile/first/00-saved.conf", "device eth0 { mtu = 1500 }\n" }
		};
		const char *base = tree(root, "save-refused", files, 3u);
		char       *text;

		check(ncfg_config_load_with_profile(base, base, &sources, err, sizeof(err)),
		    "a machine with a hook and a profile loads");
		running = compiled(&sources);
		ncfg_config_sources_free(&sources);
		check(running != NULL, "  and compiles, with the unwritten sink");

		check(!ncfg_profile_save(base, base, "second", 0, running, "pass --replace", NULL,
		    NULL, err, sizeof(err)),
		    "a configuration the renderer cannot write out is not saved");
		check(strstr(err, "cannot be written out yet") != NULL &&
		    strstr(err, "hooks") != NULL, "  and it says what is in the way");
		text = testdir_read(in(base, "conf.d/90-profile.conf"), NULL);
		check(text && strstr(text, "first") != NULL,
		    "  and the selection it changed on the way is put back");
		free(text);
		check(!testdir_exists(in(base, "profile/second")),
		    "  with nothing left of the profile it was making");
		ncfg_document_free(running);
	}
}

/* ------------------------------------------------------------------------ *
 * The defaults, read rather than written to
 * ------------------------------------------------------------------------ */

/*
 * The positions table, filled in by the compile a command actually runs.
 *
 * **The loader is where this had to be checked, not the compiler.**
 * `explain_test.c` already drives `ncfg_compile_with_provenance` on a string
 * and proves the table locates what it should; what had no caller was the path
 * from a *directory* to that call, so `ncfg explain` compiled through
 * `ncfg_config_compile` and handed `ncfg_explain` nothing. Every line of its
 * output then declined to name a file, and the notice at the top said the
 * compiler recorded no positions -- which had stopped being true several waves
 * earlier (project.md 10.208).
 *
 * Two files, because the name in an entry is the thing a single-file fixture
 * cannot get wrong: a table that recorded the position but lost which file it
 * came from would still locate everything, and would send a reader to the
 * wrong one.
 */
static void positions(const char *root)
{
	const file_t          files[] = {
		{ "netcfgd.conf", "device eth0 {\n\tmtu = 1400\n}\n" },
		{ "conf.d/10-lan.conf", "interface eth0 {\n\tconfig = \"10.0.0.1/24\"\n}\n" }
	};
	const char                    *dir = tree(root, "positions", files, 2u);
	ncfg_config_sources_t          sources = { 0 };
	ncfg_provenance_t              provenance;
	ncfg_document_t               *document;
	const ncfg_provenance_entry_t *interface;
	const ncfg_provenance_entry_t *mtu;
	char                           err[NCFG_ERROR_MAX];
	char                           where[256];

	memset(&provenance, 0, sizeof(provenance));
	err[0] = '\0';
	if (!ncfg_config_load(dir, &sources, err, sizeof(err))) {
		check(0, "the positions fixture loads");
		ncfg_config_sources_free(&sources);
		return;
	}
	document = ncfg_config_compile_with_provenance(&sources, ncfg_hook_sink_unwritten(),
	    &provenance, NULL, err, sizeof(err));
	check(document != NULL, "a configuration directory compiles with its positions beside it");
	check(provenance.count > 0u, "  and the table is not empty, which it was for every "
	    "caller that went through the loader");
	interface = ncfg_provenance_lookup(&provenance, "interfaces[eth0]");
	mtu = ncfg_provenance_lookup(&provenance, "interfaces[eth0].mtu");
	where[0] = '\0';
	if (interface) {
		ncfg_provenance_location(interface, where, sizeof(where));
	}
	check(interface && strstr(where, "10-lan.conf:1:1") != NULL,
	    "  the interface block is located in the drop-in that declares it");
	where[0] = '\0';
	if (mtu) {
		ncfg_provenance_location(mtu, where, sizeof(where));
	}
	/* The MTU is written in the *device* block of the other file, and the
	 * document carries it on the interface -- so a table that guessed the
	 * position from the document would name the wrong file. */
	check(mtu && strstr(where, "netcfgd.conf:2:2") != NULL,
	    "  and the mtu in the file that writes it, which is not the one it ends up in");

	ncfg_provenance_free(&provenance);
	ncfg_document_free(document);
	ncfg_config_sources_free(&sources);
}

static void the_defaults(void)
{
	char out[256];

	check(strcmp(NCFG_CONFIG_DIR_DEFAULT, "/etc/netcfgd") == 0 &&
	    strcmp(NCFG_FACTORY_DIR_DEFAULT, "/usr/share/netcfgd") == 0,
	    "the defaults are the machine's real directories, checked by reading them");
	check(strcmp(ncfg_config_resolve_dir("/somewhere", out, sizeof(out)), "/somewhere") == 0,
	    "an explicit directory wins");
	(void)setenv(NCFG_CONFIG_DIR_ENV, "/from-the-environment", 1);
	check(strcmp(ncfg_config_resolve_dir(NULL, out, sizeof(out)), "/from-the-environment") == 0,
	    "and the environment beats the default, which is how the fixtures run");
	(void)unsetenv(NCFG_CONFIG_DIR_ENV);
	check(strcmp(ncfg_config_resolve_dir(NULL, out, sizeof(out)), NCFG_CONFIG_DIR_DEFAULT) == 0,
	    "with nothing said, the default");
	check(strcmp(ncfg_config_resolve_factory_dir(NULL, out, sizeof(out)),
	    NCFG_FACTORY_DIR_DEFAULT) == 0, "and the same for the factory layer");
}

int main(void)
{
	const char *root = testdir_make("config");

	the_states_of_a_path(root);
	includes(root);
	layering(root);
	profiles(root);
	a_machine_that_has_a_hook(root);
	drop_ins(root);
	writing(root);
	the_fold(root);
	saving(root);
	positions(root);
	the_defaults();

	remove_tree(root);
	if (failures) {
		printf("config: %d checks failed\n", failures);
		return 1;
	}
	printf("config: every check passed\n");
	return 0;
}
