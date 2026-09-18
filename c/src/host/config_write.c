/*
 * config_write.c -- putting a drop-in on disk, and proving it still compiles.
 *
 * 0127: netcfgd is the only writer of `/etc/netcfgd`, so this is where
 * configuration a client sent ends up. Two things here are a decision rather
 * than plumbing.
 *
 * THE VERIFICATION COMPILE, AND WHICH SINK IT USES
 *   A drop-in that parses on its own can still stop the *configuration*
 *   compiling, because redefining a block another file already defines is an
 *   error by design -- so the write is followed by a compile and undone when
 *   that fails. That compile is a compile to **read**: the document is looked
 *   at and thrown away, and there is no reason to put a hook script on disk
 *   for it. It goes through `ncfg_config_compile_for_reading`, which carries
 *   `ncfg_hook_sink_unwritten()`.
 *
 *   **The refusing sink was here.** Its whole behaviour is to refuse a hook,
 *   so on any machine with one hook anywhere in its configuration this check
 *   failed for every write -- every editor in the window and every
 *   `ncfg config put` -- and reported it as *"that would stop the
 *   configuration compiling"*, about a configuration the same daemon loads on
 *   every reload. It compiles. The message blamed the file being written
 *   rather than the check doing the writing.
 *
 * THE FALLBACK FOR A DIRECTORY THAT WILL NOT TAKE A TEMPORARY
 *   Decision 0161, and the half the rest of the port left for this module. A
 *   sandbox can grant a file without granting the directory it sits in, and
 *   staging beside the target is creating a directory entry.
 */
#include "config_internal.h"
#include "host_internal.h"

#include "ncfg/base.h"
#include "ncfg/secrets.h"
#include "ncfg/state.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------------------------------------------------------ *
 * Names
 * ------------------------------------------------------------------------ */

/*
 * Whether a client-supplied string can become a filename here.
 *
 * **The rule is `ncfg_secret_name_usable`'s and is asked rather than
 * restated.** It is the same question -- a name that is a filename and a value
 * in the language at once -- and the Rust shares it for the reason its comment
 * gives: a validation a caller may skip is a validation a caller will skip,
 * and with the socket request of 0117 the caller is a remote client. An id of
 * `../../../etc/cron.d/x` would be a file written wherever the daemon can
 * write.
 *
 * What is not shared is the noun. That function says "as a secret name",
 * because every caller it was written for meant one; a person who has just
 * asked to write a drop-in should not be told about secrets. The reason is
 * taken off the end -- **the last colon, which is always the separator,
 * because no reason the rule gives contains one** -- and put back under the
 * right noun. Copying the rule to reword it is the alternative, and two copies
 * of one rule is how the two come to disagree about what a name may be.
 */
int ncfg_config_name_usable(const char *name, const char *what, char *err, size_t err_size)
{
	char        said[NCFG_ERROR_MAX];
	const char *why;

	if (ncfg_secret_name_usable(name, said, sizeof(said))) {
		return 1;
	}
	why = strrchr(said, ':');
	while (why && (why[1] == ' ' || why[1] == '\t')) {
		why++;
	}
	ncfg_error_set(err, err_size, "`%s` cannot be used as %s: %s", name ? name : "", what,
	    why ? why + 1 : said);
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Writing
 * ------------------------------------------------------------------------ */

/* The directory a path sits in, allocated. A path with no separator sits in
 * the working directory, and one directly under the root sits in it. */
static char *directory_of(const char *path, char *err, size_t err_size)
{
	const char *slash = strrchr(path, '/');
	char       *directory;

	if (!slash) {
		directory = strdup(".");
	} else if (slash == path) {
		directory = strdup("/");
	} else {
		directory = strndup(path, (size_t)(slash - path));
	}
	if (!directory) {
		ncfg_error_set(err, err_size, "out of memory building a path");
	}
	return directory;
}

/*
 * Whether this directory refuses a new entry, and with which errno.
 *
 * **Asked by making one and taking it away again**, because the question is
 * about the directory and every cheaper answer is a guess: `access(W_OK)` is
 * the same syscall family with worse resolution, and a mode test is exactly
 * the trap 0161 records -- root has `CAP_DAC_OVERRIDE` and walks straight
 * through a mode, but not through a read-only mount, so a `chmod`'d fixture
 * reproduces the shape and not the mechanism.
 *
 * Only ever reached after a write has already failed, so it costs nothing on
 * the path everything takes. `O_EXCL`, so it cannot land on somebody's file.
 *
 * Returns the errno a refusal gives, or 0 for a directory that would have
 * taken the entry -- which means the write failed for some other reason, a
 * full disk being the one that matters. Falling back there would truncate a
 * config file and then fail to refill it.
 */
static int directory_refuses(const char *directory)
{
	static unsigned long sequence;
	char                 probe[PATH_MAX];
	int                  fd;
	int                  refused;

	(void)snprintf(probe, sizeof(probe), "%s/.ncfg-probe.%ld.%lu", directory, (long)getpid(),
	    sequence++);
	fd = open(probe, O_WRONLY | O_CREAT | O_EXCL, (mode_t)0600);
	if (fd >= 0) {
		(void)close(fd);
		(void)unlink(probe);
		return 0;
	}
	refused = errno;
	if (refused == EACCES || refused == EPERM || refused == EROFS) {
		return refused;
	}
	return 0;
}

int ncfg_config_write_in_place(const char *path, const void *bytes, size_t length,
    unsigned int mode, int refusal, char *err, size_t err_size)
{
	struct stat about;
	char       *directory;
	const char *why = refusal ? strerror(refusal) : "the directory refused a temporary file";
	const char *at = bytes;
	size_t      written = 0;
	int         fd;
	int         failure;

	/*
	 * **It will not follow a symlink**, for 0161's reason: writing through
	 * one edits whatever owns the target, which nothing here has been asked
	 * to do. `/etc/resolv.conf` is a symlink into another resolver's runtime
	 * state on a great many machines, and this would edit that resolver's
	 * own file, silently, and only on the path where the sandbox makes the
	 * fallback engage.
	 */
	if (lstat(path, &about) == 0 && S_ISLNK(about.st_mode)) {
		ncfg_error_set(err, err_size,
		    "%s is a symlink and netcfgd cannot stage a replacement beside it (%s); "
		    "writing through the link would edit whatever owns the target",
		    path, why);
		return 0;
	}

	directory = directory_of(path, err, err_size);
	if (!directory) {
		return 0;
	}
	/* **Existing files only**, and `O_NOFOLLOW` as well as the check above:
	 * the check says what happened in a sentence and the flag is what makes
	 * the refusal hold against a link that arrives between the two. */
	fd = open(path, O_WRONLY | O_TRUNC | O_NOFOLLOW);
	if (fd < 0) {
		/*
		 * Two sentences, because there are two situations and they want
		 * different things done about them. A file that is not there cannot
		 * be written in place by design, so its `ENOENT` says nothing at all
		 * and the directory is the whole story.
		 *
		 * **The staging refusal is named in both**, and without it the
		 * fallback speaks over the real cause: a drop-in refused by a
		 * read-only `/etc` was reported as "No such file or directory" about
		 * a file the operator has never seen, for a write they had just
		 * asked for.
		 */
		char second[NCFG_ERROR_MAX];

		failure = errno;
		if (lstat(path, &about) == 0) {
			(void)snprintf(second, sizeof(second),
			    "and writing it in place failed too: %s", strerror(failure));
		} else {
			(void)snprintf(second, sizeof(second),
			    "and it is not there to be written in place");
		}
		ncfg_error_set(err, err_size, "%s would not take a temporary file (%s), %s%s",
		    directory, why, second,
		    /* **Named for a read-only mount alone, and as a mechanism rather
		     * than a verdict.** That is a sandbox on a systemd machine and a
		     * read-only root on an embedded one, and the sentence has to be
		     * true of both -- so it states what was measured, then says
		     * where to look. This project has met the systemd half twice
		     * (0161, 0164) and each time the message named a path and left
		     * the reader to guess at the mount. */
		    refusal == EROFS
		        ? ". The directory is mounted read-only for this process; under "
		          "systemd that is `ProtectSystem=`, and the unit has to name the "
		          "path in `ReadWritePaths=`"
		        : "");
		free(directory);
		return 0;
	}
	free(directory);

	while (written < length) {
		ssize_t put = write(fd, at + written, length - written);

		if (put < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}
		written += (size_t)put;
	}
	if (written < length || fsync(fd) != 0) {
		failure = errno;
		(void)close(fd);
		ncfg_error_set(err, err_size, "could not write %s in place (%s): %s", path, why,
		    strerror(failure));
		return 0;
	}
	if (close(fd) != 0) {
		ncfg_error_set(err, err_size, "could not write %s in place: %s", path,
		    strerror(errno));
		return 0;
	}
	/* **The mode is set explicitly**, because an open that does not create
	 * applies none -- and a secret written back at 0600 must not inherit
	 * whatever the file already carried. */
	if (chmod(path, (mode_t)mode) != 0) {
		ncfg_error_set(err, err_size, "could not set the mode on %s: %s", path,
		    strerror(errno));
		return 0;
	}
	return 1;
}

int ncfg_config_write_atomically(const char *path, const void *bytes, size_t length,
    unsigned int mode, int *denied, char *err, size_t err_size)
{
	char  staging[NCFG_ERROR_MAX];
	char *directory;
	int   refusal;

	if (denied) {
		*denied = 0;
	}
	if (ncfg_write_atomically(path, bytes, length, mode, staging, sizeof(staging))) {
		return 1;
	}
	directory = directory_of(path, err, err_size);
	if (!directory) {
		return 0;
	}
	refusal = directory_refuses(directory);
	free(directory);
	if (!refusal) {
		/* Not a refusal, so not 0161's case. A full disk lands here and must:
		 * writing in place would truncate the file and then fail to refill
		 * it, and an empty config is worse than an unchanged one. */
		ncfg_error_set(err, err_size, "%s", staging);
		return 0;
	}
	if (denied) {
		*denied = 1;
	}
	return ncfg_config_write_in_place(path, bytes, length, mode, refusal, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * Drop-ins
 * ------------------------------------------------------------------------ */

/*
 * Put back what was there, or take away what was not.
 *
 * Its own function because every failure path below needs it and each one
 * getting it slightly wrong is how a rejected write leaves a half-applied
 * change -- the case being guarded against in the first place.
 */
static void restore(const char *path, const char *previous, size_t length)
{
	char quiet[NCFG_ERROR_MAX];

	if (previous) {
		(void)ncfg_config_write_atomically(path, previous, length, 0644u, NULL, quiet,
		    sizeof(quiet));
		return;
	}
	(void)unlink(path);
}

/* The file as it is, or NULL for one that is not there. Anything else is a
 * refusal: a drop-in that exists and cannot be read cannot be put back, and
 * finding that out after the write would be finding it out too late. */
static int read_previous(const char *path, char **out, size_t *length_out, char *err,
    size_t err_size)
{
	*out = ncfg_host_read_file(path, length_out, NCFG_CONFIG_FILE_MAX);
	if (*out) {
		return 1;
	}
	if (errno == ENOENT) {
		return 1;
	}
	ncfg_error_set(err, err_size, "could not read %s to put it back: %s", path,
	    strerror(errno));
	return 0;
}

int ncfg_config_install_drop_in(const char *config_dir, const char *factory_dir, const char *name,
    const char *text, int replace, char **path_out, int *denied, char *err, size_t err_size)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *document;
	struct stat           about;
	char                 *path;
	char                 *conf_d;
	char                 *previous = NULL;
	size_t                previous_length = 0;
	char                  said[NCFG_ERROR_MAX];

	if (path_out) {
		*path_out = NULL;
	}
	if (denied) {
		*denied = 0;
	}
	if (!ncfg_config_name_usable(name, "a name here", err, err_size)) {
		return 0;
	}
	path = ncfg_config_drop_in_path(config_dir, name, err, err_size);
	if (!path) {
		return 0;
	}
	if (lstat(path, &about) == 0 && !replace) {
		ncfg_error_set(err, err_size,
		    "%s already exists. Ask to replace it if that is what you mean -- quietly "
		    "overwriting a file somebody wrote by hand is the thing this refuses to do",
		    path);
		free(path);
		return 0;
	}
	if (!read_previous(path, &previous, &previous_length, err, err_size)) {
		free(path);
		return 0;
	}

	conf_d = ncfg_host_join(config_dir, "conf.d", err, err_size);
	if (!conf_d || !ncfg_host_make_directory(conf_d, (mode_t)0755, err, err_size)) {
		free(conf_d);
		free(previous);
		free(path);
		return 0;
	}
	free(conf_d);
	if (!ncfg_config_write_atomically(path, text, strlen(text), 0644u, denied, err,
	    err_size)) {
		free(previous);
		free(path);
		return 0;
	}

	/*
	 * **With the profile, not without it.** This verified through the
	 * unprofiled loader once, so `ncfg profile set` wrote a selection,
	 * compiled a configuration that excluded the very profile it had just
	 * chosen, and reported success -- a profile whose drop-in does not parse
	 * was accepted, and every command after it failed on the config until
	 * somebody thought to run `profile unset`.
	 */
	if (!ncfg_config_load_with_profile(factory_dir, config_dir, &sources, said,
	    sizeof(said))) {
		restore(path, previous, previous_length);
		ncfg_error_set(err, err_size, "could not read %s: %s", config_dir, said);
		ncfg_config_sources_free(&sources);
		free(previous);
		free(path);
		return 0;
	}
	/* The verification compile, and it is a compile to read: see the header
	 * comment for what the refusing sink did here. */
	document = ncfg_config_compile_for_reading(&sources, said, sizeof(said));
	ncfg_config_sources_free(&sources);
	if (!document) {
		restore(path, previous, previous_length);
		ncfg_error_set(err, err_size,
		    "that would stop the configuration compiling, so it was not kept: %s", said);
		free(previous);
		free(path);
		return 0;
	}
	ncfg_document_free(document);
	free(previous);
	if (path_out) {
		*path_out = path;
	} else {
		free(path);
	}
	return 1;
}

int ncfg_config_remove_drop_in(const char *config_dir, const char *factory_dir, const char *name,
    int *removed, int *denied, char *err, size_t err_size)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *document;
	char                 *path;
	char                 *previous = NULL;
	size_t                previous_length = 0;
	char                  said[NCFG_ERROR_MAX];

	if (removed) {
		*removed = 0;
	}
	if (denied) {
		*denied = 0;
	}
	if (!ncfg_config_name_usable(name, "a name here", err, err_size)) {
		return 0;
	}
	path = ncfg_config_drop_in_path(config_dir, name, err, err_size);
	if (!path) {
		return 0;
	}
	previous = ncfg_host_read_file(path, &previous_length, NCFG_CONFIG_FILE_MAX);
	if (!previous) {
		/* **An absent file is success**: the state asked for is the state
		 * that holds. `removed` is how the caller can tell the two apart,
		 * and it had no way to -- so `ncfg config rm` printed "is not in" on
		 * the success path and told an operator their removal had not
		 * happened. It had. */
		free(path);
		return 1;
	}
	/* Removing an entry needs the directory exactly as creating one does, so
	 * this is classified the same way: a read-only `/etc` refuses a delete
	 * too. */
	if (unlink(path) != 0) {
		int failure = errno;

		if (denied && (failure == EACCES || failure == EPERM || failure == EROFS)) {
			*denied = 1;
		}
		ncfg_error_set(err, err_size, "could not remove %s: %s", path, strerror(failure));
		free(previous);
		free(path);
		return 0;
	}

	/*
	 * **A divergence: verified with the profile, as the install is.** The
	 * Rust checks this one through the unprofiled loader, which is the very
	 * thing its own comment on `install_drop_in` says is wrong -- a base file
	 * a profile writes `override interface eth0` against can be removed, and
	 * the configuration the machine actually loads then does not compile,
	 * with this function having reported success. The two are mirrors and the
	 * argument does not change direction.
	 */
	if (!ncfg_config_load_with_profile(factory_dir, config_dir, &sources, said,
	    sizeof(said))) {
		restore(path, previous, previous_length);
		ncfg_error_set(err, err_size, "could not read %s: %s", config_dir, said);
		ncfg_config_sources_free(&sources);
		free(previous);
		free(path);
		return 0;
	}
	document = ncfg_config_compile_for_reading(&sources, said, sizeof(said));
	ncfg_config_sources_free(&sources);
	if (!document) {
		restore(path, previous, previous_length);
		ncfg_error_set(err, err_size,
		    "removing that would stop the configuration compiling, so it was put back: "
		    "%s", said);
		free(previous);
		free(path);
		return 0;
	}
	ncfg_document_free(document);
	free(previous);
	free(path);
	if (removed) {
		*removed = 1;
	}
	return 1;
}
