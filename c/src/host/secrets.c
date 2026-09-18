/*
 * secrets.c -- the store, the resolver and the four providers.
 *
 * WHAT MAKES THE ONE RULE HOLD
 *   `secrets.h` states it: no secret material ever reaches a diagnostic, a log
 *   line or a rendered document. Three things enforce it and none of them is
 *   care at the call site.
 *
 *     * `ncfg_secret_t` is **opaque** and has no accessor but `expose`, which
 *       is named so that every use of it is one grep away.
 *     * Every message in this file is built from the reference, the provider,
 *       the path and the operating system's own words. Nothing that came out
 *       of the store, and nothing a helper printed, is ever quoted -- a
 *       failing secret helper prints diagnostics that may contain the very
 *       thing it failed to deliver, so its standard error goes to `/dev/null`
 *       rather than into netcfgd's log.
 *     * `secrets_test.c` drives every failure here with a value nothing may
 *       repeat and reads every buffer back for it.
 */
#include "ncfg/secrets.h"

#include "host_internal.h"
#include "ncfg/base.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * As much as any credential this store holds.
 *
 * A passphrase is tens of bytes and a certificate chain is a few thousand;
 * this is generous by three orders of magnitude and still bounded, because the
 * `exec` provider runs a program somebody else wrote and a daemon that will
 * allocate whatever a helper prints is a daemon that helper can exhaust.
 * **The Rust has no ceiling here** -- `Command::output` reads to end of file --
 * and that is the divergence rather than an accident.
 */
#define SECRET_MAX (1024u * 1024u)

/* A command line is a name from a configuration file; this is the most words
 * one may become. */
#define EXEC_ARG_MAX 32

struct ncfg_secret {
	size_t length;
	char   text[];
};

/*
 * Clear before releasing.
 *
 * Through a `volatile` pointer so that the compiler may not decide a write to
 * memory about to be freed is dead. It is not in the Rust and is not a claim
 * about it: a `String`'s bytes are freed and left where they lay. Here the
 * buffer is ours until the last instant.
 */
static void wipe(void *bytes, size_t length)
{
	volatile unsigned char *at = bytes;

	while (length--) {
		*at++ = 0;
	}
}

static ncfg_secret_t *secret_new(const char *bytes, size_t length)
{
	struct ncfg_secret *secret = malloc(sizeof(*secret) + length + 1u);

	if (!secret) {
		return NULL;
	}
	secret->length = length;
	if (length) {
		memcpy(secret->text, bytes, length);
	}
	secret->text[length] = '\0';
	return secret;
}

const char *ncfg_secret_expose(const ncfg_secret_t *secret)
{
	return secret ? secret->text : NULL;
}

size_t ncfg_secret_length(const ncfg_secret_t *secret)
{
	return secret ? secret->length : 0u;
}

int ncfg_secret_is_empty(const ncfg_secret_t *secret)
{
	return !secret || secret->length == 0u;
}

const char *ncfg_secret_redacted(void)
{
	return "<redacted>";
}

ncfg_secret_t *ncfg_secret_first_line(const ncfg_secret_t *secret)
{
	const char *newline;

	if (!secret) {
		return NULL;
	}
	newline = memchr(secret->text, '\n', secret->length);
	return secret_new(secret->text, newline ? (size_t)(newline - secret->text) : secret->length);
}

void ncfg_secret_free(ncfg_secret_t *secret)
{
	if (!secret) {
		return;
	}
	wipe(secret->text, secret->length);
	secret->length = 0;
	free(secret);
}

static void fail(ncfg_secret_error_t *why, ncfg_secret_error_t kind)
{
	if (why) {
		*why = kind;
	}
}

/* One trailing newline is what an editor or `echo` leaves behind, and a
 * passphrase that silently includes it fails to associate with no indication
 * why. Anything further is the operator's. */
static ncfg_secret_t *without_one_newline(const char *bytes, size_t length)
{
	if (length && bytes[length - 1u] == '\n') {
		length--;
	}
	return secret_new(bytes, length);
}

/* ------------------------------------------------------------ the providers */

static ncfg_secret_t *read_file_secret(const ncfg_secret_resolver_t *resolver, const char *name,
    ncfg_secret_error_t *why, char *err, size_t err_size)
{
	const char *dir = (resolver && resolver->secrets_dir) ? resolver->secrets_dir
	    : NCFG_SECRETS_DIR_DEFAULT;
	char *path;
	struct stat about;
	char *body;
	size_t length = 0;
	ncfg_secret_t *secret;

	/* A name that escaped the directory would let a configuration file read
	 * any file on the machine as root. Names are a flat namespace on purpose. */
	if (!name || !name[0] || strchr(name, '/') || strstr(name, "..")) {
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size,
		    "secret `%s`: a file secret's name may not contain a path separator",
		    name ? name : "");
		return NULL;
	}
	path = ncfg_host_join(dir, name, err, err_size);
	if (!path) {
		fail(why, NCFG_SECRET_FAILED);
		return NULL;
	}
	if (stat(path, &about) != 0) {
		if (errno == ENOENT) {
			/* The command is named because this is exactly the moment
			 * somebody needs it: the configuration refers to a credential and
			 * the machine does not have it (0075). */
			fail(why, NCFG_SECRET_NOT_FOUND);
			ncfg_error_set(err, err_size,
			    "secret `%s` was not found in %s -- `ncfg secret set %s` stores one",
			    name, dir, name);
		} else {
			fail(why, NCFG_SECRET_FAILED);
			ncfg_error_set(err, err_size, "secret `%s`: %s: %s", name, path,
			    strerror(errno));
		}
		free(path);
		return NULL;
	}
	/* Design section 3.3 specifies 0600 for the file provider. Enforcing it
	 * rather than documenting it is the difference between a rule and a
	 * suggestion: a secret in a world-readable file is already disclosed, and
	 * reading it anyway tells the operator everything is fine. */
	if ((about.st_mode & (mode_t)0077) != 0) {
		fail(why, NCFG_SECRET_EXPOSED);
		ncfg_error_set(err, err_size,
		    "secret `%s` is readable by others: %s has mode %04o. Refusing to use it -- "
		    "run `chmod 600 %s` once the value is no longer considered disclosed.",
		    name, path, (unsigned int)(about.st_mode & (mode_t)0777), path);
		free(path);
		return NULL;
	}
	body = ncfg_host_read_file(path, &length, SECRET_MAX);
	if (!body) {
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "secret `%s`: %s: %s", name, path, strerror(errno));
		free(path);
		return NULL;
	}
	free(path);
	secret = without_one_newline(body, length);
	wipe(body, length);
	free(body);
	if (!secret) {
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "secret `%s`: out of memory", name);
	}
	return secret;
}

/*
 * Run a command and take its standard output as the material.
 *
 * **No shell**, and that is the whole of why this is thirty lines rather than
 * one `popen`: a shell would make the secrets directory a place where a
 * configuration file becomes arbitrary code with word splitting and globbing
 * attached. The words are split here, on whitespace, and handed to `execvp`
 * as they stand.
 */
static ncfg_secret_t *run_command(const char *name, ncfg_secret_error_t *why, char *err,
    size_t err_size)
{
	char *line;
	char *argv[EXEC_ARG_MAX + 1u];
	size_t argc = 0;
	char *word;
	char *save = NULL;
	int fds[2];
	pid_t child;
	char *body = NULL;
	size_t length = 0;
	size_t capacity = 0;
	int status = 0;
	int too_big = 0;
	/* A read that failed or a buffer that could not grow. Kept apart from
	 * `too_big` so the message names what happened rather than the first
	 * plausible thing. */
	int capture_failed = 0;
	ncfg_secret_t *secret;

	if (!name || !name[0]) {
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "secret `%s`: an exec secret needs a command",
		    name ? name : "");
		return NULL;
	}
	line = strdup(name);
	if (!line) {
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "out of memory");
		return NULL;
	}
	for (word = strtok_r(line, " \t\n", &save); word; word = strtok_r(NULL, " \t\n", &save)) {
		if (argc == EXEC_ARG_MAX) {
			free(line);
			fail(why, NCFG_SECRET_FAILED);
			ncfg_error_set(err, err_size,
			    "secret `%s`: an exec secret's command is at most %u words", name,
			    (unsigned int)EXEC_ARG_MAX);
			return NULL;
		}
		argv[argc++] = word;
	}
	if (argc == 0) {
		free(line);
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "secret `%s`: an exec secret needs a command", name);
		return NULL;
	}
	argv[argc] = NULL;

	if (pipe(fds) != 0) {
		free(line);
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "secret `%s`: %s", name, strerror(errno));
		return NULL;
	}
	/* Nothing half-written may be inherited: a buffered line in this process'
	 * stdout would be flushed a second time by the child. */
	fflush(NULL);
	child = fork();
	if (child < 0) {
		(void)close(fds[0]);
		(void)close(fds[1]);
		free(line);
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "secret `%s`: %s", name, strerror(errno));
		return NULL;
	}
	if (child == 0) {
		int null = open("/dev/null", O_RDWR);

		(void)close(fds[0]);
		if (null >= 0) {
			/* Standard input is `/dev/null` so a helper waiting to be typed
			 * at fails rather than hanging the daemon, which is what
			 * `Command::output` does. Standard **error** goes there too, and
			 * that is a decision: a failing helper prints diagnostics that may
			 * contain the very thing it failed to deliver, and netcfgd's
			 * stderr is a log. */
			(void)dup2(null, STDIN_FILENO);
			(void)dup2(null, STDERR_FILENO);
			if (null > STDERR_FILENO) {
				(void)close(null);
			}
		}
		if (dup2(fds[1], STDOUT_FILENO) < 0) {
			_exit(127);
		}
		if (fds[1] > STDERR_FILENO) {
			(void)close(fds[1]);
		}
		(void)execvp(argv[0], argv);
		_exit(127);
	}
	(void)close(fds[1]);
	for (;;) {
		ssize_t got;

		if (length + 1u >= capacity) {
			size_t want = capacity ? capacity * 2u : 4096u;
			char *grown;

			if (want > SECRET_MAX + 2u) {
				want = SECRET_MAX + 2u;
			}
			if (length + 1u >= want) {
				too_big = 1;
				break;
			}
			grown = realloc(body, want);
			if (!grown) {
				capture_failed = 1;
				break;
			}
			body = grown;
			capacity = want;
		}
		got = read(fds[0], body + length, capacity - length - 1u);
		if (got < 0) {
			if (errno == EINTR) {
				continue;
			}
			capture_failed = 1;
			break;
		}
		if (got == 0) {
			break;
		}
		length += (size_t)got;
		if (length > SECRET_MAX) {
			too_big = 1;
			break;
		}
	}
	(void)close(fds[0]);
	if (too_big || capture_failed) {
		/* The reader has stopped, so the helper would block on its next write
		 * for ever. Ending it is what keeps a bad helper from being a wedged
		 * daemon; the wait below then takes the corpse rather than leaving a
		 * zombie. */
		(void)kill(child, SIGKILL);
	}
	while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
		continue;
	}
	free(line);

	if (too_big || capture_failed) {
		if (body) {
			wipe(body, length);
			free(body);
		}
		fail(why, NCFG_SECRET_FAILED);
		if (too_big) {
			ncfg_error_set(err, err_size,
			    "secret `%s`: the command produced more than %u bytes, which is not a "
			    "credential", name, (unsigned int)SECRET_MAX);
		} else {
			ncfg_error_set(err, err_size,
			    "secret `%s`: the command's output could not be read", name);
		}
		return NULL;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		/* The command's own output is not quoted, for the reason at the top of
		 * this file. What is said is the status, which is a fact about the
		 * process rather than about the credential. */
		if (body) {
			wipe(body, length);
			free(body);
		}
		fail(why, NCFG_SECRET_FAILED);
		if (WIFSIGNALED(status)) {
			ncfg_error_set(err, err_size, "secret `%s`: the command was killed by signal %d",
			    name, WTERMSIG(status));
		} else {
			ncfg_error_set(err, err_size, "secret `%s`: the command exited with %d", name,
			    WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		}
		return NULL;
	}
	secret = without_one_newline(body ? body : "", length);
	if (body) {
		wipe(body, length);
		free(body);
	}
	if (!secret) {
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "secret `%s`: out of memory", name);
	}
	return secret;
}

/*
 * `pass show NAME`, from the standard password-store.
 *
 * A thin wrapper over the exec provider rather than a separate mechanism, and
 * the difference from writing `@secret:exec:pass show NAME` by hand is the
 * validation: `pass` takes a store path, and a name that looks like a flag or
 * carries a second word would become an argument to `pass` itself.
 * `pass --help` is harmless; the point is that a configuration file should not
 * be able to choose what `pass` is asked to do.
 */
static ncfg_secret_t *read_pass(const char *name, ncfg_secret_error_t *why, char *err,
    size_t err_size)
{
	char command[256];
	ncfg_secret_t *whole;
	ncfg_secret_t *first;

	if (!name || !name[0] || name[0] == '-' || strpbrk(name, " \t\n") ||
	    strlen(name) > sizeof(command) - 16u) {
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size,
		    "secret `%s`: a pass secret's name is one word naming an entry in the store",
		    name ? name : "");
		return NULL;
	}
	/* `show` prints the first line and nothing else, which is the convention
	 * password-store documents for exactly this. */
	(void)snprintf(command, sizeof(command), "pass show %s", name);
	whole = run_command(command, why, err, err_size);
	if (!whole) {
		return NULL;
	}
	first = ncfg_secret_first_line(whole);
	ncfg_secret_free(whole);
	if (!first) {
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "secret `%s`: out of memory", name);
	}
	return first;
}

ncfg_secret_t *ncfg_secret_resolve(const ncfg_secret_resolver_t *resolver,
    const ncfg_secret_ref_t *reference, ncfg_secret_error_t *why, char *err, size_t err_size)
{
	fail(why, NCFG_SECRET_OK);
	if (!reference || !reference->name) {
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "a secret was asked for with no reference");
		return NULL;
	}
	switch (reference->provider) {
	case NCFG_SECRET_PROVIDER_FILE:
		return read_file_secret(resolver, reference->name, why, err, err_size);
	case NCFG_SECRET_PROVIDER_EXEC:
		return run_command(reference->name, why, err, err_size);
	case NCFG_SECRET_PROVIDER_PASS:
		return read_pass(reference->name, why, err, err_size);
	case NCFG_SECRET_PROVIDER_KEYRING:
		fail(why, NCFG_SECRET_UNSUPPORTED);
		/*
		 * **No milestone named**, because it is not scheduled and naming one
		 * that passes without the feature arriving is how a diagnostic becomes
		 * a lie. The blocker is specific: the kernel keyring is reached through
		 * `request_key(2)` and `keyctl(2)`, which have no libc wrapper -- so it
		 * means either raw syscalls or shelling out to `keyctl`, which is a
		 * dependency on a tool rather than on the kernel. Neither has been
		 * chosen.
		 */
		ncfg_error_set(err, err_size,
		    "the `keyring` secret provider is not implemented in this build; there is no "
		    "release for it yet -- see the keyring note in secrets.c");
		return NULL;
	default:
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "%d is not a secret provider", reference->provider);
		return NULL;
	}
}

char *ncfg_secret_path_for(const ncfg_secret_resolver_t *resolver,
    const ncfg_cert_source_t *source, const char *role, ncfg_secret_error_t *why, char *err,
    size_t err_size)
{
	ncfg_secret_t *secret;
	char *path;
	char *leaf;
	size_t leaf_size;
	int fd;

	fail(why, NCFG_SECRET_OK);
	if (!source || !source->has) {
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "no certificate or key was given");
		return NULL;
	}
	if (source->kind == NCFG_CERT_SOURCE_PATH) {
		char *copy = source->path ? strdup(source->path) : NULL;

		if (!copy) {
			fail(why, NCFG_SECRET_FAILED);
			ncfg_error_set(err, err_size, "a certificate path was given as nothing");
		}
		return copy;
	}
	secret = ncfg_secret_resolve(resolver, &source->stored, why, err, err_size);
	if (!secret) {
		return NULL;
	}
	if (!resolver || !resolver->materialise_dir) {
		ncfg_secret_free(secret);
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size,
		    "secret `%s`: this resolver has nowhere to materialise a stored certificate, "
		    "so it cannot produce a path for one", source->stored.name);
		return NULL;
	}
	/* **The file is named after the credential, not after its role** -- see
	 * `secrets.h`, where the CA a machine was never configured to trust is. */
	leaf_size = strlen(source->stored.name) + 1u + strlen(role ? role : "pem") + 1u;
	leaf = malloc(leaf_size);
	if (!leaf) {
		ncfg_secret_free(secret);
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "out of memory");
		return NULL;
	}
	(void)snprintf(leaf, leaf_size, "%s.%s", source->stored.name, role ? role : "pem");
	if (!ncfg_host_make_directory(resolver->materialise_dir, (mode_t)0700, err, err_size)) {
		free(leaf);
		ncfg_secret_free(secret);
		fail(why, NCFG_SECRET_FAILED);
		return NULL;
	}
	path = ncfg_host_join(resolver->materialise_dir, leaf, err, err_size);
	free(leaf);
	if (!path) {
		ncfg_secret_free(secret);
		fail(why, NCFG_SECRET_FAILED);
		return NULL;
	}
	/* 0600 **on the open**, so there is no instant at which a private key
	 * exists and is readable, and `fchmod` for the file an earlier run left
	 * wider -- `open` applies its mode only when it creates the file. */
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, (mode_t)0600);
	if (fd < 0 || fchmod(fd, (mode_t)0600) != 0) {
		if (fd >= 0) {
			(void)close(fd);
		}
		fail(why, NCFG_SECRET_FAILED);
		ncfg_error_set(err, err_size, "secret `%s`: could not write %s: %s",
		    source->stored.name, path, strerror(errno));
		free(path);
		ncfg_secret_free(secret);
		return NULL;
	}
	{
		const char *bytes = ncfg_secret_expose(secret);
		size_t length = ncfg_secret_length(secret);
		size_t written = 0;
		int ok = 1;

		while (written < length) {
			ssize_t put = write(fd, bytes + written, length - written);

			if (put < 0) {
				if (errno == EINTR) {
					continue;
				}
				ok = 0;
				break;
			}
			written += (size_t)put;
		}
		/* Durable before it is handed to a supplicant: the path this returns
		 * is opened by another process, and a file whose bytes are still in
		 * the page cache when the machine loses power is a certificate that
		 * comes back empty. */
		if (ok && fsync(fd) != 0) {
			ok = 0;
		}
		if (close(fd) != 0) {
			ok = 0;
		}
		if (!ok) {
			fail(why, NCFG_SECRET_FAILED);
			ncfg_error_set(err, err_size, "secret `%s`: could not write %s: %s",
			    source->stored.name, path, strerror(errno));
			free(path);
			ncfg_secret_free(secret);
			return NULL;
		}
	}
	ncfg_secret_free(secret);
	return path;
}

/* ---------------------------------------------------------------- the store */

int ncfg_secret_name_usable(const char *name, char *err, size_t err_size)
{
	const char *why = NULL;
	size_t length = 0;
	size_t i;

	if (!name || !name[0]) {
		why = "it is empty";
	} else if ((length = strlen(name)) > 64u) {
		why = "it is longer than 64 bytes";
	} else if (strchr(name, '"') || strchr(name, '\\')) {
		why = "it contains a quote or a backslash";
	} else if (strchr(name, '/')) {
		why = "it contains a path separator, and it names a file";
	} else if (strstr(name, "..") || name[0] == '.') {
		why = "it would name a hidden file or one outside the directory";
	} else {
		for (i = 0; i < length; i++) {
			unsigned char one = (unsigned char)name[i];

			/* C0 and delete, and the C1 block as UTF-8 spells it -- which is
			 * what Rust's `char::is_control` covers and a byte test alone
			 * would not. */
			if (one < 0x20u || one == 0x7fu ||
			    (one == 0xc2u && i + 1u < length &&
			    (unsigned char)name[i + 1u] >= 0x80u &&
			    (unsigned char)name[i + 1u] <= 0x9fu)) {
				why = "it contains a control character";
				break;
			}
		}
	}
	if (!why) {
		return 1;
	}
	/* The whole sentence rather than the Rust's fragment: there, every caller
	 * wrapped the fragment in the same words, and a fragment that reached a
	 * message on its own would read as a sentence with no subject. */
	ncfg_error_set(err, err_size, "`%s` cannot be used as a secret name: %s",
	    name ? name : "", why);
	return 0;
}

int ncfg_secret_store_put(const char *config_dir, const char *name, const char *value,
    int replace, char **path_out, char *err, size_t err_size)
{
	char *dir;
	char *path;
	struct stat about;

	if (path_out) {
		*path_out = NULL;
	}
	if (!ncfg_secret_name_usable(name, err, err_size)) {
		return 0;
	}
	if (!config_dir) {
		ncfg_error_set(err, err_size, "a secret was given nowhere to be stored");
		return 0;
	}
	if (!value || !value[0]) {
		ncfg_error_set(err, err_size,
		    "nothing was given for `%s`, and an empty secret is a secret that fails at "
		    "the moment it is used rather than now", name);
		return 0;
	}
	dir = ncfg_host_join(config_dir, "secrets", err, err_size);
	if (!dir) {
		return 0;
	}
	path = ncfg_host_join(dir, name, err, err_size);
	if (!path) {
		free(dir);
		return 0;
	}
	if (stat(path, &about) == 0 && !replace) {
		ncfg_error_set(err, err_size,
		    "%s already exists. Ask to replace it if that is what you mean -- and note "
		    "that a private key nobody has a copy of cannot be got back "
		    "(doc/decision/0042)", path);
		free(path);
		free(dir);
		return 0;
	}
	/* 0700 from the moment the directory exists and 0600 from the moment the
	 * file does, rather than created and then tightened: a file that is
	 * briefly world-readable is briefly world-readable, and this one is a
	 * password. */
	if (!ncfg_host_make_directory(dir, (mode_t)0700, err, err_size) ||
	    !ncfg_host_write_atomically(path, value, strlen(value), (mode_t)0600, err, err_size)) {
		free(path);
		free(dir);
		return 0;
	}
	free(dir);
	if (path_out) {
		*path_out = path;
	} else {
		free(path);
	}
	return 1;
}

int ncfg_secret_store_remove(const char *config_dir, const char *name, char *err,
    size_t err_size)
{
	char *dir;
	char *path;
	int ok = 1;

	if (!ncfg_secret_name_usable(name, err, err_size)) {
		return 0;
	}
	if (!config_dir) {
		ncfg_error_set(err, err_size, "a secret was asked to be removed from nowhere");
		return 0;
	}
	dir = ncfg_host_join(config_dir, "secrets", err, err_size);
	if (!dir) {
		return 0;
	}
	path = ncfg_host_join(dir, name, err, err_size);
	free(dir);
	if (!path) {
		return 0;
	}
	/* **Absent is success.** The caller asked for the credential to be gone. */
	if (unlink(path) != 0 && errno != ENOENT) {
		ncfg_error_set(err, err_size, "could not remove %s: %s", path, strerror(errno));
		ok = 0;
	}
	free(path);
	return ok;
}
