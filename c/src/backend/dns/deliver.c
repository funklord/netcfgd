/*
 * deliver.c -- handing a rendered scope to whatever resolver the host runs.
 *
 * See `dns.h` for the rule this serves and for why every path is a parameter.
 * What is here is the eight modes, the replacement that more than one process
 * may be doing at once, and the record the observer reads back.
 */
#include "ncfg/dns.h"

#include "../backend_internal.h"
#include "ncfg/base.h"
#include "ncfg/value.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define DNS_PATH_MAX 512

/*
 * Distinguishes one call of `ncfg_dns_replace` from the next within a process.
 *
 * Atomic because the pid is not enough: two threads of one process share it,
 * and the whole point of the name is that no two writers pick the same one.
 */
static _Atomic unsigned long sequence;

/* The directory `path` sits in, into `out`. `"."` where it names no directory,
 * which is what a relative name means. */
static void directory_of(const char *path, char *out, size_t out_size)
{
	const char *slash = strrchr(path, '/');
	size_t      length;

	if (!slash) {
		(void)snprintf(out, out_size, ".");
		return;
	}
	length = (size_t)(slash - path);
	if (length == 0u) {
		(void)snprintf(out, out_size, "/");
		return;
	}
	if (length + 1u > out_size) {
		length = out_size - 1u;
	}
	memcpy(out, path, length);
	out[length] = '\0';
}

static const char *name_of(const char *path)
{
	const char *slash = strrchr(path, '/');

	if (!slash || slash[1] == '\0') {
		return slash ? "netcfgd" : path;
	}
	return slash + 1u;
}

/*
 * Write a file that already exists, without staging beside it.
 *
 * **The fallback for a directory netcfgd may not add to**, and it gives up
 * atomicity: a reader can catch this mid-write where the rename could not be
 * caught at all. That is the trade, and it is the right way round -- the
 * alternative is not writing, which is what happened before.
 *
 * **It will not follow a symlink.** `/etc/resolv.conf` is a symlink into
 * another resolver's runtime state on a great many machines. The rename path
 * *replaces* such a link, which is what `write_resolv_conf` mode asks for: the
 * operator has said netcfgd owns the file. Writing through it instead would
 * scribble in a daemon's own state, so it refuses and says which situation it
 * is in.
 *
 * **Existing files only.** Opened without `O_CREAT`: a file that is absent
 * needs a writable directory anyway, so pretending otherwise would swap one
 * confusing error for another.
 */
static int in_place(const char *path, const char *text, const char *staging, char *err,
    size_t err_size)
{
	struct stat about;
	int         fd;
	size_t      left = strlen(text);
	const char *at = text;

	if (lstat(path, &about) == 0 && S_ISLNK(about.st_mode)) {
		ncfg_error_set(err, err_size,
		    "%s is a symlink, and netcfgd cannot stage a replacement beside it (%s). Writing "
		    "through the link would edit whatever owns the target -- systemd-resolved or "
		    "openresolv, usually. Point `dns_mode` at that resolver instead, or replace the "
		    "symlink with a file netcfgd may own",
		    path, staging);
		return 0;
	}
	fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
	if (fd < 0) {
		ncfg_error_set(err, err_size,
		    "could not stage beside %s (%s) and could not write it either: %s", path, staging,
		    strerror(errno));
		return 0;
	}
	while (left > 0u) {
		ssize_t put = write(fd, at, left);

		if (put < 0) {
			if (errno == EINTR) {
				continue;
			}
			ncfg_error_set(err, err_size, "could not write %s: %s", path, strerror(errno));
			(void)close(fd);
			return 0;
		}
		at += put;
		left -= (size_t)put;
	}
	if (close(fd) != 0) {
		ncfg_error_set(err, err_size, "could not write %s: %s", path, strerror(errno));
		return 0;
	}
	return 1;
}

int ncfg_dns_replace(const char *path, const char *text, char *err, size_t err_size)
{
	char          dir[DNS_PATH_MAX];
	char          temporary[DNS_PATH_MAX];
	unsigned long ticket;
	int           written;
	char          staging[NCFG_ERROR_MAX];

	if (!path || !text) {
		ncfg_error_set(err, err_size, "a resolver file was written with no name or no content");
		return 0;
	}
	directory_of(path, dir, sizeof(dir));
	ticket = atomic_fetch_add(&sequence, 1ul);
	/* **The pid because the second writer is another process, the counter
	 * because it need not be.** One staging name for every writer is how the
	 * loser of a race renames a file that is no longer there and reports it
	 * could not replace `resolv.conf` when it had written it perfectly well.
	 *
	 * The leading dot is not decoration: a `*.conf` glob over `unbound.conf.d` does not match
	 * a name beginning with a dot, and dnsmasq's `conf-dir` always skips one. */
	written = snprintf(temporary, sizeof(temporary), "%s/.%s.netcfgd.%d.%lu", dir,
	    name_of(path), (int)getpid(), ticket);
	if (written < 0 || (size_t)written >= sizeof(temporary)) {
		ncfg_error_set(err, err_size, "the staging name beside %s is longer than this build "
		                  "will build",
		    path);
		return 0;
	}

	staging[0] = '\0';
	if (!ncfg_backend_write_file(temporary, text, strlen(text), 0644, staging,
	    sizeof(staging))) {
		/* **The sandbox grants the file and the atomic replace needs the
		 * directory.** `ProtectSystem=full` mounts `/etc` read-only and the
		 * unit names `ReadWritePaths=-/etc/resolv.conf` to open one path back
		 * up -- which grants the *file*. Creating a new entry in `/etc` is
		 * still refused, and staging a temporary beside the target is creating
		 * a new entry.
		 *
		 * Only these two kinds. A full disk also fails to stage, and falling
		 * back there would truncate the resolver's configuration and then fail
		 * to refill it -- an empty `resolv.conf` being worse than an unchanged
		 * one. */
		if (errno == EACCES || errno == EPERM || errno == EROFS) {
			return in_place(path, text, staging, err, err_size);
		}
		ncfg_error_set(err, err_size, "%s", staging);
		return 0;
	}
	if (rename(temporary, path) != 0) {
		ncfg_error_set(err, err_size, "could not replace %s: %s", path, strerror(errno));
		/* A failed rename would otherwise leave the staging file next to the
		 * resolver's own configuration for ever, which is how a full disk turns
		 * into a directory nobody can read. */
		(void)unlink(temporary);
		return 0;
	}
	return 1;
}

/*
 * Run a program, optionally feeding it `input` on stdin.
 *
 * Its own process group, and its output streams are the caller's -- resolvconf
 * and resolvectl say useful things and nothing here parses them, which is the
 * difference 0014 draws between passing arguments to a documented command and
 * scraping an interactive tool's display.
 */
static int run_with_input(const char *program, const char *const *argv, const char *input,
    int *exited_ok, int *status_out, char *err, size_t err_size)
{
	int              feed[2];
	pid_t            child;
	int              status = 0;
	struct sigaction ignore;
	struct sigaction restored;
	int              have_old = 0;

	*exited_ok = 0;
	*status_out = 0;
	if (input && pipe(feed) != 0) {
		ncfg_error_set(err, err_size, "could not talk to %s: %s", program, strerror(errno));
		return 0;
	}
	child = fork();
	if (child < 0) {
		ncfg_error_set(err, err_size, "could not run %s: %s", program, strerror(errno));
		if (input) {
			(void)close(feed[0]);
			(void)close(feed[1]);
		}
		return 0;
	}
	if (child == 0) {
		(void)setpgid(0, 0);
		if (input) {
			(void)close(feed[1]);
			if (dup2(feed[0], STDIN_FILENO) < 0) {
				_exit(127);
			}
			(void)close(feed[0]);
		}
		execvp(program, (char *const *)(const void *)argv);
		_exit(127);
	}
	if (input) {
		size_t      left = strlen(input);
		const char *at = input;

		(void)close(feed[0]);
		/* **A library never ends the process.** A child that exited before
		 * reading would deliver SIGPIPE, whose default action is death, so it
		 * is ignored for the length of the write and restored afterwards --
		 * and the `EPIPE` that arrives instead is a failure this can report. */
		memset(&ignore, 0, sizeof(ignore));
		ignore.sa_handler = SIG_IGN;
		(void)sigemptyset(&ignore.sa_mask);
		have_old = sigaction(SIGPIPE, &ignore, &restored) == 0;
		while (left > 0u) {
			ssize_t put = write(feed[1], at, left);

			if (put < 0) {
				if (errno == EINTR) {
					continue;
				}
				break;
			}
			at += put;
			left -= (size_t)put;
		}
		(void)close(feed[1]);
		if (have_old) {
			(void)sigaction(SIGPIPE, &restored, NULL);
		}
	}
	for (;;) {
		pid_t got = waitpid(child, &status, 0);

		if (got == child) {
			break;
		}
		if (got < 0 && errno == EINTR) {
			continue;
		}
		ncfg_error_set(err, err_size, "%s did not finish: %s", program, strerror(errno));
		return 0;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
		ncfg_error_set(err, err_size, "notfound");
		return 0;
	}
	*status_out = status;
	*exited_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	return 1;
}

/* How an exit is described in a refusal. `exited with 2` and `killed by signal
 * 9` are different facts and an operator acts on them differently. */
static void describe_status(int status, char *out, size_t out_size)
{
	if (WIFEXITED(status)) {
		(void)snprintf(out, out_size, "exited with %d", WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		(void)snprintf(out, out_size, "was killed by signal %d", WTERMSIG(status));
	} else {
		(void)snprintf(out, out_size, "did not exit normally");
	}
}

/* ------------------------------------------------------------- the modes */

static int write_resolv_conf(const ncfg_dns_scope_t *scopes, size_t count, const char *path,
    char *err, size_t err_size)
{
	ncfg_dns_flat_t flat;
	char           *text;
	int             ok;

	if (!path) {
		ncfg_error_set(err, err_size,
		    "mode = \"write_resolv_conf\" was delivered with no resolv.conf named; netcfgd "
		    "will not guess at the file that decides whether this machine can resolve a name");
		return 0;
	}
	if (!ncfg_dns_flatten(scopes, count, &flat, err, err_size)) {
		return 0;
	}
	text = ncfg_dns_resolv_conf(&flat, "netcfgd", err, err_size);
	ncfg_dns_flat_free(&flat);
	if (!text) {
		return 0;
	}
	ok = ncfg_dns_replace(path, text, err, err_size);
	free(text);
	return ok;
}

/*
 * Hand each scope to `resolvconf`.
 *
 * `openresolv` adds one thing: `-p` marks an interface *private*, so its
 * servers are queried only for the domains its blob names. That is exactly this
 * model's exclusive routing domain, arrived at independently, and it is why
 * 0007 makes `openresolv` a separate mode rather than a capability discovered
 * from whichever resolvconf is installed.
 */
static int hand_to_resolvconf(const ncfg_dns_scope_t *scopes, size_t count, int openresolv,
    const char *program, char *err, size_t err_size)
{
	size_t at;

	if (!program) {
		program = "resolvconf";
	}
	for (at = 0u; at < count; at++) {
		char        key[DNS_PATH_MAX];
		const char *argv[5];
		char       *blob;
		int         private_scope = 0;
		int         exited_ok = 0;
		int         status = 0;
		size_t      which;
		char        said[NCFG_ERROR_MAX];
		char        how[64];
		int         ok;

		/* `resolvconf -a` keys on an interface name, so the global scope needs
		 * one too. `lo.netcfgd` is the conventional shape for a subscriber that
		 * is not really an interface. */
		if (scopes[at].name && strcmp(scopes[at].name, NCFG_DNS_GLOBAL_SCOPE) == 0) {
			(void)snprintf(key, sizeof(key), "lo.netcfgd");
		} else {
			(void)snprintf(key, sizeof(key), "%s.netcfgd", scopes[at].name);
		}
		for (which = 0u; openresolv && scopes[at].policy &&
		     which < scopes[at].policy->domain_count; which++) {
			private_scope = private_scope || scopes[at].policy->domains[which].exclusive;
		}

		blob = ncfg_dns_resolvconf_blob(scopes[at].policy, err, err_size);
		if (!blob) {
			return 0;
		}
		argv[0] = program;
		argv[1] = "-a";
		argv[2] = key;
		argv[3] = private_scope ? "-p" : NULL;
		argv[4] = NULL;

		said[0] = '\0';
		ok = run_with_input(program, argv, blob, &exited_ok, &status, said, sizeof(said));
		free(blob);
		if (!ok) {
			if (strcmp(said, "notfound") == 0) {
				ncfg_error_set(err, err_size,
				    "resolvconf is not installed; use dns_mode = \"write_resolv_conf\" "
				    "or install openresolv");
			} else {
				ncfg_error_set(err, err_size, "could not run resolvconf: %s", said);
			}
			return 0;
		}
		if (!exited_ok) {
			describe_status(status, how, sizeof(how));
			if (private_scope) {
				/* The likeliest cause of a failure with `-p` is a resolvconf
				 * that is not openresolv, and the two share a command name --
				 * so the message says which mode to use instead rather than
				 * leaving the operator to work out that their resolvconf is
				 * the wrong one. */
				ncfg_error_set(err, err_size,
				    "`resolvconf -a %s -p` %s. `-p` is openresolv's, and several tools "
				    "install a `resolvconf`; if this one is not openresolv, split DNS "
				    "cannot be delivered through it -- use mode = \"resolvconf\" for "
				    "flat delivery, and drop the exclusive routing domains",
				    key, how);
			} else {
				ncfg_error_set(err, err_size, "resolvconf -a %s %s", key, how);
			}
			return 0;
		}
	}
	return 1;
}

static int run_resolvectl(const char *program, const char *verb, const char *link,
    const char *const *values, size_t value_count, char *err, size_t err_size)
{
	const char **argv;
	int          exited_ok = 0;
	int          status = 0;
	char         said[NCFG_ERROR_MAX];
	char         how[64];
	size_t       at;
	int          ok;

	argv = calloc(value_count + 4u, sizeof(*argv));
	if (!argv) {
		ncfg_error_set(err, err_size, "out of memory building a resolvectl command");
		return 0;
	}
	argv[0] = program;
	argv[1] = verb;
	argv[2] = link;
	for (at = 0u; at < value_count; at++) {
		argv[3u + at] = values[at];
	}
	argv[3u + value_count] = NULL;

	said[0] = '\0';
	ok = run_with_input(program, argv, NULL, &exited_ok, &status, said, sizeof(said));
	free(argv);
	if (!ok) {
		if (strcmp(said, "notfound") == 0) {
			ncfg_error_set(err, err_size,
			    "resolvectl is not installed, so systemd-resolved is not running here; "
			    "mode = \"resolved\" needs it");
		} else {
			ncfg_error_set(err, err_size, "could not run resolvectl: %s", said);
		}
		return 0;
	}
	if (!exited_ok) {
		describe_status(status, how, sizeof(how));
		ncfg_error_set(err, err_size, "`resolvectl %s %s` %s", verb, link, how);
		return 0;
	}
	return 1;
}

/*
 * Hand each scope to `systemd-resolved` through `resolvectl`.
 *
 * Through the command rather than D-Bus, for the reason 0014 gave about iwd: a
 * D-Bus client would be the largest thing in this repository. The objection
 * 0014 raised to `iwctl` does not apply here, and the difference is worth
 * naming -- nothing below parses `resolvectl`'s output. Passing arguments to a
 * documented command is a contract; scraping an interactive tool's display is
 * not.
 */
static int hand_to_resolved(const ncfg_dns_scope_t *scopes, size_t count, const char *program,
    char *err, size_t err_size)
{
	size_t at;

	if (!program) {
		program = "resolvectl";
	}
	for (at = 0u; at < count; at++) {
		const ncfg_dns_policy_t *policy = scopes[at].policy;
		const char             **servers = NULL;
		char                   **domains = NULL;
		size_t                   domain_count = 0;
		size_t                   which;
		const char              *link;
		int                      ok;

		/* resolved is per-link and has no global scope of its own, so the
		 * globals scope goes to the loopback -- which is where resolved puts
		 * its own fallback configuration too. */
		link = (scopes[at].name && strcmp(scopes[at].name, NCFG_DNS_GLOBAL_SCOPE) == 0)
		    ? "lo"
		    : scopes[at].name;

		if (policy && policy->server_count > 0u) {
			servers = calloc(policy->server_count, sizeof(*servers));
			if (!servers) {
				ncfg_error_set(err, err_size, "out of memory listing %s's servers", link);
				return 0;
			}
			for (which = 0u; which < policy->server_count; which++) {
				servers[which] = policy->servers[which].addr;
			}
		}
		ok = run_resolvectl(program, "dns", link, servers,
		    policy ? policy->server_count : 0u, err, err_size);
		free((void *)servers);
		if (!ok) {
			return 0;
		}

		if (!policy) {
			continue;
		}
		domains = calloc(policy->domain_count + policy->search_count + 1u, sizeof(*domains));
		if (!domains) {
			ncfg_error_set(err, err_size, "out of memory listing %s's domains", link);
			return 0;
		}
		/* resolved spells an exclusive routing domain with a leading `~` and a
		 * search domain without one. The model already distinguishes them, so
		 * this is a rendering rather than a decision. */
		for (which = 0u; which < policy->domain_count; which++) {
			const char *suffix = policy->domains[which].suffix;
			size_t      length = strlen(suffix) + 2u;
			char       *one = malloc(length);

			if (!one) {
				break;
			}
			(void)snprintf(one, length, "%s%s",
			    policy->domains[which].exclusive ? "~" : "", suffix);
			domains[domain_count++] = one;
		}
		for (which = 0u; which < policy->search_count; which++) {
			char *one = ncfg_backend_strdup(policy->search[which]);

			if (!one) {
				break;
			}
			domains[domain_count++] = one;
		}
		ok = 1;
		if (domain_count > 0u) {
			ok = run_resolvectl(program, "domain", link, (const char *const *)domains,
			    domain_count, err, err_size);
		}
		for (which = 0u; which < domain_count; which++) {
			free(domains[which]);
		}
		free(domains);
		if (!ok) {
			return 0;
		}
	}
	return 1;
}

/*
 * Write a forwarding resolver's configuration.
 *
 * Both express a routing domain as "send this suffix to these servers", which
 * is what makes them scope-capable -- dnsmasq as `server=/suffix/address` and
 * unbound as a `forward-zone` stanza. The two spellings mean the same thing,
 * which is 0007's whole premise.
 */
static int write_forwarder(const ncfg_dns_scope_t *scopes, size_t count, const char *path,
    const char *name, char *err, size_t err_size)
{
	char        dir[DNS_PATH_MAX];
	struct stat about;
	char       *text;
	int         ok;

	if (!path) {
		ncfg_error_set(err, err_size,
		    "mode = \"%s\" was delivered with no configuration file named", name);
		return 0;
	}
	directory_of(path, dir, sizeof(dir));
	if (stat(dir, &about) != 0 || !S_ISDIR(about.st_mode)) {
		/* **Not created if it is missing.** An absent `/etc/dnsmasq.d` means
		 * dnsmasq is not installed or does not read that directory, and
		 * creating it would leave a file nothing consumes while reporting
		 * success. Constraint 2 -- the filesystem reflects use -- cuts both
		 * ways. */
		ncfg_error_set(err, err_size,
		    "%s does not exist, so %s is not installed here or does not read it; "
		    "mode = \"%s\" needs it",
		    dir, name, name);
		return 0;
	}
	text = strcmp(name, "dnsmasq") == 0 ? ncfg_dns_dnsmasq_conf(scopes, count, err, err_size)
	                    : ncfg_dns_unbound_conf(scopes, count, err, err_size);
	if (!text) {
		return 0;
	}
	ok = ncfg_dns_replace(path, text, err, err_size);
	free(text);
	return ok;
}

/*
 * Hand the whole scoped structure to a script, as JSON on stdin.
 *
 * The escape hatch, and the only backend that receives scopes rather than a
 * rendering of them -- 0007 is explicit that a site wanting resolved's
 * `MulticastDNS` or anything else outside the model puts it here.
 *
 * **Run without a shell.** The command is a config value, and a shell would
 * make the DNS mode a place where a config file becomes arbitrary code with
 * word splitting attached -- the same rule the secret resolver's exec provider
 * follows.
 */
static int hand_to_script(const ncfg_dns_scope_t *scopes, size_t count, const char *command,
    char *err, size_t err_size)
{
	char        *work;
	const char **argv = NULL;
	size_t       word_count = 0;
	size_t       capacity = 0;
	char        *at;
	char        *text = NULL;
	int          exited_ok = 0;
	int          status = 0;
	char         said[NCFG_ERROR_MAX];
	char         how[64];
	int          ok;

	if (!command || command[0] == '\0') {
		ncfg_error_set(err, err_size, "the exec dns mode needs a command");
		return 0;
	}
	work = ncfg_backend_strdup(command);
	if (!work) {
		ncfg_error_set(err, err_size, "out of memory reading the exec dns command");
		return 0;
	}
	/* Split on whitespace and nothing else. No quoting, no globbing, no
	 * substitution: a shell here would be the one place a configuration file
	 * becomes arbitrary code. */
	at = work;
	while (*at != '\0') {
		char *start;

		while (*at == ' ' || *at == '\t' || *at == '\n' || *at == '\r') {
			at++;
		}
		if (*at == '\0') {
			break;
		}
		start = at;
		while (*at != '\0' && *at != ' ' && *at != '\t' && *at != '\n' && *at != '\r') {
			at++;
		}
		if (*at != '\0') {
			*at++ = '\0';
		}
		if (word_count + 2u > capacity) {
			size_t       wanted = capacity ? capacity * 2u : 8u;
			const char **grown = realloc(argv, wanted * sizeof(*grown));

			if (!grown) {
				free(argv);
				free(work);
				ncfg_error_set(err, err_size, "out of memory reading the exec dns command");
				return 0;
			}
			argv = grown;
			capacity = wanted;
		}
		argv[word_count++] = start;
	}
	if (word_count == 0u) {
		free(argv);
		free(work);
		ncfg_error_set(err, err_size, "the exec dns mode needs a command");
		return 0;
	}
	argv[word_count] = NULL;

	text = ncfg_dns_scopes_json(scopes, count, err, err_size);
	if (!text) {
		free(argv);
		free(work);
		return 0;
	}
	said[0] = '\0';
	ok = run_with_input(argv[0], argv, text, &exited_ok, &status, said, sizeof(said));
	free(text);
	if (!ok) {
		if (strcmp(said, "notfound") == 0) {
			ncfg_error_set(err, err_size, "the dns script `%s` is not there", argv[0]);
		} else {
			ncfg_error_set(err, err_size, "could not run %s: %s", argv[0], said);
		}
		free(argv);
		free(work);
		return 0;
	}
	if (!exited_ok) {
		describe_status(status, how, sizeof(how));
		ncfg_error_set(err, err_size, "the dns script `%s` %s", argv[0], how);
		free(argv);
		free(work);
		return 0;
	}
	free(argv);
	free(work);
	return 1;
}

/* --------------------------------------------------------- what was done */

int ncfg_dns_record(const ncfg_dns_scope_t *scopes, size_t count, const char *run_dir, char *err,
    size_t err_size)
{
	char   dir[DNS_PATH_MAX];
	size_t at;

	if (!run_dir) {
		ncfg_error_set(err, err_size,
		    "the dns delivery was asked to record itself with no run directory");
		return 0;
	}
	if (!ncfg_backend_join(dir, sizeof(dir), run_dir, "dns", err, err_size) ||
	    !ncfg_backend_make_dir(dir, 0755, err, err_size)) {
		return 0;
	}
	for (at = 0u; at < count; at++) {
		const ncfg_dns_policy_t *policy = scopes[at].policy;
		char                     path[DNS_PATH_MAX];
		ncfg_buf_t               buf;
		char                    *blob;
		size_t                   which;
		int                      ok;

		if (!ncfg_backend_path(path, sizeof(path), run_dir, "dns", scopes[at].name, ".conf",
		    err, err_size)) {
			return 0;
		}
		blob = ncfg_dns_resolvconf_blob(policy, err, err_size);
		if (!blob) {
			return 0;
		}
		ncfg_buf_init(&buf, 0u);
		ncfg_buf_addf(&buf, "# scope: %s\n# mode:  %s\n", scopes[at].name,
		    ncfg_dns_mode_name((ncfg_dns_mode_t)(policy ? policy->mode.mode
		                           : NCFG_DNS_MODE_NONE)));
		ncfg_buf_add_text(&buf, blob);
		free(blob);
		for (which = 0u; policy && which < policy->domain_count; which++) {
			ncfg_buf_addf(&buf, "# routing domain %s%s\n", policy->domains[which].suffix,
			    policy->domains[which].exclusive ? " (exclusive)" : "");
		}
		if (ncfg_buf_failed(&buf)) {
			ncfg_error_set(err, err_size, "the record for scope %s is larger than this build "
			                  "will render",
			    scopes[at].name);
			ncfg_buf_free(&buf);
			return 0;
		}
		ok = ncfg_backend_write_file(path, ncfg_buf_text(&buf),
		    strlen(ncfg_buf_text(&buf)), 0644, err, err_size);
		ncfg_buf_free(&buf);
		if (!ok) {
			return 0;
		}
	}
	return 1;
}

void ncfg_dns_delivered_free(char **delivered, size_t count)
{
	size_t at;

	if (!delivered) {
		return;
	}
	for (at = 0u; at < count; at++) {
		free(delivered[at]);
	}
	free(delivered);
}

/* The scope names, for a caller that wants to know which were delivered. */
static int delivered_names(const ncfg_dns_scope_t *scopes, size_t count, char ***out,
    size_t *out_count, char *err, size_t err_size)
{
	char **names;
	size_t at;

	*out = NULL;
	*out_count = 0;
	if (count == 0u) {
		return 1;
	}
	names = calloc(count, sizeof(*names));
	if (!names) {
		ncfg_error_set(err, err_size, "out of memory listing the delivered dns scopes");
		return 0;
	}
	for (at = 0u; at < count; at++) {
		names[at] = ncfg_backend_strdup(scopes[at].name ? scopes[at].name : "");
		if (!names[at]) {
			ncfg_dns_delivered_free(names, at);
			ncfg_error_set(err, err_size, "out of memory listing the delivered dns scopes");
			return 0;
		}
	}
	*out = names;
	*out_count = count;
	return 1;
}

int ncfg_dns_deliver(const ncfg_dns_scope_t *scopes, size_t count,
    const ncfg_dns_targets_t *targets, char ***delivered_out, size_t *delivered_count, char *err,
    size_t err_size)
{
	int    mode;
	size_t at;

	if (delivered_out) {
		*delivered_out = NULL;
	}
	if (delivered_count) {
		*delivered_count = 0;
	}
	if (count == 0u) {
		return 1;
	}
	if (!targets) {
		ncfg_error_set(err, err_size, "the dns delivery was asked for with nowhere to put it");
		return 0;
	}
	if (!scopes[0].policy) {
		ncfg_error_set(err, err_size, "the dns scope `%s` carries no policy",
		    scopes[0].name ? scopes[0].name : "");
		return 0;
	}

	/* **Every scope in one delivery must agree on the mode**: a host cannot
	 * both own resolv.conf and hand it to resolvconf. Disagreement is a config
	 * error rather than something to resolve by picking one. */
	mode = scopes[0].policy->mode.mode;
	for (at = 1u; at < count; at++) {
		if (!scopes[at].policy) {
			ncfg_error_set(err, err_size, "the dns scope `%s` carries no policy",
			    scopes[at].name ? scopes[at].name : "");
			return 0;
		}
		if (scopes[at].policy->mode.mode != mode) {
			ncfg_error_set(err, err_size,
			    "scopes disagree about the dns mode: %s wants %s and %s wants %s",
			    scopes[0].name, ncfg_dns_mode_name((ncfg_dns_mode_t)mode),
			    scopes[at].name,
			    ncfg_dns_mode_name((ncfg_dns_mode_t)scopes[at].policy->mode.mode));
			return 0;
		}
	}

	switch (mode) {
	case NCFG_DNS_MODE_NONE:
		/* netcfgd does not touch resolution. Nothing is written and nothing is
		 * recorded -- a record would claim a scope netcfgd delivered. */
		return 1;
	case NCFG_DNS_MODE_WRITE_RESOLV_CONF:
		if (!write_resolv_conf(scopes, count, targets->resolv_conf, err, err_size)) {
			return 0;
		}
		break;
	case NCFG_DNS_MODE_RESOLVCONF:
		if (!hand_to_resolvconf(scopes, count, 0, targets->resolvconf_program, err,
		    err_size)) {
			return 0;
		}
		break;
	case NCFG_DNS_MODE_OPENRESOLV:
		if (!hand_to_resolvconf(scopes, count, 1, targets->resolvconf_program, err,
		    err_size)) {
			return 0;
		}
		break;
	case NCFG_DNS_MODE_RESOLVED:
		if (!hand_to_resolved(scopes, count, targets->resolvectl_program, err, err_size)) {
			return 0;
		}
		break;
	case NCFG_DNS_MODE_DNSMASQ:
		if (!write_forwarder(scopes, count, targets->dnsmasq_conf, "dnsmasq", err,
		    err_size)) {
			return 0;
		}
		break;
	case NCFG_DNS_MODE_UNBOUND:
		if (!write_forwarder(scopes, count, targets->unbound_conf, "unbound", err,
		    err_size)) {
			return 0;
		}
		break;
	case NCFG_DNS_MODE_EXEC:
		if (!hand_to_script(scopes, count, scopes[0].policy->mode.command, err, err_size)) {
			return 0;
		}
		break;
	default:
		ncfg_error_set(err, err_size, "the dns mode %d is not one this build delivers", mode);
		return 0;
	}

	if (!ncfg_dns_record(scopes, count, targets->run_dir, err, err_size)) {
		return 0;
	}
	if (delivered_out && delivered_count &&
	    !delivered_names(scopes, count, delivered_out, delivered_count, err, err_size)) {
		return 0;
	}
	return 1;
}
