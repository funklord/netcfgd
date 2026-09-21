/*
 * hooks.c -- the two sinks, and the write that is nobody's side effect.
 *
 * See `hooks.h` for why recording and writing are separate steps and why there
 * are two sinks. What is here is the naming rule, the shebang rule and the
 * open that carries the mode.
 */
#include "ncfg/hooks.h"

#include "host_internal.h"
#include "ncfg/base.h"
#include "ncfg/value.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * A hook body is an operator's shell script, not a document, so the ceiling is
 * generous -- and it is a ceiling rather than no limit because the body
 * arrives from a configuration file a client may have written, and a daemon
 * that will allocate whatever it is handed is a daemon a client can exhaust.
 */
#define HOOK_BODY_MAX (1024u * 1024u)

typedef struct {
	char *path;
	char *script;
	size_t script_length;
} pending_one_t;

struct ncfg_pending_hooks {
	/* `run_dir/hooks`, named at construction and never created here. */
	char *dir;
	pending_one_t *at;
	size_t count;
	size_t capacity;
	/* Handed out by `ncfg_pending_hooks_sink`, and pointing back at this. */
	ncfg_hook_sink_t sink;
};

char *ncfg_hook_script(const char *body, size_t body_length, size_t *length_out, char *err,
    size_t err_size)
{
	static const char shebang[] = "#!/bin/sh\n";
	size_t prefix = 0;
	char *out;

	if (length_out) {
		*length_out = 0;
	}
	if (!body) {
		body = "";
		body_length = 0;
	}
	if (body_length > HOOK_BODY_MAX) {
		ncfg_error_set(err, err_size,
		    "a hook body of %zu bytes is past the %u this build will write",
		    body_length, (unsigned int)HOOK_BODY_MAX);
		return NULL;
	}
	/* **A body that already declares a shebang keeps it**, which is what makes
	 * an editor's round trip stable: read the script back, write it out again,
	 * and it does not grow a line (0258). */
	if (!(body_length >= 2u && body[0] == '#' && body[1] == '!')) {
		prefix = sizeof(shebang) - 1u;
	}
	out = malloc(prefix + body_length + 1u);
	if (!out) {
		ncfg_error_set(err, err_size, "out of memory building a hook script");
		return NULL;
	}
	if (prefix) {
		memcpy(out, shebang, prefix);
	}
	if (body_length) {
		memcpy(out + prefix, body, body_length);
	}
	out[prefix + body_length] = '\0';
	if (length_out) {
		*length_out = prefix + body_length;
	}
	return out;
}

/*
 * Fill in a reference for a body, without deciding where it goes.
 *
 * Shared by both sinks so that the unwritten one hashes **exactly** what the
 * pending one would have written. A second copy of the shebang rule here would
 * be a document whose hash does not match the file the runner checks, which is
 * a hook refused for a difference nobody can see.
 */
static int reference_for(int phase, const char *body, size_t body_length, char *path,
    ncfg_hook_ref_t *out, char *err, size_t err_size)
{
	size_t script_length = 0;
	char *script;
	char *hash;

	script = ncfg_hook_script(body, body_length, &script_length, err, err_size);
	if (!script) {
		return 0;
	}
	hash = malloc(NCFG_SHA256_HEX_SIZE);
	if (!hash) {
		free(script);
		ncfg_error_set(err, err_size, "out of memory hashing a hook");
		return 0;
	}
	ncfg_sha256_hex(script, script_length, hash);
	free(script);

	memset(out, 0, sizeof(*out));
	out->phase = phase;
	out->path = path;
	out->sha256 = hash;
	/* `run_as` and `timeout` are absent on every machine: the model carries
	 * them and the runner honours both, and the configuration language has no
	 * key for either (0258). Writing anything here would be inventing a
	 * mechanism no operator can reach. */
	return 1;
}

static int pending_record(void *state, int phase, const char *owner, const char *body,
    size_t body_length, ncfg_hook_ref_t *out, char *err, size_t err_size)
{
	struct ncfg_pending_hooks *pending = state;
	const char *phase_name = ncfg_hook_phase_name((ncfg_hook_phase_t)phase);
	char leaf[256];
	char *path;
	char *script;
	size_t script_length = 0;

	if (!pending || !out) {
		ncfg_error_set(err, err_size, "a hook was recorded into nothing");
		return 0;
	}
	if (!phase_name) {
		ncfg_error_set(err, err_size, "%d is not a hook phase", phase);
		return 0;
	}
	/*
	 * `<owner>.<phase>.<index>`, which is the Rust's name byte for byte. The
	 * index is what keeps two hooks of one phase on one interface apart, and
	 * it is the count so far rather than a per-owner counter -- so the name is
	 * a function of the order the compiler reached them, exactly as it is
	 * there.
	 */
	if ((size_t)snprintf(leaf, sizeof(leaf), "%s.%s.%zu", owner ? owner : "", phase_name,
	    pending->count) >= sizeof(leaf)) {
		ncfg_error_set(err, err_size, "the name for a hook on `%s` does not fit a filename",
		    owner ? owner : "");
		return 0;
	}
	path = ncfg_host_join(pending->dir, leaf, err, err_size);
	if (!path) {
		return 0;
	}
	script = ncfg_hook_script(body, body_length, &script_length, err, err_size);
	if (!script) {
		free(path);
		return 0;
	}
	if (pending->count == pending->capacity) {
		size_t want = pending->capacity ? pending->capacity * 2u : 4u;
		pending_one_t *grown = realloc(pending->at, want * sizeof(*grown));

		if (!grown) {
			free(path);
			free(script);
			ncfg_error_set(err, err_size, "out of memory recording a hook");
			return 0;
		}
		pending->at = grown;
		pending->capacity = want;
	}
	/* The document's strings are its own, so the reference gets a copy of the
	 * path rather than the one this set holds: freeing the document must not
	 * leave the pending set pointing at freed bytes. */
	{
		char *owned = strdup(path);

		if (!owned) {
			ncfg_error_set(err, err_size, "out of memory recording a hook");
		}
		if (!owned || !reference_for(phase, body, body_length, owned, out, err, err_size)) {
			free(owned);
			free(path);
			free(script);
			return 0;
		}
	}
	pending->at[pending->count].path = path;
	pending->at[pending->count].script = script;
	pending->at[pending->count].script_length = script_length;
	pending->count++;
	return 1;
}

ncfg_pending_hooks_t *ncfg_pending_hooks_new(const char *run_dir, char *err, size_t err_size)
{
	struct ncfg_pending_hooks *pending;

	if (!run_dir || !run_dir[0]) {
		ncfg_error_set(err, err_size, "a hook materialiser needs a run directory");
		return NULL;
	}
	pending = calloc(1u, sizeof(*pending));
	if (!pending) {
		ncfg_error_set(err, err_size, "out of memory");
		return NULL;
	}
	pending->dir = ncfg_host_join(run_dir, "hooks", err, err_size);
	if (!pending->dir) {
		free(pending);
		return NULL;
	}
	pending->sink.record = pending_record;
	pending->sink.state = pending;
	return pending;
}

const ncfg_hook_sink_t *ncfg_pending_hooks_sink(ncfg_pending_hooks_t *pending)
{
	return pending ? &pending->sink : NULL;
}

size_t ncfg_pending_hooks_count(const ncfg_pending_hooks_t *pending)
{
	return pending ? pending->count : 0u;
}

/*
 * Write one script that is 0700 from the instant it exists.
 *
 * **The mode goes on the open.** This was a write followed by a chmod to 0700,
 * which puts the body into a world-readable file and tightens it afterwards --
 * so the script is exposed for the window, and a descriptor opened in that
 * window goes on reading after the chmod. `/run/netcfgd` is traversable by
 * anyone on the machine, because the unit says `RuntimeDirectoryMode=0755`,
 * and a hook body is an operator's own shell: whatever they put in it.
 *
 * The `fchmod` is not belt and braces: `open` applies its mode only when it
 * creates the file, so one left wider by an older build would keep that mode.
 * It is on the descriptor rather than the path, so nothing can be swapped
 * underneath it between the two calls.
 *
 * The mode itself: the hook runs as root and nobody else needs to read it, let
 * alone write it. A world-writable hook is a root shell for whoever finds it.
 */
static int write_private(const char *path, const char *bytes, size_t length, char *err,
    size_t err_size)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, (mode_t)0700);
	size_t written = 0;

	if (fd < 0) {
		ncfg_error_set(err, err_size, "could not write %s: %s", path, strerror(errno));
		return 0;
	}
	if (fchmod(fd, (mode_t)0700) != 0) {
		ncfg_error_set(err, err_size, "could not set permissions on %s: %s", path,
		    strerror(errno));
		(void)close(fd);
		return 0;
	}
	while (written < length) {
		ssize_t put = write(fd, bytes + written, length - written);

		if (put < 0) {
			if (errno == EINTR) {
				continue;
			}
			ncfg_error_set(err, err_size, "could not write %s: %s", path,
			    strerror(errno));
			(void)close(fd);
			return 0;
		}
		written += (size_t)put;
	}
	if (close(fd) != 0) {
		ncfg_error_set(err, err_size, "could not write %s: %s", path, strerror(errno));
		return 0;
	}
	return 1;
}

int ncfg_pending_hooks_write(const ncfg_pending_hooks_t *pending, char *err, size_t err_size)
{
	size_t i;

	if (!pending || pending->count == 0u) {
		/* **Nothing recorded, nothing created -- not even the directory.**
		 * `apply` calls this unconditionally and most machines have no hooks
		 * at all; creating an empty directory for them would put a side
		 * effect back on a path that no longer has one. */
		return 1;
	}
	/* 0755, which is what the Rust's `create_dir_all` produces under the
	 * daemon's umask, and what `/run/netcfgd` itself already is. The scripts
	 * inside are 0700; the directory being traversable is not what protects
	 * them and never was. */
	if (!ncfg_host_make_directory(pending->dir, (mode_t)0755, err, err_size)) {
		return 0;
	}
	for (i = 0; i < pending->count; i++) {
		if (!write_private(pending->at[i].path, pending->at[i].script,
		    pending->at[i].script_length, err, err_size)) {
			return 0;
		}
	}
	return 1;
}

void ncfg_pending_hooks_free(ncfg_pending_hooks_t *pending)
{
	size_t i;

	if (!pending) {
		return;
	}
	for (i = 0; i < pending->count; i++) {
		free(pending->at[i].path);
		free(pending->at[i].script);
	}
	free(pending->at);
	free(pending->dir);
	free(pending);
}

static int unwritten_record(void *state, int phase, const char *owner, const char *body,
    size_t body_length, ncfg_hook_ref_t *out, char *err, size_t err_size)
{
	char *path;

	(void)state;
	(void)owner;
	if (!out) {
		ncfg_error_set(err, err_size, "a hook was recorded into nothing");
		return 0;
	}
	if (!ncfg_hook_phase_name((ncfg_hook_phase_t)phase)) {
		ncfg_error_set(err, err_size, "%d is not a hook phase", phase);
		return 0;
	}
	path = strdup(NCFG_HOOK_NOT_MATERIALISED);
	if (!path) {
		ncfg_error_set(err, err_size, "out of memory recording a hook");
		return 0;
	}
	if (!reference_for(phase, body, body_length, path, out, err, err_size)) {
		free(path);
		return 0;
	}
	return 1;
}

const ncfg_hook_sink_t *ncfg_hook_sink_unwritten(void)
{
	/* Stateless, so one instance serves every caller: there is nothing to
	 * record and nothing to free. */
	static const ncfg_hook_sink_t sink = { unwritten_record, NULL };

	return &sink;
}

/* ------------------------------------------------------------------------ *
 * What a client is shown
 * ------------------------------------------------------------------------ */

void ncfg_hook_scripts_free(ncfg_hook_script_t *scripts, size_t count)
{
	size_t at;

	if (!scripts) {
		return;
	}
	for (at = 0u; at < count; at++) {
		free(scripts[at].interface);
		free(scripts[at].path);
		free(scripts[at].text);
	}
	free(scripts);
}

/* A copy of `text`, or NULL. */
static char *hook_dup(const char *text)
{
	size_t size;
	char  *copy;

	if (!text) {
		text = "";
	}
	size = strlen(text) + 1u;
	copy = malloc(size);
	if (copy) {
		memcpy(copy, text, size);
	}
	return copy;
}

int ncfg_hooks_list(const ncfg_document_t *desired, ncfg_hook_script_t **out,
    size_t *count_out, char *err, size_t err_size)
{
	ncfg_hook_script_t *found = NULL;
	size_t              room = 0;
	size_t              taken = 0;
	size_t              at;
	size_t              which;

	if (!out || !count_out) {
		ncfg_error_set(err, err_size, "a hook listing was asked for with nowhere to put it");
		return 0;
	}
	*out = NULL;
	*count_out = 0;
	if (!desired) {
		return 1;
	}
	for (at = 0u; at < desired->interface_count; at++) {
		room += desired->interfaces[at].hook_count;
	}
	if (room == 0u) {
		return 1;
	}
	found = calloc(room, sizeof(*found));
	if (!found) {
		ncfg_error_set(err, err_size, "out of memory listing the hooks");
		return 0;
	}
	for (at = 0u; at < desired->interface_count; at++) {
		const ncfg_interface_t *interface = &desired->interfaces[at];

		for (which = 0u; which < interface->hook_count; which++) {
			const ncfg_hook_ref_t *hook = &interface->hooks[which];
			size_t                 length = 0;
			char                  *text = hook->path ?
			    ncfg_host_read_file(hook->path, &length, NCFG_HOOK_SCRIPT_MAX) : NULL;

			found[taken].interface = hook_dup(interface->name);
			found[taken].path = hook_dup(hook->path);
			found[taken].phase = hook->phase;
			found[taken].readable = text != NULL;
			/* Empty where it could not be read, which `hooks.h` keeps
			 * distinct from an empty script through `readable`. */
			found[taken].text = text ? text : hook_dup("");
			if (!found[taken].interface || !found[taken].path || !found[taken].text) {
				ncfg_hook_scripts_free(found, taken + 1u);
				ncfg_error_set(err, err_size, "out of memory listing the hooks");
				return 0;
			}
			taken++;
		}
	}
	*out = found;
	*count_out = taken;
	return 1;
}
