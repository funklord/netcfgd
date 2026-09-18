/*
 * hooks_test.c -- the split, the round trip, and the mode that is not a chmod.
 *
 * WHAT THESE CASES ARE FOR
 *   Four of them name a defect that shipped.
 *
 *     * **Recording writes nothing.** The materialiser used to write during
 *       compilation, which made five of six read-only CLI paths write files
 *       and left a failed compile with some of its scripts already on disk.
 *       The directory is asserted **absent** rather than empty: an empty
 *       `hooks/` on a machine that ran `ncfg plan` would still be a read-only
 *       verb having written.
 *     * **And asking puts exactly what the reference promised on disk.** The
 *       pair is the test: the first half alone would pass against a sink that
 *       silently dropped the body.
 *     * **A body carrying its own shebang comes back byte-identical** (0258).
 *       The materialiser prepends `#!/bin/sh` to a body that has none; a body
 *       that already declares one keeps it, and the editor writes the block
 *       unindented, so the script netcfgd runs does not grow a line every time
 *       somebody saves it.
 *     * **The mode goes on the open, not on a later chmod.** This was a write
 *       followed by a chmod, and `the_mode_is_never_wide_even_for_an_instant`
 *       is a real race detector rather than an assertion about the end state:
 *       a second process stats the file in a loop while this one writes a
 *       megabyte into it. It was run against a write-then-chmod
 *       implementation while it was being written and caught mode 0666 on the
 *       first round every time; against this one it has never seen anything
 *       but 0700. Like the Rust's two-writer test, **it can only pass when
 *       there is nothing to find.**
 *
 *   The digest has the published vectors and the padding boundaries, because
 *   an implementation that is nearly right is worth nothing and looks fine.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY
 *   The daemon this is a port of is running on this machine with real
 *   configuration. Every path here is under one `mkdtemp` directory, which is
 *   removed at the end; see `testdir.h`.
 */
#include "ncfg/base.h"
#include "ncfg/hooks.h"
#include "ncfg/lower.h"
#include "ncfg/value.h"

#include "testdir.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-64s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static int ends_with(const char *text, const char *tail)
{
	size_t length;
	size_t want;

	if (!text) {
		return 0;
	}
	length = strlen(text);
	want = strlen(tail);
	return length >= want && strcmp(text + length - want, tail) == 0;
}

static const char *hex_of(const char *text)
{
	static char out[NCFG_SHA256_HEX_SIZE];

	ncfg_sha256_hex(text, strlen(text), out);
	return out;
}

/* ------------------------------------------------------------ the digest */

static void the_digest_matches_the_published_vectors(void)
{
	char out[NCFG_SHA256_HEX_SIZE];
	char many[64];

	check(strcmp(hex_of(""),
	    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
	    "sha256 of nothing is the published vector");
	check(strcmp(hex_of("abc"),
	    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
	    "sha256 of `abc` is the published vector");
	check(strcmp(hex_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
	    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
	    "sha256 of the two-block vector is the published one");

	/* 55, 56 and 64 bytes take different paths through the length-append, and
	 * an off-by-one there is invisible on short input. */
	memset(many, 'a', sizeof(many));
	ncfg_sha256_hex(many, 55u, out);
	check(strcmp(out,
	    "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318") == 0,
	    "55 bytes, the last that fits with its length");
	ncfg_sha256_hex(many, 56u, out);
	check(strcmp(out,
	    "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a") == 0,
	    "56 bytes, the first that needs a second block");
	ncfg_sha256_hex(many, 64u, out);
	check(strcmp(out,
	    "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb") == 0,
	    "64 bytes, exactly one block of message");
}

/* ------------------------------------------------------------- the sinks */

static void recording_touches_nothing(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	char hooks_dir[512];
	ncfg_pending_hooks_t *pending = ncfg_pending_hooks_new(run_dir, message, sizeof(message));
	const ncfg_hook_sink_t *sink = ncfg_pending_hooks_sink(pending);
	ncfg_hook_ref_t reference;

	memset(&reference, 0, sizeof(reference));
	check(pending != NULL, "a materialiser is made without touching the filesystem");
	check(sink && sink->record(sink->state, NCFG_HOOK_PHASE_POST_UP, "eth0", "echo hi\n", 8u,
	    &reference, message, sizeof(message)),
	    "a body is recorded");
	check(ends_with(reference.path, "eth0.post_up.0"),
	    "the reference names the file the document will refer to");
	check(reference.sha256 && strcmp(reference.sha256, hex_of("#!/bin/sh\necho hi\n")) == 0,
	    "and carries the hash of the script, shebang included");
	check(reference.phase == NCFG_HOOK_PHASE_POST_UP && reference.run_as == NULL &&
	    reference.timeout.has == 0,
	    "run_as and timeout are absent, as they are on every machine (0258)");
	check(ncfg_pending_hooks_count(pending) == 1u, "one is waiting");
	check(!testdir_exists(testdir_in(run_dir, "hooks", hooks_dir, sizeof(hooks_dir))),
	    "recording creates no directory, let alone the file");

	free(reference.path);
	free(reference.sha256);
	ncfg_pending_hooks_free(pending);
}

static void writing_puts_the_recorded_body_where_the_reference_says(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_pending_hooks_t *pending = ncfg_pending_hooks_new(run_dir, message, sizeof(message));
	const ncfg_hook_sink_t *sink = ncfg_pending_hooks_sink(pending);
	ncfg_hook_ref_t reference;
	char *written;
	size_t length = 0;
	static const char body[] = "#!/bin/dash\nexit 0\n";

	memset(&reference, 0, sizeof(reference));
	check(sink && sink->record(sink->state, NCFG_HOOK_PHASE_PRE_UP, "wlan0", body,
	    sizeof(body) - 1u, &reference, message, sizeof(message)), "a body is recorded");
	check(ncfg_pending_hooks_write(pending, message, sizeof(message)),
	    "and writing it is the second, explicit step");

	written = testdir_read(reference.path, &length);
	/* **A body with its own shebang keeps it**, which is what makes an
	 * editor's round trip stable: read the file back, write it out again, and
	 * the script does not grow a line (0258). */
	check(written && length == sizeof(body) - 1u && memcmp(written, body, length) == 0,
	    "the script on disk is the body, byte for byte");
	check(written && strcmp(hex_of(written), reference.sha256) == 0,
	    "and hashes to what the document says it does");
	check(testdir_mode(reference.path) == 0700,
	    "a hook is root's shell and nobody else's: 0700");

	free(written);
	free(reference.path);
	free(reference.sha256);
	ncfg_pending_hooks_free(pending);
}

static void a_body_with_no_shebang_gets_one(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_pending_hooks_t *pending = ncfg_pending_hooks_new(run_dir, message, sizeof(message));
	const ncfg_hook_sink_t *sink = ncfg_pending_hooks_sink(pending);
	ncfg_hook_ref_t first;
	ncfg_hook_ref_t second;
	char *written;
	size_t length = 0;

	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));
	check(sink && sink->record(sink->state, NCFG_HOOK_PHASE_DOWN, "eth0", "ip -o link\n", 11u,
	    &first, message, sizeof(message)) &&
	    sink->record(sink->state, NCFG_HOOK_PHASE_DOWN, "eth0", "ip -o addr\n", 11u, &second,
	    message, sizeof(message)),
	    "two hooks of one phase on one interface are recorded");
	/* The index is what keeps them apart, and it is the count so far rather
	 * than a per-owner counter -- the same name the Rust produces. */
	check(ends_with(first.path, "eth0.down.0") && ends_with(second.path, "eth0.down.1"),
	    "and they are named apart by the order the compiler reached them");
	check(ncfg_pending_hooks_write(pending, message, sizeof(message)), "both are written");

	written = testdir_read(first.path, &length);
	check(written && strcmp(written, "#!/bin/sh\nip -o link\n") == 0,
	    "a body with no shebang is given one, and is not indented");
	free(written);

	free(first.path);
	free(first.sha256);
	free(second.path);
	free(second.sha256);
	ncfg_pending_hooks_free(pending);
}

static void writing_nothing_creates_nothing(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	char hooks_dir[512];
	ncfg_pending_hooks_t *pending = ncfg_pending_hooks_new(run_dir, message, sizeof(message));

	/* `apply` calls the write unconditionally, and most machines have no hooks
	 * at all; creating an empty directory for them would put a side effect
	 * back on a path that no longer has one. */
	check(ncfg_pending_hooks_write(pending, message, sizeof(message)),
	    "writing nothing succeeds");
	check(!testdir_exists(testdir_in(run_dir, "hooks", hooks_dir, sizeof(hooks_dir))),
	    "and creates nothing, not even the directory");
	ncfg_pending_hooks_free(pending);
}

static void the_unwritten_sink_names_a_path_that_cannot_run(void)
{
	char message[NCFG_ERROR_MAX] = "";
	const ncfg_hook_sink_t *sink = ncfg_hook_sink_unwritten();
	ncfg_hook_ref_t reference;
	ncfg_hook_ref_t from_pending;
	ncfg_pending_hooks_t *pending;

	memset(&reference, 0, sizeof(reference));
	memset(&from_pending, 0, sizeof(from_pending));
	check(sink->record(sink->state, NCFG_HOOK_PHASE_POST_UP, "eth0", "echo hi\n", 8u,
	    &reference, message, sizeof(message)),
	    "a caller compiling to read accepts a hook rather than refusing it");
	/*
	 * The refusing sink is what those callers used, and every one of them gave
	 * a wrong answer on any machine with a hook: `install_drop_in` refused
	 * every configuration write, and `load_with_profile` returned before
	 * adding the selected profile's directory (0258, 0262).
	 */
	check(reference.path && strcmp(reference.path, NCFG_HOOK_NOT_MATERIALISED) == 0,
	    "and names the placeholder rather than a file");
	check(reference.path && reference.path[0] == '/',
	    "which is absolute, because validate refuses a hook path that is not");

	/* **The same hash as the pending sink would have produced.** Two copies of
	 * the shebang rule would be a document whose hash does not match the file
	 * the runner checks. */
	pending = ncfg_pending_hooks_new("/nonexistent-run-dir-never-created", message,
	    sizeof(message));
	{
		const ncfg_hook_sink_t *other = ncfg_pending_hooks_sink(pending);

		check(other->record(other->state, NCFG_HOOK_PHASE_POST_UP, "eth0", "echo hi\n", 8u,
		    &from_pending, message, sizeof(message)) &&
		    strcmp(from_pending.sha256, reference.sha256) == 0,
		    "the two sinks hash exactly the same bytes");
	}
	ncfg_pending_hooks_free(pending);
	free(from_pending.path);
	free(from_pending.sha256);
	free(reference.path);
	free(reference.sha256);
}

/* ------------------------------------------------- the mode, while it is written */

/* A megabyte, which is what opens the window wide enough to look into. Under
 * the materialiser's own ceiling, with room for the shebang it will prepend. */
#define BIG_BODY (1024u * 1024u - 64u)

/* Nothing here may outlive the round it belongs to: the poller stops on the
 * flag file the parent writes, and on its own clock if that never arrives. */
#define POLL_SECONDS 3

/*
 * Every permission bit ever seen on the file other than 0700, or 0.
 *
 * The child stats in a loop until the flag appears. It reports through a pipe
 * rather than an exit status because a mode does not fit in one.
 */
static int widest_mode_seen_while_writing(const char *path, const char *flag,
    ncfg_pending_hooks_t *pending)
{
	int fds[2];
	pid_t child;
	int seen = 0;
	char message[NCFG_ERROR_MAX] = "";

	if (pipe(fds) != 0) {
		return -1;
	}
	fflush(NULL);
	child = fork();
	if (child < 0) {
		(void)close(fds[0]);
		(void)close(fds[1]);
		return -1;
	}
	if (child == 0) {
		time_t stop = time(NULL) + POLL_SECONDS;
		long i;
		int found = 0;

		(void)close(fds[0]);
		for (i = 0; i < 40000000L; i++) {
			struct stat about;

			if (stat(path, &about) == 0) {
				int mode = (int)(about.st_mode & (mode_t)0777);

				if (mode != 0700) {
					found |= mode;
				}
			}
			if ((i & 1023) == 0) {
				if (testdir_exists(flag) || time(NULL) > stop) {
					break;
				}
			}
		}
		(void)!write(fds[1], &found, sizeof(found));
		(void)close(fds[1]);
		_exit(0);
	}
	(void)close(fds[1]);
	/* Long enough that the poller is certainly in its loop before the write
	 * starts, and short enough that a person waits for it. */
	{
		struct timespec wanted = { 0, 2000000L };

		(void)nanosleep(&wanted, NULL);
	}
	(void)ncfg_pending_hooks_write(pending, message, sizeof(message));
	(void)close(open(flag, O_WRONLY | O_CREAT, 0600));
	if (read(fds[0], &seen, sizeof(seen)) != (ssize_t)sizeof(seen)) {
		seen = -1;
	}
	(void)close(fds[0]);
	while (waitpid(child, NULL, 0) < 0) {
		if (errno != EINTR) {
			break;
		}
	}
	(void)unlink(flag);
	return seen;
}

static void the_mode_is_never_wide_even_for_an_instant(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	char flag[512];
	char last[512] = "";
	char *body = malloc(BIG_BODY);
	int seen = 0;
	int round;
	mode_t previous;

	if (!body) {
		check(0, "a big body could be allocated");
		return;
	}
	memset(body, 'a', BIG_BODY);
	body[BIG_BODY - 1u] = '\n';
	(void)testdir_in(run_dir, "written", flag, sizeof(flag));

	/* **With no umask**, so that nothing but this code's own mode can be what
	 * tightens the file. A materialiser that leaned on the umask would be one
	 * that leaves a hook world-readable wherever the umask is 0, which a
	 * daemon started from a shell that said so is. */
	previous = umask(0);
	for (round = 0; round < 6 && seen == 0; round++) {
		ncfg_pending_hooks_t *pending = ncfg_pending_hooks_new(run_dir, message,
		    sizeof(message));
		const ncfg_hook_sink_t *sink = ncfg_pending_hooks_sink(pending);
		ncfg_hook_ref_t reference;

		memset(&reference, 0, sizeof(reference));
		if (!sink->record(sink->state, NCFG_HOOK_PHASE_UP, "eth0", body, BIG_BODY,
		    &reference, message, sizeof(message))) {
			check(0, "a big body is recorded");
			ncfg_pending_hooks_free(pending);
			break;
		}
		(void)unlink(reference.path);
		seen = widest_mode_seen_while_writing(reference.path, flag, pending);
		(void)snprintf(last, sizeof(last), "%s", reference.path);
		free(reference.path);
		free(reference.sha256);
		ncfg_pending_hooks_free(pending);
	}
	(void)umask(previous);

	/*
	 * **The round has to have written something**, or the poller looked at a
	 * file that never appeared and reported a clean result about nothing. This
	 * is the assertion that stops that being a pass.
	 */
	{
		size_t length = 0;
		char *written = last[0] ? testdir_read(last, &length) : NULL;

		check(written && length == BIG_BODY + 10u,
		    "the megabyte script was written while it was being watched");
		free(written);
	}
	check(testdir_mode(last) == 0700, "and it is 0700 under umask 0");
	check(seen == 0, "no other process can ever see it at a wider mode than 0700");
	if (seen > 0) {
		printf("    the widest mode seen while it was being written was %04o\n",
		    (unsigned int)seen);
	}
	free(body);
}

static void a_file_an_older_build_left_wide_is_tightened(const char *run_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_pending_hooks_t *pending = ncfg_pending_hooks_new(run_dir, message, sizeof(message));
	const ncfg_hook_sink_t *sink = ncfg_pending_hooks_sink(pending);
	ncfg_hook_ref_t reference;
	char *written;

	memset(&reference, 0, sizeof(reference));
	(void)sink->record(sink->state, NCFG_HOOK_PHASE_CARRIER, "eth1", "true\n", 5u, &reference,
	    message, sizeof(message));
	/* The directory has to exist for the fixture, which is what the write
	 * would have made. */
	(void)ncfg_pending_hooks_write(pending, message, sizeof(message));
	check(chmod(reference.path, (mode_t)0666) == 0 && testdir_mode(reference.path) == 0666,
	    "a hook left world-readable by an older build");
	check(ncfg_pending_hooks_write(pending, message, sizeof(message)) &&
	    testdir_mode(reference.path) == 0700,
	    "is tightened rather than trusted: `open` only applies its mode on create");
	written = testdir_read(reference.path, NULL);
	check(written && strcmp(written, "#!/bin/sh\ntrue\n") == 0,
	    "and holds the script, not a truncated one");
	free(written);
	free(reference.path);
	free(reference.sha256);
	ncfg_pending_hooks_free(pending);
}

int main(void)
{
	const char *run_dir = testdir_make("hooks");

	printf("== hooks_test in %s\n", run_dir);
	the_digest_matches_the_published_vectors();
	recording_touches_nothing(run_dir);
	writing_nothing_creates_nothing(run_dir);
	writing_puts_the_recorded_body_where_the_reference_says(run_dir);
	a_body_with_no_shebang_gets_one(run_dir);
	the_unwritten_sink_names_a_path_that_cannot_run();
	a_file_an_older_build_left_wide_is_tightened(run_dir);
	the_mode_is_never_wide_even_for_an_instant(run_dir);
	testdir_remove(run_dir);

	if (failures == 0) {
		printf("hooks_test: all checks passed\n");
	} else {
		printf("hooks_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
