/*
 * hooks.h -- naming hook bodies now, and writing them when somebody asks.
 *
 * WHAT A HOOK IS
 *   Section 2.2: the configuration language lets an author write inline shell
 *   in a `post_up { ... }` block, and the document carries only
 *   `{phase, path, sha256}`. A document that could carry shell would be remote
 *   code execution with extra steps, and the reference closes that
 *   structurally rather than by policy.
 *
 * WHY RECORDING AND WRITING ARE TWO STEPS
 *   Turning a body into that triple needs no filesystem -- the path is a
 *   naming rule and the hash is of the body -- so this records, and writing is
 *   a second, explicit step a caller has to ask for.
 *
 *   **It used to write during compilation.** That made five of six read-only
 *   CLI paths write files, and left a compile that failed halfway with some of
 *   its scripts already on disk. `ncfg plan` said it changed nothing while
 *   changing the machine, and a compile could not run anywhere without
 *   privilege. See `lower.h`'s `ncfg_hook_sink_t`, which is the interface
 *   these two implement.
 *
 * TWO SINKS, AND WHY THE SECOND EXISTS
 *   `ncfg_pending_hooks_t` records and writes on request. `ncfg_hook_sink_
 *   unwritten` records and names no file, for a caller that compiles the
 *   machine's configuration in order to **read** it.
 *
 *   **Not every compile is a compile to run** (0258, 0262). Something like a
 *   dozen places compile the configuration to ask it a question -- which
 *   profile is selected, does this drop-in still parse, what did forgetting
 *   that network leave behind -- and then throw the document away. Every one
 *   of them used the refusing sink, whose whole behaviour is to refuse, so
 *   every one gave a wrong answer on any machine with a hook in its
 *   configuration. Two of the consequences were not small: `install_drop_in`
 *   refused **every** configuration write on such a machine -- which is every
 *   editor in the window and `ncfg config put` -- and `load_with_profile`
 *   returned before adding the selected profile's directory, so the profile
 *   silently did not load. The refusing sink stays for what it is documented
 *   as: a caller producing a document to *act* on with nowhere to put the
 *   scripts, where refusing loudly is right.
 *
 * WHERE THE HASH LIVES
 *   The Rust keeps `sha256_hex` in `netcfgd-model` so that the hash written
 *   here and the hash checked before execution cannot disagree. `document.h`
 *   is final and carries no hash, so the one implementation is here and the
 *   runner calls it rather than growing a second: two implementations of one
 *   digest is a hook that is refused at execution time for a difference nobody
 *   can see.
 */
#ifndef NCFG_HOOKS_H
#define NCFG_HOOKS_H

#include <stddef.h>

#include "ncfg/document.h"
#include "ncfg/lower.h"

/* 64 hex digits and the terminator. */
#define NCFG_SHA256_HEX_SIZE 65

/*
 * SHA-256 of `length` bytes, as lowercase hex, NUL-terminated.
 *
 * `out` is `NCFG_SHA256_HEX_SIZE` bytes. Never fails: there is nothing to
 * allocate and no input it refuses.
 */
void ncfg_sha256_hex(const void *bytes, size_t length, char *out);

/*
 * The path a document gets when nothing was written.
 *
 * Absolute, because `ncfg_document_validate` requires a hook path to be -- a
 * sentence in parentheses was refused there, which is the check doing its job.
 * Under `/nonexistent`, because a document from the unwritten sink is for
 * reading: if one ever reaches the runner anyway it has to fail at the `exec`
 * naming this path, rather than run whatever happens to sit somewhere
 * plausible.
 */
#define NCFG_HOOK_NOT_MATERIALISED "/nonexistent/netcfgd/hook-compiled-for-reading"

/*
 * The bytes that get written, from the body as the author wrote it.
 *
 * A hook body is shell and the runner executes it directly rather than through
 * `sh -c`, so it needs a shebang and the execute bit. **A body that already
 * declares one keeps it** -- which is what makes an editor's round trip stable:
 * read the file back, write it out again, and the script does not grow a line
 * (0258). The body is never indented for the same reason; indent it and the
 * shebang stops being a shebang, so the next save adds another one and the
 * script netcfgd runs grows by a line every time it is edited.
 *
 * Returns the bytes, which the caller owns and frees, with the length in
 * `*length_out` where that is given. NULL on allocation failure.
 */
char *ncfg_hook_script(const char *body, size_t body_length, size_t *length_out, char *err,
    size_t err_size);

/*
 * Hook bodies named and held, ready to be written.
 *
 * Opaque: what it holds is the naming rule's output and the bodies, and a
 * caller that could see them would be a caller tempted to write them itself.
 */
typedef struct ncfg_pending_hooks ncfg_pending_hooks_t;

/*
 * Name into `run_dir/hooks/`, **without creating it**.
 *
 * `run_dir` is copied. Returns NULL with a sentence in `err`.
 */
ncfg_pending_hooks_t *ncfg_pending_hooks_new(const char *run_dir, char *err, size_t err_size);

/* The sink to hand `ncfg_lower` or `ncfg_compile`. Valid while the pending set
 * is, and it is the same pointer every time. */
const ncfg_hook_sink_t *ncfg_pending_hooks_sink(ncfg_pending_hooks_t *pending);

/*
 * How many are waiting.
 *
 * Zero is the ordinary case: most configurations have no hooks, and a caller
 * that writes unconditionally should still not have to create a directory for
 * nothing.
 */
size_t ncfg_pending_hooks_count(const ncfg_pending_hooks_t *pending);

/*
 * Write every recorded body to the path the document refers to.
 *
 * **Called only where the hooks are about to be needed.** A read-only verb has
 * a document that names them and no reason to put them on disk; the one that
 * runs them does.
 *
 * The directory is created only when there is something to put in it, so a
 * machine with no hooks grows no empty directory and a read-only run directory
 * is not touched at all.
 *
 * Each script is **0700 from the instant it exists**: the mode goes on the
 * open, not on a later chmod. This was a write followed by a chmod, which puts
 * an operator's own shell into a world-readable file and tightens it
 * afterwards -- so the script is exposed for the window, and a descriptor
 * opened in it goes on reading after the chmod. `/run/netcfgd` is traversable
 * by anyone on the machine (`RuntimeDirectoryMode=0755`), so the window is
 * reachable. A file that already existed keeps its own mode through `open`, so
 * one left wider by an older build is tightened rather than trusted.
 *
 * Returns 1, or 0 with a sentence naming the file that could not be written.
 */
int ncfg_pending_hooks_write(const ncfg_pending_hooks_t *pending, char *err, size_t err_size);

/* Release what it holds. Freeing NULL, and one never filled in, is nothing. */
void ncfg_pending_hooks_free(ncfg_pending_hooks_t *pending);

/*
 * A sink for a caller that compiles to **read** the configuration.
 *
 * Accepts a hook, hashes exactly what `ncfg_pending_hooks_t` would have
 * written, and names no file -- see the header comment for the ten call sites
 * this exists for. Stateless, so one instance serves every caller and there is
 * nothing to free.
 */
const ncfg_hook_sink_t *ncfg_hook_sink_unwritten(void);

/*
 * The most of a hook script a listing will read back.
 *
 * `NCFG_CONFIG_FILE_MAX`'s reluctance, one file along: what a hook may contain
 * is somebody's shell and any number is invented, but `ncfg_host_read_file`
 * takes a ceiling and there is no way to spell "none" that does not overflow
 * its arithmetic. A megabyte is far past any hook and short of anything that
 * hurts a daemon whose whole resident budget is five -- and a script this
 * refuses to show is still run: nothing here decides what executes.
 */
#define NCFG_HOOK_SCRIPT_MAX (1024u * 1024u)

/*
 * One hook a document declares, with the script netcfgd would run.
 *
 * `text` is empty where `readable` is 0, and the two are not the same answer:
 * an empty script is a file somebody wrote and an unreadable one is a file
 * netcfgd could not open.
 */
typedef struct {
	char *interface;
	int   phase; /* ncfg_hook_phase_t, from value.h */
	char *path;
	int   readable;
	char *text;
} ncfg_hook_script_t;

void ncfg_hook_scripts_free(ncfg_hook_script_t *scripts, size_t count);

/*
 * Every hook the document declares, read back from disk.
 *
 * **Read rather than remembered.** The bodies pass through this process at
 * every reload -- the compiler names them and `ncfg_pending_hooks_t` writes
 * them -- and keeping a copy would be a second answer to "what runs at
 * `post_up`" that can disagree with the file the runner opens. What a caller
 * is shown is the same bytes the runner executes, including the `#!/bin/sh`
 * the materialiser prepends to a body that has none.
 *
 * **A file that is not there is listed as itself rather than skipped.** The
 * document names it, so a client that never saw the row would write an
 * `interface` block with the hook missing -- which is to say, delete a hook
 * because netcfgd could not read it. That is the opposite of
 * `ncfg_config_list_drop_ins`' rule and for the opposite reason: there the
 * listing *is* the file, and here the listing is the document's claim about a
 * file.
 *
 * **Interface hooks only.** A `network` block may carry them and this build
 * runs none of them at any phase, which the planner warns about; listing them
 * would offer an editor for something that does not execute.
 *
 * A NULL document lists nothing and is not an error: a machine whose
 * configuration does not compile declares no hooks.
 */
int ncfg_hooks_list(const ncfg_document_t *desired, ncfg_hook_script_t **out,
    size_t *count_out, char *err, size_t err_size);

#endif /* NCFG_HOOKS_H */
