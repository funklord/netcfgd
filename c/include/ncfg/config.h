/*
 * config.h -- reading the configuration directory, and writing into it.
 *
 * This is `crates/netcfgd-host/src/config.rs` in C: the one thing the compiler
 * will not do for itself. `lower.h` opens no files on purpose -- that is what
 * keeps the whole front end testable from strings -- so somebody has to decide
 * which files are the configuration, in which order, and this is that
 * somebody.
 *
 * WHAT THE ORDER IS
 *   `netcfgd.conf` first, then every `*.conf` under `conf.d` in lexical
 *   filename order, then the selected profile's directory. The factory layer
 *   under `/usr/share` comes before the writable one under `/etc`, and it gets
 *   **no special override rule**: a runtime block redefining a factory block
 *   is the same error as one drop-in redefining another. An implicit override
 *   for one directory would make the same text mean different things depending
 *   on which directory it sat in, and the operator reading the runtime file
 *   could not tell it was discarding something.
 *
 * WHICH HOOK SINK, AND WHY IT IS THE SAME ONE EVERYWHERE HERE
 *   **Every compile in this module is a compile to read.** Which profile is
 *   selected, would this drop-in still compile, does the fold reproduce what
 *   the machine runs -- each throws the document away afterwards and none of
 *   them has anywhere to put a script. So every one of them passes
 *   `ncfg_hook_sink_unwritten()`, and each call site says so.
 *
 *   The Rust reached for `NoHooks` -- `ncfg_hook_sink_refusing()` here --
 *   whose entire behaviour is to refuse a hook, at ten such sites, and two of
 *   the consequences were not small (project.md, the `UnwrittenHooks`
 *   section): `install_drop_in` refused **every** configuration write on any
 *   machine with one hook in its configuration, blaming the file being written
 *   rather than the check doing the writing; and `load_with_profile` returned
 *   before adding the selected profile's directory, so `ncfg profile set`
 *   wrote a selection, reported success, and the profile was never read again.
 *   Both have a case in `c/tests/config_test.c` naming them.
 *
 *   Nothing in this module compiles a document to *act* on, so the refusing
 *   sink is right at none of these sites.
 *
 * THE CONVENTIONS ARE `base.h`'S
 *   1 for success and 0 for failure, `NULL` for a pointer, `char *err` last,
 *   and one `_free` per aggregate.
 *
 *   The one addition is `denied`, an optional `int *` on the writing calls.
 *   **It is not inferable from the message and must not be inferred from it.**
 *   `ncfg wifi add` run by a member of the `wifi` group has the permission and
 *   not the access, and has to tell "the kernel would not let me write this"
 *   apart from every other refusal so it can ask the daemon instead. Matching
 *   on the words of a sentence would work and would stop working silently the
 *   day somebody rewords one.
 */
#ifndef NCFG_CONFIG_H
#define NCFG_CONFIG_H

#include <stddef.h>

#include "ncfg/document.h"
#include "ncfg/lower.h"

/* Where config lives when nothing says otherwise. */
#define NCFG_CONFIG_DIR_DEFAULT "/etc/netcfgd"

/*
 * Where the factory-default config lives when nothing says otherwise.
 *
 * Under `/usr/share` rather than `/etc` because it is part of the image, not
 * part of the machine's configuration: on a read-only squashfs root `/etc` is
 * the writable overlay and this is what sits underneath it. A machine with no
 * factory config -- which is every ordinary install -- simply has nothing
 * here, and the layering costs it a `stat`.
 */
#define NCFG_FACTORY_DIR_DEFAULT "/usr/share/netcfgd"

/* What overrides each, so the whole tool can be exercised against a fixture
 * tree without touching `/etc`. Every test in this port does exactly that. */
#define NCFG_CONFIG_DIR_ENV "NCFG_CONFIG_DIR"
#define NCFG_FACTORY_DIR_ENV "NCFG_FACTORY_DIR"

/*
 * The drop-in `ncfg profile set` owns, without its `.conf`.
 *
 * Numbered high so a profile selection layers over the `conf.d` files that
 * describe the machine, and fixed so that switching twice edits one file
 * rather than accumulating them. Named once and read from here by the command
 * that writes it and by the guard that checks it, so the two cannot drift
 * apart -- a guard watching a filename the writer no longer uses is a guard
 * that passes vacuously for ever.
 */
#define NCFG_PROFILE_DROP_IN "90-profile"

/*
 * The most a single configuration file may be.
 *
 * **A divergence, and a reluctant one.** The Rust deliberately refuses a size
 * limit here and checks the file *type* instead, on the argument that a
 * configuration file is something somebody wrote and any number would be
 * invented. The type check is kept and is still the real defence -- it is what
 * stops `include "/dev/zero"` allocating until the machine runs out -- but
 * `ncfg_host_read_file` takes a ceiling and there is no way to spell "none"
 * that does not overflow its arithmetic. Sixteen megabytes is far past any
 * configuration and short of anything that hurts a daemon whose whole resident
 * budget is five.
 */
#define NCFG_CONFIG_FILE_MAX (16u * 1024u * 1024u)

/*
 * The config directory to use: the explicit one, then the environment, then
 * the default.
 *
 * Copies into `out` and returns it, which is `ncfg_state_resolve_dir`'s shape
 * and for its reason: one buffer, no ownership question. Never NULL.
 */
const char *ncfg_config_resolve_dir(const char *explicit_dir, char *out, size_t out_size);

/* The same for the factory layer. */
const char *ncfg_config_resolve_factory_dir(const char *explicit_dir, char *out, size_t out_size);

/* ------------------------------------------------------------------------ *
 * What a directory holds
 * ------------------------------------------------------------------------ */

/*
 * One file the loader read: the name to put on a diagnostic, and the text.
 *
 * `text` is the file **with its `include` statements already expanded away**:
 * the included file arrives as its own entry, ahead of the one that names it,
 * and the statement is dropped. The compiler opens no files and refuses an
 * unresolved include by name, so anything missed here is reported rather than
 * quietly lost.
 */
typedef struct {
	char  *name;
	char  *text;
	size_t length;
} ncfg_config_file_t;

/*
 * Every file a load found, in precedence order.
 *
 * This is the Rust's `SourceMap` and it holds text rather than trees on
 * purpose: **a file that does not parse still has to be in the set.** The
 * loader's job is to say what the configuration *is*, and a base that does not
 * compile has no profile to find -- the caller compiles it next and reports a
 * diagnostic that points at the line. A loader that refused here would replace
 * that diagnostic with one that points nowhere.
 *
 * Declare one as `ncfg_config_sources_t sources = {0}` and free it with
 * `ncfg_config_sources_free`.
 */
typedef struct {
	ncfg_config_file_t *at;
	size_t              count;
	size_t              capacity;
} ncfg_config_sources_t;

/* Release what a source set holds, and leave it usable and empty. Freeing one
 * that was never filled in is nothing. */
void ncfg_config_sources_free(ncfg_config_sources_t *sources);

/*
 * Read one config directory into `out`, appending in precedence order.
 *
 * **A missing directory is not an error**: an empty config is a legitimate
 * state and compiles to an empty document, which plans to do nothing. A
 * directory or a file that is *there and cannot be examined* is a different
 * thing and is refused, naming the path and the kernel's own reason.
 *
 *   Measured before that distinction existed, with `netcfgd.conf` made a
 *   symlink to itself: `ncfg apply` compiled an empty document, printed
 *   `ok addr.del read0`, took the address off the interface and exited 0. A
 *   machine deconfigured because a file could not be read, with nothing
 *   anywhere saying so.
 *
 * `out` is appended to rather than replaced, so a caller may layer.
 */
int ncfg_config_load(const char *dir, ncfg_config_sources_t *out, char *err, size_t err_size);

/*
 * The factory layer and then the writable one.
 *
 * Ordering is the whole mechanism and it is the drop-in ordering the language
 * already has: the factory directory behaves exactly as if its files sorted
 * before the runtime ones. Neither layer has to exist.
 *
 * The same directory named twice is read once. Harmless today -- merging a
 * block with an identical copy is a no-op -- but it would double every
 * `members` list, so it is refused rather than relied upon.
 */
int ncfg_config_load_layered(const char *factory_dir, const char *config_dir,
    ncfg_config_sources_t *out, char *err, size_t err_size);

/*
 * The base configuration, plus the chosen profile's directory if there is one.
 *
 * **A profile is the same mechanism pointed at another directory** (0151):
 * every `*.conf` under `<root>/profile/<name>`, factory then runtime, read
 * after `conf.d` so it layers on top and `override` means what it always
 * meant.
 *
 * **Finding the name costs a compile.** The selector is in the configuration
 * language rather than a bare file beside it, so the base has to be compiled
 * before netcfgd knows which directory to open -- with the unwritten hook
 * sink, because this is a question and not an application.
 *
 * **A profile that names a profile is refused** rather than followed. A loader
 * that re-read until the answer stopped changing is the same shape as the
 * automatic switching 0151 declined, and it would let a profile capture the
 * machine.
 *
 * **A hand edit cannot take the selection away.** What `90-profile` asks for
 * on its own is checked against what the configuration as a whole says; a
 * disagreement means some other file wrote `override global` and replaced the
 * block whole, taking the profile with it, and that is the automatic switch to
 * no profile 0151 forbids. The refusal names the likely culprit.
 *
 * A base configuration that does not compile is **not** an error here.
 */
int ncfg_config_load_with_profile(const char *factory_dir, const char *config_dir,
    ncfg_config_sources_t *out, char *err, size_t err_size);

/*
 * Parse everything in `sources` and compile it.
 *
 * The other half of the loader: `ncfg_compile` takes parsed trees, and the
 * only thing that ever knew which bytes came from which file is whatever read
 * the directory.
 *
 * Returns the document, or NULL with every diagnostic in `diags` -- parse
 * failures included, each carrying the name of the file it is about -- and the
 * first sentence in `err`. `diags` may be NULL for a caller that wants only
 * the sentence.
 *
 * `hooks` is the caller's choice and the header comment says which one every
 * caller in this module passes.
 *
 * **A set of no files compiles to an empty document**, which is a divergence
 * from `ncfg_merge` and not from the Rust: merge refuses "nothing to merge",
 * which is right for a caller that passed nothing by mistake and wrong for the
 * one caller that legitimately has none. A machine with no `/etc/netcfgd` is
 * an ordinary machine and must plan to do nothing rather than fail to compile.
 */
ncfg_document_t *ncfg_config_compile(const ncfg_config_sources_t *sources,
    const ncfg_hook_sink_t *hooks, ncfg_lower_diags_t *diags, char *err, size_t err_size);

/*
 * The same compile, with the side table of where each field was written.
 *
 * `provenance` is zeroed by the caller and filled in here, and is the caller's
 * to free with `ncfg_provenance_free` however the compile ends -- a compile
 * that failed part way still recorded the positions it had reached, and
 * leaving them unreachable would be a leak on the path that already went
 * wrong.
 *
 * **Separate from the call above rather than an argument to it**, which is the
 * Rust's arrangement and `lower.h`'s: almost every caller wants a document and
 * nothing else, and a positions table nobody reads is a second thing that has
 * to go on agreeing with the document. `ncfg explain` is the one caller that
 * wants it -- it answers "because `conf.d/10-lan.conf` line 4 says so" -- and
 * this is how it asks.
 *
 * A set of no files fills in nothing and is not a failure, exactly as above.
 */
ncfg_document_t *ncfg_config_compile_with_provenance(const ncfg_config_sources_t *sources,
    const ncfg_hook_sink_t *hooks, ncfg_provenance_t *provenance, ncfg_lower_diags_t *diags,
    char *err, size_t err_size);

/*
 * Every config file in one directory, in the order the loader would read them.
 *
 * The list `ncfg reset` removes, and the list it prints. Deliberately the same
 * enumeration as the loader rather than a glob written twice: a reset that
 * removed a different set from the one that gets loaded would leave files
 * behind that still configure the machine.
 *
 * Files pulled in by `include` are not in it. An include may point anywhere,
 * including outside the config directory, and deleting a path because
 * something mentioned it is not a thing a reset should do.
 *
 * A missing directory lists nothing and is not an error.
 */
int ncfg_config_writable_files(const char *config_dir, char ***out, size_t *count_out, char *err,
    size_t err_size);

/*
 * One configuration file, as a client is shown it.
 *
 * `name` is the drop-in's stem and is **empty for a file that is not one**:
 * `name` is what `config put` and `config delete` take, so a file without one
 * is a file a client cannot address. `file` is relative to the config
 * directory -- `netcfgd.conf`, or `conf.d/wifi-home.conf` -- which is what a
 * person recognises and what a client shows.
 */
typedef struct {
	char *name;
	char *file;
	int   removable;
	char *text;
} ncfg_config_entry_t;

void ncfg_config_entries_free(ncfg_config_entry_t *entries, size_t count);

/*
 * Every configuration file netcfgd reads, with its contents.
 *
 * The same enumeration as the loader, through `ncfg_config_writable_files`,
 * for that call's reason: a listing that showed a different set from the one
 * that gets loaded would offer an editor for a file that configures nothing,
 * or hide one that does.
 *
 * **A file under `conf.d` is removable and everything else is not**, which is
 * the same rule `ncfg_config_remove_drop_in` enforces: the base configuration
 * is the operator's own and netcfgd does not offer to delete it.
 *
 * A file that cannot be read is left out rather than listed empty. An empty
 * `text` means an empty file, and a client that wrote that back would truncate
 * a file it was never shown -- which is the one mistake this listing could
 * cause. **That case is a race and nothing else**: the enumeration stats every
 * candidate and takes only regular files, so a file reaches the read here
 * unless it is removed in between. It is handled rather than asserted on for
 * that reason, and a sabotage of it catches nothing because nothing can set it
 * up. A directory that is not there lists nothing and is not an error.
 */
int ncfg_config_list_drop_ins(const char *config_dir, ncfg_config_entry_t **out,
    size_t *count_out, char *err, size_t err_size);

/*
 * One probe script, as a client is shown it.
 *
 * `directory` is where it was found, spelled out, so a client showing two of
 * the same name can say which is which -- and `editable` says whether this is
 * the copy `probe put` would replace: netcfgd writes into the operator's
 * directory and never into the one the package ships.
 */
typedef struct {
	char *name;
	char *directory;
	char *text;
	int   editable;
} ncfg_probe_entry_t;

void ncfg_probe_entries_free(ncfg_probe_entry_t *entries, size_t count);

/*
 * Every probe script this machine has, the operator's layer first.
 *
 * **A name in the operator's directory hides the shipped one of that name**,
 * which is what running one does: the probe runner looks in the same order, so
 * a listing that showed both would offer an editor for a script that never
 * executes.
 *
 * Sorted within each directory, so two runs of the same machine list the same
 * thing in the same order. Only regular files, and one that cannot be read is
 * left out for `ncfg_config_list_drop_ins`' reason -- an empty `text` written
 * back would truncate a program netcfgd runs as root.
 *
 * A directory that is not there contributes nothing and is not an error: a
 * machine with no probes of its own is the ordinary one.
 */
int ncfg_probe_list(const char *config_dir, const char *factory_dir,
    ncfg_probe_entry_t **out, size_t *count_out, char *err, size_t err_size);

/* Free a list of paths and zero the count. Freeing NULL is nothing. */
void ncfg_config_paths_free(char **paths, size_t count);

/* ------------------------------------------------------------------------ *
 * Writing
 * ------------------------------------------------------------------------ */

/*
 * Write a file, through a temporary and a rename where the directory allows
 * it and in place where it does not.
 *
 * The staging half is `ncfg_write_atomically`'s, shared rather than copied. A
 * reader -- and the daemon's inotify watch is one -- sees either the old file
 * or the new one and never half of either, and the temporary carries the final
 * mode from the moment it exists, which for a credential is the whole point.
 *
 * **The fallback is decision 0161 and it is the half the previous worker left
 * here.** A sandbox can grant a *file* without granting the directory it sits
 * in: `packaging/systemd/netcfgd.service` names `/etc/resolv.conf` in
 * `ReadWritePaths=` while `ProtectSystem=full` holds `/etc` read-only, and
 * staging a temporary beside a file is creating a new entry in a directory
 * that stays refused. Every path netcfgd writes today sits in a directory the
 * unit grants whole, so this is unreached on the packaged unit -- it is here
 * because the shape is the same and the next path added must not have to
 * rediscover it.
 *
 * It engages on a refusal and on nothing else. A full disk also fails to
 * stage, and falling back there would truncate a config file and then fail to
 * refill it.
 *
 * `denied` may be NULL; where it is given it says whether the filesystem
 * refused this process rather than the request being wrong.
 */
int ncfg_config_write_atomically(const char *path, const void *bytes, size_t length,
    unsigned int mode, int *denied, char *err, size_t err_size);

/*
 * Write a file that already exists, without staging beside it.
 *
 * `ncfg_config_write_atomically`'s fallback, exposed because 0161 is a
 * property of the pattern rather than of one caller and because a test that
 * cannot reach it proves nothing about it.
 *
 * It gives up atomicity, which is the trade: a reader can catch this mid-write
 * where a rename could not be caught at all, and the alternative is not
 * writing.
 *
 * **It will not follow a symlink.** Writing through one edits whatever owns
 * the target, which nothing here has been asked to do. **Existing files only**,
 * and the mode is set explicitly, because a secret written back at 0600 must
 * not inherit whatever the file already carried.
 *
 * `refusal` is the errno the staging failure gave, and every message names it:
 * without that the fallback speaks over the real cause. Opening a file that is
 * not there answers `ENOENT`, so a drop-in refused by a read-only `/etc` was
 * reported as "No such file or directory" about a file the operator has never
 * seen, for a write they had just asked for.
 *
 * **The errno rather than its sentence**, because the message is only half of
 * what a caller needs from it: `EROFS` earns an extra sentence about the mount
 * and `EACCES` does not, and deciding that by looking for the words
 * "Read-only file system" would be a test that stops working in another
 * locale, silently, by turning the sentence off. 0 where the caller has no
 * errno to give.
 */
int ncfg_config_write_in_place(const char *path, const void *bytes, size_t length,
    unsigned int mode, int refusal, char *err, size_t err_size);

/*
 * Put a configuration drop-in on disk, and prove the result still compiles.
 *
 * 0127: netcfgd is the only writer of `/etc/netcfgd`, so this is where
 * configuration a client sent ends up.
 *
 * **The compile-back check is not a formality.** A drop-in that parses on its
 * own can still break the whole configuration, because redefining a block
 * another file already defines is an error by design -- and a machine whose
 * configuration stopped compiling is one where the next reload changes nothing
 * and says why in a log nobody is reading. Refusing costs the caller a
 * diagnostic; accepting costs the operator their next boot.
 *
 * **Verified with the profile, not without it.** This checked through the
 * unprofiled loader once, so `ncfg profile set` wrote a selection, compiled a
 * configuration that excluded the very profile it had just chosen, and
 * reported success.
 *
 * **What was there is put back when the result would not compile**, including
 * an absence: refusing after the write means the file on disk is briefly the
 * new one, and leaving it there would be a rejected change that took effect
 * anyway.
 *
 * An existing file is refused unless `replace`. `path_out` and `denied` may be
 * NULL; what `path_out` receives is the caller's to free.
 */
int ncfg_config_install_drop_in(const char *config_dir, const char *factory_dir, const char *name,
    const char *text, int replace, char **path_out, int *denied, char *err, size_t err_size);

/*
 * Remove a drop-in, and prove what is left still compiles.
 *
 * The mirror of the install and it needs the same check for the same reason:
 * removing a file can break the configuration as surely as adding one -- a
 * drop-in another file's `override` refers to, say -- and the file is put back
 * when it does.
 *
 * **An absent file is success, and `removed` is how the caller can tell.** It
 * had no way to: the Rust returned the same thing for a drop-in it removed and
 * for one that was never there, so `ncfg config rm` printed "is not in" on the
 * success path and told an operator their removal had not happened. It had.
 *
 * `removed` and `denied` may be NULL.
 */
int ncfg_config_remove_drop_in(const char *config_dir, const char *factory_dir, const char *name,
    int *removed, int *denied, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Profiles
 * ------------------------------------------------------------------------ */

/* One profile this machine has. `shipped` says it came from the factory layer,
 * which is what decides whether editing it is editing the image. */
typedef struct {
	char *name;
	int   shipped;
} ncfg_profile_entry_t;

void ncfg_profile_entries_free(ncfg_profile_entry_t *entries, size_t count);

/*
 * The profiles this machine has, in name order, from both layers.
 *
 * The operator's are listed first, so a name in both reads as theirs -- which
 * is what it effectively is, since their files layer over the shipped ones.
 * The same rule the loader reads by, so the list and the load agree: two
 * enumerations of one directory is how a gui comes to offer a profile the
 * loader will not read.
 *
 * A directory that cannot be read lists nothing. This is a listing, and a
 * machine that has never configured a profile is the ordinary case.
 */
int ncfg_profile_list(const char *config_dir, const char *factory_dir,
    ncfg_profile_entry_t **out, size_t *count_out, char *err, size_t err_size);

/*
 * Whether a name can be a profile.
 *
 * **A profile name is two things and this used to check only one.** It is a
 * directory under `profile/`, which is why `/`, `..` and a leading dot are
 * refused -- and it is also written into a quoted string in the `90-profile`
 * drop-in, which nothing escaped. So a name carrying a quote and a newline
 * closed the string and appended whatever followed:
 *
 *     ncfg profile save 'evil"
 *     }
 *     global {
 *     	hostname = "PWNED"
 *     }
 *     global {
 *     	profile = "evil'
 *
 * compiled, which is what got it past the drop-in's own name check, and the
 * next reload took the injected `hostname`. Reproduced against the shipped
 * binary; a `hooks` block in the same position is shell that runs as root.
 *
 * It is `ncfg_secret_name_usable` asked again rather than restated, because
 * that is the same question -- a name that is both a filename and a value in
 * the language -- and one place to be right beats two to keep in step.
 */
int ncfg_profile_name_usable(const char *name, char *err, size_t err_size);

/*
 * Select a profile: write the `90-profile` drop-in, and prove it compiles
 * **with that profile's own directory folded in**.
 *
 * The verification is the install's, which is what makes this more than a
 * write: a profile whose drop-in does not parse was accepted once, and every
 * command after it failed on the config until somebody thought to run
 * `profile unset`.
 *
 * The one place that spells `global { profile = "..." }`, so the name is
 * validated before it can reach a quoted string.
 */
int ncfg_profile_set(const char *config_dir, const char *factory_dir, const char *name,
    int *denied, char *err, size_t err_size);

/* Take the selection away, leaving the base exactly as it is. `removed` says
 * whether there was one; both out parameters may be NULL. */
int ncfg_profile_unset(const char *config_dir, const char *factory_dir, int *removed, int *denied,
    char *err, size_t err_size);

/*
 * Take the machine off its profile without changing what it is running.
 *
 * 0151: changing a setting by hand puts the machine on "none chosen". The
 * profile's own drop-ins are folded into `conf.d` in the same step, so the
 * compiled document is identical afterwards and only the label moves. Without
 * that, a one-line edit could drop every override a profile carried -- an
 * address, a route, the link the operator is connected over -- as a side
 * effect of changing something unrelated.
 *
 * **The fold is proved, not trusted.** The document is compiled before and
 * after and must be equal but for the selection itself; anything else and
 * nothing is written. That is this tree's rule for a mechanical rewrite,
 * applied here because this one is made on somebody's behalf while they were
 * doing something else.
 *
 * **Verified through the real loader rather than a model of it.** A first
 * attempt built a candidate in memory and appended the folded file last, which
 * is not where it sorts on disk -- so it proved a layering that would never
 * happen and passed a fold that changed the machine's MTU. That is why this
 * writes first and undoes when the answer is wrong.
 *
 * Returns 1 with `*folded_out` naming the profile that was folded, or NULL
 * where none was chosen -- which is the common case and is not an error. What
 * `folded_out` receives is the caller's to free.
 */
int ncfg_profile_adopt(const char *config_dir, const char *factory_dir, char **folded_out,
    char *err, size_t err_size);

/*
 * Undo a fold, because the settings write it was made for did not happen.
 *
 * The fold has to come first -- folding after the write would have to preserve
 * a document in which the profile still overrides the new edit, so it would
 * land late and the edit would never take effect. Coming first means it can be
 * made for a write that is then refused, and a rejected edit must not move the
 * selection.
 */
int ncfg_profile_restore(const char *config_dir, const char *name, char *err, size_t err_size);

/*
 * Write what this machine is running into a profile, and select it.
 *
 * `running` is the document to snapshot. The order matters and each step
 * undoes on failure: the fold comes out of `conf.d` first, because leaving it
 * would keep a copy of the old profile in the base for ever -- still in force
 * after switching away, which is not what "saved it into office" means to
 * anybody -- then the snapshot, then the selection, then the proof.
 *
 * **The proof is what the machine compiles to now against what it was
 * running**, but for the selection this just made. A snapshot that does not
 * reproduce it is a fault in the renderer rather than in the configuration,
 * and nothing is kept.
 *
 * An existing profile is refused rather than merged unless `replace`; the
 * message names `how_to_replace`, because only the caller knows whether that
 * is a flag or a button and a message naming the wrong one is worse than one
 * naming neither. A profile directory with no snapshot in it was written by
 * hand and is refused outright: saving over it would discard files this cannot
 * reproduce.
 */
int ncfg_profile_save(const char *config_dir, const char *factory_dir, const char *name,
    int replace, const ncfg_document_t *running, const char *how_to_replace, char **path_out,
    int *denied, char *err, size_t err_size);

#endif /* NCFG_CONFIG_H */
