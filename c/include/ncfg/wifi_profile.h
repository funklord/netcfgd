/*
 * wifi_profile.h -- writing a `network` block, for every caller allowed to.
 *
 * This is `crates/netcfgd-host/src/wifi_profile.rs` in C, and 0263 named it
 * twice as the gap that made three verbs refuse: `daemon.h`'s
 * `ncfg_wifi_install_fn` is a seam with no implementation, and `ncfg wifi add`
 * and `ncfg wifi forget` are dispatch arms that said the module was not
 * ported. This is that module, and the seam's one implementation is
 * `ncfg_wifi_profile_installer` below.
 *
 * WHY THE RENDERING LIVES HERE AND NOT IN EITHER CALLER
 *   Two callers write a `network` block: the CLI, from flags an operator
 *   typed, and the daemon, from the typed request 0117 added for a client with
 *   no permission to write the file itself. Two implementations of "what a
 *   `network` block looks like" is the drift this tree keeps finding -- most
 *   recently as three spellings of one access point's name -- so there is one,
 *   and `ncfg_wifi_profile_t` is `daemon.h`'s type rather than a second
 *   spelling of the same five fields.
 *
 * WHAT IS DELIBERATELY NOT HERE
 *   Where the credential came from. The CLI prompts with echo off; the daemon
 *   takes it from a decoded request. Both hand these bytes to
 *   `ncfg_wifi_profile_install`, which writes them through the store and
 *   leaves an `@secret:` reference in the block -- so the *document* stays free
 *   of secret material whichever caller asked.
 *
 * THE CREDENTIAL IS BYTES AND A LENGTH, AND IS NEVER COPIED
 *   0263: the request's own bytes travel to the installer, so a passphrase --
 *   or a TLS private key, which travels the same field -- exists in exactly one
 *   place for exactly as long as the decoded line does. That rule ends here:
 *   this module writes those bytes to a file and keeps none of them, and no
 *   function in it puts a credential in a buffer, a message or a path.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   Each is argued where it is implemented and listed in 0263. The three that
 *   change what is refused:
 *
 *   * **The round trip compares every field the block can carry**, where the
 *     Rust compares the enterprise five and nothing else -- although its own
 *     comment says the check covers "an SSID whose hex form did not round-trip",
 *     which nothing in it looks at. section 10.160 is the same shape one layer up.
 *   * **A credential carrying a NUL is refused**, because nothing downstream
 *     can carry one: the supplicant's control socket is lines, and anything
 *     treating the value as a C string silently stores the part before it.
 *   * **An empty credential is refused**, which is `ncfg_secret_store_put`'s
 *     rule applied at the other door into the same directory.
 */
#ifndef NCFG_WIFI_PROFILE_H
#define NCFG_WIFI_PROFILE_H

#include <stddef.h>

#include "ncfg/buf.h"
#include "ncfg/daemon.h"
#include "ncfg/document.h"

/*
 * The longest `wifi-<id>` this writes, which bounds the id at 64 bytes.
 *
 * Published so that a test cannot spell the number itself, and so that the
 * name and the check of it cannot drift: `ncfg_wifi_profile_usable_id` refuses
 * an id this would not hold.
 */
#define NCFG_WIFI_PROFILE_ID_MAX   64u
#define NCFG_WIFI_PROFILE_NAME_MAX (NCFG_WIFI_PROFILE_ID_MAX + 8u)

/*
 * Whether an id can be a block label, a filename and a secret name at once.
 *
 * It has to be all three and the strictest wins. The label half keeps a quote
 * or a backslash out of generated configuration -- a value that ended its own
 * string would produce a file that does not compile, which takes every other
 * interface on the machine with it, since the loader compiles the directory as
 * one document. The rest is `ncfg_secret_name_usable`'s, asked rather than
 * restated: that is the same question, and one place to be right beats two to
 * keep in step.
 *
 * **Checked inside `ncfg_wifi_profile_install` rather than left to a caller.**
 * With 0117's request that caller is a remote client, and an id of
 * `../../../etc/cron.d/x` would be a file written wherever the daemon can
 * write. A validation a caller may skip is a validation a caller will skip.
 */
int ncfg_wifi_profile_usable_id(const char *id, char *err, size_t err_size);

/*
 * `wifi-<id>`: what `config put` and `config delete` call this file.
 *
 * The same string as the path below, minus the directory and the suffix,
 * because a client asks netcfgd to take a drop-in away **by name** and this is
 * the name. Written once so the two cannot drift: a forget that removed
 * `wifi-<id>` while the writer wrote `wifi_<id>` would report success and
 * leave the network configured.
 *
 * `out` is `NCFG_WIFI_PROFILE_NAME_MAX` bytes or more.
 */
int ncfg_wifi_profile_drop_in(const char *id, char *out, size_t out_size, char *err,
    size_t err_size);

/*
 * `<config_dir>/conf.d/wifi-<id>.conf`, allocated, or NULL with a sentence.
 *
 * Flat, and `.conf`, because that is what the loader reads: it takes every
 * `*.conf` under `conf.d` and does not descend, so a subdirectory per client
 * would configure nothing. The `wifi-` prefix says where the file came from without
 * claiming ownership of it -- there is no marker file and no registry, and a
 * block edited by hand afterwards is simply the configuration.
 */
char *ncfg_wifi_profile_path(const char *config_dir, const char *id, char *err, size_t err_size);

/* Where the `file` provider will look for this network's credential. */
char *ncfg_wifi_profile_secret_path(const char *config_dir, const char *id, char *err,
    size_t err_size);

/*
 * The block, as text, appended to `out`.
 *
 * Kept to what was asked for. netcfgd's defaults are the ones a laptop wants
 * -- `autoconnect` is on, `metered` is off, and a PSK negotiates WPA2 and WPA3
 * both -- and writing them out anyway would turn every generated file into a
 * list of things to wonder about.
 *
 * `out` carries the failure, which is `buf.h`'s bargain: a block that did not
 * fit hands out the empty string rather than the part that fitted, because
 * half a `network` block that parses is the failure mode this refuses.
 */
int ncfg_wifi_profile_render(const ncfg_wifi_profile_t *profile, ncfg_buf_t *out, char *err,
    size_t err_size);

/* What an install wrote, so a caller can say so. Both paths are owned. */
typedef struct {
	char *file;
	/* NULL for an open network, which stores nothing. */
	char *secret;
} ncfg_wifi_installed_t;

/* Release what it holds and leave it usable and empty. Freeing one that was
 * never filled in is nothing. */
void ncfg_wifi_installed_free(ncfg_wifi_installed_t *installed);

/*
 * Write the credential and the block, then prove the machine can use them.
 *
 * The order is the safety property and is not arbitrary:
 *
 *   1. **Refuse first.** A second block with the same label is a compile
 *      error, so writing one would break every interface on the machine to add
 *      one network. An existing file or stored credential is refused rather
 *      than overwritten -- this does not clobber what it did not write.
 *   2. **The credential, then the block.** A block referring to a credential
 *      that is not there is a network that cannot join; the other order is a
 *      stored passphrase for a network that does not exist.
 *   3. **Compile it back.** Through the same loader and compiler the daemon
 *      uses, because a generated file that does not compile is worse than no
 *      file at all -- it takes the whole directory with it. Where the machine
 *      cannot use what this wrote, both files are removed and the caller is
 *      told why.
 *
 * `credential` is bytes and a length, never a C string: see the header. NULL
 * for an open network. `out` and `denied` may be NULL; `denied` is
 * `config.h`'s classification and is not inferable from the message.
 *
 * Nothing is left behind by a failure.
 */
int ncfg_wifi_profile_install(const char *config_dir, const char *factory_dir,
    const ncfg_wifi_profile_t *profile, const char *credential, size_t credential_length,
    ncfg_wifi_installed_t *out, int *denied, char *err, size_t err_size);

/*
 * The installer as `daemon.h`'s seam, for `ncfg_wifi_configure_network`.
 *
 * `context` is one of these, which carries the two directories in and what was
 * written out. The seam exists because this module was not ported when the
 * daemon's wifi half was; it stays a seam rather than becoming a direct call
 * because `daemon.h` may not depend on the host module -- and because a test
 * of the request's validation should not have to write a file to reach it.
 */
typedef struct {
	const char           *config_dir;
	const char           *factory_dir;
	/* Filled by the call. The caller frees what `installed` holds. */
	ncfg_wifi_installed_t installed;
	int                   denied;
} ncfg_wifi_installer_t;

int ncfg_wifi_profile_installer(void *context, const ncfg_wifi_profile_t *profile,
    const char *credential, size_t credential_length, char *err, size_t err_size);

/*
 * What a forget took away, and what it left.
 *
 * Two lists rather than one flag, because "the passphrase went with it" and
 * "the passphrase is still here because something else uses it" are different
 * sentences and an operator wants whichever is true. Neither list holds a
 * value: these are names.
 */
typedef struct {
	char **removed;
	size_t removed_count;
	char **kept;
	size_t kept_count;
} ncfg_wifi_forgotten_t;

void ncfg_wifi_forgotten_free(ncfg_wifi_forgotten_t *forgotten);

/*
 * Take a configured network away, and its credential with it.
 *
 * **The credential goes when nothing else refers to it.** A stored credential
 * nothing names is the fault `ncfg_secret_list` exists to surface, and
 * forgetting a network is exactly when one is created. The question is asked
 * of the configuration *after* the removal rather than before, because what
 * matters is whether anything still refers to it, and it is asked of the whole
 * document rather than of the other networks: a passphrase shared with an
 * access point block is still in use.
 *
 * **It fails closed.** Where the configuration cannot be read back after the
 * removal, every credential is kept. Removing one on a guess is unrecoverable
 * in the way 0042 describes, and leaving one behind is visible in a listing.
 *
 * **The drop-in goes first**, so that a refusal leaves the credential where it
 * was. The other order would take a passphrase away from a network that is
 * still configured, which is the one outcome here nobody can undo.
 *
 * Refuses an id that cannot be a name, a network the document does not have,
 * and one netcfgd did not write the file for. `out` and `denied` may be NULL.
 */
int ncfg_wifi_profile_forget(const char *config_dir, const char *factory_dir,
    const ncfg_document_t *document, const char *id, ncfg_wifi_forgotten_t *out, int *denied,
    char *err, size_t err_size);

#endif /* NCFG_WIFI_PROFILE_H */
