/*
 * secrets.h -- the credentials this machine holds, by name and never by value.
 *
 * THE ONE RULE
 *   **No secret material ever reaches a diagnostic, a log line or a rendered
 *   document.** Every message here names the reference, the provider and the
 *   reason and stops there. A passphrase in a log is a passphrase in every log
 *   aggregator downstream, and the thing that makes a rule like this hold is
 *   not care at the call sites -- it is that the type cannot be printed.
 *   `ncfg_secret_t` is opaque and the only way to the bytes is
 *   `ncfg_secret_expose`, named so that every use of it is one grep away and
 *   has to look deliberate where it is written.
 *
 *   `secrets_test.c` proves it rather than asserting it in a comment: it drives
 *   every failure this module has with a value nothing may repeat, and reads
 *   every buffer and every byte of captured output back for that value.
 *
 * THREE THINGS, ONE FILE
 *   * **The store**: the `file` provider's directory, what `ncfg secret set`
 *     writes into it and what removes an entry.
 *   * **The resolver**: a `ncfg_secret_ref_t` to the material it names,
 *     through one of four providers. This is the only place in netcfgd where
 *     secret material exists at all -- the document carries indirections and
 *     never values (constraint 5), `/run` holds none, and the plan carries
 *     none, so a secret's whole life is: resolved here, handed to a backend,
 *     dropped.
 *   * **The walk**: every `@secret:` reference a document makes, and who makes
 *     it. **One walk, in one place**, because `ncfg secret set` reports which
 *     blocks refer to a name and the socket needs the same knowledge inverted;
 *     two walks would be two chances to miss a shape when the model grows one,
 *     and the model has grown three since it was written -- stored
 *     certificates, a WireGuard peer's preshared key, and 802.1X on a wired
 *     port.
 *
 * WHERE `@secret:NAME` IS SPELLED, AND IT IS NOT HERE
 *   The prefix is the configuration language's and the compiler owns it:
 *   `ncfg_as_secret` in `src/compile/lower_value.c` turns the text into an
 *   `ncfg_secret_ref_t` and says so in the operator's words when it will not.
 *   This module never sees the spelling, only the parsed reference. A second
 *   parser for it would be a second answer to "is `@secret:file:x` a provider
 *   or a name", and the two would disagree the first time the syntax grew.
 *
 * UNSAFE STORAGE IS REFUSED RATHER THAN READ
 *   A secret in a world-readable file is already disclosed; reading it anyway
 *   and carrying on tells the operator everything is fine. Design section 3.3
 *   specifies 0600 for the file provider, and this enforces it.
 */
#ifndef NCFG_SECRETS_H
#define NCFG_SECRETS_H

#include <stddef.h>

#include "ncfg/document.h"

/* Where the `file` provider looks when nothing says otherwise. */
#define NCFG_SECRETS_DIR_DEFAULT "/etc/netcfgd/secrets"

/*
 * Why a secret could not be resolved.
 *
 * A kind as well as a sentence, because the caller acts on the difference.
 * **"Not there" and "cannot be looked at" are different sentences**: every
 * failure used to become "not found", whose message tells the operator to run
 * `ncfg secret set` -- advice that is wrong, and destructive if taken, for a
 * secret sitting right there behind a permission error, a symlink loop or a
 * failing disk.
 */
typedef enum {
	NCFG_SECRET_OK = 0,
	/* Nothing of that name, and `ncfg secret set` is the remedy. */
	NCFG_SECRET_NOT_FOUND,
	/* It exists, and anybody can read it. */
	NCFG_SECRET_EXPOSED,
	/* The provider is not implemented in this build. */
	NCFG_SECRET_UNSUPPORTED,
	/* Anything else, in the operating system's words rather than the store's. */
	NCFG_SECRET_FAILED
} ncfg_secret_error_t;

/*
 * Secret material, which cannot print itself.
 *
 * Opaque deliberately: a struct holding a passphrase ends up inside something
 * formatted into an error eventually, and the one place to stop that is the
 * type. There is no `to_text`, no length-prefixed accessor and no comparison
 * against a string -- what exists is below, and nothing else.
 */
typedef struct ncfg_secret ncfg_secret_t;

/*
 * The material, for handing to a backend.
 *
 * **Named `expose` rather than `text` so that every use is visible in a grep**
 * and has to look deliberate at the call site. NUL-terminated, and valid until
 * the secret is freed. Never NULL for a live secret.
 */
const char *ncfg_secret_expose(const ncfg_secret_t *secret);

/* How long it is, which is safe to say and occasionally useful: a passphrase
 * of length zero is a common and confusing misconfiguration. */
size_t ncfg_secret_length(const ncfg_secret_t *secret);
int ncfg_secret_is_empty(const ncfg_secret_t *secret);

/*
 * What a diagnostic may say about one, which is nothing.
 *
 * `<redacted>`, always, whatever it holds -- the shape the Rust's `Display`
 * has. It exists so that a caller with a format string has something correct
 * to put in it rather than reaching for `expose`.
 */
const char *ncfg_secret_redacted(void);

/*
 * The first line of a password-store entry.
 *
 * A `pass(1)` entry conventionally holds the secret on line one and notes
 * below it -- a URL, a username, recovery codes. Taking the whole thing would
 * hand a supplicant a passphrase with somebody's recovery codes appended, and
 * the failure is an association that does not work for a reason the operator
 * cannot see, because nothing will print the value.
 *
 * A function of its own rather than a step inside the provider, so the rule
 * can be tested without a `pass` binary on the machine. Returns a new secret,
 * or NULL when there is nothing to allocate it with.
 */
ncfg_secret_t *ncfg_secret_first_line(const ncfg_secret_t *secret);

/*
 * Release it, wiping the bytes first.
 *
 * **The wipe is not in the Rust and is not a claim about it.** A `String`'s
 * bytes are freed and left where they lay; here the buffer is ours until the
 * last instant, and clearing it costs a `memset` and shortens the window in
 * which a core dump, a swapped page or a later allocation of the same block
 * carries a passphrase. It cannot undo a copy somebody else made -- which is
 * the argument for `expose` being conspicuous.
 */
void ncfg_secret_free(ncfg_secret_t *secret);

/*
 * Where to look, and where a stored certificate may be put.
 *
 * A plain struct rather than an opaque type: it is two borrowed paths, and a
 * constructor for that would be ceremony. Both may be NULL, and they mean
 * different things when they are -- see each.
 */
typedef struct {
	/* NULL means `NCFG_SECRETS_DIR_DEFAULT`. */
	const char *secrets_dir;
	/*
	 * Where `ncfg_secret_path_for` writes stored certificates. **NULL means it
	 * refuses rather than choosing somewhere**: a resolver that invented a
	 * directory would write key material somewhere its caller did not choose,
	 * which is the one thing this module must not do quietly.
	 */
	const char *materialise_dir;
} ncfg_secret_resolver_t;

/*
 * Resolve a reference to the material it names.
 *
 * Returns the secret, or NULL with the kind in `*why` (which may be NULL) and
 * a sentence in `err` that discloses nothing.
 *
 * The four providers:
 *   `file`    a 0600 file under `secrets_dir`, refused if anybody else can
 *             read it, with one trailing newline stripped -- that is what an
 *             editor or `echo` leaves behind, and a passphrase that silently
 *             includes it fails to associate with no indication why.
 *   `exec`    the name is a command, run with **no shell**: a shell would make
 *             the secrets directory a place where a configuration file becomes
 *             arbitrary code with word splitting and globbing attached.
 *   `pass`    `pass show NAME`, validated so that a name cannot become a flag
 *             or a second argument to `pass` itself.
 *   `keyring` refused, with the reason: `request_key(2)` and `keyctl(2)` have
 *             no libc wrapper, and neither widening the syscall surface nor
 *             depending on the `keyctl` tool has been chosen.
 */
ncfg_secret_t *ncfg_secret_resolve(const ncfg_secret_resolver_t *resolver,
    const ncfg_secret_ref_t *reference, ncfg_secret_error_t *why, char *err, size_t err_size);

/*
 * A filesystem path for a certificate or key, whichever kind it is.
 *
 * **This is the function that makes EAP-TLS work.** `wpa_supplicant` opens
 * `ca_cert`, `client_cert` and `private_key` as files, so everything reaching
 * it has to be a path -- and the only way to have one used to be to put the
 * file there yourself, which a desktop client cannot do (0127). A `stored`
 * source is content netcfgd already holds; this writes it where the supplicant
 * can read it and hands back that path, which the caller owns and frees.
 *
 * **Written at 0600 under a 0700 directory, by the open rather than after it**,
 * so there is no instant at which a private key exists and is readable. The
 * mode is not chosen per kind: a CA certificate is public and could be 0644,
 * but uniform is simpler to reason about and gives up nothing, since the only
 * reader is a process netcfgd started as root.
 *
 * **Overwritten every time rather than cached**: the content is what the store
 * says now, and a stale file is a certificate rotated everywhere except here.
 *
 * `role` is the caller's word for what the file is for -- `ca.pem`,
 * `client.pem`, `client.key` -- and it is a **suffix, not the name**. The name
 * is the credential's. That is not tidiness: the role alone is a literal, so
 * every network with a stored CA wrote one `ca.pem` and every network's
 * `ca_cert=` pointed at it; one supplicant is given every network in one loop,
 * so the last one rendered won for all of them and a machine with a work
 * network and a university network validated **both** servers against whichever
 * CA was written last. That is the corporate network trusting an authority it
 * was never configured to trust, which is the whole of what a CA pin is for.
 *
 * A `path` source is handed back as it stands, resolving nothing.
 */
char *ncfg_secret_path_for(const ncfg_secret_resolver_t *resolver,
    const ncfg_cert_source_t *source, const char *role, ncfg_secret_error_t *why, char *err,
    size_t err_size);

/*
 * Whether a name can be a block label, a filename and a secret name at once.
 *
 * It has to be all three and the strictest wins, and it is checked **inside**
 * the store rather than left to a caller: a caller that forgot would be
 * handing a name straight into a path join, and with the socket request of
 * 0117 that caller is a remote client -- a name of `../../../etc/cron.d/x`
 * would be a file written wherever the daemon can write. A validation a caller
 * may skip is a validation a caller will skip.
 *
 * Returns 1, or 0 with the reason as a whole sentence.
 */
int ncfg_secret_name_usable(const char *name, char *err, size_t err_size);

/*
 * Store a credential the configuration refers to.
 *
 * 0127's other half: a client cannot write `/etc/netcfgd/secrets`, so a value
 * it holds arrives over the socket and netcfgd writes it. The directory is
 * created at 0700 and the file at 0600, from the moment each exists rather
 * than created and then tightened -- a file that is briefly world-readable is
 * briefly world-readable, and this one is a password.
 *
 * **Nothing here reads a value back**, and no caller of this can: the only
 * direction credentials travel in netcfgd is inward.
 *
 * An empty value is refused, because an empty secret is a secret that fails at
 * the moment it is used rather than now. An existing file is refused unless
 * `replace` -- a private key nobody has a copy of cannot be got back (0042).
 *
 * `path_out` may be NULL; where it is not, the caller owns and frees what it
 * receives.
 */
int ncfg_secret_store_put(const char *config_dir, const char *name, const char *value,
    int replace, char **path_out, char *err, size_t err_size);

/*
 * Take one away. **Absent is success.**
 *
 * No compile check: a secret is read when a backend needs it rather than
 * compiled into the document, so removing one cannot make the configuration
 * invalid. It can make it fail later, which is a different thing and one
 * `ncfg plan` reports as a stranded credential.
 */
int ncfg_secret_store_remove(const char *config_dir, const char *name, char *err,
    size_t err_size);

/*
 * One credential name, whether the store holds it, and who refers to it.
 *
 * The Rust's `SecretEntry`, with owned strings. `proto.h`'s
 * `ncfg_proto_secret_t` is the same three facts as borrowed counted strings
 * for the wire; the daemon borrows from one of these to build one of those,
 * rather than either type being built twice.
 */
typedef struct {
	char  *name;
	int    stored;
	/* `network Cafe`, `interface eth0 (802.1X client key)`. Sorted and
	 * de-duplicated. */
	char **used_by;
	size_t used_by_count;
} ncfg_secret_entry_t;

/*
 * Every credential name, whether the store holds it, and who refers to it.
 *
 * **The union of two sets rather than either alone**, because the interesting
 * faults are opposite ways round. A referenced name with no file is a network
 * that will never join, and it fails at association time with an error about
 * the radio rather than about the missing passphrase. A stored name nothing
 * refers to is a credential still on the machine after whatever wanted it was
 * deleted.
 *
 * **Nothing here reads a secret's contents.** The store is consulted only for
 * whether a file exists, which is what makes "referenced but not stored"
 * answerable without handling the value.
 *
 * `document` may be NULL, for a machine whose configuration does not compile:
 * the store's own contents are still worth listing. Sorted by name.
 */
int ncfg_secret_list(const char *config_dir, const ncfg_document_t *document,
    ncfg_secret_entry_t **out, size_t *count_out, char *err, size_t err_size);

void ncfg_secret_entries_free(ncfg_secret_entry_t *entries, size_t count);

/*
 * The blocks that refer to one name, sorted and de-duplicated.
 *
 * A stored secret nothing uses gets an empty list, which is the honest answer.
 */
int ncfg_secret_referring_to(const ncfg_document_t *document, const char *name, char ***out,
    size_t *count_out, char *err, size_t err_size);

/*
 * Every credential one block's security refers to, by name.
 *
 * The same walk as `ncfg_secret_list`'s pointed at one block instead of a
 * document, **through the same function**, so that a model growing a fifth
 * place to keep a credential cannot be covered there and missed here. `forget`
 * needs this to know what a network is about to stop referring to.
 */
int ncfg_secret_named_by(const ncfg_security_t *security, char ***out, size_t *count_out,
    char *err, size_t err_size);

/* Free a list of names. Freeing NULL, or a count of zero, is nothing. */
void ncfg_secret_names_free(char **names, size_t count);

#endif /* NCFG_SECRETS_H */
