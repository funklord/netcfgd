/*
 * lower.h -- drop-in precedence, and turning what was written into what it
 * means.
 *
 * This is `crates/netcfgd-compile/src/merge.rs` and `lower.rs` in C: the two
 * passes between a parsed file and an `ncfg_document_t`. Everything before
 * them says what a file *contains*; everything after works on what the machine
 * should *look like*, and these are where one becomes the other.
 *
 * TWO PASSES, AND WHY THEY ARE NOT ONE
 *
 *   **merge** applies precedence and nothing else. `netcfgd.conf` first, then
 *   every `.conf` under `conf.d` in lexical filename order; later wins for a
 *   scalar key, and a block that redefines one is an error unless it says
 *   `override` -- because silent last-wins is where every configuration system
 *   becomes unpredictable. It interprets nothing, so it can say that
 *   `interface eth0` is already defined without knowing what an interface is.
 *
 *   **lower** interprets, and is the only place in this port that decides what
 *   a word in the language means. It is kept separate so that every diagnostic
 *   can still point at the text that caused it -- a tree that had already
 *   decided what a block meant would have nothing left to point at.
 *
 * WHERE THE VALIDATION IS, AND WHY IT IS NOT HERE
 *
 *   `document.h` already validates and canonicalises, so lowering ends by
 *   handing a document over to those two and reporting what they say. There is
 *   deliberately no second validator: the invariants the language cannot
 *   express structurally -- two DHCP clients on one link, a routing domain
 *   under a mode that cannot route, a duplicate interface -- belong to the
 *   document, which is also reachable over the socket and from a file on disk.
 *   A copy here would be a second opinion, and the two would eventually
 *   disagree about which configurations are legal depending on how they
 *   arrived.
 *
 * NO I/O, AND NO HOOK FILES
 *
 *   This module opens no files. `include` is the caller's to resolve before
 *   parsing, and a hook body is handed to an `ncfg_hook_sink_t` rather than
 *   written: the document carries `{phase, path, sha256}` and never shell,
 *   and both of those are computable from a body and a naming rule with no
 *   filesystem at all. Five of the six commands that compile are read-only,
 *   and while this wrote the scripts itself every one of them wrote to `/run`
 *   as a side effect of being asked what *would* happen.
 *
 * Conventions are `base.h`'s: 1 for success and 0 for failure, `NULL` for a
 * pointer, `char *err` last, and one free per aggregate.
 */
#ifndef NCFG_LOWER_H
#define NCFG_LOWER_H

#include <stddef.h>

#include "ncfg/ast.h"
#include "ncfg/document.h"
#include "ncfg/lex.h"
#include "ncfg/parse.h"
#include "ncfg/state.h"

/*
 * One parsed file, with the name it came from.
 *
 * **The name travels beside the tree rather than inside it**, which is
 * `lex.h`'s position: one span type for every module, carrying no source id,
 * because the lexer is handed one file's bytes and the caller is the only
 * thing that ever knew which. Merge and lower are the first passes that see
 * more than one file at a time, so this is where the two are put back
 * together.
 *
 * Both fields are borrowed and must outlive the merge, the lowering, and every
 * diagnostic either produced.
 */
typedef struct {
	const char            *name;
	const ncfg_ast_file_t *file;
} ncfg_source_t;

/*
 * One failure, as a sentence, a place, and the file the place is in.
 *
 * **The one thing this port adds to `ncfg_diag_t`.** A parse diagnostic needs
 * no file name because a parse is one file and the caller knows which;
 * `ncfg_diag_render` takes the name as an argument for exactly that reason.
 * These come from a set of files at once -- "`interface eth0` is already
 * defined; first defined at conf.d/10-office.conf:3" is the whole point of the
 * redefinition check -- so the name has to be on the diagnostic or the reader
 * is sent to the wrong file.
 *
 * `message` is a single sentence and never has a second line, which is the
 * same join `parse.h` describes: where the Rust attached a separate help
 * string, the two are joined with `": "`.
 *
 * `source` is borrowed from the `ncfg_source_t` it came from.
 */
typedef struct {
	const char *source;
	ncfg_span_t span;
	char       *message;
} ncfg_lower_diag_t;

/*
 * Every failure a merge or a lowering found.
 *
 * Declare one as `ncfg_lower_diags_t diags = {0}` and free it with
 * `ncfg_lower_diags_free`. `count` is how many are kept and `total` is how
 * many there were; they differ only past `NCFG_DIAGS_MAX`, which is
 * `parse.h`'s bound and is kept here for its reason -- a diagnostic per line
 * is a file-sized allocation bought with a malformed file, and nobody reads
 * the sixty-fifth.
 */
typedef struct {
	ncfg_lower_diag_t *at;
	size_t             count;
	size_t             total;
	size_t             capacity;
} ncfg_lower_diags_t;

/* Release what a set of diagnostics holds, and leave it usable and empty.
 * Freeing one that was never filled in is nothing. */
void ncfg_lower_diags_free(ncfg_lower_diags_t *diags);

/* `name:line:column: message`, which is what an operator reads. Always
 * NUL-terminates; a diagnostic with no file name renders as `<unknown>`
 * rather than leaving a stray colon, which is `ncfg_diag_render`'s rule. */
void ncfg_lower_diag_render(const ncfg_lower_diag_t *diag, char *out, size_t out_size);

/*
 * Turns a hook body into a reference, and keeps the body for later.
 *
 * **This is not a writer, and that is the whole design.** Section 2.2 requires
 * the document to carry `{phase, path, sha256}` rather than shell, and both
 * are computable from the body and a naming rule -- so a compile that failed
 * halfway no longer leaves half the scripts on disk, `ncfg plan` no longer
 * writes anything while saying it changes nothing, and a compile can run
 * somewhere with no privileges at all.
 *
 * `record` is handed the phase (an `ncfg_hook_phase_t`), the name of the
 * interface or network the hook belongs to, and the body exactly as the lexer
 * produced it -- closing line excluded, every other newline kept, because a
 * hook body is shell and re-indenting it changes what the shell does. It fills
 * `out` with strings the document will own and free, and returns 1; or returns
 * 0 with a sentence in `err`, which is reported at the hook's position.
 *
 * `state` is the implementation's and this module never looks at it.
 */
typedef struct {
	int (*record)(void *state, int phase, const char *owner, const char *body,
	    size_t body_length, ncfg_hook_ref_t *out, char *err, size_t err_size);
	void *state;
} ncfg_hook_sink_t;

/*
 * A sink that refuses every hook, for a caller with nowhere to put them.
 *
 * Refusing loudly beats silently dropping them and producing a document that
 * describes a system nobody asked for.
 */
const ncfg_hook_sink_t *ncfg_hook_sink_refusing(void);

/*
 * Everything the files collectively say, with precedence already applied.
 *
 * Opaque, because what it holds is a mixture of blocks borrowed from the
 * parsed files and item lists this module built while folding `global`
 * together, and a caller that could see the difference would be a caller that
 * had to care about it.
 */
typedef struct ncfg_merged ncfg_merged_t;

/*
 * Apply drop-in precedence across `count` files given in precedence order.
 *
 * Returns 1 with the result in `*out`, or 0 with `*out` NULL. Every block
 * redefined without `override` is a diagnostic naming **both** positions, so
 * the reader can see which two files disagree; with a factory layer under a
 * writable one they are in different directories, where "line 1" on its own
 * sends the reader to the wrong file.
 *
 * `global` is the documented exception and `merge.c` has the argument at
 * length: it is a singleton several independent things contribute to, so
 * distinct contributions combine and a genuine collision is still an error.
 *
 * The sources are borrowed and must outlive the result.
 */
int ncfg_merge(const ncfg_source_t *sources, size_t count, ncfg_merged_t **out,
    ncfg_lower_diags_t *diags, char *err, size_t err_size);

/* Release a merge result. The parsed files it borrowed from are not touched.
 * Freeing NULL is nothing. */
void ncfg_merged_free(ncfg_merged_t *merged);

/*
 * Lower merged blocks into a document.
 *
 * Returns the document, or NULL with every diagnostic in `diags` and the first
 * one's sentence in `err`. A partly built document is never handed back: half
 * a configuration that looks whole is what `buf.h` refuses to hand out and it
 * is worse here, because this one would be applied to a machine.
 *
 * The document is **not** canonicalised or validated -- see `ncfg_compile`,
 * which is this followed by both.
 */
ncfg_document_t *ncfg_lower(const ncfg_merged_t *merged, const ncfg_hook_sink_t *hooks,
    ncfg_lower_diags_t *diags, char *err, size_t err_size);

/*
 * Parse nothing, merge, lower, canonicalise and validate: the whole pipeline
 * from parsed files to a document that has been checked.
 *
 * **Canonicalised before validated**, so that a diagnostic about a duplicate
 * interface names the same entry every time regardless of which drop-in file
 * introduced it.
 *
 * A host-wide `networking = "off"` is applied here rather than left to the
 * planner, so that `ncfg show` and `ncfg plan` say what netcfgd actually
 * wants. A planner rule would leave the document describing a configuration
 * that something downstream quietly ignores, which is the shape of every
 * "netcfgd says it is configured and the machine is not" report.
 *
 * `diags` may be NULL for a caller that wants only the first sentence.
 */
ncfg_document_t *ncfg_compile(const ncfg_source_t *sources, size_t count,
    const ncfg_hook_sink_t *hooks, ncfg_lower_diags_t *diags, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * Where each field came from
 * ------------------------------------------------------------------------ */

/*
 * How many positions one compile records.
 *
 * `state.h` says why the table is a side table and not part of the document.
 * What it does not say is that the compiler is the only thing that decides how
 * large one gets, and that the input deciding it is a directory an edit can
 * grow -- so this is `NCFG_DIAGS_MAX`'s arrangement applied to the other list
 * lowering produces. Past it nothing more is recorded, which leaves exactly
 * the state `explain.h` already describes and tests: a table with entries that
 * does not cover every field, where the gap is per field and no blanket claim
 * is made about it.
 *
 * It is deliberately far past any real configuration -- a machine with two
 * hundred interfaces records something like six entries each -- and it is
 * **published so that a test cannot spell the number itself**, which is the
 * linkset walk's rule and right for the same reason.
 *
 * A caller that wants to know whether it was reached compares
 * `provenance->count` against it; there is no `total` beside the count,
 * because the count lives in a file whose members are the Rust's and adding
 * one would be a second definition of that format.
 */
#define NCFG_PROVENANCE_MAX 4096u

/*
 * Lower, and record where each field was written.
 *
 * `provenance` may be NULL, which is `ncfg_lower` exactly. Otherwise it is
 * filled in and left **empty on any failure**, since a table describing a
 * document that was never handed over is a table pointing at fields nothing
 * has. Hand in one that is empty, or one that has been freed: whatever is in
 * it when a lowering fails goes with the failure.
 *
 * The entries are in the order lowering reached them and are not yet
 * canonical: `ncfg_compile_with_provenance` is what orders them, for the same
 * reason it canonicalises the document.
 */
ncfg_document_t *ncfg_lower_with_provenance(const ncfg_merged_t *merged,
    const ncfg_hook_sink_t *hooks, ncfg_provenance_t *provenance, ncfg_lower_diags_t *diags,
    char *err, size_t err_size);

/*
 * `ncfg_compile`, and the side table `ncfg explain` names a file and a line
 * out of.
 *
 * This is `compile_with_provenance` in the Rust, and `ncfg_compile` is the
 * same call with nowhere to put the table -- one pipeline rather than two, so
 * that the two cannot come to disagree about what a compile is.
 *
 * **The keys are the dotted paths the planner and `explain` already use**, and
 * that is a contract rather than a convention: a table keyed differently is
 * worse than no table, because every lookup would miss while the table looked
 * full. They are `interfaces[<name>]` and its fields, and `rule.<id>`,
 * `access_point.<id>`, `network.<id>` and `linkset.<name>` for the blocks that
 * have one name and no fields recorded.
 *
 * The table is canonicalised here -- ordered by path, first record for a path
 * kept -- so that two compiles of one configuration produce one file, which is
 * the whole reason the positions are not in the document.
 *
 * `provenance` may be NULL, which is `ncfg_compile`.
 */
ncfg_document_t *ncfg_compile_with_provenance(const ncfg_source_t *sources, size_t count,
    const ncfg_hook_sink_t *hooks, ncfg_provenance_t *provenance, ncfg_lower_diags_t *diags,
    char *err, size_t err_size);

#endif /* NCFG_LOWER_H */
