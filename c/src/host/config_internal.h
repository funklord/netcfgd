/*
 * config_internal.h -- what the three configuration files share.
 *
 * Private to the configuration half of `src/host/`, the way
 * `host_internal.h` is private to the module as a whole. These are the four
 * operations that would otherwise be written once per file: the drop-in path
 * rule, the compile whose diagnostics become a sentence, and the two pieces of
 * name handling. A path rule written three times is three chances to spell
 * `conf.d` wrong, and the naming is exactly what one of these files exists to
 * be strict about.
 */
#ifndef NCFG_CONFIG_INTERNAL_H
#define NCFG_CONFIG_INTERNAL_H

#include <stddef.h>

#include "ncfg/config.h"
#include "ncfg/document.h"
#include "ncfg/lower.h"
#include "ncfg_json.h"

/* `<config_dir>/conf.d/<name>.conf`, allocated. NULL with a sentence. */
char *ncfg_config_drop_in_path(const char *config_dir, const char *name, char *err,
    size_t err_size);

/*
 * Compile `sources` for reading, and turn a refusal into one sentence.
 *
 * Every caller of this is asking the configuration a question, so the hook
 * sink is `ncfg_hook_sink_unwritten()` and is not a parameter: a sink argument
 * here would be a chance to pass the refusing one, which is the defect this
 * module's header describes at length.
 *
 * Returns the document, or NULL with `err` holding the first diagnostic
 * rendered -- file, line, column and message -- which is what the operator
 * needs to find the line. **The first rather than all of them**: `err` is one
 * sentence and one buffer, which is the same join `parse.h` makes where the
 * Rust rendered a list.
 */
ncfg_document_t *ncfg_config_compile_for_reading(const ncfg_config_sources_t *sources, char *err,
    size_t err_size);

/*
 * The `global { profile = "..." }` a selection is written as.
 *
 * One spelling, because the name goes inside a quoted string and the check
 * that makes that safe has to sit in front of every writer of it.
 */
char *ncfg_config_profile_block(const char *name, char *err, size_t err_size);

/* `<name>.conf` with the `.conf` taken off, as a borrowed pointer into `out`.
 * Used to recognise the profile drop-in among the loaded sources. */
const char *ncfg_config_file_stem(const char *path, char *out, size_t out_size);

/*
 * Whether a client-supplied string can become a filename here.
 *
 * `what` is the noun for the message -- "a name here", "a profile name" --
 * because the rule is shared and the sentence is not. The rule itself is
 * `ncfg_secret_name_usable`'s; see the implementation for why it is asked
 * rather than restated.
 */
int ncfg_config_name_usable(const char *name, const char *what, char *err, size_t err_size);

/*
 * Where a folded profile is tried, in order, and nothing else is one.
 *
 * **Early first, and the proof decides.** A profile is read after all of
 * `conf.d`, so folding it in late is what reproduces its precedence -- and
 * late is exactly wrong afterwards, because the operator is on no profile now
 * and the next drop-in they write should win. Landing it at `zz-` cost that: a
 * person changed a setting, the folded file sorted after their drop-in, and
 * `override interface` replaced the block whole, so their edit did nothing and
 * said nothing. Found by running the workflow rather than by reading it.
 *
 * So `05-` is tried first, which is where a future edit beats it, and `zz-`
 * only when the early position would change what the machine runs. Neither
 * name is load-bearing on its own: the proof is what makes the choice safe.
 */
#define NCFG_FOLDED_PREFIX_COUNT 2u
extern const char *const ncfg_config_folded_prefixes[NCFG_FOLDED_PREFIX_COUNT];

/* One file `ncfg_config_take_folded` took out of `conf.d`, with what was in
 * it, so that a save which does not stand can put it back. */
typedef struct {
	char  *path;
	char  *text;
	size_t length;
} ncfg_config_taken_t;

/*
 * Take the folded profile files out of `conf.d`, returning what was removed.
 *
 * `ncfg profile save` writes the running configuration into a profile, and
 * leaving the fold behind would keep a copy of the old profile in the base for
 * ever -- so it would still be in force after switching to a different
 * profile, which is not what "saved it into office" means to anybody.
 */
int ncfg_config_take_folded(const char *config_dir, ncfg_config_taken_t **out, size_t *count_out,
    char *err, size_t err_size);

/* Put back what it took, because the save did not stand. */
void ncfg_config_restore_folded(const ncfg_config_taken_t *taken, size_t count);

void ncfg_config_taken_free(ncfg_config_taken_t *taken, size_t count);

/*
 * The document as JSON, as the model's own writer produces it.
 *
 * The caller owns what it receives. `length_out` may be NULL.
 */
char *ncfg_config_document_json(const ncfg_document_t *document, size_t *length_out, char *err,
    size_t err_size);

/* Whether two parsed JSON values say the same thing. See
 * `document_compare.c` for why a comparison of documents goes this way round
 * rather than field by field. */
int ncfg_config_json_same(const ncfg_json_doc_t *a, uint32_t x, const ncfg_json_doc_t *b,
    uint32_t y);

/*
 * Whether `got` describes the same machine as `want`, but for the selection.
 *
 * `profile` is what `got` must have chosen -- NULL for none -- because every
 * comparison in this module is "the same but for the profile" and that is the
 * one thing being changed. `generated_by` takes no part: `document.h` excludes
 * it from equality, since two documents differing only there plan identically.
 *
 * `where` may be NULL; where it is given, a difference fills it with the block
 * that differs, as a sentence to append to a refusal.
 */
int ncfg_config_documents_agree(const ncfg_document_t *want, const char *profile,
    const ncfg_document_t *got, char *where, size_t where_size);

#endif /* NCFG_CONFIG_INTERNAL_H */
