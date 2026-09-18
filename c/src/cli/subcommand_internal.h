/*
 * subcommand_internal.h -- what the verbs that change the configuration share.
 *
 * WHY THESE FOUR ARE TOGETHER
 *   `control`, `config`, `profile` and `secret` are the verbs that write, and
 *   every one of them asks the same two questions before it does: what does
 *   this machine currently compile to, and what do I say when a local write was
 *   refused. Three of them also write through the same drop-in. The Rust
 *   answers all of that in `drop_in.rs` and the other three call across; this
 *   is that set of answers, in one place, with no reader outside `src/cli/`.
 *
 *   `cli_internal.h` holds what *every* `ncfg` source shares -- the counted
 *   string, the two buffer sizes, the monitor stream. These are narrower: a
 *   renderer never writes a file. What the socket half of the same question
 *   needs -- which socket, is anything there, is the answer `ok` -- is in
 *   `cli.h` instead, because a test has to reach it.
 *
 * WHY THE ENTRY POINTS RETURN 1 AND 0 RATHER THAN AN EXIT CODE
 *   The Rust's four `run` functions return `Result<ExitCode, String>`, and
 *   every `Ok` arm in all four is `ExitCode::SUCCESS` -- the code carries no
 *   information the `Result` does not. So they are 0263's convention exactly:
 *   1, or 0 with a sentence the dispatch prints. `cli.h` declares them.
 */
#ifndef NCFG_CLI_SUBCOMMAND_INTERNAL_H
#define NCFG_CLI_SUBCOMMAND_INTERNAL_H

#include "cli_internal.h"

#include "ncfg/document.h"
#include "ncfg/json_write.h"
#include "ncfg/proto.h"

#include <stddef.h>

/*
 * Long enough for a config directory, a run directory and a socket under it.
 *
 * Longer than `NCFG_CLI_TEXT_MAX`, which is sized for one rendered value, and
 * shorter than the kernel's `PATH_MAX`: these are directories an operator
 * typed or a package chose, and the refusal where one does not fit names the
 * path rather than truncating it.
 */
#define NCFG_CLI_PATH_MAX 512

/* ------------------------------------------------------------------------ *
 * Compiling to read
 * ------------------------------------------------------------------------ */

/*
 * The configuration this machine would load, compiled to be **read**.
 *
 * Every caller of this is asking the document a question -- who may talk to
 * the daemon, which profile is selected, does anything refer to this
 * credential, what is this machine running that a snapshot must reproduce --
 * and throws it away afterwards. So the sink is `ncfg_hook_sink_unwritten()`
 * at every one of them, which is the choice 0258 exists for: the refusing sink
 * would have made each of these answer wrongly on any machine with one hook in
 * its configuration, and `ncfg control set` is the command a machine's
 * *bootstrap* runs.
 *
 * It matters a second time for `profile save`: `ncfg_profile_save` proves the
 * snapshot by compiling the result through `ncfg_config_compile_for_reading`
 * and comparing it against the document handed in. A document compiled with a
 * different sink names its hooks differently, so the comparison would fail on
 * the hook paths alone and refuse a snapshot that was perfectly good.
 *
 * Returns the document, which the caller frees, or NULL with the first
 * diagnostic in `err`.
 */
ncfg_document_t *ncfg_cli_compile_to_read(const ncfg_cli_options_t *options, char *err,
    size_t err_size);

/* ------------------------------------------------------------------------ *
 * Drop-ins, which three of the four verbs write through
 * ------------------------------------------------------------------------ */

/*
 * What a drop-in write actually did, for the verb that has to say it.
 *
 * **Here because a command prints one document and the shared helper is not
 * the command.** `ncfg config rm` and `ncfg profile unset` both go through
 * `ncfg_cli_remove_named`, and their answers are not the same answer: one is
 * about a drop-in by name, the other is about which profile the machine is on.
 * A helper that wrote a document of its own would put two values on a stream
 * that promised one, so it hands the facts back and the verb composes.
 *
 * `daemon` is the route: netcfgd took the write, so nothing was written here
 * and `path` is absent. `removed` is `ncfg_cli_remove_named`'s alone and is
 * meaningless on the daemon route -- an absent file is success there and the
 * answer cannot tell the two apart, which is why the caller must not report it
 * when `daemon` is set.
 */
typedef struct {
	int   daemon;
	int   removed;
	char *path;
	char *folded;
} ncfg_cli_wrote_t;

void ncfg_cli_wrote_free(ncfg_cli_wrote_t *wrote);

/*
 * Store one drop-in: the daemon when it is listening, the directory when it is
 * not.
 *
 * `subject` is how the file is named back to the reader, since "the profile
 * `office`" means something to somebody that `90-profile` does not.
 *
 * `wrote` may be NULL where the caller has nothing to say about the route. The
 * human lines are printed here as they always were, and not at all under
 * `--json`; see `ncfg_cli_say_json`.
 */
int ncfg_cli_put_text(const char *name, const char *text, int replace, const char *subject,
    const ncfg_cli_options_t *options, ncfg_cli_wrote_t *wrote, char *err, size_t err_size);

/* Take one away, by the same daemon-then-directory rule. */
int ncfg_cli_remove_named(const char *name, const char *subject,
    const ncfg_cli_options_t *options, ncfg_cli_wrote_t *wrote, char *err, size_t err_size);

/* ------------------------------------------------------------------------ *
 * `--json` at a verb that writes
 * ------------------------------------------------------------------------ *
 *
 * WHY THESE SIX DO IT THEMSELVES AND THE RENDERERS DO NOT
 *   0263 closed `--json` at the dispatch for every verb that renders one
 *   answer, and named this as the part it could not: these print their own
 *   sentences as they go, so `say_json_ok` after one of them would put prose
 *   and then a document on one stream. The flag is therefore a test at each
 *   line, inside the verb -- the human form and the document are the two arms
 *   of one `if`, so a line added to either side has the other in front of it.
 *
 * WHAT THE OBJECT HOLDS
 *   `cli.h`'s rule, unchanged: the payload, compact, one line, no `"response"`
 *   envelope, an optional member absent rather than null. Where the socket
 *   already names a fact these verbs report -- `chosen` for a profile,
 *   `used_by` for a credential, `secured` for a network -- that spelling is
 *   taken rather than invented, so `ncfg profile set --json` and `ncfg profile
 *   get --json` answer in the same word.
 *
 *   **An absent member is "not known", never "none".** These verbs have two
 *   routes and the daemon route cannot answer everything the local one can: it
 *   does not say which credentials it removed, whether a file had been there,
 *   or whether anything in the configuration can use what was just added. A
 *   member written as an empty list on the route that looked and omitted on
 *   the route that could not is the only shape that does not invite a script
 *   to read silence as a finding.
 */

/*
 * One document on stdout, or 0 with the sentence saying why there is not one.
 *
 * `run.c`'s `say_json` for the verbs that answer 1 or 0 with an `err` rather
 * than an exit code. **Nothing is printed when the render failed**, for that
 * one's reason: `ncfg_buf_t` hands out the empty string for a buffer that
 * failed rather than the part that fitted, so a caller that printed anyway
 * would emit half a document that looks whole.
 *
 * **And the sentence says the command already happened**, which `run.c`'s does
 * not need to: these six write before they answer, so a reader told only that
 * a document could not be rendered would conclude the write did not happen and
 * do it again somewhere else. The refusal a caller meets here is a name off
 * `argv` that is not valid UTF-8.
 */
int ncfg_cli_say_json(const ncfg_json_writer_t *writer, const char *what, char *err,
    size_t err_size);

/*
 * Say the other half when a local write was refused.
 *
 * **Two things to do about it, and a raw errno names neither.** The filesystem
 * refused this process, *and* there was no daemon to ask instead -- a reader
 * told only the first goes looking for a permission to grant when starting
 * netcfgd would have done.
 *
 * **Only on a refusal.** A drop-in rejected for not compiling has nothing to
 * do with who may write, and appending "nothing is listening" to it would send
 * a reader to start a daemon that would have refused the same text. `denied`
 * is `config.h`'s classification, set from the kind the kernel gave rather
 * than from the words in the message -- matching words is how a fallback
 * silently switches itself off.
 */
void ncfg_cli_refused_locally(int denied, const char *message, const char *socket_path, char *err,
    size_t err_size);

#endif /* NCFG_CLI_SUBCOMMAND_INTERNAL_H */
