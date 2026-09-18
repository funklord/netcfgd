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
 * Store one drop-in: the daemon when it is listening, the directory when it is
 * not.
 *
 * `subject` is how the file is named back to the reader, since "the profile
 * `office`" means something to somebody that `90-profile` does not.
 */
int ncfg_cli_put_text(const char *name, const char *text, int replace, const char *subject,
    const ncfg_cli_options_t *options, char *err, size_t err_size);

/* Take one away, by the same daemon-then-directory rule. */
int ncfg_cli_remove_named(const char *name, const char *subject,
    const ncfg_cli_options_t *options, char *err, size_t err_size);

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
