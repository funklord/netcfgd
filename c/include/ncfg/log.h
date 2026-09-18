/*
 * log.h -- what netcfgd says, and to whom.
 *
 * Two halves, and **the header says which is for a program and which for a
 * library**, because one of them ends the process and the other must never:
 *
 *   * `ncfg_log_*` writes a diagnostic to **stderr**. It is the library half.
 *     It never exits, never asserts, never allocates without a ceiling, and a
 *     write it cannot complete is dropped -- a log line nobody can receive is
 *     not a reason to take a daemon down. Anything in `libncfg` may call it.
 *   * `ncfg_out_*` writes a **program's output** to stdout, and ends the
 *     process at 141 when the reader has gone. It is the one thing in this
 *     library that exits, it exists for `ncfg` and the daemon's own `main`, and
 *     **no library code may call it**. Decision 0263 names it as the single
 *     exception to "a library never exits", which is what keeps the rest of the
 *     rule enforceable.
 *
 * WHY THE SEVERITY AND THE SUBSYSTEM
 *   **Shaped after `flog`**, the C logging library two of the sibling projects
 *   share as a submodule, because the holder asked for the same shape and
 *   because netcfgd had none of it. Every message this daemon emitted was
 *   `eprintln!("netcfgd: ...")`: one stream, no severity, no subsystem, and no
 *   way to ask for less. Measured on the reporting machine, an adoption line
 *   printed every five seconds for twenty minutes -- ordinary, correct, and
 *   indistinguishable at a glance from the failure that was causing it.
 *
 *   The severity vocabulary is flog's, name for name, and so is the rendering:
 *   `[subsystem] Error: text`, `!` for a note, and no label at all for info, on
 *   the argument that the ordinary case should read as a sentence rather than
 *   as a log line. The accept level is flog's mask as a threshold, because
 *   netcfgd's severities are ordered and a mask that cannot express "warnings
 *   but not errors" is a mask nobody wanted. The subsystem is flog's fourth
 *   argument and the thing netcfgd most obviously lacked -- `dhcp`,
 *   `supplicant`, `confirm`, `netlink`, `portal` -- and with it
 *   `journalctl -u netcfgd | grep '\[dhcp\]'` is a question somebody can ask.
 *
 *   **Deliberately not copied: message ids and source location.** flog carries
 *   both for embedded targets, where a numeric id saves the string table and
 *   `__FILE__` is how a crash is placed. netcfgd runs under a journal that
 *   timestamps and attributes every line, its messages are sentences an
 *   operator reads rather than codes a receiver decodes, and `file:line` in an
 *   operator-facing message is noise. Decision 0187.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   * **No macros.** Rust needs `log_error!` and friends because `format!` is a
 *     macro; C has varargs, so `ncfg_log_errorf(subsystem, "...", x)` is one
 *     call and a function-like macro over it would only hide which one. The
 *     trade flog makes -- format before you filter -- is kept: a message the
 *     level refuses still costs its arguments, and netcfgd's messages are rare
 *     enough that a saved `vsnprintf` is not worth a macro that hides control
 *     flow.
 *   * **A formatted line has a ceiling** (`NCFG_LOG_MAX`) and is truncated
 *     rather than grown. Rust's `format!` allocates whatever the arguments
 *     need; a daemon rendering a name a client chose has to bound the result,
 *     which is `buf.h`'s reasoning applied to a path that must not allocate at
 *     all.
 *   * **The level lives in an atomic that this reads back by value**, as the
 *     Rust does. An unknown stored byte reads as info, which is the default and
 *     the safe answer.
 */
#ifndef NCFG_LOG_H
#define NCFG_LOG_H

#include <stddef.h>

/*
 * The longest line this will render, including the prefix and the newline.
 *
 * A diagnostic that reaches an operator is a sentence; anything longer is a
 * payload, and a payload in a log line is how a journal gets filled by
 * something a client sent.
 */
#define NCFG_LOG_MAX 1024

/*
 * What a message is, in flog's vocabulary.
 *
 * Ordered, most severe first, because the accept level is a threshold: a
 * message is taken when its severity compares **less than or equal to** the
 * level in force, which is what makes `NCFG_LOG_DEBUG` the most talkative
 * setting and `NCFG_LOG_CRITICAL` the quietest.
 */
typedef enum {
	/* The daemon cannot continue doing the thing it exists to do. */
	NCFG_LOG_CRITICAL = 0,
	/* Something asked for did not happen. */
	NCFG_LOG_ERROR = 1,
	/* Something happened that the operator would want to have chosen. */
	NCFG_LOG_WARNING = 2,
	/* Worth noticing on an ordinary day. */
	NCFG_LOG_NOTE = 3,
	/* The ordinary running commentary. */
	NCFG_LOG_INFO = 4,
	/* The commentary somebody debugging asked for. */
	NCFG_LOG_VERBOSE = 5,
	/* For whoever is working on netcfgd itself. */
	NCFG_LOG_DEBUG = 6
} ncfg_severity_t;

/*
 * The label flog prints, or NULL where it prints none.
 *
 * Info and verbose carry no label on purpose: the ordinary line is a sentence,
 * and `Info:` in front of every one of them is furniture.
 */
const char *ncfg_log_label(ncfg_severity_t severity);

/* The name `NCFG_LOG` takes, and the one a diagnostic prints back. */
const char *ncfg_log_name(ncfg_severity_t severity);

/* The level a name asks for. 0 for a word this does not know. */
int ncfg_log_from_name(const char *text, ncfg_severity_t *severity);

/* Set, and read, the level messages are taken at. */
void ncfg_log_accept(ncfg_severity_t level);
ncfg_severity_t ncfg_log_accepted(void);

/*
 * Take the level from the environment, once, at startup.
 *
 * **`NCFG_LOG` and nothing cleverer.** A config key would mean a level that
 * only applies after the configuration has been read, which is exactly the
 * window somebody debugging a startup problem cares about. A word this does not
 * know is *said* rather than ignored: a misspelt level that silently keeps the
 * default is the whole family of faults this tree spent a day on.
 */
void ncfg_log_accept_from_env(void);

/*
 * Emit one message, if the level takes it.
 *
 * The rendering is flog's: `[subsystem] Label: text`, with no label for the
 * ordinary levels. The `netcfgd:` in front is netcfgd's own and predates this
 * -- a line read out of a terminal, a `journalctl -f` of several units, or a
 * bug report pasted into a mail says which program is speaking.
 *
 * **One `write` and not two.** Two would let another thread's line land between
 * the prefix and the text, which is how interleaved logs are made. So the line
 * is rendered into one buffer on the stack and handed over whole.
 *
 * **Nothing is returned and nothing exits.** The only write that fails here is
 * one whose reader has gone, and a daemon whose journal went away is still
 * doing its job.
 */
void ncfg_log_emit(const char *subsystem, ncfg_severity_t severity, const char *text);
void ncfg_log_emitf(const char *subsystem, ncfg_severity_t severity, const char *format, ...);

/*
 * Write a program's output to stdout, or leave.
 *
 * **`ncfg status | head -1` aborted with a Rust panic.** Exit status 134, and
 * four lines on stderr about `library/std/src/io/stdio.rs`, because `println!`
 * unwraps the write and Rust ignores `SIGPIPE`. So the ordinary shapes --
 * `| head`, `| less` quit early, `ncfg show | jq .interfaces[0]` -- printed a
 * crash report at somebody who had done nothing wrong.
 *
 * **The one-line fix is the wrong one.** Restoring `SIGPIPE` to its default
 * would make stdout behave like every other Unix tool, and it would also apply
 * to the socket a client writes its requests into: a daemon restarted
 * mid-request would kill `ncfg` where today it prints "cannot send to netcfgd".
 * The C client reached the same junction from the other side and answered it
 * the same way -- `send` with `MSG_NOSIGNAL` per call, and a comment refusing
 * to change a process-wide disposition on a program's behalf. A dead reader on
 * **stdout** is this program's own business; a dead peer on a **socket** is a
 * diagnostic somebody needs.
 *
 * **What is different in C, and it is worth knowing before relying on either
 * half.** C does not ignore `SIGPIPE`, so a program that has left the
 * disposition alone is killed by the signal and the shell reports 141 without
 * this function doing anything. Where the disposition has been set to
 * `SIG_IGN` -- which is what a daemon that talks to sockets does, and what the
 * Rust runtime did unconditionally -- the write returns `EPIPE` instead, and
 * *that* is the path this covers: it leaves with 141, the same status, so the
 * two dispositions are indistinguishable from outside.
 *
 * 141 is 128 + 13, which is what `cat /dev/urandom | head -1` reports.
 *
 * **It leaves through `_exit`**, skipping `atexit` handlers and the stdio
 * flush, exactly as the signal would have. That is safe for what prints through
 * it -- a report, a list, a usage message -- and is worth knowing before
 * anything that has a terminal to restore starts using it.
 *
 * **No error is returned and none could be acted on.** The only write that
 * fails here is one whose reader has gone, and there is nowhere to report that
 * to: stdout is the thing that broke, and stderr is likely the same pipe.
 */
void ncfg_out_write(const char *text);
void ncfg_out_writef(const char *format, ...);

/* `puts`, for a program that may be at the sharp end of a pipe. The empty
 * string writes a blank line, which is what `println!()` spells. */
void ncfg_out_line(const char *text);

#endif /* NCFG_LOG_H */
