/*
 * out.c -- a program's output, and the one place in this library that ends a
 * process.
 *
 * **This file is for a program's `main`, not for the library around it.**
 * Decision 0263 allows exactly one exception to "a library never exits" and
 * this is it; keeping it in a file of its own is what makes the exception
 * countable -- `grep -rn '_exit' src/` names this file and nothing else, which
 * is a check anybody can run. log.h says why the split runs between stdout and
 * stderr rather than between two kinds of message.
 */
#include "ncfg/log.h"

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

/*
 * What a shell reports for a program killed by `SIGPIPE`.
 *
 * 128 + 13, so that `ncfg status | head -1` reports what
 * `cat /dev/urandom | head -1` reports. See log.h for why the two dispositions
 * -- the signal's default and `SIG_IGN` -- have to be indistinguishable from
 * outside.
 */
#define BROKEN_PIPE 141

/*
 * Leave the way the signal would have.
 *
 * `_exit` and not `exit`: `exit` runs `atexit` handlers and flushes stdio,
 * which means writing to the same broken pipe again on the way out. Skipping
 * destructors is what `SIGPIPE` does, and it is safe for what prints through
 * here -- a report, a list, a usage message.
 */
static void leave(void)
{
	_exit(BROKEN_PIPE);
}

/*
 * Flush what was just written and leave if the reader has gone.
 *
 * **Flushed per call, which is what Rust's `LineWriter` does**, and not an
 * oversight about buffering: a program that discovers its reader went away
 * three screens later has already built three screens of output nobody wanted,
 * and `ncfg show | head -1` is the shape this exists for.
 */
static void settle(int wrote)
{
	if (wrote < 0 || fflush(stdout) != 0 || ferror(stdout)) {
		leave();
	}
}

void ncfg_out_write(const char *text)
{
	if (!text) {
		return;
	}
	settle(fputs(text, stdout));
}

void ncfg_out_line(const char *text)
{
	int wrote = 0;

	if (text && text[0] != '\0') {
		wrote = fputs(text, stdout);
	}
	if (wrote >= 0) {
		wrote = fputc('\n', stdout);
	}
	settle(wrote);
}

/*
 * No ceiling here, unlike a log line.
 *
 * A log line is a sentence and a bounded one; a program's output is the whole
 * of what it was asked for -- a document, a table of every interface -- and
 * truncating that at a kilobyte would be answering a different question. The
 * bound on what a *client* can make netcfgd render lives in `ncfg_buf_t`, where
 * the untrusted text is.
 */
void ncfg_out_writef(const char *format, ...)
{
	va_list args;
	int wrote;

	if (!format) {
		return;
	}
	va_start(args, format);
	wrote = vfprintf(stdout, format, args);
	va_end(args);
	settle(wrote);
}
