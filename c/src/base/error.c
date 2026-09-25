/*
 * error.c -- the error convention described in base.h.
 */
#include <errno.h>
#include "ncfg/base.h"

#include <stdio.h>

void ncfg_error_setv(char *err, size_t err_size, const char *format, va_list args)
{
	/*
	 * **`errno` is restored, because callers read it after this returns.**
	 * `vsnprintf` is allowed to set `errno` on success and glibc's does for
	 * some conversions, so a function that reported a failure and then let a
	 * caller ask *which* failure was handing it whatever the formatting left
	 * behind.
	 *
	 * The case that found it: the resolver's staging write distinguishes a
	 * read-only `/etc` -- where it falls back to writing in place -- from a
	 * full disk, where falling back would truncate a working `resolv.conf`
	 * and then fail to refill it. That test is `errno == EACCES || EPERM ||
	 * EROFS`, read after a call that formats a message, and an `EROFS` that
	 * became something else would empty somebody's resolver.
	 *
	 * Saved and restored here rather than at each caller: there is one of
	 * these and there are hundreds of those, and a rule that has to be
	 * remembered at every site is one that will be missed at some of them.
	 */
	int saved = errno;

	if (!err || !err_size) {
		return;
	}
	/* The return value is deliberately ignored: truncation is the only
	 * outcome worth having here, and a failure to format is a bug in the
	 * caller's format string rather than something a message can report. */
	(void)vsnprintf(err, err_size, format, args);
	errno = saved;
}

void ncfg_error_set(char *err, size_t err_size, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	ncfg_error_setv(err, err_size, format, args);
	va_end(args);
}
