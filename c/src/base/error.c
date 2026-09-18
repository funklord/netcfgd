/*
 * error.c -- the error convention described in base.h.
 */
#include "ncfg/base.h"

#include <stdio.h>

void ncfg_error_setv(char *err, size_t err_size, const char *format, va_list args)
{
	if (!err || !err_size) {
		return;
	}
	/* The return value is deliberately ignored: truncation is the only
	 * outcome worth having here, and a failure to format is a bug in the
	 * caller's format string rather than something a message can report. */
	(void)vsnprintf(err, err_size, format, args);
}

void ncfg_error_set(char *err, size_t err_size, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	ncfg_error_setv(err, err_size, format, args);
	va_end(args);
}
