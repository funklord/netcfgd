/*
 * base_test.c -- the error convention and the buffer.
 *
 * WHY THIS EXISTS
 *   Everything in the port builds text through `ncfg_buf_t`, so a fault here
 *   is a fault in every rendered block and every message. The two properties
 *   worth pinning are the ones a caller relies on without thinking: that a
 *   failure is sticky, so twenty appends need one check, and that a buffer
 *   which failed hands out nothing rather than half of something.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

int main(void)
{
	{
		char message[NCFG_ERROR_MAX];

		message[0] = 'x';
		ncfg_error_set(message, sizeof(message), "`%s` is not a %s", "eth0", "link");
		check(strcmp(message, "`eth0` is not a link") == 0, "an error is a sentence, not a code");
		/* A caller that does not want the message passes NULL, and every
		 * failure path calls this unconditionally. */
		ncfg_error_set(NULL, 0, "nobody is listening");
		check(1, "and a caller that wants none may pass none");
	}

	{
		ncfg_buf_t buf;

		ncfg_buf_init(&buf, 0);
		ncfg_buf_add_text(&buf, "interface ");
		ncfg_buf_add_text(&buf, "eth0");
		ncfg_buf_add_char(&buf, ' ');
		ncfg_buf_addf(&buf, "{ config = \"%s\" }", "dhcp");
		check(strcmp(ncfg_buf_text(&buf), "interface eth0 { config = \"dhcp\" }") == 0,
		    "text, bytes and a format all land in order");
		check(!ncfg_buf_failed(&buf), "and nothing failed");
		ncfg_buf_free(&buf);
	}

	{
		ncfg_buf_t buf;
		size_t length = 0;
		char *taken;

		ncfg_buf_init(&buf, 0);
		ncfg_buf_add(&buf, "ab\0cd", 5u);
		check(buf.length == 5u, "a NUL inside the bytes is data, not an end");
		taken = ncfg_buf_take(&buf, &length);
		check(taken != NULL && length == 5u && memcmp(taken, "ab\0cd", 5u) == 0,
		    "and taking it hands over exactly what went in");
		free(taken);
		check(ncfg_buf_text(&buf)[0] == '\0', "leaving the buffer empty");
		ncfg_buf_free(&buf);
	}

	/* **The ceiling, which is the reason this type exists rather than a
	 * `char *` and `realloc`.** A caller that bounds its output gets the
	 * bound enforced on the result, not on each append. */
	{
		ncfg_buf_t buf;
		int i;

		ncfg_buf_init(&buf, 8u);
		for (i = 0; i < 100; i++) {
			ncfg_buf_add_text(&buf, "x");
		}
		check(ncfg_buf_failed(&buf), "a buffer past its limit says so");
		check(ncfg_buf_text(&buf)[0] == '\0',
		    "and hands out nothing rather than the part that fitted");
		check(ncfg_buf_take(&buf, NULL) == NULL, "and has nothing to take");
		ncfg_buf_free(&buf);
	}

	/* Sticky, which is what makes one check after twenty appends correct. */
	{
		ncfg_buf_t buf;

		ncfg_buf_init(&buf, 4u);
		ncfg_buf_add_text(&buf, "toolong");
		check(ncfg_buf_failed(&buf), "the append that did not fit failed");
		ncfg_buf_add_text(&buf, "ok");
		check(ncfg_buf_failed(&buf), "and the one after it is still failed");
		ncfg_buf_free(&buf);
		ncfg_buf_init(&buf, 4u);
		check(!ncfg_buf_failed(&buf), "while a fresh buffer is not");
		ncfg_buf_free(&buf);
	}

	if (failures == 0) {
		printf("base_test: all checks passed\n");
	} else {
		printf("base_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
