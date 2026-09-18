/*
 * observe_internal.h -- what the observer's three sources share.
 *
 * Not installed and not `ncfg_`-prefixed for that reason: these are internal
 * to `src/observe/` the way `plan_internal.h` is internal to `src/plan/`.
 * `code-style.md`'s rule about prefixing anything that reaches the linker
 * still applies, so every name here begins `observe_`.
 */
#ifndef NCFG_OBSERVE_INTERNAL_H
#define NCFG_OBSERVE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/base.h"

/* A copy of `text`, or NULL. A NULL argument copies the empty string, because
 * every caller here is filling in a model field whose Rust counterpart is a
 * `String` rather than an `Option<String>`. */
char *observe_dup(const char *text);

/* Append a copy of `text` to a counted array of strings, growing it exactly.
 * Exact rather than doubling because these lists are short and are built once:
 * an interface name list is the length of the machine's link table. */
int observe_list_add(char ***list, size_t *count, const char *text);

/* Every string of `in`, copied. */
int observe_list_copy(char ***out, size_t *out_count, char *const *in, size_t count);

/* Whether the list holds this exact name. */
int observe_list_has(char *const *list, size_t count, const char *text);

/* Byte order, so that a list reads the same twice running. */
void observe_list_sort(char **list, size_t count);

/* Release a list this module built. A NULL one is nothing. */
void observe_names_free(char **names, size_t count);

/*
 * A number the kernel reports, into the width the model holds it in.
 *
 * **Checked rather than cast**, with the field named in the refusal, which is
 * 0263's narrowing rule pointed in the reading direction: everything above is
 * `int64_t` and the kernel's fields are unsigned, so the one value that cannot
 * cross is one above `INT64_MAX`. A silent cast would put a negative metric in
 * an observation and a planner would compare against it for ever.
 */
int observe_widen(uint64_t value, const char *what, int64_t *out, char *err, size_t err_size);

#endif /* NCFG_OBSERVE_INTERNAL_H */
