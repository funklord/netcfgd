/*
 * host_internal.h -- what the host module's files share, and nothing else.
 *
 * Private to `src/host/`, the way `src/model/field.h` is private to the model:
 * these are not answers callers need, they are the four or five operations
 * that would otherwise be written once per file here. A path join written
 * three times is three chances to forget the separator; an atomic write
 * written twice is the defect `state.c` documents at length, where two copies
 * of one rule drifted into one that named its temporary after the process and
 * one that called every temporary `<name>.tmp`.
 */
#ifndef NCFG_HOST_INTERNAL_H
#define NCFG_HOST_INTERNAL_H

#include <stddef.h>
#include <sys/types.h>

/* `<dir>/<leaf>`, allocated. NULL with a sentence on failure. */
char *ncfg_host_join(const char *dir, const char *leaf, char *err, size_t err_size);

/* `mkdir -p`, with `mode` on every component this call creates. An existing
 * directory is success, which is what every caller means. */
int ncfg_host_make_directory(const char *path, mode_t mode, char *err, size_t err_size);

/*
 * Write a file via a temporary and a rename.
 *
 * The implementation behind `ncfg_write_atomically`; see `state.h` for the
 * reasoning, which is a defect rather than a preference.
 */
int ncfg_host_write_atomically(const char *path, const void *bytes, size_t length, mode_t mode,
    char *err, size_t err_size);

/*
 * Read a whole file.
 *
 * Returns the bytes NUL-terminated (so a caller may treat text as text) with
 * the length in `*length_out`, or NULL. `errno` is left as the failing call
 * set it, because the callers here distinguish "not there" from "cannot be
 * looked at" and a boolean cannot carry that.
 */
char *ncfg_host_read_file(const char *path, size_t *length_out, size_t ceiling);

/* Append a copy of `text` to a growable array of strings. Returns 1, or 0 with
 * the array unchanged. */
int ncfg_host_strings_add(char ***items, size_t *count, size_t *capacity, const char *text);

/* Append a copy of `length` bytes, NUL-terminated. */
int ncfg_host_strings_add_bytes(char ***items, size_t *count, size_t *capacity,
    const char *text, size_t length);

/* Sort by name and drop repeats, in place. */
void ncfg_host_strings_sort_unique(char **items, size_t *count);

/* Free a string array and zero the count. */
void ncfg_host_strings_free(char **items, size_t count);

/* Whether a directory entry is a writer's staging file rather than content.
 *
 * `netcfgd-apply`'s `is_staging`, which is deliberately broader than the names
 * netcfgd itself generates: **anything** beginning with a dot, so a
 * third-party writer that stages under some other dotted name is safe by
 * following the contract's wording rather than by matching netcfgd's spelling
 * exactly -- and `.` and `..` are excluded for free. It lives here until the
 * apply module lands, and moves there when it does. */
int ncfg_host_is_staging(const char *name);

#endif /* NCFG_HOST_INTERNAL_H */
