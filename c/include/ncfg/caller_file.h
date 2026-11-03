/*
 * caller_file.h -- a file a root daemon writes where a less trusted caller asks.
 *
 * WHY THIS EXISTS
 *   0309 carries netcfgd's requests over fuzznet, whose framing answers a
 *   document by writing it to a path the client names (fuzznet sec 843:
 *   `get status PATH`, answered `ok` with the length). netcfgd runs as root,
 *   and the caller may hold only the `observe` tier. Writing to whatever path
 *   it names would let it make root create or overwrite any file -- a symlink
 *   left in /tmp is enough -- so the path is held to a rule before a byte is
 *   written (project.md 10.680).
 *
 * THE RULE
 *   - The path is absolute, and names a file, not a directory.
 *   - Its directory is owned by the caller, and writable by nobody else:
 *     the caller could have made the file there itself, and nobody else can
 *     swap the name between the check and the open.
 *   - The file is new: created with O_EXCL and O_NOFOLLOW, so an existing
 *     file or a symlink in its place is refused rather than written through.
 *   - It is made 0600 and given to the caller, so what root wrote is the
 *     caller's file, as if it had written it.
 *   Root as the caller is held to the same rule; it gains nothing by asking
 *   the daemon what it could not do itself.
 */
#ifndef NCFG_CALLER_FILE_H
#define NCFG_CALLER_FILE_H

#include <stddef.h>
#include <sys/types.h>

/*
 * Create `path` for `uid` (`gid` its primary group) under the rule above and
 * write `length` bytes of `body` into it. 1 on success; 0 with a sentence in
 * `err`, having created nothing -- or, where the write itself failed part way,
 * having removed what it created.
 */
int ncfg_caller_file_create(const char *path, uid_t uid, gid_t gid, const char *body,
    size_t length, char *err, size_t err_size);

#endif /* NCFG_CALLER_FILE_H */
