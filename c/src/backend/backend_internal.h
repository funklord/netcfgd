/*
 * backend_internal.h -- what the four backends share, and nothing else.
 *
 * Private to `src/backend/`, the way `src/host/host_internal.h` is private to
 * the host module and `src/model/field.h` to the model. What is here is the
 * handful of operations that would otherwise be written once per daemon:
 * building a path, making the run directory, reading a log back, starting a
 * program and picking the lines out of its log that say why it would not run.
 *
 * WHY IT IS NOT `host_internal.h`
 *   That header says in its first sentence that it is private to `src/host/`,
 *   and reaching across a boundary a module states is worse than a second
 *   small copy of `mkdir -p`. The two should become one when a public
 *   filesystem header lands; until then this is the smaller of the two wrongs
 *   and it is written down rather than discovered.
 *
 * WHY THE LOG READER IS SHARED AND THE MARKERS ARE NOT
 *   radvd, hostapd and openvpn each have a `complaints` in the Rust and all
 *   three are the same function with a different word list -- "a daemon that
 *   fails announces the reason and then narrates its shutdown, so the tail is
 *   the wrong lines". One implementation, three tables. The three had already
 *   drifted in the Rust: hostapd's alone special-cases a line beginning `Line `
 *   and lowercases before matching, which is a rule the other two would want
 *   if anybody had noticed.
 *
 * WHY A PROGRAM IS A PARAMETER EVERYWHERE BELOW
 *   The Rust finds `radvd`, `hostapd` and `openvpn` by searching `/usr/sbin`
 *   first, and openvpn's own comment records what that cost: `tests/live/
 *   openvpn.sh` faked the daemon on `PATH` to check the command line netcfgd
 *   builds, the search reached the real one first, and 20 of its 45 checks
 *   were silently exercising the machine's openvpn (0101). `NCFG_OPENVPN` was
 *   added for that and the other two never got one. Here the caller passes the
 *   program, and `ncfg_backend_find_program` is what a caller with no opinion
 *   calls -- so a test points at a program it wrote and cannot reach a real
 *   daemon by accident, and no environment variable decides which binary a
 *   daemon runs.
 */
#ifndef NCFG_BACKEND_INTERNAL_H
#define NCFG_BACKEND_INTERNAL_H

#include <stddef.h>
#include <sys/types.h>

/*
 * Build `<dir>/<leaf>` into `out`. 1 on success.
 *
 * Truncation is a failure rather than a shorter path: a path that lost its
 * last component names a different file, and every caller here is about to
 * write to it.
 */
int ncfg_backend_join(char *out, size_t out_size, const char *dir, const char *leaf, char *err,
    size_t err_size);

/* `<dir>/<middle>/<leaf><suffix>`, for the `<run>/<daemon>/<iface>.conf` shape
 * every one of these modules has. Any of `middle` or `suffix` may be NULL. */
int ncfg_backend_path(char *out, size_t out_size, const char *dir, const char *middle,
    const char *leaf, const char *suffix, char *err, size_t err_size);

/* `mkdir -p`, with `mode` on every component this call creates. An existing
 * directory is success, which is what every caller means. */
int ncfg_backend_make_dir(const char *path, mode_t mode, char *err, size_t err_size);

/*
 * Read a whole file, NUL-terminated, at most `ceiling` bytes.
 *
 * NULL with `errno` left as the failing call set it: the callers here have to
 * tell "not there" from "cannot be looked at", and one of them -- hostapd's
 * recorded policy -- gives opposite answers for the two.
 */
char *ncfg_backend_read_file(const char *path, size_t *length_out, size_t ceiling);

/*
 * Write `length` bytes to `path`, creating it with `mode`.
 *
 * **The mode is corrected on the open handle before a byte is written**, and
 * that is not belt and braces. `open(2)`'s mode argument applies only when the
 * call creates the file, so rewriting one that already exists keeps whatever
 * mode it already had -- measured against a hostapd configuration left at 0644,
 * which stayed 0644 through exactly the write that put the passphrase in it.
 * `/run` survives a restart by design, so "it cannot already exist" is not
 * true either.
 */
int ncfg_backend_write_file(const char *path, const void *bytes, size_t length, mode_t mode,
    char *err, size_t err_size);

/*
 * Run `program` with `argv`, sending both its output streams to `log_path`.
 *
 * `argv` is NULL-terminated and `argv[0]` is the program's own name. The exit
 * status is what `waitpid` reported; `*exited_ok` is 1 only where the child
 * exited with status 0.
 *
 * **The child is put in its own process group before the exec.** A daemon that
 * ignores its parent's terminal is the ordinary case, and the one that matters
 * is a program that does not: a test's fake, or a daemon that will not
 * daemonize, must be killable as a group rather than leaving whatever it
 * spawned behind. The three daemons here all fork and return, so the wait is
 * on the parent alone and cannot hang on a grandchild holding the pipe -- which
 * is why the streams go to a file rather than to a pipe this would have to
 * drain.
 */
int ncfg_backend_run(const char *program, const char *const *argv, const char *log_path,
    int *exited_ok, int *status_out, char *err, size_t err_size);

/*
 * The lines of a log that say what went wrong, joined with `; `.
 *
 * `markers` are matched case-insensitively against each line; `line_prefixes`
 * are matched at the start of a line with case, for hostapd's `Line 6: ...`.
 * At most `count` lines are chosen, and where nothing matches the last `count`
 * lines are taken instead -- the most recent thing the daemon had to say beats
 * reporting only an exit status.
 *
 * 0 where the log says nothing at all, so a caller can fall back to the status.
 * Joined rather than kept as lines because this ends up in a single-line
 * journal record, where an embedded newline breaks the alignment of everything
 * after it.
 */
int ncfg_backend_complaints(const char *log_path, const char *const *markers, size_t marker_count,
    const char *const *line_prefixes, size_t prefix_count, size_t count, char *out,
    size_t out_size);

/* A copy of `text`, or NULL. Named rather than `strdup` because every other
 * module here open-codes `malloc` plus `memcpy` for it, and a library that
 * uses both spellings is one where a reader has to check which. */
char *ncfg_backend_strdup(const char *text);

/*
 * Find a daemon by name, `/usr/sbin` first and then `PATH`.
 *
 * Allocated, or NULL where nothing was found. `/usr/sbin` is not on a non-root
 * `PATH` on Debian and several others, so searching `PATH` alone finds nothing
 * on a machine that has the package.
 */
char *ncfg_backend_find_program(const char *name);

/*
 * Find a program on `PATH` and nowhere else.
 *
 * **For the DHCP clients only**, which is where the two searches differ and
 * the difference is the Rust's: it runs `Command::new("dhcpcd")` for those,
 * which consults `PATH` alone, while `hostapd`, `radvd`, `openvpn`, `pppd`
 * and `wpa_supplicant` each get the `/usr/sbin`-first search above. A client
 * is something an operator installs and may shadow; a daemon is something the
 * package manager puts in a directory an ordinary `PATH` does not carry.
 *
 * `tests/live/exec_refused.sh` depends on this half: it points `PATH` at a
 * directory holding a stand-in and expects netcfgd to run it, which the
 * `/usr/sbin`-first search would defeat on any machine with dhcpcd installed.
 */
char *ncfg_backend_find_on_path(const char *name);

#endif /* NCFG_BACKEND_INTERNAL_H */
