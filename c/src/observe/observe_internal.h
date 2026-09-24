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
#include "ncfg/netlink.h"
#include "ncfg/observe.h"

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
 * The whole of a file netcfgd generated, or NULL, with a ceiling on it.
 *
 * Absent, unreadable and past the ceiling are one answer throughout this
 * module and it is never a failure: a daemon netcfgd never started has no
 * generated file, and a `/run` cleared under a running one has none either.
 * Neither is a statement about what the daemon is doing.
 */
char *observe_read_generated(const char *path);

/*
 * The value of `key=` in a generated configuration, copied into `out`.
 *
 * The first match wins, which is how hostapd reads its own file. 1 with the
 * value, 0 where the key is absent **or would not fit** -- and those are one
 * answer on purpose: a truncated value compares unequal to what the document
 * asks for, which restarts a working daemon on every reconcile, and that is
 * the failure these passes exist to avoid rather than to cause.
 */
int observe_config_value(const char *text, const char *key, char *out, size_t out_size);

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

/*
 * A netfilter socket for the nftables round, and the exchange that speaks to
 * it.
 *
 * Internal because its caller is in this module and the pair it produces is
 * one public argument: `ncfg_observe_current` opens one beside the route
 * socket for a whole observation. There was a second caller --
 * `ncfg_observe_netfilter`, which opened one for a single read -- and nothing
 * ever asked for a single read, so it is gone (project.md 10.258). 0 is a
 * machine with no nftables, which is a note rather than a
 * failure and is said there -- the socket is left closed and the caller asks
 * nothing.
 */
int observe_netfilter_open(ncfg_netlink_t *socket, ncfg_observe_kernel_t *out);

/*
 * A generic netlink socket for the offloads round, and the exchange that
 * speaks to it.
 *
 * Internal for `observe_netfilter_open`'s reason, and the two are deliberately
 * the same shape: `ncfg_observe_current` opens one beside the other two for a
 * whole observation, and the single-read entry point each of them had is gone
 * for the reason given there. 0 is a machine whose netlink this process may
 * not open, which is a note rather than a failure and is said there -- the
 * socket is left closed and the caller asks nothing.
 *
 * **The protocol, not the family.** Every generic netlink family shares one
 * socket, and the two WireGuard passes -- which this comment described as
 * still deferred for several waves after they landed -- ask their family over
 * this one rather than a fourth.
 */
int observe_genl_open(ncfg_netlink_t *socket, ncfg_observe_kernel_t *out);

#endif /* NCFG_OBSERVE_INTERNAL_H */
