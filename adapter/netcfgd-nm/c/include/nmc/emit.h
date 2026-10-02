/*
 * nmc/emit.h -- noticing that a property changed, and saying so.
 *
 * WHY THIS IS WHERE THE CACHE LIVES
 *   `state.h` says every getter asks netcfgd and there is no cache, and gives
 *   the reason: a cache without the change tracking that invalidates it is a
 *   bug. This is that tracking, so this is where a cache is honest -- it holds
 *   the LAST VALUE SEEN, which is exactly what "did it change" needs and
 *   nothing a getter would read.
 *
 * WHAT IS COMPARED
 *   The marshalled bytes of the value, not a rendering of it. A comparison that
 *   went through a string would have to know every type the tables can declare
 *   -- `a{sv}`, `aa{sv}`, `(uu)` -- and would be a second marshaller to keep
 *   right. libdbus already has one.
 *
 *   First sight is not a change. A property seen for the first time is
 *   remembered and nothing is emitted, or every client would get a
 *   `PropertiesChanged` for everything the moment the shim started.
 */
#ifndef NMC_EMIT_H
#define NMC_EMIT_H

#include "nmc/bus.h"

typedef struct nmc_watch nmc_watch_t;

nmc_watch_t *nmc_watch_new(void);
void         nmc_watch_free(nmc_watch_t *watch);

/*
 * Read every property of `object`, and emit `PropertiesChanged` per interface
 * whose values moved.
 *
 * Answers how many signals were sent, which is 0 on a converged machine and is
 * the number worth watching: a poll that always emits is a property whose
 * getter is not stable, and that is a defect rather than a busy network.
 */
size_t nmc_watch_poll(nmc_watch_t *watch, DBusConnection *connection,
    const nmc_object_t *object);

/*
 * Forget everything remembered about paths under `prefix`.
 *
 * For a device that has gone: without this its last values stay, and a device
 * that comes back on the same number would be compared against what the
 * previous one said and emit nothing.
 */
void nmc_watch_forget(nmc_watch_t *watch, const char *prefix);

/*
 * Whether this property's value moved since the last look, remembering what it
 * says now.
 *
 * **Exposed because "no signals were emitted" is not evidence on its own.** A
 * converged machine emits nothing and so does a detector that can never fire,
 * and the two are indistinguishable from the bus. This is the predicate the
 * poll is built on, and a test can drive it without a connection: first sight
 * answers 0 and remembers, an unchanged value answers 0, and a changed one
 * answers 1.
 */
int nmc_watch_moved(nmc_watch_t *watch, const char *path, const nmc_interface_t *interface,
    const nmc_property_t *property, void *object);

/*
 * The marshalled bytes of one property's value, for the test that proves the
 * comparison can tell two values apart. Answers 0 where the value could not be
 * read. `*out` is the caller's to `free`.
 */
int nmc_watch_value_bytes(const nmc_property_t *property, void *object, unsigned char **out,
    size_t *out_length);

#endif /* NMC_EMIT_H */
