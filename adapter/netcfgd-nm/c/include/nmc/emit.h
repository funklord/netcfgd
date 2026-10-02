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
 * A number, remembered, with what it was before.
 *
 * **Because `PropertiesChanged` carries the new value and NM's `StateChanged`
 * carries both.** A client cannot reconstruct a transition from the new state
 * alone -- "went to disconnected" and "has been disconnected" are the same
 * message -- so the old one has to be kept, and the property detector cannot
 * supply it: it overwrites what it remembered.
 *
 * Answers 1 when the value moved, with `was` filled. First sight remembers and
 * answers 0, for the reason the property detector does: a signal per value at
 * startup is a storm.
 */
int nmc_watch_number(nmc_watch_t *watch, const char *key, unsigned long now,
    unsigned long *was);

/*
 * A set of names, remembered, diffed.
 *
 * **For the signals that say what APPEARED rather than what changed.**
 * `DeviceAdded`, `NewConnection` and `AccessPointAdded` are about membership, and
 * a `PropertiesChanged` on the list carries the whole list -- which tells a
 * client that something moved and makes it diff to find out what. NM says which,
 * so this does the diffing once here rather than in every client.
 *
 * `added` and `gone` are filled with pointers into the CALLER's `names` for
 * additions, and into the watch's own memory for removals -- so a removal's
 * name is valid until the next call for the same key. Answers 0 where nothing
 * moved, including first sight: the set is remembered and nothing is announced,
 * or a client would be told every device appeared the moment the shim started.
 */
int nmc_watch_set(nmc_watch_t *watch, const char *key, const char *const *names, size_t count,
    const char **added, size_t *added_count, const char **gone, size_t *gone_count,
    size_t room);

/* Send one signal carrying a single object path. */
void nmc_emit_path(DBusConnection *connection, const char *path, const char *interface,
    const char *member, const char *argument);

/* Send one signal carrying one, two or three `u` arguments -- NM's state
 * signals, whose shapes are `u`, `uu` and `uuu`. */
void nmc_emit_numbers(DBusConnection *connection, const char *path, const char *interface,
    const char *member, const dbus_uint32_t *values, size_t count);

/*
 * The marshalled bytes of one property's value, for the test that proves the
 * comparison can tell two values apart. Answers 0 where the value could not be
 * read. `*out` is the caller's to `free`.
 */
int nmc_watch_value_bytes(const nmc_property_t *property, void *object, unsigned char **out,
    size_t *out_length);

#endif /* NMC_EMIT_H */
