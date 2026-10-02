/*
 * nmc/bus.h -- the object model this shim serves, as tables.
 *
 * WHY TABLES AND NOT A FUNCTION PER MESSAGE
 *   The Rust shim this replaces declares its interfaces with
 *   `#[zbus::interface]` and gets introspection, property access and method
 *   dispatch generated from the declaration. libdbus generates nothing: a
 *   handler is handed a `DBusMessage` and everything after that is the
 *   program's. Written once per interface that is eleven interfaces' worth of
 *   `strcmp` chains, each able to disagree with the introspection XML beside
 *   it -- and a client reads the XML, so a disagreement is a defect a client
 *   sees and the program does not.
 *
 *   So the interface is DATA. `Introspect` is rendered from the same table the
 *   dispatcher routes with, which is what makes them unable to drift: there is
 *   no second list to forget. Decision 0043's argument about quirks, applied
 *   to a bus surface -- a quirk expressed as a branch grows a second branch.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO
 *   No signals yet. `Device.Wireless` has two and `emit.rs` is 1,177 lines of
 *   change tracking; that is its own piece of work and this header will gain a
 *   member rather than being rearranged for it.
 *
 *   No object manager. NetworkManager does not serve one, and the shim is
 *   judged by what libnm believes (0264).
 */
#ifndef NMC_BUS_H
#define NMC_BUS_H

#include <dbus/dbus.h>

#include <stddef.h>

/* The longest error sentence a handler may hand back. */
#define NMC_ERROR_MAX 512

/*
 * How a property is reached.
 *
 * `NMC_READ` is the common case by a wide margin: of the interfaces 0264
 * counted, one property in a hundred is writable. A writable one with no
 * `set` is a declaration the dispatcher refuses rather than a silent
 * read-only, because the two are different answers to a client.
 */
typedef enum {
	NMC_READ = 0,
	NMC_READWRITE
} nmc_access_t;

/*
 * One property.
 *
 * `get` appends the VALUE, not the variant: the dispatcher opens the variant
 * with `signature` and closes it, so a property cannot disagree with the
 * signature it published. That is the whole reason the signature is in the
 * table rather than inferred from what `get` happened to write.
 */
typedef struct {
	const char  *name;
	const char  *signature;
	nmc_access_t access;
	int (*get)(DBusMessageIter *into, void *object, char *err, size_t err_size);
	int (*set)(DBusMessageIter *from, void *object, char *err, size_t err_size);
} nmc_property_t;

/* One method. `reply` is already built; a handler appends its arguments. */
typedef struct {
	const char *name;
	/* D-Bus signatures, for introspection and for refusing a bad call
	 * before it reaches the handler. Empty string means no arguments. */
	const char *in_signature;
	const char *out_signature;
	/*
	 * `connection` is handed over because **a method that cannot reach the
	 * bus cannot ask who is calling**, and a write has to: the uid comes
	 * from `GetConnectionUnixUser` and never from the message. See
	 * `nmc/authorize.h`.
	 */
	int (*call)(DBusConnection *connection, DBusMessage *call, DBusMessage *reply,
	    void *object, char *err, size_t err_size);
} nmc_method_t;

/*
 * One signal this interface may emit.
 *
 * Declared so introspection publishes it, which is the half that matters even
 * before anything emits one: a client reads the document to decide whether to
 * subscribe, and a signal nobody declared is a signal nobody waits for.
 */
typedef struct {
	const char *name;
	const char *signature;
} nmc_signal_t;

/* One interface: a name and what it answers for. */
typedef struct {
	const char           *name;
	const nmc_property_t *properties;
	size_t                property_count;
	const nmc_method_t   *methods;
	size_t                method_count;
	const nmc_signal_t   *signals;
	size_t                signal_count;
} nmc_interface_t;

/*
 * One object path and the interfaces at it.
 *
 * `interfaces` is NULL-terminated rather than counted, because an object's
 * list is written out literally at a call site and a count beside it is a
 * second thing to keep right. The property and method arrays are counted
 * because they are `sizeof` divisions the compiler does.
 */
typedef struct {
	const char                   *path;
	const nmc_interface_t *const *interfaces;
	void                         *data;
} nmc_object_t;

/*
 * A family of objects under one path prefix, resolved per message.
 *
 * **Why a prefix and not a registration per device.** NM serves a device at
 * `/org/freedesktop/NetworkManager/Devices/<n>`, and the set changes as a cable
 * is plugged or a radio is rfkilled. Registering and unregistering a path per
 * device means the bus layer has to be told about every change, which is the
 * cache `state.h` says this port does not have yet -- so libdbus's fallback
 * handler takes the whole subtree and the tail is resolved when a message
 * arrives. The set is then never stale, because it is never stored.
 *
 * `resolve` is handed the tail after the prefix and one `/` -- "3" for
 * `.../Devices/3` -- and answers the object data or NULL for no such object.
 * A NULL answer is `UnknownObject`, which is what a client holding a path to a
 * device that has gone must be told.
 *
 * `enumerate` is for `Introspect` on the prefix itself, which lists child
 * nodes. libnm never needs it -- it reads the `Devices` property -- but
 * `busctl tree` does, and a subtree that introspects as empty looks broken to
 * whoever is debugging it. NULL means "say no children".
 */
typedef struct {
	const char                   *prefix;
	/* The interfaces every child serves, where they all serve the same ones.
	 * `interfaces_for` overrides this per object and is what a family of
	 * differing objects needs. */
	const nmc_interface_t *const *interfaces;
	/*
	 * The interfaces THIS object serves, or NULL to use the list above.
	 *
	 * **Because a device serves exactly one subtype interface.** NM puts
	 * `.Device` on every device and `.Wireless` on precisely the ones that
	 * are radios, and libnm reads the introspection document to decide what
	 * a device is -- so serving `.Wireless` on an ethernet port is not an
	 * unused interface, it is a lie a client acts on.
	 */
	const nmc_interface_t *const *(*interfaces_for)(void *object);
	/*
	 * What the PREFIX itself serves, or NULL for nothing.
	 *
	 * **Because a path cannot be both an object and a fallback.** libdbus
	 * refuses the second registration, loudly -- which is how this member
	 * came to exist: `/Settings` serves `...Settings` and `/Settings/N`
	 * serves `...Settings.Connection`, so registering an object at the one
	 * and a fallback at the other's parent is the same path twice.
	 *
	 * `/Devices` is the other case and wants NULL: NM serves nothing there
	 * either.
	 */
	const nmc_interface_t *const *root_interfaces;
	void                         *root_data;
	void *(*resolve)(const char *tail, void *context);
	/* Write up to `max` child names into `names`; answer how many. */
	size_t (*enumerate)(const char **names, size_t max, void *context);
	void *context;
} nmc_subtree_t;

/*
 * Serve `objects` on `connection` until `nmc_bus_stop` or the bus goes away.
 *
 * Returns 1 on an orderly stop and 0 with a sentence in `err` when a path
 * could not be registered -- which is a programming error rather than a
 * runtime one, so it is worth failing loudly at startup.
 */
/*
 * `tick` is called once per wake, which is where a poll for changed properties
 * belongs: the loop already wakes on a timer so the stop flag is reachable, and
 * hanging the poll off that costs no second timer and no thread.
 */
int nmc_bus_serve(DBusConnection *connection, const nmc_object_t *objects, size_t count,
    const nmc_subtree_t *subtrees, size_t subtree_count, void (*tick)(void *context),
    void *tick_context, char *err, size_t err_size);

/* Ask the loop to return. Safe from a signal handler. */
void nmc_bus_stop(void);

/*
 * The introspection XML for one object, rendered from its tables.
 *
 * Exposed because the policy gate reads the served interface names, and
 * asking the program what it serves beats parsing the source for attributes
 * -- which is how `tool/dbus_policy_gate.py` came to miss one (0264).
 *
 * `children` are the node names to advertise beneath this path, or NULL for
 * none. **Without them a client's tree walk stops here**, which is how
 * `busctl tree` came to show the manager and not one device: the paths were
 * served and reachable, and nothing said they existed.
 */
int nmc_bus_introspect(const nmc_object_t *object, const char *const *children,
    size_t child_count, char *out, size_t out_size);

#endif /* NMC_BUS_H */
