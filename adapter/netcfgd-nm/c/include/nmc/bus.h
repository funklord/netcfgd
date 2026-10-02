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
	int (*call)(DBusMessage *call, DBusMessage *reply, void *object, char *err,
	    size_t err_size);
} nmc_method_t;

/* One interface: a name and what it answers for. */
typedef struct {
	const char           *name;
	const nmc_property_t *properties;
	size_t                property_count;
	const nmc_method_t   *methods;
	size_t                method_count;
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
 * Serve `objects` on `connection` until `nmc_bus_stop` or the bus goes away.
 *
 * Returns 1 on an orderly stop and 0 with a sentence in `err` when a path
 * could not be registered -- which is a programming error rather than a
 * runtime one, so it is worth failing loudly at startup.
 */
int nmc_bus_serve(DBusConnection *connection, const nmc_object_t *objects, size_t count,
    char *err, size_t err_size);

/* Ask the loop to return. Safe from a signal handler. */
void nmc_bus_stop(void);

/*
 * The introspection XML for one object, rendered from its tables.
 *
 * Exposed because the policy gate reads the served interface names, and
 * asking the program what it serves beats parsing the source for attributes
 * -- which is how `tool/dbus_policy_gate.py` came to miss one (0264).
 */
int nmc_bus_introspect(const nmc_object_t *object, char *out, size_t out_size);

#endif /* NMC_BUS_H */
