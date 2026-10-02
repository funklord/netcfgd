/* emit.c -- the last value seen, and the signal when it moves. */
#include "nmc/emit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One remembered value. */
typedef struct {
	char          *path;
	const char    *interface; /* borrowed from the table, which outlives this */
	const char    *property;
	unsigned char *bytes;
	size_t         length;
} seen_t;

struct nmc_watch {
	seen_t *at;
	size_t  count;
	size_t  capacity;
};

nmc_watch_t *nmc_watch_new(void)
{
	return calloc(1, sizeof(nmc_watch_t));
}

void nmc_watch_free(nmc_watch_t *watch)
{
	size_t at;

	if (!watch) {
		return;
	}
	for (at = 0u; at < watch->count; at++) {
		free(watch->at[at].path);
		free(watch->at[at].bytes);
	}
	free(watch->at);
	free(watch);
}

/*
 * One value, marshalled.
 *
 * **A scratch message, because libdbus marshals messages and not values.** The
 * header it produces is identical for every call here -- same type, same path,
 * same member, and a serial of 0 because the message is never sent -- so a
 * difference in the bytes is a difference in the value. `bus_test` asserts
 * exactly that rather than leaving it as an assumption: equal values give equal
 * bytes and different values do not.
 */
int nmc_watch_value_bytes(const nmc_property_t *property, void *object, unsigned char **out,
    size_t *out_length)
{
	DBusMessage    *scratch;
	DBusMessageIter append;
	DBusMessageIter variant;
	char           *marshalled = NULL;
	int             length = 0;
	char            err[NMC_ERROR_MAX] = "";

	*out = NULL;
	*out_length = 0u;
	scratch = dbus_message_new_method_call("org.netcfgd.Scratch", "/", "org.netcfgd.Scratch",
	    "Value");
	if (!scratch) {
		return 0;
	}
	dbus_message_iter_init_append(scratch, &append);
	if (!dbus_message_iter_open_container(&append, DBUS_TYPE_VARIANT, property->signature,
	        &variant)) {
		dbus_message_unref(scratch);
		return 0;
	}
	if (!property->get(&variant, object, err, sizeof(err))) {
		(void)dbus_message_iter_abandon_container_if_open(&append, &variant);
		dbus_message_unref(scratch);
		return 0;
	}
	(void)dbus_message_iter_close_container(&append, &variant);
	if (!dbus_message_marshal(scratch, &marshalled, &length) || length <= 0) {
		dbus_message_unref(scratch);
		return 0;
	}
	*out = malloc((size_t)length);
	if (!*out) {
		dbus_free(marshalled);
		dbus_message_unref(scratch);
		return 0;
	}
	memcpy(*out, marshalled, (size_t)length);
	*out_length = (size_t)length;
	dbus_free(marshalled);
	dbus_message_unref(scratch);
	return 1;
}

static seen_t *remembered(nmc_watch_t *watch, const char *path, const char *interface,
    const char *property)
{
	size_t at;

	for (at = 0u; at < watch->count; at++) {
		if (strcmp(watch->at[at].path, path) == 0 &&
		    strcmp(watch->at[at].interface, interface) == 0 &&
		    strcmp(watch->at[at].property, property) == 0) {
			return &watch->at[at];
		}
	}
	return NULL;
}

static seen_t *remember(nmc_watch_t *watch, const char *path, const char *interface,
    const char *property)
{
	seen_t *slot;

	if (watch->count == watch->capacity) {
		size_t  bigger = watch->capacity ? watch->capacity * 2u : 64u;
		seen_t *grown = realloc(watch->at, bigger * sizeof(*grown));

		if (!grown) {
			return NULL;
		}
		watch->at = grown;
		watch->capacity = bigger;
	}
	slot = &watch->at[watch->count];
	memset(slot, 0, sizeof(*slot));
	slot->path = strdup(path);
	if (!slot->path) {
		return NULL;
	}
	slot->interface = interface;
	slot->property = property;
	watch->count++;
	return slot;
}

void nmc_watch_forget(nmc_watch_t *watch, const char *prefix)
{
	size_t at = 0u;
	size_t length = strlen(prefix);

	while (at < watch->count) {
		if (strncmp(watch->at[at].path, prefix, length) == 0) {
			free(watch->at[at].path);
			free(watch->at[at].bytes);
			/* Swapped with the last rather than shifted: the order
			 * means nothing and a shift is quadratic over a sweep. */
			watch->at[at] = watch->at[watch->count - 1u];
			watch->count--;
			continue;
		}
		at++;
	}
}

/*
 * Whether this property moved, remembering whatever it says now.
 *
 * Answers 1 only for a value that was seen before AND differs. First sight
 * stores and answers 0, or a client would get a `PropertiesChanged` naming
 * everything the moment the shim started.
 */
int nmc_watch_moved(nmc_watch_t *watch, const char *path, const nmc_interface_t *interface,
    const nmc_property_t *property, void *object)
{
	unsigned char *bytes = NULL;
	size_t         length = 0u;
	seen_t        *slot;
	int            changed;

	if (!nmc_watch_value_bytes(property, object, &bytes, &length)) {
		/*
		 * A property that could not be read is not a property that
		 * changed. Emitting for it would tell a client to re-read
		 * something that is going to fail again -- and netcfgd being
		 * away makes every getter fail at once, which would be a storm.
		 */
		return 0;
	}
	slot = remembered(watch, path, interface->name, property->name);
	if (!slot) {
		slot = remember(watch, path, interface->name, property->name);
		if (!slot) {
			free(bytes);
			return 0;
		}
		slot->bytes = bytes;
		slot->length = length;
		return 0;
	}
	changed = slot->length != length || memcmp(slot->bytes, bytes, length) != 0;
	free(slot->bytes);
	slot->bytes = bytes;
	slot->length = length;
	return changed;
}

size_t nmc_watch_poll(nmc_watch_t *watch, DBusConnection *connection, const nmc_object_t *object)
{
	size_t sent = 0u;
	size_t which;

	if (!watch || !connection || !object || !object->interfaces) {
		return 0u;
	}
	for (which = 0u; object->interfaces[which] != NULL; which++) {
		const nmc_interface_t *interface = object->interfaces[which];
		const nmc_property_t  *changed[64];
		size_t                 count = 0u;
		size_t                 at;
		DBusMessage           *signal;
		DBusMessageIter        body;
		DBusMessageIter        array;
		DBusMessageIter        invalidated;

		for (at = 0u; at < interface->property_count &&
		     count < sizeof(changed) / sizeof(changed[0]);
		     at++) {
			if (nmc_watch_moved(watch, object->path, interface,
			        &interface->properties[at], object->data)) {
				changed[count++] = &interface->properties[at];
			}
		}
		if (count == 0u) {
			continue;
		}
		signal = dbus_message_new_signal(object->path, DBUS_INTERFACE_PROPERTIES,
		    "PropertiesChanged");
		if (!signal) {
			continue;
		}
		dbus_message_iter_init_append(signal, &body);
		(void)dbus_message_iter_append_basic(&body, DBUS_TYPE_STRING, &interface->name);
		if (!dbus_message_iter_open_container(&body, DBUS_TYPE_ARRAY, "{sv}", &array)) {
			dbus_message_unref(signal);
			continue;
		}
		for (at = 0u; at < count; at++) {
			DBusMessageIter entry;
			DBusMessageIter variant;
			char            err[NMC_ERROR_MAX] = "";

			if (!dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL,
			        &entry)) {
				break;
			}
			(void)dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
			    &changed[at]->name);
			if (!dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
			        changed[at]->signature, &variant) ||
			    !changed[at]->get(&variant, object->data, err, sizeof(err))) {
				(void)dbus_message_iter_abandon_container_if_open(&entry, &variant);
				(void)dbus_message_iter_abandon_container_if_open(&array, &entry);
				continue;
			}
			(void)dbus_message_iter_close_container(&entry, &variant);
			(void)dbus_message_iter_close_container(&array, &entry);
		}
		(void)dbus_message_iter_close_container(&body, &array);
		/*
		 * The empty `as` of invalidated names, which the signature
		 * requires. **Nothing is ever invalidated here**: this shim
		 * always has a value to offer, and `invalidated` is for a
		 * property whose new value is deliberately withheld.
		 */
		if (dbus_message_iter_open_container(&body, DBUS_TYPE_ARRAY, "s", &invalidated)) {
			(void)dbus_message_iter_close_container(&body, &invalidated);
		}
		if (dbus_connection_send(connection, signal, NULL)) {
			sent++;
		}
		dbus_message_unref(signal);
	}
	return sent;
}
