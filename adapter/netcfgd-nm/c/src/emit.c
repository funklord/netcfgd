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

/* One remembered number, for a signal that carries its own previous value. */
typedef struct {
	char          key[128];
	unsigned long value;
} number_t;

/* One remembered set of names, for the membership signals. */
typedef struct {
	char    key[128];
	char  **names;
	size_t  count;
	/*
	 * The previous names, kept until this key is asked again.
	 *
	 * **Per key and not one static buffer**, which the first version of this
	 * got wrong: a shared buffer means two keys with removals in one tick free
	 * each other's answers, and the caller is left holding pointers into
	 * memory the next call released. Devices and connections can both lose a
	 * member in one tick, so that was reachable rather than theoretical.
	 */
	char  **previous;
	size_t  previous_count;
} nameset_t;

struct nmc_watch {
	seen_t   *at;
	size_t    count;
	size_t    capacity;
	number_t *numbers;
	size_t    number_count;
	size_t    number_capacity;
	nameset_t *sets;
	size_t     set_count;
	size_t     set_capacity;
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
	free(watch->numbers);
	for (at = 0u; at < watch->set_count; at++) {
		size_t which;

		for (which = 0u; which < watch->sets[at].count; which++) {
			free(watch->sets[at].names[which]);
		}
		free(watch->sets[at].names);
		for (which = 0u; which < watch->sets[at].previous_count; which++) {
			free(watch->sets[at].previous[which]);
		}
		free(watch->sets[at].previous);
	}
	free(watch->sets);
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

/* ------------------------------------------------ numbers, with the old one */

int nmc_watch_number(nmc_watch_t *watch, const char *key, unsigned long now,
    unsigned long *was)
{
	size_t at;

	if (!watch || !key) {
		return 0;
	}
	for (at = 0u; at < watch->number_count; at++) {
		if (strcmp(watch->numbers[at].key, key) == 0) {
			unsigned long before = watch->numbers[at].value;

			watch->numbers[at].value = now;
			if (before == now) {
				return 0;
			}
			if (was) {
				*was = before;
			}
			return 1;
		}
	}
	if (watch->number_count == watch->number_capacity) {
		size_t    bigger = watch->number_capacity ? watch->number_capacity * 2u : 32u;
		number_t *grown = realloc(watch->numbers, bigger * sizeof(*grown));

		if (!grown) {
			return 0;
		}
		watch->numbers = grown;
		watch->number_capacity = bigger;
	}
	(void)snprintf(watch->numbers[watch->number_count].key,
	    sizeof(watch->numbers[watch->number_count].key), "%s", key);
	watch->numbers[watch->number_count].value = now;
	watch->number_count++;
	/* First sight remembers and announces nothing. */
	return 0;
}

/* ----------------------------------------------------------- name sets */

static nameset_t *set_for(nmc_watch_t *watch, const char *key)
{
	size_t at;

	for (at = 0u; at < watch->set_count; at++) {
		if (strcmp(watch->sets[at].key, key) == 0) {
			return &watch->sets[at];
		}
	}
	if (watch->set_count == watch->set_capacity) {
		size_t     bigger = watch->set_capacity ? watch->set_capacity * 2u : 8u;
		nameset_t *grown = realloc(watch->sets, bigger * sizeof(*grown));

		if (!grown) {
			return NULL;
		}
		watch->sets = grown;
		watch->set_capacity = bigger;
	}
	memset(&watch->sets[watch->set_count], 0, sizeof(watch->sets[watch->set_count]));
	(void)snprintf(watch->sets[watch->set_count].key,
	    sizeof(watch->sets[watch->set_count].key), "%s", key);
	watch->set_count++;
	return &watch->sets[watch->set_count - 1u];
}

static int holds(const nameset_t *set, const char *name)
{
	size_t at;

	for (at = 0u; at < set->count; at++) {
		if (set->names[at] && strcmp(set->names[at], name) == 0) {
			return 1;
		}
	}
	return 0;
}

static int in_list(const char *const *names, size_t count, const char *name)
{
	size_t at;

	for (at = 0u; at < count; at++) {
		if (names[at] && strcmp(names[at], name) == 0) {
			return 1;
		}
	}
	return 0;
}

int nmc_watch_set(nmc_watch_t *watch, const char *key, const char *const *names, size_t count,
    const char **added, size_t *added_count, const char **gone, size_t *gone_count,
    size_t room)
{
	nameset_t *set;
	size_t     at;
	int        first;
	char     **kept;

	*added_count = 0u;
	*gone_count = 0u;
	if (!watch || !key) {
		return 0;
	}
	set = set_for(watch, key);
	if (!set) {
		return 0;
	}
	/*
	 * **First sight is the empty set having never been seen, not an empty
	 * set.** A key whose names array is NULL has not been looked at; one whose
	 * count is 0 has. Without that distinction a shim starting with no devices
	 * would announce the first one twice -- once as first sight and once as an
	 * addition.
	 */
	first = set->names == NULL;
	if (!first) {
		for (at = 0u; at < count && *added_count < room; at++) {
			if (names[at] && !holds(set, names[at])) {
				added[(*added_count)++] = names[at];
			}
		}
		for (at = 0u; at < set->count && *gone_count < room; at++) {
			if (set->names[at] && !in_list(names, count, set->names[at])) {
				gone[(*gone_count)++] = set->names[at];
			}
		}
	}
	/*
	 * The new set is built before the old one is freed, and the removals above
	 * point INTO the old one -- so the old names are freed by the caller's next
	 * call rather than here. That is what the header promises: a removal's name
	 * is valid until the next call for this key.
	 */
	kept = calloc(count ? count : 1u, sizeof(*kept));
	if (!kept) {
		return 0;
	}
	for (at = 0u; at < count; at++) {
		kept[at] = names[at] ? strdup(names[at]) : NULL;
	}
	/*
	 * This key's previous names are released now and the ones just replaced
	 * become the previous -- so a `gone` pointer handed back above stays valid
	 * until this key is asked again, and no other key's call can invalidate it.
	 */
	{
		size_t which;

		for (which = 0u; which < set->previous_count; which++) {
			free(set->previous[which]);
		}
		free(set->previous);
		set->previous = set->names;
		set->previous_count = set->count;
		set->names = kept;
		set->count = count;
	}
	return (*added_count + *gone_count) > 0u ? 1 : 0;
}

/* ------------------------------------------------------------ the sending */

void nmc_emit_path(DBusConnection *connection, const char *path, const char *interface,
    const char *member, const char *argument)
{
	DBusMessage *signal = dbus_message_new_signal(path, interface, member);

	if (!signal) {
		return;
	}
	if (dbus_message_append_args(signal, DBUS_TYPE_OBJECT_PATH, &argument,
	        DBUS_TYPE_INVALID)) {
		(void)dbus_connection_send(connection, signal, NULL);
	}
	dbus_message_unref(signal);
}

void nmc_emit_numbers(DBusConnection *connection, const char *path, const char *interface,
    const char *member, const dbus_uint32_t *values, size_t count)
{
	DBusMessage    *signal = dbus_message_new_signal(path, interface, member);
	DBusMessageIter out;
	size_t          at;

	if (!signal) {
		return;
	}
	dbus_message_iter_init_append(signal, &out);
	for (at = 0u; at < count; at++) {
		(void)dbus_message_iter_append_basic(&out, DBUS_TYPE_UINT32, &values[at]);
	}
	(void)dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);
}
