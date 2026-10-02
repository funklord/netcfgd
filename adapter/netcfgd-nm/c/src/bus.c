/*
 * bus.c -- one message handler for every object, driven by the tables.
 *
 * `org.freedesktop.DBus.Introspectable` and `.Properties` are implemented here
 * once, from `nmc_interface_t`, rather than per interface. libdbus answers
 * neither for us: it hands over a `DBusMessage` and the program decides.
 */
#include "nmc/bus.h"

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Set from a signal handler, so `volatile sig_atomic_t` and nothing larger.
 * The loop below polls it between dispatches, which is the only place it is
 * safe to act on: tearing down a connection from inside a handler would free
 * what libdbus is still walking.
 */
static volatile sig_atomic_t stopping = 0;

void nmc_bus_stop(void)
{
	stopping = 1;
}

/* ---------------------------------------------------------------- lookups */

static const nmc_interface_t *interface_named(const nmc_object_t *object, const char *name)
{
	size_t at;

	for (at = 0u; object->interfaces[at] != NULL; at++) {
		if (strcmp(object->interfaces[at]->name, name) == 0) {
			return object->interfaces[at];
		}
	}
	return NULL;
}

static const nmc_property_t *property_named(const nmc_interface_t *interface, const char *name)
{
	size_t at;

	for (at = 0u; at < interface->property_count; at++) {
		if (strcmp(interface->properties[at].name, name) == 0) {
			return &interface->properties[at];
		}
	}
	return NULL;
}

static const nmc_method_t *method_named(const nmc_interface_t *interface, const char *name)
{
	size_t at;

	for (at = 0u; at < interface->method_count; at++) {
		if (strcmp(interface->methods[at].name, name) == 0) {
			return &interface->methods[at];
		}
	}
	return NULL;
}

/*
 * A property by name across every interface at this object.
 *
 * **Because a client may ask with an empty interface name**, which
 * `org.freedesktop.DBus.Properties` permits and `busctl` does. Answering
 * "unknown interface" to that is a refusal a real NetworkManager does not
 * give, and the shim is judged by what its clients believe.
 */
static const nmc_property_t *property_anywhere(const nmc_object_t *object, const char *name,
    const nmc_interface_t **found_in)
{
	size_t at;

	for (at = 0u; object->interfaces[at] != NULL; at++) {
		const nmc_property_t *property = property_named(object->interfaces[at], name);

		if (property) {
			if (found_in) {
				*found_in = object->interfaces[at];
			}
			return property;
		}
	}
	return NULL;
}

/* ----------------------------------------------------------- introspection */

/*
 * Append one line, refusing rather than truncating.
 *
 * A truncated introspection document is worse than none: a client parses what
 * arrived, finds valid XML describing half an interface, and believes it.
 */
static int say(char *out, size_t out_size, size_t *used, const char *format, ...)
{
	va_list args;
	int     wrote;

	va_start(args, format);
	wrote = vsnprintf(out + *used, out_size - *used, format, args);
	va_end(args);
	if (wrote < 0 || (size_t)wrote >= out_size - *used) {
		return 0;
	}
	*used += (size_t)wrote;
	return 1;
}

/*
 * The `<arg>` elements for one signature, in one direction.
 *
 * An empty or NULL signature is "no arguments" and renders nothing, which is
 * the common case for a getter-shaped method.
 */
static int render_args(char *out, size_t out_size, size_t *used, const char *signature,
    const char *direction)
{
	DBusSignatureIter iter;
	int               index = 0;

	if (!signature || signature[0] == '\0') {
		return 1;
	}
	if (!dbus_signature_validate(signature, NULL)) {
		return 0;
	}
	dbus_signature_iter_init(&iter, signature);
	do {
		char *one = dbus_signature_iter_get_signature(&iter);
		int   ok;

		if (!one) {
			return 0;
		}
		/* **A signal's arguments carry no direction**, and emitting
		 * `direction="out"` on one is a document `dbus-send --xml` and
		 * some generators reject. NULL is how a signal asks for that. */
		if (direction) {
			ok = say(out, out_size, used,
			    "\t\t\t<arg name=\"arg%d\" type=\"%s\" direction=\"%s\"/>\n",
			    index, one, direction);
		} else {
			ok = say(out, out_size, used,
			    "\t\t\t<arg name=\"arg%d\" type=\"%s\"/>\n", index, one);
		}
		dbus_free(one);
		if (!ok) {
			return 0;
		}
		index++;
	} while (dbus_signature_iter_next(&iter));
	return 1;
}

int nmc_bus_introspect(const nmc_object_t *object, const char *const *children,
    size_t child_count, char *out, size_t out_size)
{
	size_t used = 0u;
	size_t at;

	if (!object || !out || out_size == 0u) {
		return 0;
	}
	out[0] = '\0';
	if (!say(out, out_size, &used, "%s", DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE) ||
	    !say(out, out_size, &used, "<node>\n")) {
		return 0;
	}
	/* The two every object answers for, named here because a client that
	 * reads the XML to decide what to call must see them. */
	if (!say(out, out_size, &used,
	        "\t<interface name=\"org.freedesktop.DBus.Introspectable\">\n"
	        "\t\t<method name=\"Introspect\">\n"
	        "\t\t\t<arg name=\"xml_data\" type=\"s\" direction=\"out\"/>\n"
	        "\t\t</method>\n"
	        "\t</interface>\n"
	        "\t<interface name=\"org.freedesktop.DBus.Properties\">\n"
	        "\t\t<method name=\"Get\">\n"
	        "\t\t\t<arg name=\"interface_name\" type=\"s\" direction=\"in\"/>\n"
	        "\t\t\t<arg name=\"property_name\" type=\"s\" direction=\"in\"/>\n"
	        "\t\t\t<arg name=\"value\" type=\"v\" direction=\"out\"/>\n"
	        "\t\t</method>\n"
	        "\t\t<method name=\"GetAll\">\n"
	        "\t\t\t<arg name=\"interface_name\" type=\"s\" direction=\"in\"/>\n"
	        "\t\t\t<arg name=\"props\" type=\"a{sv}\" direction=\"out\"/>\n"
	        "\t\t</method>\n"
	        "\t\t<method name=\"Set\">\n"
	        "\t\t\t<arg name=\"interface_name\" type=\"s\" direction=\"in\"/>\n"
	        "\t\t\t<arg name=\"property_name\" type=\"s\" direction=\"in\"/>\n"
	        "\t\t\t<arg name=\"value\" type=\"v\" direction=\"in\"/>\n"
	        "\t\t</method>\n"
	        "\t</interface>\n")) {
		return 0;
	}
	for (at = 0u; object->interfaces[at] != NULL; at++) {
		const nmc_interface_t *interface = object->interfaces[at];
		size_t                 i;

		if (!say(out, out_size, &used, "\t<interface name=\"%s\">\n", interface->name)) {
			return 0;
		}
		for (i = 0u; i < interface->method_count; i++) {
			const nmc_method_t *method = &interface->methods[i];

			if (!say(out, out_size, &used, "\t\t<method name=\"%s\">\n",
			        method->name)) {
				return 0;
			}
			/*
			 * One `arg` per COMPLETE type, which is why libdbus's
			 * signature iterator does the walking: `a{sv}` is one
			 * argument and four characters, and splitting a
			 * signature per byte would publish four.
			 *
			 * Named `arg0`, `arg1`: NetworkManager's own argument
			 * names are not part of its wire contract, and a
			 * client that wants them reads NM's documentation
			 * rather than this. Direction is what a client needs
			 * and it is exact.
			 */
			if (!render_args(out, out_size, &used, method->in_signature, "in") ||
			    !render_args(out, out_size, &used, method->out_signature, "out")) {
				return 0;
			}
			if (!say(out, out_size, &used, "\t\t</method>\n")) {
				return 0;
			}
		}
		for (i = 0u; i < interface->signal_count; i++) {
			const nmc_signal_t *signal = &interface->signals[i];

			if (!say(out, out_size, &used, "\t\t<signal name=\"%s\">\n",
			        signal->name) ||
			    !render_args(out, out_size, &used, signal->signature, NULL) ||
			    !say(out, out_size, &used, "\t\t</signal>\n")) {
				return 0;
			}
		}
		for (i = 0u; i < interface->property_count; i++) {
			const nmc_property_t *property = &interface->properties[i];

			if (!say(out, out_size, &used,
			        "\t\t<property name=\"%s\" type=\"%s\" access=\"%s\"/>\n",
			        property->name, property->signature,
			        property->access == NMC_READWRITE ? "readwrite" : "read")) {
				return 0;
			}
		}
		if (!say(out, out_size, &used, "\t</interface>\n")) {
			return 0;
		}
	}
	for (at = 0u; at < child_count; at++) {
		if (!say(out, out_size, &used, "\t<node name=\"%s\"/>\n", children[at])) {
			return 0;
		}
	}
	return say(out, out_size, &used, "</node>\n");
}


/* ------------------------------------------------------------- the replies */

static DBusHandlerResult send_and_drop(DBusConnection *connection, DBusMessage *reply)
{
	if (!reply) {
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	if (!dbus_connection_send(connection, reply, NULL)) {
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	dbus_message_unref(reply);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult fail(DBusConnection *connection, DBusMessage *call, const char *name,
    const char *sentence)
{
	return send_and_drop(connection, dbus_message_new_error(call, name, sentence));
}

/* ------------------------------------------------------- the two standards */

/*
 * The introspection document, on the heap.
 *
 * Not a stack buffer: the full object surface is eleven interfaces and about a
 * hundred properties, which is tens of kilobytes, and a handler frame is the
 * wrong place for it. `nmc_bus_introspect` refuses rather than truncating, so
 * growing past this is a loud failure and not a half document.
 */
#define NMC_INTROSPECT_MAX 65536u

static DBusHandlerResult answer_introspect(DBusConnection *connection, DBusMessage *call,
    const nmc_object_t *object)
{
	char        *xml = malloc(NMC_INTROSPECT_MAX);
	DBusMessage *reply;
	const char  *text;
	char       **children = NULL;
	size_t       count = 0u;

	if (!xml) {
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	/*
	 * **The children come from libdbus rather than from a list here.** It
	 * knows what has been registered beneath this path -- object or fallback
	 * -- so a subtree added later advertises itself with no second list to
	 * update. `dbus_connection_list_registered` answers for one level, which
	 * is what a node listing is.
	 */
	if (!dbus_connection_list_registered(connection, object->path, &children)) {
		children = NULL;
	}
	for (count = 0u; children && children[count] != NULL; count++) {
		/* Counting is all this loop does. */
	}
	if (!nmc_bus_introspect(object, (const char *const *)children, count, xml,
	        NMC_INTROSPECT_MAX)) {
		dbus_free_string_array(children);
		free(xml);
		return fail(connection, call, DBUS_ERROR_FAILED,
		    "the introspection document for this object does not fit this build's "
		    "buffer, so none is offered rather than half of one");
	}
	dbus_free_string_array(children);
	reply = dbus_message_new_method_return(call);
	if (!reply) {
		free(xml);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	text = xml;
	if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &text, DBUS_TYPE_INVALID)) {
		dbus_message_unref(reply);
		free(xml);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	free(xml);
	return send_and_drop(connection, reply);
}

/* One property into an open container, wrapped in its declared variant. */
static int append_one(DBusMessageIter *into, const nmc_property_t *property,
    const nmc_object_t *object, char *err, size_t err_size)
{
	DBusMessageIter variant;

	if (!dbus_message_iter_open_container(into, DBUS_TYPE_VARIANT, property->signature,
	        &variant)) {
		snprintf(err, err_size, "no memory for %s", property->name);
		return 0;
	}
	if (!property->get(&variant, object->data, err, err_size)) {
		(void)dbus_message_iter_abandon_container_if_open(into, &variant);
		return 0;
	}
	/* `dbus_bool_t` is unsigned and this returns `int`, so the
	 * conversion is made explicit rather than left to the warning
	 * floor to complain about. */
	return dbus_message_iter_close_container(into, &variant) ? 1 : 0;
}

static DBusHandlerResult answer_get(DBusConnection *connection, DBusMessage *call,
    const nmc_object_t *object)
{
	const char            *interface_name = NULL;
	const char            *property_name = NULL;
	const nmc_property_t  *property;
	const nmc_interface_t *interface;
	DBusMessage           *reply;
	DBusMessageIter        out;
	char                   err[NMC_ERROR_MAX] = "";

	if (!dbus_message_get_args(call, NULL, DBUS_TYPE_STRING, &interface_name,
	        DBUS_TYPE_STRING, &property_name, DBUS_TYPE_INVALID)) {
		return fail(connection, call, DBUS_ERROR_INVALID_ARGS,
		    "Get takes an interface name and a property name");
	}
	if (interface_name[0] == '\0') {
		property = property_anywhere(object, property_name, NULL);
	} else {
		interface = interface_named(object, interface_name);
		if (!interface) {
			return fail(connection, call, DBUS_ERROR_UNKNOWN_INTERFACE,
			    "this object does not serve that interface");
		}
		property = property_named(interface, property_name);
	}
	if (!property) {
		return fail(connection, call, DBUS_ERROR_UNKNOWN_PROPERTY,
		    "no such property on this object");
	}
	reply = dbus_message_new_method_return(call);
	if (!reply) {
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	dbus_message_iter_init_append(reply, &out);
	if (!append_one(&out, property, object, err, sizeof(err))) {
		dbus_message_unref(reply);
		return fail(connection, call, DBUS_ERROR_FAILED, err[0] ? err : "could not read it");
	}
	return send_and_drop(connection, reply);
}

static DBusHandlerResult answer_get_all(DBusConnection *connection, DBusMessage *call,
    const nmc_object_t *object)
{
	const char     *interface_name = NULL;
	DBusMessage    *reply;
	DBusMessageIter out;
	DBusMessageIter array;
	size_t          at;
	char            err[NMC_ERROR_MAX] = "";

	if (!dbus_message_get_args(call, NULL, DBUS_TYPE_STRING, &interface_name,
	        DBUS_TYPE_INVALID)) {
		return fail(connection, call, DBUS_ERROR_INVALID_ARGS,
		    "GetAll takes an interface name");
	}
	reply = dbus_message_new_method_return(call);
	if (!reply) {
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	dbus_message_iter_init_append(reply, &out);
	if (!dbus_message_iter_open_container(&out, DBUS_TYPE_ARRAY, "{sv}", &array)) {
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	/*
	 * An empty interface name means every interface, which the spec allows
	 * and `busctl` uses. Answering "unknown interface" to it would be a
	 * refusal NetworkManager does not give.
	 */
	for (at = 0u; object->interfaces[at] != NULL; at++) {
		const nmc_interface_t *interface = object->interfaces[at];
		size_t                 i;

		if (interface_name[0] != '\0' && strcmp(interface->name, interface_name) != 0) {
			continue;
		}
		for (i = 0u; i < interface->property_count; i++) {
			const nmc_property_t *property = &interface->properties[i];
			DBusMessageIter       entry;

			if (!dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL,
			        &entry)) {
				break;
			}
			if (!dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
			        &property->name) ||
			    !append_one(&entry, property, object, err, sizeof(err))) {
				(void)dbus_message_iter_abandon_container_if_open(&array, &entry);
				continue;
			}
			(void)dbus_message_iter_close_container(&array, &entry);
		}
	}
	if (!dbus_message_iter_close_container(&out, &array)) {
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	return send_and_drop(connection, reply);
}

static DBusHandlerResult answer_set(DBusConnection *connection, DBusMessage *call,
    const nmc_object_t *object)
{
	DBusMessageIter        args;
	DBusMessageIter        variant;
	const char            *interface_name = NULL;
	const char            *property_name = NULL;
	const nmc_interface_t *interface;
	const nmc_property_t  *property;
	char                   err[NMC_ERROR_MAX] = "";

	if (!dbus_message_iter_init(call, &args) ||
	    dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		return fail(connection, call, DBUS_ERROR_INVALID_ARGS,
		    "Set takes an interface name, a property name and a variant");
	}
	dbus_message_iter_get_basic(&args, &interface_name);
	if (!dbus_message_iter_next(&args) ||
	    dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		return fail(connection, call, DBUS_ERROR_INVALID_ARGS, "Set needs a property name");
	}
	dbus_message_iter_get_basic(&args, &property_name);
	if (!dbus_message_iter_next(&args) ||
	    dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_VARIANT) {
		return fail(connection, call, DBUS_ERROR_INVALID_ARGS, "Set needs a variant");
	}
	if (interface_name[0] == '\0') {
		property = property_anywhere(object, property_name, NULL);
	} else {
		interface = interface_named(object, interface_name);
		if (!interface) {
			return fail(connection, call, DBUS_ERROR_UNKNOWN_INTERFACE,
			    "this object does not serve that interface");
		}
		property = property_named(interface, property_name);
	}
	if (!property) {
		return fail(connection, call, DBUS_ERROR_UNKNOWN_PROPERTY,
		    "no such property on this object");
	}
	/*
	 * **A writable property with no `set` is refused as a declaration
	 * error, not as a read-only property.** The two are different answers:
	 * one says "you may not", the other says this build is wrong. Saying
	 * the first for the second is how a missing setter survives.
	 */
	if (property->access != NMC_READWRITE) {
		return fail(connection, call, DBUS_ERROR_PROPERTY_READ_ONLY,
		    "this property is read-only");
	}
	if (!property->set) {
		return fail(connection, call, DBUS_ERROR_FAILED,
		    "this property is declared writable and this build has no setter for it");
	}
	dbus_message_iter_recurse(&args, &variant);
	if (!property->set(&variant, object->data, err, sizeof(err))) {
		return fail(connection, call, DBUS_ERROR_INVALID_ARGS,
		    err[0] ? err : "the value was refused");
	}
	return send_and_drop(connection, dbus_message_new_method_return(call));
}

/* --------------------------------------------------------- the own methods */

static DBusHandlerResult answer_method(DBusConnection *connection, DBusMessage *call,
    const nmc_object_t *object, const nmc_interface_t *interface)
{
	const nmc_method_t *method = method_named(interface, dbus_message_get_member(call));
	DBusMessage        *reply;
	char                err[NMC_ERROR_MAX] = "";

	if (!method) {
		return fail(connection, call, DBUS_ERROR_UNKNOWN_METHOD,
		    "this interface has no such method in this build");
	}
	/*
	 * **The signature is checked here and not in the handler.** It is in
	 * the table because introspection publishes it, so a call that does
	 * not match it is a call the client was told not to make -- and
	 * refusing it once, centrally, is what keeps every handler from
	 * starting with the same four lines of argument validation and one of
	 * them getting it wrong.
	 */
	if (!dbus_message_has_signature(call, method->in_signature ? method->in_signature : "")) {
		return fail(connection, call, DBUS_ERROR_INVALID_ARGS,
		    "the arguments do not match the signature this interface publishes");
	}
	reply = dbus_message_new_method_return(call);
	if (!reply) {
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	if (!method->call(call, reply, object->data, err, sizeof(err))) {
		dbus_message_unref(reply);
		return fail(connection, call, DBUS_ERROR_FAILED,
		    err[0] ? err : "the call failed and said nothing");
	}
	return send_and_drop(connection, reply);
}

/* ------------------------------------------------------------ the handler */

static DBusHandlerResult handle(DBusConnection *connection, DBusMessage *message, void *user)
{
	const nmc_object_t    *object = user;
	const char            *interface_name = dbus_message_get_interface(message);
	const nmc_interface_t *interface;

	if (dbus_message_get_type(message) != DBUS_MESSAGE_TYPE_METHOD_CALL) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	if (dbus_message_is_method_call(message, DBUS_INTERFACE_INTROSPECTABLE, "Introspect")) {
		return answer_introspect(connection, message, object);
	}
	if (dbus_message_is_method_call(message, DBUS_INTERFACE_PROPERTIES, "Get")) {
		return answer_get(connection, message, object);
	}
	if (dbus_message_is_method_call(message, DBUS_INTERFACE_PROPERTIES, "GetAll")) {
		return answer_get_all(connection, message, object);
	}
	if (dbus_message_is_method_call(message, DBUS_INTERFACE_PROPERTIES, "Set")) {
		return answer_set(connection, message, object);
	}
	if (!interface_name) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	interface = interface_named(object, interface_name);
	if (!interface) {
		return fail(connection, message, DBUS_ERROR_UNKNOWN_INTERFACE,
		    "this object does not serve that interface");
	}
	return answer_method(connection, message, object, interface);
}

/* ------------------------------------------------------------- a subtree */

/*
 * The node listing for the prefix itself.
 *
 * Children only, and no interfaces: the prefix is not an object. NM serves
 * nothing at `/org/freedesktop/NetworkManager/Devices` either, and a client
 * that asked would be told so by the empty interface list rather than by an
 * error.
 */
static DBusHandlerResult answer_subtree_root(DBusConnection *connection, DBusMessage *call,
    const nmc_subtree_t *subtree)
{
	const char  *names[256];
	size_t       count = 0u;
	size_t       at;
	char         xml[8192];
	size_t       used = 0u;
	DBusMessage *reply;
	const char  *text = xml;

	if (subtree->enumerate) {
		count = subtree->enumerate(names, sizeof(names) / sizeof(names[0]),
		    subtree->context);
	}
	xml[0] = '\0';
	if (!say(xml, sizeof(xml), &used, "%s<node>\n",
	        DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE)) {
		return fail(connection, call, DBUS_ERROR_FAILED, "the node listing does not fit");
	}
	for (at = 0u; at < count; at++) {
		if (!say(xml, sizeof(xml), &used, "\t<node name=\"%s\"/>\n", names[at])) {
			return fail(connection, call, DBUS_ERROR_FAILED,
			    "there are more children than this build will list");
		}
	}
	if (!say(xml, sizeof(xml), &used, "</node>\n")) {
		return fail(connection, call, DBUS_ERROR_FAILED, "the node listing does not fit");
	}
	reply = dbus_message_new_method_return(call);
	if (!reply) {
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &text, DBUS_TYPE_INVALID)) {
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	return send_and_drop(connection, reply);
}

static DBusHandlerResult fallback(DBusConnection *connection, DBusMessage *message, void *user)
{
	const nmc_subtree_t *subtree = user;
	const char          *path = dbus_message_get_path(message);
	size_t               prefix_length;
	const char          *tail;
	void                *data;
	nmc_object_t         resolved;

	if (dbus_message_get_type(message) != DBUS_MESSAGE_TYPE_METHOD_CALL || !path) {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	prefix_length = strlen(subtree->prefix);
	if (strcmp(path, subtree->prefix) == 0) {
		if (dbus_message_is_method_call(message, DBUS_INTERFACE_INTROSPECTABLE,
		        "Introspect")) {
			return answer_subtree_root(connection, message, subtree);
		}
		/* Nothing else is served at the prefix, and saying so is better
		 * than an unresolvable child. */
		return fail(connection, message, DBUS_ERROR_UNKNOWN_OBJECT,
		    "nothing is served at this path; its children are");
	}
	if (strncmp(path, subtree->prefix, prefix_length) != 0 || path[prefix_length] != '/') {
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}
	tail = path + prefix_length + 1u;
	/*
	 * **One level, deliberately.** A tail with a `/` in it is a path this
	 * subtree does not serve, and resolving the first component of it would
	 * answer for `.../Devices/3/anything` as though it were the device.
	 */
	if (strchr(tail, '/') != NULL) {
		return fail(connection, message, DBUS_ERROR_UNKNOWN_OBJECT,
		    "this object has no children");
	}
	data = subtree->resolve ? subtree->resolve(tail, subtree->context) : NULL;
	if (!data) {
		/* What a client holding a path to a device that has gone is
		 * told. Not an empty answer, which it would cache. */
		return fail(connection, message, DBUS_ERROR_UNKNOWN_OBJECT,
		    "no such object; it may have gone since the path was handed out");
	}
	resolved.path = path;
	resolved.interfaces = subtree->interfaces_for ? subtree->interfaces_for(data)
	                                              : subtree->interfaces;
	resolved.data = data;
	if (!resolved.interfaces) {
		return fail(connection, message, DBUS_ERROR_UNKNOWN_OBJECT,
		    "this object serves nothing this build knows about");
	}
	return handle(connection, message, &resolved);
}

static const DBusObjectPathVTable FALLBACK_VTABLE = {
	.unregister_function = NULL,
	.message_function = fallback,
};

static const DBusObjectPathVTable VTABLE = {
	.unregister_function = NULL,
	.message_function = handle,
};

/* -------------------------------------------------------------- the loop */

int nmc_bus_serve(DBusConnection *connection, const nmc_object_t *objects, size_t count,
    const nmc_subtree_t *subtrees, size_t subtree_count, void (*tick)(void *context),
    void *tick_context, char *err, size_t err_size)
{
	size_t at;

	if (!connection || !objects) {
		snprintf(err, err_size, "serving needs a connection and some objects");
		return 0;
	}
	for (at = 0u; at < count; at++) {
		DBusError problem;

		dbus_error_init(&problem);
		/*
		 * The object is registered with a pointer INTO the caller's
		 * array, so that array has to outlive the loop -- which is why
		 * every caller builds it as a static or a stack frame that
		 * encloses this call, and why this takes a `const` pointer
		 * rather than copying: a copy would make the lifetime look
		 * like this function's and it is not.
		 */
		if (!dbus_connection_try_register_object_path(connection, objects[at].path, &VTABLE,
		        (void *)&objects[at], &problem)) {
			snprintf(err, err_size, "cannot serve %s: %s", objects[at].path,
			    dbus_error_is_set(&problem) ? problem.message : "already registered");
			dbus_error_free(&problem);
			return 0;
		}
		dbus_error_free(&problem);
	}
	for (at = 0u; at < subtree_count; at++) {
		DBusError problem;

		dbus_error_init(&problem);
		if (!dbus_connection_try_register_fallback(connection, subtrees[at].prefix,
		        &FALLBACK_VTABLE, (void *)&subtrees[at], &problem)) {
			snprintf(err, err_size, "cannot serve the subtree at %s: %s",
			    subtrees[at].prefix,
			    dbus_error_is_set(&problem) ? problem.message : "already registered");
			dbus_error_free(&problem);
			return 0;
		}
		dbus_error_free(&problem);
	}
	/*
	 * **A bounded wait rather than a blocking one, so the stop flag is
	 * reachable.** `dbus_connection_read_write_dispatch` with -1 returns
	 * only when a message arrives or the bus goes away, and a shim told to
	 * stop would then sit until somebody happened to call it. One second
	 * is the granularity of the shutdown and costs a wakeup per second.
	 */
	while (!stopping) {
		if (tick) {
			tick(tick_context);
		}
		if (!dbus_connection_read_write_dispatch(connection, 1000)) {
			/* The bus went away. That is an orderly end for a shim
			 * whose whole job is answering it, and systemd restarts
			 * it when the bus comes back. */
			break;
		}
	}
	for (at = 0u; at < count; at++) {
		(void)dbus_connection_unregister_object_path(connection, objects[at].path);
	}
	for (at = 0u; at < subtree_count; at++) {
		(void)dbus_connection_unregister_object_path(connection, subtrees[at].prefix);
	}
	return 1;
}
