/*
 * make_seeds -- marshal a handful of settings dictionaries into corpus files.
 *
 * WHY A PROGRAM AND NOT COMMITTED BYTES ALONE
 *   The thing being fuzzed takes a D-Bus message, and a D-Bus message is not
 *   something anybody writes by hand: a header with typed fields, a body whose
 *   every container carries its own length, alignment at every boundary. The
 *   seeds have to be produced by libdbus or they are not seeds.
 *
 *   The output IS committed, because a fuzz run must not need a build step to
 *   start, and because a seed is an input somebody chose rather than a
 *   generated artifact -- see `fuzz/README`. This program is how the choosing
 *   was done and where to add the next one.
 *
 * WHAT THE DICTIONARIES ARE
 *   What `nmcli` and `plasma-nm` actually send to `AddConnection`, group for
 *   group: the shapes `tests/live/nm.sh` drives and `tests/bus_test.c` builds
 *   by hand. Each one is a dictionary the renderer accepts today -- checked by
 *   the replay, which renders every seed -- so a mutation of one is a near
 *   miss rather than noise.
 *
 * TERMINATION
 *   One pass over a fixed list of dictionaries. Nothing spawned, nothing read,
 *   and it writes exactly the files it names.
 */
#include <dbus/dbus.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static DBusMessage *call_new(void)
{
	DBusMessage *call = dbus_message_new_method_call("org.freedesktop.NetworkManager",
	    "/org/freedesktop/NetworkManager/Settings",
	    "org.freedesktop.NetworkManager.Settings", "AddConnection");

	/* **Marshalling refuses a message with no serial**, which a message built
	 * for a test never needs and one written to a file does. */
	if (call) {
		dbus_message_set_serial(call, 1u);
	}
	return call;
}

static void open_group(DBusMessageIter *groups, const char *name, DBusMessageIter *entry,
    DBusMessageIter *pairs)
{
	(void)dbus_message_iter_open_container(groups, DBUS_TYPE_DICT_ENTRY, NULL, entry);
	(void)dbus_message_iter_append_basic(entry, DBUS_TYPE_STRING, &name);
	(void)dbus_message_iter_open_container(entry, DBUS_TYPE_ARRAY, "{sv}", pairs);
}

static void close_group(DBusMessageIter *groups, DBusMessageIter *entry, DBusMessageIter *pairs)
{
	(void)dbus_message_iter_close_container(entry, pairs);
	(void)dbus_message_iter_close_container(groups, entry);
}

static void say_string(DBusMessageIter *pairs, const char *key, const char *text)
{
	DBusMessageIter pair;
	DBusMessageIter value;

	(void)dbus_message_iter_open_container(pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair);
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &key);
	(void)dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "s", &value);
	(void)dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &text);
	(void)dbus_message_iter_close_container(&pair, &value);
	(void)dbus_message_iter_close_container(pairs, &pair);
}

static void say_bool(DBusMessageIter *pairs, const char *key, int flag)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	dbus_bool_t     on = flag ? TRUE : FALSE;

	(void)dbus_message_iter_open_container(pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair);
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &key);
	(void)dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "b", &value);
	(void)dbus_message_iter_append_basic(&value, DBUS_TYPE_BOOLEAN, &on);
	(void)dbus_message_iter_close_container(&pair, &value);
	(void)dbus_message_iter_close_container(pairs, &pair);
}

static void say_number(DBusMessageIter *pairs, const char *key, dbus_uint32_t number)
{
	DBusMessageIter pair;
	DBusMessageIter value;

	(void)dbus_message_iter_open_container(pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair);
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &key);
	(void)dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "u", &value);
	(void)dbus_message_iter_append_basic(&value, DBUS_TYPE_UINT32, &number);
	(void)dbus_message_iter_close_container(&pair, &value);
	(void)dbus_message_iter_close_container(pairs, &pair);
}

/* An SSID is `ay`, which is the one place NM's dictionary carries octets. */
static void say_ssid(DBusMessageIter *pairs, const char *key, const char *text)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	DBusMessageIter bytes;
	size_t          at;

	(void)dbus_message_iter_open_container(pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair);
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &key);
	(void)dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "ay", &value);
	(void)dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY, "y", &bytes);
	for (at = 0u; at < strlen(text); at++) {
		unsigned char byte = (unsigned char)text[at];

		(void)dbus_message_iter_append_basic(&bytes, DBUS_TYPE_BYTE, &byte);
	}
	(void)dbus_message_iter_close_container(&value, &bytes);
	(void)dbus_message_iter_close_container(&pair, &value);
	(void)dbus_message_iter_close_container(pairs, &pair);
}

static void say_strings(DBusMessageIter *pairs, const char *key, const char *const *texts,
    size_t count)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	DBusMessageIter array;
	size_t          at;

	(void)dbus_message_iter_open_container(pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair);
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &key);
	(void)dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "as", &value);
	(void)dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY, "s", &array);
	for (at = 0u; at < count; at++) {
		(void)dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &texts[at]);
	}
	(void)dbus_message_iter_close_container(&value, &array);
	(void)dbus_message_iter_close_container(&pair, &value);
	(void)dbus_message_iter_close_container(pairs, &pair);
}

/* `aa{sv}`: NM's `address-data` and `route-data`, which is where a static
 * profile's addresses live and the deepest nesting a client sends. */
static void say_entries(DBusMessageIter *pairs, const char *key, const char *address,
    dbus_uint32_t prefix)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	DBusMessageIter array;
	DBusMessageIter entry;
	DBusMessageIter inner;

	(void)dbus_message_iter_open_container(pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair);
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &key);
	(void)dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "aa{sv}", &value);
	(void)dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY, "a{sv}", &array);
	(void)dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY, "{sv}", &entry);
	say_string(&entry, "address", address);
	(void)dbus_message_iter_open_container(&entry, DBUS_TYPE_DICT_ENTRY, NULL, &inner);
	{
		const char     *name = "prefix";
		DBusMessageIter number;

		(void)dbus_message_iter_append_basic(&inner, DBUS_TYPE_STRING, &name);
		(void)dbus_message_iter_open_container(&inner, DBUS_TYPE_VARIANT, "u", &number);
		(void)dbus_message_iter_append_basic(&number, DBUS_TYPE_UINT32, &prefix);
		(void)dbus_message_iter_close_container(&inner, &number);
	}
	(void)dbus_message_iter_close_container(&entry, &inner);
	(void)dbus_message_iter_close_container(&array, &entry);
	(void)dbus_message_iter_close_container(&value, &array);
	(void)dbus_message_iter_close_container(&pair, &value);
	(void)dbus_message_iter_close_container(pairs, &pair);
}

static int write_message(const char *path, DBusMessage *message)
{
	char  *bytes = NULL;
	int    length = 0;
	FILE  *handle;
	size_t written;

	if (!message || !dbus_message_marshal(message, &bytes, &length)) {
		fprintf(stderr, "make_seeds: cannot marshal %s\n", path);
		return 0;
	}
	handle = fopen(path, "wb");
	if (!handle) {
		fprintf(stderr, "make_seeds: cannot write %s\n", path);
		dbus_free(bytes);
		return 0;
	}
	written = fwrite(bytes, 1u, (size_t)length, handle);
	(void)fclose(handle);
	dbus_free(bytes);
	if (written != (size_t)length) {
		fprintf(stderr, "make_seeds: short write on %s\n", path);
		return 0;
	}
	printf("make_seeds: %s, %d bytes\n", path, length);
	return 1;
}

/* The `connection` group every profile carries. */
static void connection_group(DBusMessageIter *groups, const char *id, const char *type)
{
	DBusMessageIter entry;
	DBusMessageIter pairs;

	open_group(groups, "connection", &entry, &pairs);
	say_string(&pairs, "id", id);
	say_string(&pairs, "type", type);
	say_string(&pairs, "uuid", "7c3f1a2e-0000-4000-8000-000000000001");
	close_group(groups, &entry, &pairs);
}

int main(int argc, char **argv)
{
	const char     *dir = (argc > 1) ? argv[1] : "fuzz/corpus/dictionary";
	char            path[512];
	DBusMessage    *call;
	DBusMessageIter args;
	DBusMessageIter groups;
	DBusMessageIter entry;
	DBusMessageIter pairs;
	int             fail = 0;

#define BEGIN()                                                                               \
	do {                                                                                  \
		call = call_new();                                                            \
		if (!call) {                                                                  \
			return 1;                                                             \
		}                                                                             \
		dbus_message_iter_init_append(call, &args);                                   \
		(void)dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sa{sv}}",    \
		    &groups);                                                                 \
	} while (0)
#define END(name)                                                                             \
	do {                                                                                  \
		(void)dbus_message_iter_close_container(&args, &groups);                      \
		(void)snprintf(path, sizeof(path), "%s/%s", dir, name);                       \
		if (!write_message(path, call)) {                                             \
			fail = 1;                                                             \
		}                                                                             \
		dbus_message_unref(call);                                                     \
	} while (0)

	/* An open network: the smallest thing the renderer accepts. */
	BEGIN();
	connection_group(&groups, "Cafe", "802-11-wireless");
	open_group(&groups, "802-11-wireless", &entry, &pairs);
	say_ssid(&pairs, "ssid", "Cafe");
	say_string(&pairs, "mode", "infrastructure");
	close_group(&groups, &entry, &pairs);
	END("seed-open.bin");

	/* WPA2, with the passphrase a client sends on an add. */
	BEGIN();
	connection_group(&groups, "Office", "802-11-wireless");
	open_group(&groups, "802-11-wireless", &entry, &pairs);
	say_ssid(&pairs, "ssid", "Office");
	say_bool(&pairs, "hidden", 1);
	close_group(&groups, &entry, &pairs);
	open_group(&groups, "802-11-wireless-security", &entry, &pairs);
	say_string(&pairs, "key-mgmt", "wpa-psk");
	say_string(&pairs, "psk", "a passphrase of some length");
	close_group(&groups, &entry, &pairs);
	END("seed-wpa2-psk.bin");

	/* WPA3, which is `sae` and the arm a security table gets wrong. */
	BEGIN();
	connection_group(&groups, "Secure", "802-11-wireless");
	open_group(&groups, "802-11-wireless", &entry, &pairs);
	say_ssid(&pairs, "ssid", "Secure");
	close_group(&groups, &entry, &pairs);
	open_group(&groups, "802-11-wireless-security", &entry, &pairs);
	say_string(&pairs, "key-mgmt", "sae");
	say_string(&pairs, "psk", "another passphrase");
	close_group(&groups, &entry, &pairs);
	END("seed-wpa3-sae.bin");

	/* A static profile: both IP groups, addresses, gateway and resolvers --
	 * the deepest nesting a client sends. */
	BEGIN();
	connection_group(&groups, "Static", "802-11-wireless");
	open_group(&groups, "802-11-wireless", &entry, &pairs);
	say_ssid(&pairs, "ssid", "Static");
	close_group(&groups, &entry, &pairs);
	open_group(&groups, "ipv4", &entry, &pairs);
	say_string(&pairs, "method", "manual");
	say_entries(&pairs, "address-data", "192.0.2.5", 24u);
	say_string(&pairs, "gateway", "192.0.2.1");
	{
		static const char *const servers[] = { "192.0.2.1", "9.9.9.9" };
		static const char *const search[] = { "example.invalid" };

		say_strings(&pairs, "dns-search", search, 1u);
		say_strings(&pairs, "dns-options", servers, 2u);
	}
	close_group(&groups, &entry, &pairs);
	open_group(&groups, "ipv6", &entry, &pairs);
	say_string(&pairs, "method", "auto");
	close_group(&groups, &entry, &pairs);
	END("seed-static.bin");

	/* Told not to join by itself, metered, and ranked: the three keys of the
	 * `connection` group that are not identity. */
	BEGIN();
	open_group(&groups, "connection", &entry, &pairs);
	say_string(&pairs, "id", "Manual");
	say_string(&pairs, "type", "802-11-wireless");
	say_string(&pairs, "uuid", "7c3f1a2e-0000-4000-8000-000000000002");
	say_bool(&pairs, "autoconnect", 0);
	say_number(&pairs, "metered", 1u);
	say_number(&pairs, "autoconnect-priority", 42u);
	close_group(&groups, &entry, &pairs);
	open_group(&groups, "802-11-wireless", &entry, &pairs);
	say_ssid(&pairs, "ssid", "Manual");
	close_group(&groups, &entry, &pairs);
	END("seed-autoconnect-off.bin");

	/*
	 * A secret agent's reply, which `nmc_block_passphrase_in` reads: the same
	 * `a{sa{sv}}` shape carrying only the security group. Kept as its own seed
	 * because it is the one dictionary that arrives from somebody ELSE's
	 * process rather than from a client of ours (0031).
	 */
	BEGIN();
	open_group(&groups, "802-11-wireless-security", &entry, &pairs);
	say_string(&pairs, "psk", "what the agent answered");
	close_group(&groups, &entry, &pairs);
	END("seed-agent-reply.bin");

	/*
	 * Groups and keys nothing reads, which is what every real client sends
	 * some of: `proxy` is NM's and netcfgd has no notion of it. This one
	 * RENDERS, so it reaches the dropped-settings note rather than a refusal
	 * -- the two are different paths and both want a seed.
	 */
	BEGIN();
	connection_group(&groups, "Unread", "802-11-wireless");
	open_group(&groups, "802-11-wireless", &entry, &pairs);
	say_ssid(&pairs, "ssid", "Unread");
	say_number(&pairs, "mtu", 1500u);
	close_group(&groups, &entry, &pairs);
	open_group(&groups, "proxy", &entry, &pairs);
	say_string(&pairs, "method", "none");
	close_group(&groups, &entry, &pairs);
	END("seed-unread-groups.bin");

	/* 802.1X, which is the refusal a client is most likely to meet: netcfgd
	 * has no enterprise wifi and says so by name. */
	BEGIN();
	connection_group(&groups, "Campus", "802-11-wireless");
	open_group(&groups, "802-11-wireless", &entry, &pairs);
	say_ssid(&pairs, "ssid", "Campus");
	close_group(&groups, &entry, &pairs);
	open_group(&groups, "802-11-wireless-security", &entry, &pairs);
	say_string(&pairs, "key-mgmt", "wpa-eap");
	close_group(&groups, &entry, &pairs);
	END("seed-enterprise-refused.bin");

	/*
	 * **A key name carrying a newline**, which is the shape that found the
	 * configuration injection: the dropped-settings note wrote the name into a
	 * comment, the newline ended the comment, and the rest was configuration
	 * the client chose (project.md 10.509). Kept as a seed so the fuzzer
	 * starts from it rather than having to rediscover that a key name is a
	 * place to put one, and as a regression input: the note sanitises now, and
	 * `fuzz/shape.c` asserts the block is still one block.
	 */
	BEGIN();
	connection_group(&groups, "Victim", "802-11-wireless");
	open_group(&groups, "802-11-wireless", &entry, &pairs);
	say_ssid(&pairs, "ssid", "Victim");
	close_group(&groups, &entry, &pairs);
	open_group(&groups, "connection", &entry, &pairs);
	say_string(&pairs,
	    "x\"\n}\n\nnetwork \"injected\" {\n\tssid = \"anything\"\n\twifi { open = true }\n}\n# ",
	    "whatever");
	close_group(&groups, &entry, &pairs);
	END("seed-newline-in-a-key-name.bin");

	return fail;
}
