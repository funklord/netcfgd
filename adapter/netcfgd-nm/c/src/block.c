/*
 * block.c -- a client's settings dictionary as a netcfgd network block.
 *
 * `emit.rs`, the renderer half: the dictionary comes in as `a{sa{sv}}` and a
 * block of netcfgd configuration comes out. Nothing here touches the bus or the
 * filesystem, which is what makes it a function a test can call -- `settings.c`
 * authorizes the caller and writes what this returns.
 *
 * WHY IT WALKS THE MESSAGE INSTEAD OF PARSING IT INTO A STRUCT FIRST
 *   `dbus_message_get_args` cannot express a nested dictionary, so either way
 *   the iterator is stepped by hand. Asking the message for one key at a time
 *   keeps each reader next to the one rule it enforces -- an address is checked
 *   where it is read -- and a settings dictionary is a few dozen entries, so
 *   walking it per key costs nothing worth a second representation to keep
 *   right.
 *
 * WHAT A REFUSAL COSTS AND WHY IT IS STILL THE ANSWER
 *   Every refusal here happens before `settings.c` writes anything, so a client
 *   that asked for the inexpressible gets a sentence and the configuration
 *   directory is untouched. The alternative -- write the part that translates
 *   and say nothing about the rest -- is how somebody finds out months later
 *   that a setting never took effect.
 */

#include "nmc/block.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/*
 * The model's `RANK_CEILING`, which the daemon's supplicant backend also spells
 * out for itself. A third copy because this program links `client/` and nothing
 * else, and the client library does not publish the model's constants: the two
 * directions of the scaling have to agree with each other, and both are here.
 */
#define NMC_RANK_CEILING 4096L

/* NM's priority band, which the scaling maps onto. */
#define NMC_PRIORITY_CEILING 999L

/* -------------------------------------------------------------- the text */

typedef struct {
	char  *at;
	size_t cap;
	size_t used;
	int    overflowed;
} text_t;

static void text_init(text_t *text, char *into, size_t cap)
{
	text->at = into;
	text->cap = cap;
	text->used = 0u;
	text->overflowed = 0;
	if (cap > 0u) {
		into[0] = '\0';
	}
}

/*
 * Append, and remember having failed to.
 *
 * A short write is recorded rather than reported here so that the renderer
 * reads as a sequence of lines; the flag is checked once, at the end, and turns
 * into a refusal. Truncation is never returned to a caller: half a block is a
 * file that will not compile, and netcfgd reads the drop-in directory as one
 * document, so it would take every other network on the machine down with it.
 */
static void putf(text_t *text, const char *fmt, ...)
{
	va_list args;
	int     wrote;
	size_t  room;

	if (text->overflowed || text->used >= text->cap) {
		text->overflowed = 1;
		return;
	}
	room = text->cap - text->used;
	va_start(args, fmt);
	wrote = vsnprintf(text->at + text->used, room, fmt, args);
	va_end(args);
	if (wrote < 0 || (size_t)wrote >= room) {
		text->overflowed = 1;
		return;
	}
	text->used += (size_t)wrote;
}

/* ------------------------------------------------- reading the dictionary */

/* The value under `key` in an `a{sv}`, recursed past the variant. */
static int pair_value(DBusMessageIter *pairs, const char *key, DBusMessageIter *out)
{
	DBusMessageIter walk = *pairs;

	while (dbus_message_iter_get_arg_type(&walk) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter pair;
		const char     *name = NULL;

		dbus_message_iter_recurse(&walk, &pair);
		if (dbus_message_iter_get_arg_type(&pair) == DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&pair, &name);
		}
		(void)dbus_message_iter_next(&pair);
		if (name && strcmp(name, key) == 0 &&
		    dbus_message_iter_get_arg_type(&pair) == DBUS_TYPE_VARIANT) {
			dbus_message_iter_recurse(&pair, out);
			return 1;
		}
		(void)dbus_message_iter_next(&walk);
	}
	return 0;
}

/*
 * The value under `group`.`key` in the settings dictionary.
 *
 * A group whose shape is not what the signature promised is skipped rather than
 * refused: the dispatcher has already checked the argument's signature, so a
 * surprise here would be libdbus disagreeing with itself.
 */
static int value_of(DBusMessage *call, const char *group, const char *key, DBusMessageIter *out)
{
	DBusMessageIter args;
	DBusMessageIter groups;

	if (!dbus_message_iter_init(call, &args) ||
	    dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY) {
		return 0;
	}
	dbus_message_iter_recurse(&args, &groups);
	while (dbus_message_iter_get_arg_type(&groups) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;
		const char     *name = NULL;

		dbus_message_iter_recurse(&groups, &entry);
		if (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&entry, &name);
		}
		(void)dbus_message_iter_next(&entry);
		if (name && strcmp(name, group) == 0 &&
		    dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_ARRAY) {
			DBusMessageIter pairs;

			dbus_message_iter_recurse(&entry, &pairs);
			if (pair_value(&pairs, key, out)) {
				return 1;
			}
		}
		(void)dbus_message_iter_next(&groups);
	}
	return 0;
}

/*
 * A string setting, copied out.
 *
 * **An empty string counts as absent**, which the Rust reaches by a longer
 * road: it reads `Some("")` and then refuses the value as malformed. Every
 * caller here wants the same thing from a key a client sent empty as from one
 * it did not send -- `method`, `gateway`, an id -- so saying so once is clearer
 * than three refusals that each have to explain themselves.
 *
 * A value too long for `cap` is absent as well, and the caller's "missing"
 * sentence covers it: an id of 300 bytes is refused either way, and the
 * difference between the two messages is not worth a second return value.
 */
static int read_text(DBusMessage *call, const char *group, const char *key, char *out, size_t cap)
{
	DBusMessageIter value;
	const char     *text = NULL;

	if (cap > 0u) {
		out[0] = '\0';
	}
	if (!value_of(call, group, key, &value) ||
	    dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_STRING) {
		return 0;
	}
	dbus_message_iter_get_basic(&value, &text);
	if (!text || text[0] == '\0' || strlen(text) >= cap) {
		return 0;
	}
	(void)snprintf(out, cap, "%s", text);
	return 1;
}

/* A number setting, in either of the two widths NM sends. */
static int read_number(DBusMessage *call, const char *group, const char *key, long *out)
{
	DBusMessageIter value;

	if (!value_of(call, group, key, &value)) {
		return 0;
	}
	switch (dbus_message_iter_get_arg_type(&value)) {
	case DBUS_TYPE_INT32: {
		dbus_int32_t signed_number = 0;

		dbus_message_iter_get_basic(&value, &signed_number);
		*out = (long)signed_number;
		return 1;
	}
	case DBUS_TYPE_UINT32: {
		dbus_uint32_t unsigned_number = 0u;

		dbus_message_iter_get_basic(&value, &unsigned_number);
		*out = (long)unsigned_number;
		return 1;
	}
	default:
		return 0;
	}
}

/* A boolean setting. Answers whether it was there; `*out` is what it said. */
static int read_flag(DBusMessage *call, const char *group, const char *key, int *out)
{
	DBusMessageIter value;
	dbus_bool_t     yes = FALSE;

	if (!value_of(call, group, key, &value) ||
	    dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_BOOLEAN) {
		return 0;
	}
	dbus_message_iter_get_basic(&value, &yes);
	*out = yes ? 1 : 0;
	return 1;
}

/*
 * The SSID, which is octets rather than text.
 *
 * `ay`, and that is not pedantry: an SSID may hold a byte that is not UTF-8 at
 * all, which is why the block can carry it as hex. Reading it as a string is
 * what made this shim's `GetSettings` send a property libnm refuses.
 */
static int read_octets(DBusMessage *call, const char *group, const char *key, unsigned char *out,
    size_t cap, size_t *len)
{
	DBusMessageIter value;
	DBusMessageIter bytes;

	*len = 0u;
	if (!value_of(call, group, key, &value) ||
	    dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_ARRAY) {
		return 0;
	}
	dbus_message_iter_recurse(&value, &bytes);
	while (dbus_message_iter_get_arg_type(&bytes) == DBUS_TYPE_BYTE) {
		unsigned char byte = 0u;

		if (*len >= cap) {
			return 0;
		}
		dbus_message_iter_get_basic(&bytes, &byte);
		out[*len] = byte;
		(*len)++;
		(void)dbus_message_iter_next(&bytes);
	}
	return 1;
}

/* The entries of an `aa{sv}` -- `address-data` and `route-data`. */
static int read_entries(DBusMessage *call, const char *group, const char *key,
    DBusMessageIter *out)
{
	DBusMessageIter value;

	if (!value_of(call, group, key, &value) ||
	    dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_ARRAY) {
		return 0;
	}
	dbus_message_iter_recurse(&value, out);
	return 1;
}

/* A string member of one such entry. */
static int entry_text(DBusMessageIter *entry, const char *key, char *out, size_t cap)
{
	DBusMessageIter pairs;
	DBusMessageIter value;
	const char     *text = NULL;

	if (cap > 0u) {
		out[0] = '\0';
	}
	dbus_message_iter_recurse(entry, &pairs);
	if (!pair_value(&pairs, key, &value) ||
	    dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_STRING) {
		return 0;
	}
	dbus_message_iter_get_basic(&value, &text);
	if (!text || text[0] == '\0' || strlen(text) >= cap) {
		return 0;
	}
	(void)snprintf(out, cap, "%s", text);
	return 1;
}

/* A numeric member of one such entry. */
static int entry_number(DBusMessageIter *entry, const char *key, unsigned long *out)
{
	DBusMessageIter pairs;
	DBusMessageIter value;

	dbus_message_iter_recurse(entry, &pairs);
	if (!pair_value(&pairs, key, &value) ||
	    dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_UINT32) {
		return 0;
	}
	{
		dbus_uint32_t number = 0u;

		dbus_message_iter_get_basic(&value, &number);
		*out = (unsigned long)number;
	}
	return 1;
}

/*
 * Whether this is an address at all.
 *
 * Checked rather than trusted, because the value goes into a configuration
 * file: one that is not an address would make the file refuse to compile, which
 * the caller would see as netcfgd rejecting a network its client thought was
 * fine.
 */
static int is_address(const char *text)
{
	struct in_addr  v4;
	struct in6_addr v6;

	return inet_pton(AF_INET, text, &v4) == 1 || inet_pton(AF_INET6, text, &v6) == 1;
}

/*
 * Whether a label is one the DSL will take back.
 *
 * It is written between quotes, so a quote or a newline inside it would end the
 * string and turn the rest of the line into configuration. That is the
 * injection this refuses; it is not a style rule.
 */
static int is_writable_label(const char *id)
{
	size_t at;
	size_t length = strlen(id);

	if (length == 0u || length > 64u) {
		return 0;
	}
	for (at = 0u; at < length; at++) {
		unsigned char c = (unsigned char)id[at];

		if (c == '"' || c == '\\' || c < 0x20u || c == 0x7fu) {
			return 0;
		}
	}
	return 1;
}

/* ---------------------------------------------------- lists inside the block */

/*
 * A quoted, comma-separated list -- `config`, `routes`, `servers`, `search`.
 *
 * It carries its own count so that the separator is a property of the list
 * rather than of whoever is adding to it, and the empty case is `count == 0`
 * rather than a string somebody has to inspect.
 */
typedef struct {
	text_t text;
	size_t count;
} list_t;

static void list_init(list_t *list, char *into, size_t cap)
{
	text_init(&list->text, into, cap);
	list->count = 0u;
}

static void list_add(list_t *list, const char *item)
{
	putf(&list->text, "%s\"%s\"", list->count > 0u ? ", " : "", item);
	list->count++;
}

/* ------------------------------------------------- what netcfgd cannot say */

/*
 * Keys that carry no information netcfgd is missing.
 *
 * Either derived here anyway (`uuid`), meaningless to a file-backed store
 * (`timestamp`), or NM's own bookkeeping. Listing them means the dropped note
 * in a generated file names things an operator would actually want to know
 * about, rather than fifteen lines of noise every client sends.
 *
 * A name ending in `.` is a whole group.
 */
static const char *const UNINTERESTING[] = { "connection.id", "connection.uuid",
	"connection.type", "connection.timestamp", "connection.permissions",
	"connection.autoconnect", "connection.autoconnect-priority", "connection.metered",
	"connection.interface-name", "802-11-wireless.ssid", "802-11-wireless.mode",
	"802-11-wireless.security", "802-11-wireless.hidden", "802-11-wireless.seen-bssids",
	"802-11-wireless-security.key-mgmt", "802-11-wireless-security.psk",
	"802-11-wireless-security.auth-alg", "802-11-wireless-security.psk-flags",
	"802-11-wireless-security.wep-key-flags", "802-11-wireless-security.leap-password-flags",
	"ipv4.method", "ipv4.address-data", "ipv4.gateway", "ipv4.route-data", "ipv4.addresses",
	"ipv4.routes", "ipv4.dns", "ipv4.dns-data", "ipv4.dns-search", "ipv6.method",
	"ipv6.address-data", "ipv6.gateway", "ipv6.route-data", "ipv6.addresses", "ipv6.routes",
	"ipv6.dns", "ipv6.dns-data", "ipv6.dns-search", "ipv6.addr-gen-mode", "proxy." };

static int uninteresting(const char *group, const char *key)
{
	char   joined[160];
	size_t at;

	(void)snprintf(joined, sizeof(joined), "%s.%s", group, key);
	for (at = 0u; at < sizeof(UNINTERESTING) / sizeof(UNINTERESTING[0]); at++) {
		if (strcmp(UNINTERESTING[at], joined) == 0) {
			return 1;
		}
	}
	(void)snprintf(joined, sizeof(joined), "%s.", group);
	for (at = 0u; at < sizeof(UNINTERESTING) / sizeof(UNINTERESTING[0]); at++) {
		if (strcmp(UNINTERESTING[at], joined) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * Whether a value says nothing.
 *
 * NM sends `address-data` as an empty array on every profile, so reporting that
 * as dropped would bury the one line that matters under fourteen that do not.
 */
static int says_nothing(DBusMessageIter *value)
{
	switch (dbus_message_iter_get_arg_type(value)) {
	case DBUS_TYPE_STRING: {
		const char *text = NULL;

		dbus_message_iter_get_basic(value, &text);
		return !text || text[0] == '\0';
	}
	case DBUS_TYPE_ARRAY: {
		DBusMessageIter inner;

		dbus_message_iter_recurse(value, &inner);
		return dbus_message_iter_get_arg_type(&inner) == DBUS_TYPE_INVALID;
	}
	case DBUS_TYPE_UINT32: {
		dbus_uint32_t number = 0u;

		dbus_message_iter_get_basic(value, &number);
		return number == 0u;
	}
	case DBUS_TYPE_BOOLEAN: {
		dbus_bool_t yes = FALSE;

		dbus_message_iter_get_basic(value, &yes);
		return !yes;
	}
	default:
		return 0;
	}
}

/* As many as a note is worth reading; a client sending more has said enough. */
#define NMC_DROPPED_MAX 48u

/*
 * Everything the client asked for that this translation did not carry over,
 * written into the file as comments.
 *
 * 0034: what netcfgd cannot express is named rather than dropped. The names are
 * the client's own spelling of them, so an operator can look the setting up.
 */
static void note_dropped(DBusMessage *call, text_t *into)
{
	struct {
		const char *group;
		const char *key;
	} dropped[NMC_DROPPED_MAX];
	size_t          count = 0u;
	size_t          at;
	DBusMessageIter args;
	DBusMessageIter groups;

	if (!dbus_message_iter_init(call, &args) ||
	    dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY) {
		return;
	}
	dbus_message_iter_recurse(&args, &groups);
	while (dbus_message_iter_get_arg_type(&groups) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;
		DBusMessageIter pairs;
		const char     *group = NULL;

		dbus_message_iter_recurse(&groups, &entry);
		if (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&entry, &group);
		}
		(void)dbus_message_iter_next(&entry);
		if (!group || dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_ARRAY) {
			(void)dbus_message_iter_next(&groups);
			continue;
		}
		dbus_message_iter_recurse(&entry, &pairs);
		while (dbus_message_iter_get_arg_type(&pairs) == DBUS_TYPE_DICT_ENTRY) {
			DBusMessageIter pair;
			DBusMessageIter value;
			const char     *key = NULL;

			dbus_message_iter_recurse(&pairs, &pair);
			if (dbus_message_iter_get_arg_type(&pair) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&pair, &key);
			}
			(void)dbus_message_iter_next(&pair);
			if (key && dbus_message_iter_get_arg_type(&pair) == DBUS_TYPE_VARIANT &&
			    count < NMC_DROPPED_MAX && !uninteresting(group, key)) {
				dbus_message_iter_recurse(&pair, &value);
				if (!says_nothing(&value)) {
					dropped[count].group = group;
					dropped[count].key = key;
					count++;
				}
			}
			(void)dbus_message_iter_next(&pairs);
		}
		(void)dbus_message_iter_next(&groups);
	}
	if (count == 0u) {
		return;
	}
	/*
	 * Sorted, so that two clients sending the same settings in a different
	 * order produce the same file -- which is what makes a generated file
	 * diffable. Insertion sort because the list is at most 48 long and the
	 * alternative is a comparison function for two fields.
	 */
	for (at = 1u; at < count; at++) {
		size_t back = at;

		while (back > 0u) {
			int order = strcmp(dropped[back - 1u].group, dropped[back].group);

			if (order == 0) {
				order = strcmp(dropped[back - 1u].key, dropped[back].key);
			}
			if (order <= 0) {
				break;
			}
			{
				const char *group = dropped[back - 1u].group;
				const char *key = dropped[back - 1u].key;

				dropped[back - 1u].group = dropped[back].group;
				dropped[back - 1u].key = dropped[back].key;
				dropped[back].group = group;
				dropped[back].key = key;
			}
			back--;
		}
	}
	putf(into, "#\n# The client also asked for the settings below. netcfgd has no way to\n"
	           "# say them, so they are recorded here rather than silently discarded:\n");
	for (at = 0u; at < count; at++) {
		putf(into, "#   %s.%s\n", dropped[at].group, dropped[at].key);
	}
}

/* ---------------------------------------------------------- the addressing */

/*
 * The static addresses in one family's `address-data`.
 *
 * NM keeps the address and the prefix apart; netcfgd writes CIDR, which is what
 * an operator types and what `ip addr` prints. Rejoining them here is what makes
 * the file read like one somebody wrote.
 */
static int static_addresses(DBusMessage *call, const char *group, list_t *list, char *err,
    size_t err_size)
{
	DBusMessageIter entries;

	if (!read_entries(call, group, "address-data", &entries)) {
		(void)snprintf(err, err_size,
		    "`%s.method` is `manual` and the settings carry no `%s.address-data`: a "
		    "static network with no address is not one netcfgd can bring up",
		    group, group);
		return 0;
	}
	while (dbus_message_iter_get_arg_type(&entries) == DBUS_TYPE_ARRAY) {
		char          address[64];
		char          cidr[80];
		unsigned long prefix = 0ul;

		if (!entry_text(&entries, "address", address, sizeof(address)) ||
		    !entry_number(&entries, "prefix", &prefix)) {
			(void)snprintf(err, err_size,
			    "a `%s.address-data` entry has no address and prefix this shim can "
			    "read; netcfgd writes them together as CIDR and needs both",
			    group);
			return 0;
		}
		if (!is_address(address)) {
			(void)snprintf(err, err_size,
			    "`%s` is not an address, so the block netcfgd would be asked to "
			    "compile could not be compiled",
			    address);
			return 0;
		}
		(void)snprintf(cidr, sizeof(cidr), "%s/%lu", address, prefix);
		list_add(list, cidr);
		(void)dbus_message_iter_next(&entries);
	}
	return 1;
}

/*
 * How netcfgd spells the addressing NM asked for.
 *
 * Both families in one list, because netcfgd's `config` is one list -- decision
 * 0006's composition rather than NM's two independent settings.
 *
 * **An unrecognised method is refused, where the Rust ignores it.** `shared` is
 * the case that matters: NM means address translation for other machines by it,
 * netcfgd has no spelling for that, and a network written as though the method
 * had not been named is one whose whole point was silently removed. `disabled`
 * and `link-local` for v4 stay silent deliberately -- an interface netcfgd is
 * given no addressing for gets none, which is what both of those mean.
 */
static int addressing(DBusMessage *call, list_t *list, char *err, size_t err_size)
{
	char method[32];

	if (read_text(call, "ipv4", "method", method, sizeof(method))) {
		if (strcmp(method, "auto") == 0) {
			list_add(list, "dhcp");
		} else if (strcmp(method, "manual") == 0) {
			if (!static_addresses(call, "ipv4", list, err, err_size)) {
				return 0;
			}
		} else if (strcmp(method, "disabled") != 0 && strcmp(method, "link-local") != 0) {
			(void)snprintf(err, err_size,
			    "netcfgd has no ipv4 addressing that means `%s`; it can be `auto`, "
			    "`manual`, `disabled` or `link-local`",
			    method);
			return 0;
		}
	}
	if (read_text(call, "ipv6", "method", method, sizeof(method))) {
		if (strcmp(method, "auto") == 0) {
			list_add(list, "slaac");
		} else if (strcmp(method, "dhcp") == 0) {
			list_add(list, "dhcp6");
		} else if (strcmp(method, "link-local") == 0) {
			list_add(list, "link_local");
		} else if (strcmp(method, "manual") == 0) {
			if (!static_addresses(call, "ipv6", list, err, err_size)) {
				return 0;
			}
		} else if (strcmp(method, "disabled") != 0 && strcmp(method, "ignore") != 0) {
			(void)snprintf(err, err_size,
			    "netcfgd has no ipv6 addressing that means `%s`; it can be `auto`, "
			    "`dhcp`, `manual`, `link-local` or `disabled`",
			    method);
			return 0;
		}
	}
	return 1;
}

/*
 * The routes a client asked for, as netcfgd writes them.
 *
 * The gateway comes back together with them: NM keeps the default route's next
 * hop in `gateway` and everything else in `route-data` (0033), and netcfgd has
 * one list of routes with `default` in it like any other destination.
 */
static int family_routes(DBusMessage *call, const char *group, list_t *list, char *err,
    size_t err_size)
{
	char            gateway[64];
	DBusMessageIter entries;

	if (read_text(call, group, "gateway", gateway, sizeof(gateway))) {
		char line[96];

		if (!is_address(gateway)) {
			(void)snprintf(err, err_size,
			    "`%s` is not an address, so it cannot be a default route's next hop",
			    gateway);
			return 0;
		}
		(void)snprintf(line, sizeof(line), "default via %s", gateway);
		list_add(list, line);
	}
	if (!read_entries(call, group, "route-data", &entries)) {
		return 1;
	}
	while (dbus_message_iter_get_arg_type(&entries) == DBUS_TYPE_ARRAY) {
		char          destination[64];
		char          next_hop[64];
		char          line[192];
		text_t        route;
		unsigned long prefix = 0ul;
		unsigned long metric = 0ul;

		if (!entry_text(&entries, "dest", destination, sizeof(destination))) {
			(void)dbus_message_iter_next(&entries);
			continue;
		}
		if (!is_address(destination)) {
			(void)snprintf(err, err_size,
			    "`%s` is not an address, so it cannot be a route's destination",
			    destination);
			return 0;
		}
		(void)entry_number(&entries, "prefix", &prefix);
		text_init(&route, line, sizeof(line));
		putf(&route, "%s/%lu", destination, prefix);
		if (entry_text(&entries, "next-hop", next_hop, sizeof(next_hop))) {
			if (!is_address(next_hop)) {
				(void)snprintf(err, err_size,
				    "`%s` is not an address, so it cannot be a route's next hop",
				    next_hop);
				return 0;
			}
			putf(&route, " via %s", next_hop);
		}
		if (entry_number(&entries, "metric", &metric)) {
			putf(&route, " metric %lu", metric);
		}
		list_add(list, line);
		(void)dbus_message_iter_next(&entries);
	}
	return 1;
}

/* ------------------------------------------------------------------- the dns */

/*
 * A list of strings out of a settings group.
 *
 * Answers 1 when the key was there, 0 when it was not, and -1 for a refusal --
 * three answers because the caller has to tell "the client sent no `dns-data`"
 * from "the client sent an empty one". The first falls back to the packed form
 * an older client sends; the second is a client saying there are none, and
 * reading the packed form after it would resurrect addresses it had removed.
 */
static int read_strings(DBusMessage *call, const char *group, const char *key, list_t *list,
    int addresses, char *err, size_t err_size)
{
	DBusMessageIter value;
	DBusMessageIter items;

	if (!value_of(call, group, key, &value) ||
	    dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_ARRAY) {
		return 0;
	}
	dbus_message_iter_recurse(&value, &items);
	while (dbus_message_iter_get_arg_type(&items) == DBUS_TYPE_STRING) {
		const char *text = NULL;

		dbus_message_iter_get_basic(&items, &text);
		if (text && text[0] != '\0') {
			if (addresses && !is_address(text)) {
				(void)snprintf(err, err_size,
				    "`%s` is not an address, so it cannot be a nameserver", text);
				return -1;
			}
			list_add(list, text);
		}
		(void)dbus_message_iter_next(&items);
	}
	return 1;
}

/*
 * The packed nameservers an older client sends.
 *
 * IPv4 only: NM's IPv6 `dns` is an array of byte arrays, and a client old
 * enough to send that is older than this shim intends to serve -- so it is
 * reported as dropped rather than half-read.
 *
 * The four bytes are taken in the machine's own order, which is what NM's
 * clients put there and what the Rust reads; `9.9.9.9` is the one address that
 * cannot tell a byte-order mistake apart, which is why the live script uses it
 * and the unit tests use an asymmetric one.
 */
static void read_packed_dns(DBusMessage *call, const char *group, list_t *list)
{
	DBusMessageIter value;
	DBusMessageIter words;

	if (!value_of(call, group, "dns", &value) ||
	    dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_ARRAY) {
		return;
	}
	dbus_message_iter_recurse(&value, &words);
	while (dbus_message_iter_get_arg_type(&words) == DBUS_TYPE_UINT32) {
		dbus_uint32_t word = 0u;
		unsigned char octets[4];
		char          text[16];

		dbus_message_iter_get_basic(&words, &word);
		memcpy(octets, &word, sizeof(octets));
		(void)snprintf(text, sizeof(text), "%u.%u.%u.%u", (unsigned)octets[0],
		    (unsigned)octets[1], (unsigned)octets[2], (unsigned)octets[3]);
		list_add(list, text);
		(void)dbus_message_iter_next(&words);
	}
}

/*
 * The `dns` block a profile's nameservers and search domains become.
 *
 * Both families at once: netcfgd's policy is one scope per network rather than
 * one per address family, which is decision 0007's shape rather than NM's.
 */
static int dns_block(DBusMessage *call, text_t *into, char *err, size_t err_size)
{
	char   server_text[320];
	char   search_text[320];
	list_t servers;
	list_t search;
	size_t family;

	list_init(&servers, server_text, sizeof(server_text));
	list_init(&search, search_text, sizeof(search_text));
	for (family = 0u; family < 2u; family++) {
		const char *group = family == 0u ? "ipv4" : "ipv6";
		int         listed = read_strings(call, group, "dns-data", &servers, 1, err, err_size);

		if (listed < 0) {
			return 0;
		}
		if (listed == 0) {
			read_packed_dns(call, group, &servers);
		}
		if (read_strings(call, group, "dns-search", &search, 0, err, err_size) < 0) {
			return 0;
		}
	}
	if (servers.text.overflowed || search.text.overflowed) {
		(void)snprintf(err, err_size,
		    "more nameservers and search domains than this shim will write into one "
		    "block; put them in /etc/netcfgd by hand");
		return 0;
	}
	if (servers.count == 0u && search.count == 0u) {
		return 1;
	}
	putf(into, "\tdns { ");
	if (servers.count > 0u) {
		putf(into, "servers = [%s]", server_text);
	}
	if (servers.count > 0u && search.count > 0u) {
		putf(into, "; ");
	}
	if (search.count > 0u) {
		putf(into, "search = [%s]", search_text);
	}
	putf(into, " }\n");
	return 1;
}

/* ------------------------------------------------------------- the radio */

/*
 * What goes inside the `wifi` block.
 *
 * **A network with a passphrase is refused, and that is this slice's boundary
 * rather than an oversight.** Writing one means putting the credential in the
 * secret provider and a `@secret:` reference in the block (0030, 0031), which
 * is a second write through a second tier and its own piece of work. A renderer
 * that wrote the open case and silently dropped the `psk` would hand a client a
 * secured network with no credential and no error -- so until the secret half
 * is here, the whole network is refused and the message says where to go.
 */
static int security_of(DBusMessage *call, char *out, size_t cap, char *err, size_t err_size)
{
	char mechanism[48];

	if (!read_text(call, "802-11-wireless-security", "key-mgmt", mechanism,
	        sizeof(mechanism))) {
		(void)snprintf(out, cap, "open = true");
		return 1;
	}
	if (strcmp(mechanism, "owe") == 0) {
		(void)snprintf(out, cap, "owe = true");
		return 1;
	}
	if (strcmp(mechanism, "wpa-psk") == 0 || strcmp(mechanism, "sae") == 0) {
		(void)snprintf(err, err_size,
		    "this build of the shim writes open and OWE networks over the bus and not "
		    "ones with a passphrase: the credential has to go to netcfgd's secret "
		    "provider and the block carry a reference to it, and writing half of that "
		    "would leave you a secured network with no credential. Use "
		    "`ncfg wifi add`");
		return 0;
	}
	if (strcmp(mechanism, "wpa-eap") == 0 || strcmp(mechanism, "wpa-eap-suite-b-192") == 0) {
		(void)snprintf(err, err_size,
		    "netcfgd has no enterprise wifi: a `network` block says `open`, `owe` or a "
		    "passphrase, and 802.1X is not among them");
		return 0;
	}
	(void)snprintf(err, err_size,
	    "netcfgd has no wifi security that means `%s`; it knows open networks, OWE and "
	    "a passphrase",
	    mechanism);
	return 0;
}

/*
 * NM's `autoconnect-priority`, as netcfgd's network `metric`.
 *
 * **The inverse of what the read direction reports**, and it has to be: that
 * side scales `join_rank(metric)` down into NM's 0..999, so this scales back up
 * and undoes the inversion. Two conversions that are not inverses would make a
 * profile change its own ranking every time a desktop client read it back and
 * wrote it out.
 *
 * **Land in the middle of the band, not at its edge** (0207). Many metrics map
 * to one priority -- 4096 values into 1000 -- so coming back is a choice of
 * which metric in that band to name, and truncating chose the edge. The edge is
 * the value that maps to the next priority down when it is sent again, so a
 * profile a client read and wrote back walked upward every trip: 100, 103, 107,
 * 111. Adding half a band picks the midpoint, which maps back to the priority it
 * came from.
 */
static int network_metric(DBusMessage *call, long *out, int *present, char *err, size_t err_size)
{
	long priority = 0l;
	long rank;

	*present = 0;
	*out = 0l;
	if (!read_number(call, "connection", "autoconnect-priority", &priority)) {
		return 1;
	}
	if (priority < 0l) {
		/* A metric counts up from zero, so a negative priority cannot be
		 * expressed. Refusing by name beats clamping, which would turn a
		 * network the operator deliberately deprioritised into an ordinary
		 * one. */
		(void)snprintf(err, err_size,
		    "a netcfgd metric counts up from zero, so an autoconnect-priority of %ld "
		    "has no spelling; a network ranked below the others is one with a larger "
		    "metric than theirs",
		    priority);
		return 0;
	}
	if (priority == 0l) {
		/* NM's default. Saying nothing leaves the interface's `preference` in
		 * charge, which is what an unranked network should do. */
		return 1;
	}
	rank = (priority * NMC_RANK_CEILING + NMC_RANK_CEILING / 2l) / NMC_PRIORITY_CEILING;
	if (rank > NMC_RANK_CEILING) {
		rank = NMC_RANK_CEILING;
	}
	*out = NMC_RANK_CEILING - rank;
	*present = 1;
	return 1;
}

/*
 * The drop-in's stem: `nm-` and the label sanitised to what a filename should
 * be, because an SSID may contain a slash and a label is not a path.
 *
 * Two ids that sanitise the same collide, and netcfgd catches that rather than
 * this: two blocks with one label is a compile error, which the write reports.
 */
static void stem_of(const char *id, char *out, size_t cap)
{
	size_t at;
	size_t used;

	(void)snprintf(out, cap, "nm-");
	used = strlen(out);
	for (at = 0u; id[at] != '\0' && used + 1u < cap; at++) {
		unsigned char c = (unsigned char)id[at];
		int           keep = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';

		out[used] = keep ? (char)c : '_';
		used++;
	}
	out[used] = '\0';
}

/* -------------------------------------------------------------- the block */

int nmc_block_render(DBusMessage *call, nmc_block_t *out, char *err, size_t err_size)
{
	text_t        text;
	list_t        config;
	list_t        routes;
	char          config_text[512];
	char          route_text[1024];
	char          kind[64];
	char          id[256];
	char          security[64];
	unsigned char ssid[32];
	size_t        ssid_len = 0u;
	long          metered = 0l;
	long          metric = 0l;
	int           has_metric = 0;
	int           flag = 0;

	memset(out, 0, sizeof(*out));
	text_init(&text, out->text, sizeof(out->text));
	list_init(&config, config_text, sizeof(config_text));
	list_init(&routes, route_text, sizeof(route_text));

	/*
	 * **The type is asked of the dictionary rather than assumed.** An
	 * `802-11-wireless` group being present is a hint and not the answer,
	 * since a client may send groups for a type it did not name -- and the
	 * refusal has to name what was asked for to be worth reading.
	 */
	if (!read_text(call, "connection", "type", kind, sizeof(kind))) {
		(void)snprintf(err, err_size,
		    "these settings name no `connection.type`, so there is nothing to create; "
		    "netcfgd-nm creates wifi networks");
		return 0;
	}
	if (strcmp(kind, "802-11-wireless") != 0) {
		(void)snprintf(err, err_size,
		    "netcfgd-nm can create wifi networks and nothing else; this asked for "
		    "`%s`. An interface is configured by an `interface` block in /etc/netcfgd, "
		    "which is a file to edit rather than a profile to create",
		    kind);
		return 0;
	}
	if (!read_text(call, "connection", "id", id, sizeof(id))) {
		(void)snprintf(err, err_size,
		    "these settings carry no `connection.id` this shim can read, and the id is "
		    "the label of the block it would write");
		return 0;
	}
	if (!is_writable_label(id)) {
		(void)snprintf(err, err_size,
		    "`%s` is not a label netcfgd's configuration can carry: it is written "
		    "between quotes, so a quote, a backslash or a control character in it "
		    "would end the string and turn the rest of the line into configuration",
		    id);
		return 0;
	}
	if (!read_octets(call, "802-11-wireless", "ssid", ssid, sizeof(ssid), &ssid_len) ||
	    ssid_len == 0u) {
		(void)snprintf(err, err_size,
		    "these settings carry no `802-11-wireless.ssid` of 1 to 32 octets, which is "
		    "what a station needs to find the network");
		return 0;
	}
	if (!security_of(call, security, sizeof(security), err, err_size)) {
		return 0;
	}
	/*
	 * Everything is parsed before anything is rendered, so that a refusal
	 * happens before `settings.c` has written a file rather than after.
	 */
	if (!network_metric(call, &metric, &has_metric, err, err_size)) {
		return 0;
	}
	if (!addressing(call, &config, err, err_size)) {
		return 0;
	}
	if (!family_routes(call, "ipv4", &routes, err, err_size) ||
	    !family_routes(call, "ipv6", &routes, err, err_size)) {
		return 0;
	}
	if (config.text.overflowed || routes.text.overflowed) {
		(void)snprintf(err, err_size,
		    "more addresses and routes than this shim will write into one block; put "
		    "them in /etc/netcfgd by hand");
		return 0;
	}

	putf(&text, "# Written by netcfgd-nm from a NetworkManager client. This file is\n");
	putf(&text, "# ordinary netcfgd configuration: edit it, diff it, commit it, or delete\n");
	putf(&text, "# it. Deleting netcfgd-nm leaves it behind, still valid.\n");
	note_dropped(call, &text);
	putf(&text, "\nnetwork \"%s\" {\n", id);
	/* NM's `metered` is an enumeration and 1 is `NM_METERED_YES`, so it is a
	 * number here rather than the boolean netcfgd writes. */
	if (read_number(call, "connection", "metered", &metered) && metered == 1l) {
		putf(&text, "\tmetered = true\n");
	}
	/* Beside `metered`, which is where 0154 put it: a metric ranks this network
	 * against every link on the machine rather than describing the radio, so it
	 * is not a `wifi` key. */
	if (has_metric) {
		putf(&text, "\tmetric = %ld\n", metric);
	}
	/*
	 * The SSID as hex whenever it is not exactly the label. An SSID is octets
	 * and a label is text, so a network whose name has a space, or is not UTF-8
	 * at all, needs both -- and writing the hex form unconditionally would make
	 * every generated file harder to read than it has to be.
	 */
	if (ssid_len != strlen(id) || memcmp(ssid, id, ssid_len) != 0) {
		static const char digits[] = "0123456789abcdef";
		char              hex[sizeof(ssid) * 2u + 1u];
		size_t            at;

		for (at = 0u; at < ssid_len; at++) {
			hex[at * 2u] = digits[ssid[at] >> 4];
			hex[at * 2u + 1u] = digits[ssid[at] & 0x0fu];
		}
		hex[ssid_len * 2u] = '\0';
		putf(&text, "\tssid = \"%s\"\n", hex);
	}
	/* One key today. It was a list because `autoconnect-priority` was written in
	 * here as `priority` until 0154 moved it out to a network-level `metric`,
	 * and nothing else has ever belonged inside `wifi`. */
	putf(&text, "\twifi { %s }\n", security);
	if (read_flag(call, "802-11-wireless", "hidden", &flag) && flag) {
		putf(&text, "\thidden = true\n");
	}
	if (read_flag(call, "connection", "autoconnect", &flag) && !flag) {
		putf(&text, "\tautoconnect = false\n");
	}
	if (config.count > 0u) {
		putf(&text, "\tconfig = [%s]\n", config_text);
	}
	if (routes.count > 0u) {
		putf(&text, "\troutes = [%s]\n", route_text);
	}
	if (!dns_block(call, &text, err, err_size)) {
		return 0;
	}
	putf(&text, "}\n");

	if (text.overflowed) {
		(void)snprintf(err, err_size,
		    "the block these settings describe is larger than this shim will write; "
		    "put it in /etc/netcfgd by hand");
		return 0;
	}
	(void)snprintf(out->label, sizeof(out->label), "%s", id);
	stem_of(id, out->stem, sizeof(out->stem));
	return 1;
}
