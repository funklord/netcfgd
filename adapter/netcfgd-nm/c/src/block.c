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

/*
 * Whether `text` can go inside a quoted value in the block.
 *
 * **The same character rule as a label, for the same reason, and the reason is
 * not tidiness.** A quote or a backslash ends or escapes the string the
 * renderer is writing; a newline ends the LINE. Either way the file that comes
 * out is not the file this code meant to write, and the daemon compiles
 * whatever is there -- so a client that can choose those bytes can choose
 * configuration.
 *
 * Found by fuzzing, 2026-10-21: a `dns-search` entry went into
 * `search = ["..."]` unchecked, and a client could close the list, close the
 * block and open a `network` block of its own. project.md 10.509 has the
 * reproduction.
 */
/* The longest group or key name the note writes before it says `...`. NM's own
 * are well under this; the number is here to bound a client's, not theirs. */
#define NMC_NAME_MAX 96u

static int is_quotable(const char *text)
{
	size_t at;

	for (at = 0u; text[at] != '\0'; at++) {
		unsigned char c = (unsigned char)text[at];

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
/*
 * A group or key name, written into a comment so that it cannot be anything
 * else.
 *
 * **Sanitised rather than refused, which is the opposite choice from
 * `dns-search` above and deliberate.** This note exists because 0034 says an
 * unexpressible setting is NAMED rather than dropped -- so refusing the call
 * over a name would throw away a profile the client can otherwise have, to
 * protect a comment. What matters is that the comment stays a comment: a
 * newline in a key name ended the line and let a client write a `network`
 * block of its own into the file, which is the defect fuzzing found
 * (project.md 10.509).
 *
 * Anything outside printable ASCII becomes `?`, so the reader sees that the
 * name had bytes in it rather than seeing a name that was never sent. The
 * length is bounded as well: a key name is an identifier, and a client sending
 * a kilobyte of one is filling the block's budget rather than describing a
 * setting.
 */
static void put_name(text_t *into, const char *name)
{
	size_t at;

	for (at = 0u; name[at] != '\0' && at < NMC_NAME_MAX; at++) {
		unsigned char c = (unsigned char)name[at];

		putf(into, "%c", (c < 0x20u || c >= 0x7fu) ? '?' : (char)c);
	}
	if (name[at] != '\0') {
		putf(into, "...");
	}
}

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
		putf(into, "#   ");
		put_name(into, dropped[at].group);
		putf(into, ".");
		put_name(into, dropped[at].key);
		putf(into, "\n");
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
			/*
			 * **Refused rather than rewritten**, which is the choice between
			 * two honest answers: a client's search domain is a value
			 * somebody typed, and quietly editing it would leave them with a
			 * resolver configuration they did not ask for. A domain cannot
			 * contain a quote, a backslash or a control character in the
			 * first place, so nothing legitimate is being turned away.
			 */
			if (!is_quotable(text)) {
				(void)snprintf(err, err_size,
				    "a `%s.%s` entry has a quote, a backslash or a control "
				    "character in it, and netcfgd configuration cannot carry "
				    "one inside a value",
				    group, key);
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
 * Whether a passphrase is one that can be sent at all.
 *
 * **The CLI's `check_passphrase`, made where the client can still fix it.** Its
 * comment is the argument: at association time the failure is a bare `FAIL`,
 * half an hour after the file was written. A fourth copy of the range because
 * this program links `client/` and nothing else -- the model's
 * `PASSPHRASE_OCTETS`, the CLI's check and this one have to agree, and 0229
 * says what they are counting.
 *
 * **The length is safe to report and the value is not**, which is the rule
 * `secrets.h` keeps everywhere and which a refusal crossing the bus makes
 * sharper: a message naming the passphrase would put it in every client's log.
 *
 * The control-character rule comes with it rather than being left out as the
 * Rust leaves it: such a passphrase cannot be sent to the supplicant at all,
 * so storing it would buy a credential that is certain not to work.
 */
static int passphrase_fits(const char *passphrase, char *err, size_t err_size)
{
	size_t length = strlen(passphrase);
	size_t at;

	if (length < 8u || length > 63u) {
		(void)snprintf(err, err_size,
		    "a WPA passphrase is 8 to 63 octets and that one is %zu -- a character "
		    "outside ASCII counts as more than one. A 64-digit hex key -- a "
		    "pre-computed PMK rather than a passphrase -- is not something netcfgd "
		    "can send",
		    length);
		return 0;
	}
	for (at = 0u; at < length; at++) {
		unsigned char one = (unsigned char)passphrase[at];

		if (one < 0x20u || one == 0x7fu) {
			(void)snprintf(err, err_size,
			    "that passphrase contains a control character, which cannot be sent "
			    "to the supplicant at all");
			return 0;
		}
	}
	return 1;
}

/*
 * What goes inside the `wifi` block, and where the credential goes.
 *
 * **The passphrase is taken out of the dictionary and left in `out->secret`,
 * never in the block.** What the block carries is `@secret:<id>` -- constraint
 * 5, and the whole reason netcfgd's document holds references rather than
 * values. The secret's name is the profile's, which makes the reference
 * readable in the file and the file findable in the secrets directory.
 *
 * **A `psk` mechanism with no passphrase is refused rather than written.** A
 * block naming a credential that was never stored is a network netcfgd will
 * try to join and cannot, which is worse than a refusal a client can show.
 * The update path has an answer for this -- a client editing a profile sends
 * back what `GetSettings` gave it, which never contains the passphrase -- and
 * it belongs with `Update`, where there is an existing secret to leave alone.
 */
static int security_of(DBusMessage *call, const char *id, int stored, nmc_block_t *out,
    char *security, size_t cap, char *err, size_t err_size)
{
	char mechanism[48];
	char passphrase[128];

	if (!read_text(call, "802-11-wireless-security", "key-mgmt", mechanism,
	        sizeof(mechanism))) {
		(void)snprintf(security, cap, "open = true");
		return 1;
	}
	if (strcmp(mechanism, "owe") == 0) {
		(void)snprintf(security, cap, "owe = true");
		return 1;
	}
	if (strcmp(mechanism, "wpa-psk") == 0 || strcmp(mechanism, "sae") == 0) {
		int fits;

		if (!read_text(call, "802-11-wireless-security", "psk", passphrase,
		        sizeof(passphrase))) {
			if (!stored) {
				(void)snprintf(err, err_size,
				    "these settings ask for `%s` and carry no "
				    "`802-11-wireless-security.psk`; netcfgd cannot store a "
				    "credential it was not given, and a network referring to one "
				    "that is not there is a network this machine will try to join "
				    "and cannot",
				    mechanism);
				return 0;
			}
			/*
			 * An edit of something else. The block keeps the reference it
			 * already had and no credential is written: requiring one here
			 * would refuse every change to a secured network that is not a
			 * password change, which is most of them.
			 */
			(void)snprintf(security, cap, "psk = \"@secret:%s\"; proto = \"%s\"", id,
			    strcmp(mechanism, "sae") == 0 ? "wpa3" : "wpa2");
			return 1;
		}
		fits = passphrase_fits(passphrase, err, err_size);
		if (fits) {
			size_t length = strlen(passphrase);

			/* Bounded again here, although `passphrase_fits` has just
			 * bounded it to 63 octets: a copy into a credential buffer whose
			 * only bound lives in another function is one a later edit
			 * breaks without anything saying so. */
			if (length >= sizeof(out->secret)) {
				explicit_bzero(passphrase, sizeof(passphrase));
				(void)snprintf(err, err_size,
				    "that passphrase is longer than this shim will carry");
				return 0;
			}
			memcpy(out->secret, passphrase, length + 1u);
			out->has_secret = 1;
			/* 0229's generations: `sae` is WPA3 and `wpa-psk` is WPA2. A
			 * client that asked for one must not be given the other --
			 * netcfgd pins what is negotiated, so guessing would downgrade
			 * a network silently. */
			(void)snprintf(security, cap, "psk = \"@secret:%s\"; proto = \"%s\"", id,
			    strcmp(mechanism, "sae") == 0 ? "wpa3" : "wpa2");
		}
		/* The local copy goes whether it was used or not: a refused
		 * passphrase is still a passphrase, and the error path is the one
		 * that forgets to. */
		explicit_bzero(passphrase, sizeof(passphrase));
		return fits;
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
 * A netcfgd metric as NM's `autoconnect-priority`: the inverse of
 * `network_metric` above, and the reason that one carries half a band.
 *
 * **Scaled, not clamped.** NM takes 0..999 where the model's rank runs to
 * 4096, and clamping would map every metric below about 3100 onto the same
 * number -- which is to say it would throw the ordering away for exactly the
 * networks an operator ranked.
 *
 * **And never 0, which is not a low priority but the absence of one.** The
 * scale bottoms out five ranks early -- a rank under 4096/999 scales to
 * nothing -- so metrics 4092 and above came out as NM's default, which this
 * turns back into no metric at all. The worst-ranked networks are the ones an
 * operator went furthest out of their way to rank, and they were the ones the
 * trip discarded. A floor of 1 costs six metrics of precision there and keeps
 * the ranking.
 */
int nmc_block_passphrase_in(DBusMessage *reply, char *out, size_t cap)
{
	return read_text(reply, "802-11-wireless-security", "psk", out, cap);
}

int nmc_block_priority(int metric)
{
	long rank;
	long scaled;

	if (metric < 0) {
		/* The document ranks this network against nothing, and NM's way of
		 * saying that is for the key not to be there. */
		return 0;
	}
	rank = metric >= NMC_RANK_CEILING ? 0l : NMC_RANK_CEILING - (long)metric;
	scaled = rank * NMC_PRIORITY_CEILING / NMC_RANK_CEILING;
	return scaled < 1l ? 1 : (int)scaled;
}

/*
 * The drop-in's stem: `nm-` and the label sanitised to what a filename should
 * be, because an SSID may contain a slash and a label is not a path.
 *
 * Two ids that sanitise the same collide, and netcfgd catches that rather than
 * this: two blocks with one label is a compile error, which the write reports.
 *
 * **Exported because the delete side needs the same answer.** A profile is one
 * this shim wrote if netcfgd has a drop-in under this name, so the rule that
 * makes the name has to be one function -- two spellings of it would make a
 * network that can be created and not removed.
 */
void nmc_block_stem(const char *id, char *out, size_t cap)
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

void nmc_block_forget(nmc_block_t *block)
{
	if (block) {
		/* `explicit_bzero` rather than `memset`, because memory about to go
		 * out of scope is exactly what a compiler is entitled to skip
		 * clearing -- which is the whole of the difference here. */
		explicit_bzero(block, sizeof(*block));
	}
}

int nmc_block_render(DBusMessage *call, int stored, nmc_block_t *out, char *err, size_t err_size)
{
	text_t        text;
	list_t        config;
	list_t        routes;
	char          config_text[512];
	char          route_text[1024];
	char          kind[64];
	char          id[256];
	/*
	 * `psk = "@secret:<id>"; proto = "wpa3"`. Sized for the longest id
	 * `read_text` can hand back rather than for the 64 the label rule allows,
	 * so that the line cannot be a truncation of a label that was refused --
	 * a half-written `@secret:` reference names a credential that is not
	 * there.
	 */
	char          security[352];
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
	if (!security_of(call, id, stored, out, security, sizeof(security), err, err_size)) {
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
	/*
	 * **Two keys, and `autoconnect` is the second because that is where the
	 * language takes it.** This wrote it at network level -- where the model's
	 * JSON carries it, and where `emit.rs` writes it too -- and netcfgd
	 * refused the whole file:
	 *
	 *     nm-Opts.conf:10:2: unknown network key `autoconnect`
	 *
	 * So `AddConnection` failed whole for any client that asked for a network
	 * it should not join by itself, because the daemon compiles back and keeps
	 * nothing that will not compile. Asked of the daemon rather than reasoned
	 * about: at network level it is refused, inside `wifi` it is accepted, and
	 * `hidden`, `metered` and `metric` are network-level in the same test.
	 *
	 * The JSON and the DSL differ here on purpose, which is why the model's
	 * field list is no evidence about the language: `psk` is inside `wifi` in
	 * the one and inside `security` in the other.
	 *
	 * `priority` was a third key here until 0154 moved it out to a
	 * network-level `metric`, and the diagnostic for the old spelling still
	 * lives in the lowering beside this one.
	 */
	if (read_flag(call, "connection", "autoconnect", &flag) && !flag) {
		putf(&text, "\twifi { %s; autoconnect = false }\n", security);
	} else {
		putf(&text, "\twifi { %s }\n", security);
	}
	if (read_flag(call, "802-11-wireless", "hidden", &flag) && flag) {
		putf(&text, "\thidden = true\n");
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
	nmc_block_stem(id, out->stem, sizeof(out->stem));
	return 1;
}
