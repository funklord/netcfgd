/*
 * The same dictionary, built from the fuzzer's bytes instead of demarshalled.
 *
 * WHY BOTH THIS AND `dictionary.c`
 *   `dictionary.c` fuzzes the real boundary: bytes off the bus, through
 *   `dbus_message_demarshal`, into the renderer. It reaches the renderer's key
 *   comparisons -- libFuzzer infers `"ipv4"`, `"gateway"` and `"owe"` as
 *   dictionary tokens from it, which it could not do otherwise.
 *
 *   **And it could not find an injected overflow.** With `read_text`'s length
 *   check removed and its bounded copy replaced by a `memcpy`, 2.7 million
 *   executions found nothing. The reason is structural rather than a matter of
 *   patience: a D-Bus body is length-prefixed at every level, so lengthening
 *   one string means editing the string's own prefix, its array's, its dict
 *   entry's and the header's body length together. A byte-level mutator
 *   produces a message that fails to demarshal instead, every time.
 *
 *   So this target hands the fuzzer the dimensions that matter directly: WHICH
 *   group, WHICH key, WHICH type, and HOW LONG. A 400-byte value is one byte
 *   of input here. With the same sabotage in place it finds the overflow in
 *   seconds -- which is what says the pair is worth having rather than either
 *   alone.
 *
 * WHAT IT CANNOT SEE, SAID PLAINLY
 *   Only what this builder knows how to build. A type combination nobody
 *   thought of here is one the fuzzer cannot reach, which is exactly the
 *   limitation `dictionary.c` does not have. Neither target is the other's
 *   replacement.
 *
 * WHY THE GENERATED STRINGS ARE PRINTABLE ASCII
 *   Not caution: libdbus REFUSES a string that is not valid UTF-8, loudly, in
 *   a check that is a programming-error path rather than an input one -- so a
 *   generator feeding it arbitrary bytes would be reporting its own bug on
 *   every run. Encoding is `dictionary.c`'s business, where the bytes arrive
 *   from the wire and the demarshaller validates them as it would a client's.
 */
#include "fuzz.h"

#include "shape.h"

#include "nmc/block.h"
#include "nmc/bus.h"

#include <dbus/dbus.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The groups NM sends and netcfgd reads, plus two it does not: an unread group
 * is the dropped-settings path, and a name from the bytes is the one nobody
 * wrote down. */
static const char *const GROUPS[] = { "connection", "802-11-wireless",
	"802-11-wireless-security", "ipv4", "ipv6", "proxy", "802-3-ethernet" };

/* Keys across all of those, in one table on purpose: a key in the wrong group
 * is a case the renderer has to answer, and keeping the tables apart would
 * make it unreachable. */
static const char *const KEYS[] = { "id", "type", "uuid", "autoconnect", "metered",
	"autoconnect-priority", "ssid", "mode", "hidden", "key-mgmt", "psk", "method",
	"address-data", "gateway", "route-data", "dns", "dns-search", "dns-options",
	"prefix", "address", "mtu", "interface-name" };

/* Values a client really sends, so that a one-byte mutation can land on the
 * string the renderer is comparing against. */
static const char *const WORDS[] = { "802-11-wireless", "infrastructure", "auto", "manual",
	"wpa-psk", "sae", "owe", "none", "shared", "link-local", "disabled", "192.0.2.5",
	"2001:db8::1", "a passphrase of some length", "", "Office" };

#define COUNT(table) (sizeof(table) / sizeof((table)[0]))

/* The fuzzer's bytes, read one decision at a time. Exhausted means zero, which
 * ends every loop rather than wrapping -- a wrapping cursor makes the input
 * length meaningless and the corpus unminimisable. */
typedef struct {
	const unsigned char *at;
	size_t               left;
} cursor_t;

static unsigned char take(cursor_t *bytes)
{
	if (!bytes->left) {
		return 0u;
	}
	bytes->left--;
	return *bytes->at++;
}

/* A string the fuzzer chose: one of the real words, or a run of printable
 * bytes whose LENGTH it also chose. The second arm is the one that reaches a
 * copy into a fixed buffer. */
static char *text_of(cursor_t *bytes)
{
	unsigned char pick = take(bytes);
	size_t        length;
	size_t        at;
	char         *text;

	if (pick < 0x80u) {
		const char *word = WORDS[pick % COUNT(WORDS)];

		return ncfg_fuzz_text((const unsigned char *)word, strlen(word));
	}
	/* Up to 1,020 bytes from two of the fuzzer's own, which is past every
	 * buffer this renderer copies into and well inside what a client may
	 * legitimately send. */
	length = (size_t)take(bytes) * 4u;
	text = malloc(length + 1u);
	if (!text) {
		return NULL;
	}
	for (at = 0u; at < length; at++) {
		unsigned char one = take(bytes);

		text[at] = (char)(0x20u + (one % 0x5fu));
	}
	text[length] = '\0';
	return text;
}

static void say_text(DBusMessageIter *pairs, const char *key, cursor_t *bytes)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	char           *text = text_of(bytes);
	const char     *cursor = text ? text : "";

	(void)dbus_message_iter_open_container(pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair);
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &key);
	(void)dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "s", &value);
	(void)dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &cursor);
	(void)dbus_message_iter_close_container(&pair, &value);
	(void)dbus_message_iter_close_container(pairs, &pair);
	free(text);
}

static void say_basic(DBusMessageIter *pairs, const char *key, int type, cursor_t *bytes)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	char            signature[2] = { (char)type, '\0' };
	dbus_uint32_t   word = (dbus_uint32_t)take(bytes) | ((dbus_uint32_t)take(bytes) << 8);
	dbus_int32_t    signed_word = (dbus_int32_t)word - 32768;
	dbus_bool_t     flag = take(bytes) & 1u ? TRUE : FALSE;
	const void     *held = &word;

	if (type == DBUS_TYPE_BOOLEAN) {
		held = &flag;
	} else if (type == DBUS_TYPE_INT32) {
		held = &signed_word;
	}
	(void)dbus_message_iter_open_container(pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair);
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &key);
	(void)dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, signature, &value);
	(void)dbus_message_iter_append_basic(&value, type, held);
	(void)dbus_message_iter_close_container(&pair, &value);
	(void)dbus_message_iter_close_container(pairs, &pair);
}

/* `ay`, which is how an SSID arrives: octets, so any byte is legal here. */
static void say_bytes(DBusMessageIter *pairs, const char *key, cursor_t *bytes)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	DBusMessageIter array;
	size_t          length = (size_t)take(bytes) * 2u;
	size_t          at;

	(void)dbus_message_iter_open_container(pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair);
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &key);
	(void)dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "ay", &value);
	(void)dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY, "y", &array);
	for (at = 0u; at < length; at++) {
		unsigned char one = take(bytes);

		(void)dbus_message_iter_append_basic(&array, DBUS_TYPE_BYTE, &one);
	}
	(void)dbus_message_iter_close_container(&value, &array);
	(void)dbus_message_iter_close_container(&pair, &value);
	(void)dbus_message_iter_close_container(pairs, &pair);
}

static void say_strings(DBusMessageIter *pairs, const char *key, cursor_t *bytes)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	DBusMessageIter array;
	size_t          count = (size_t)(take(bytes) % 8u);
	size_t          at;

	(void)dbus_message_iter_open_container(pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair);
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &key);
	(void)dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "as", &value);
	(void)dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY, "s", &array);
	for (at = 0u; at < count; at++) {
		char       *text = text_of(bytes);
		const char *cursor = text ? text : "";

		(void)dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &cursor);
		free(text);
	}
	(void)dbus_message_iter_close_container(&value, &array);
	(void)dbus_message_iter_close_container(&pair, &value);
	(void)dbus_message_iter_close_container(pairs, &pair);
}

/* `aa{sv}`: `address-data` and `route-data`, the deepest thing a client sends
 * and the one place the renderer walks a list of dictionaries. */
static void say_entries(DBusMessageIter *pairs, const char *key, cursor_t *bytes)
{
	DBusMessageIter pair;
	DBusMessageIter value;
	DBusMessageIter array;
	size_t          count = (size_t)(take(bytes) % 4u);
	size_t          at;

	(void)dbus_message_iter_open_container(pairs, DBUS_TYPE_DICT_ENTRY, NULL, &pair);
	(void)dbus_message_iter_append_basic(&pair, DBUS_TYPE_STRING, &key);
	(void)dbus_message_iter_open_container(&pair, DBUS_TYPE_VARIANT, "aa{sv}", &value);
	(void)dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY, "a{sv}", &array);
	for (at = 0u; at < count; at++) {
		DBusMessageIter entry;
		size_t          inner = (size_t)(take(bytes) % 4u);
		size_t          each;

		(void)dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY, "{sv}", &entry);
		for (each = 0u; each < inner; each++) {
			const char *name = KEYS[take(bytes) % COUNT(KEYS)];

			if (take(bytes) & 1u) {
				say_text(&entry, name, bytes);
			} else {
				say_basic(&entry, name, DBUS_TYPE_UINT32, bytes);
			}
		}
		(void)dbus_message_iter_close_container(&array, &entry);
	}
	(void)dbus_message_iter_close_container(&value, &array);
	(void)dbus_message_iter_close_container(&pair, &value);
	(void)dbus_message_iter_close_container(pairs, &pair);
}

static void one_pair(DBusMessageIter *pairs, cursor_t *bytes)
{
	const char *key = KEYS[take(bytes) % COUNT(KEYS)];

	switch (take(bytes) % 7u) {
	case 0:
	case 1:
		say_text(pairs, key, bytes);
		break;
	case 2:
		say_basic(pairs, key, DBUS_TYPE_BOOLEAN, bytes);
		break;
	case 3:
		say_basic(pairs, key, DBUS_TYPE_UINT32, bytes);
		break;
	case 4:
		say_bytes(pairs, key, bytes);
		break;
	case 5:
		say_strings(pairs, key, bytes);
		break;
	default:
		say_entries(pairs, key, bytes);
		break;
	}
}

int ncfg_fuzz_one(const unsigned char *data, size_t length)
{
	cursor_t        bytes = { data, length };
	DBusMessage    *call;
	DBusMessageIter args;
	DBusMessageIter groups;
	nmc_block_t     block;
	char            err[NMC_ERROR_MAX];
	char            passphrase[96];
	size_t          count;
	size_t          at;

	call = dbus_message_new_method_call("org.freedesktop.NetworkManager",
	    "/org/freedesktop/NetworkManager/Settings",
	    "org.freedesktop.NetworkManager.Settings", "AddConnection");
	if (!call) {
		return 0;
	}
	dbus_message_iter_init_append(call, &args);
	(void)dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sa{sv}}", &groups);
	count = (size_t)(take(&bytes) % 8u);
	for (at = 0u; at < count; at++) {
		DBusMessageIter entry;
		DBusMessageIter pairs;
		const char     *name = GROUPS[take(&bytes) % COUNT(GROUPS)];
		size_t          pairs_count = (size_t)(take(&bytes) % 10u);
		size_t          each;

		(void)dbus_message_iter_open_container(&groups, DBUS_TYPE_DICT_ENTRY, NULL,
		    &entry);
		(void)dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &name);
		(void)dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY, "{sv}", &pairs);
		for (each = 0u; each < pairs_count; each++) {
			one_pair(&pairs, &bytes);
		}
		(void)dbus_message_iter_close_container(&entry, &pairs);
		(void)dbus_message_iter_close_container(&groups, &entry);
	}
	(void)dbus_message_iter_close_container(&args, &groups);

	memset(&block, 0, sizeof(block));
	if (nmc_block_render(call, 0, &block, err, sizeof(err))) {
		/* The same invariants `dictionary.c` asserts, for the same reason: a
		 * fuzzer that only looked for crashes would pass a renderer that
		 * wrote a block with no label or put the credential in the text. */
		if (block.label[0] == '\0' || block.stem[0] == '\0') {
			abort();
		}
		if (block.has_secret) {
			char needle[128];

			if (block.secret[0] == '\0') {
				abort(); /* a credential promised and not carried */
			}
			/*
			 * **The credential must never be the VALUE of `psk`.** This said
			 * "the secret appears nowhere in the text", which is a stronger
			 * claim than the code owes and it fired on a passphrase that
			 * happened to equal a group name the dropped-settings note lists
			 * -- a false positive that cost an investigation. What 0042 and
			 * 0229 actually require is that the file carries a REFERENCE: the
			 * octets live in the secret store, and `psk` says `@secret:`.
			 */
			(void)snprintf(needle, sizeof(needle), "psk = \"%s\"", block.secret);
			if (strstr(block.text, needle) != NULL) {
				abort(); /* the passphrase itself was written into the file */
			}
			if (strstr(block.text, "@secret:") == NULL) {
				abort(); /* a credential, and nothing pointing at it */
			}
		}
		/* The shape, which is what caught the configuration injection that a
		 * crash-only run walked past for millions of executions. */
		nmc_fuzz_check_shape(block.text);
	}
	nmc_block_forget(&block);

	memset(&block, 0, sizeof(block));
	(void)nmc_block_render(call, 1, &block, err, sizeof(err));
	nmc_block_forget(&block);

	(void)nmc_block_passphrase_in(call, passphrase, sizeof(passphrase));
	memset(passphrase, 0, sizeof(passphrase));

	dbus_message_unref(call);
	return 0;
}
