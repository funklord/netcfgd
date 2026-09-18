/*
 * protocol.c -- the control protocol's text, in and out.
 *
 * Pure: bytes to structs and back. `wpa_supplicant` is not on every machine
 * that builds netcfgd, and association needs a radio besides, so the part that
 * can be tested exhaustively without either is kept separate from the part
 * that cannot.
 *
 * The quoting rules below are the reason this file is worth reading. A control
 * socket that takes `SET_NETWORK 0 ssid "..."` is a place where a value from a
 * config file becomes protocol syntax, and an SSID is 32 arbitrary octets
 * chosen by whoever named the network -- including, if they like, ones
 * containing a quote.
 */
#include "ncfg/supplicant.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------- small parts */

static int is_digit(char one)
{
	return one >= '0' && one <= '9';
}

static int is_space(char one)
{
	return one == ' ' || one == '\t' || one == '\n' || one == '\r' || one == '\v' || one == '\f';
}

static int hex_value(unsigned char byte, unsigned char *out)
{
	if (byte >= '0' && byte <= '9') {
		*out = (unsigned char)(byte - '0');
		return 1;
	}
	if (byte >= 'a' && byte <= 'f') {
		*out = (unsigned char)(byte - 'a' + 10);
		return 1;
	}
	if (byte >= 'A' && byte <= 'F') {
		*out = (unsigned char)(byte - 'A' + 10);
		return 1;
	}
	return 0;
}

/*
 * One line of a body, the way Rust's `str::lines` gives it.
 *
 * Splits on `\n` and drops a trailing `\r`, which matters because this reads
 * what another program wrote: a body that arrived with carriage returns would
 * otherwise put one on the end of every flags field, where it would be
 * compared against and printed.
 *
 * Returns the start of the line and its length, and advances `*cursor` past
 * it. NULL at the end.
 */
static const char *next_line(const char **cursor, size_t *length_out)
{
	const char *start = *cursor;
	const char *stop;

	if (!start || *start == '\0') {
		return NULL;
	}
	stop = strchr(start, '\n');
	if (stop) {
		*length_out = (size_t)(stop - start);
		*cursor = stop + 1;
	} else {
		*length_out = strlen(start);
		*cursor = start + *length_out;
	}
	if (*length_out > 0u && start[*length_out - 1u] == '\r') {
		(*length_out)--;
	}
	return start;
}

/* A copy of `length` bytes as a NUL-terminated string, or NULL. */
static char *own(const char *bytes, size_t length)
{
	char *out = malloc(length + 1u);

	if (!out) {
		return NULL;
	}
	if (length) {
		memcpy(out, bytes, length);
	}
	out[length] = '\0';
	return out;
}

/*
 * Grow an array of `size`-byte items to hold one more.
 *
 * Doubling rather than growing by one: a scan on a busy band is a hundred
 * rows, and a realloc per row is a hundred copies of a list that is being
 * built in a daemon's apply path.
 */
static int room_for_one(void **items, size_t count, size_t *capacity, size_t size)
{
	size_t wanted;
	void  *bigger;

	if (count < *capacity) {
		return 1;
	}
	wanted = *capacity ? *capacity * 2u : 8u;
	/* The list is bounded by a datagram, so this cannot be large -- but an
	 * overflow check costs nothing and its absence is a rewrite away from
	 * mattering. */
	if (wanted > (size_t)-1 / size) {
		return 0;
	}
	bigger = realloc(*items, wanted * size);
	if (!bigger) {
		return 0;
	}
	*items = bigger;
	*capacity = wanted;
	return 1;
}

/* A whole field as a number, or 0 where any of it is not one. */
static int exact_number(const char *text, size_t length, int64_t *out)
{
	int64_t value = 0;
	int     negative = 0;
	size_t  index = 0;

	if (length == 0u) {
		return 0;
	}
	if (text[0] == '-') {
		negative = 1;
		index = 1u;
	} else if (text[0] == '+') {
		index = 1u;
	}
	if (index >= length) {
		return 0;
	}
	for (; index < length; index++) {
		if (!is_digit(text[index])) {
			return 0;
		}
		/* A frequency or a signal level that does not fit is a row this
		 * cannot make sense of, which is the same answer as a row whose
		 * field is not a number at all. */
		if (value > (INT64_MAX - (text[index] - '0')) / 10) {
			return 0;
		}
		value = value * 10 + (text[index] - '0');
	}
	*out = negative ? -value : value;
	return 1;
}

/* ------------------------------------------------------------------ replies */

int ncfg_supplicant_reply_parse(char *raw)
{
	size_t length;

	if (!raw) {
		return NCFG_SUPPLICANT_REPLY_FAIL;
	}
	length = strlen(raw);
	while (length > 0u && raw[length - 1u] == '\n') {
		raw[--length] = '\0';
	}
	if (strcmp(raw, "OK") == 0) {
		return NCFG_SUPPLICANT_REPLY_OK;
	}
	/* `UNKNOWN COMMAND` is the supplicant's answer to a command a build
	 * without that feature does not have. It is a refusal, not a body: a
	 * caller reading it as data would carry the sentence around as though it
	 * were the value it asked for. */
	if (strcmp(raw, "FAIL") == 0 || strcmp(raw, "UNKNOWN COMMAND") == 0) {
		return NCFG_SUPPLICANT_REPLY_FAIL;
	}
	return NCFG_SUPPLICANT_REPLY_DATA;
}

/* ------------------------------------------------------------------- events */

int ncfg_supplicant_is_event(const char *line)
{
	const char *close;

	if (!line || line[0] != '<') {
		return 0;
	}
	close = strchr(line, '>');
	/* A priority is one or two digits, so the closing bracket is at index 2
	 * or 3. Anything further along is a line that merely opens with a
	 * bracket, which a network name may. */
	return close != NULL && (size_t)(close - line) <= 3u;
}

int ncfg_supplicant_event_parse(const char *line, ncfg_supplicant_event_t *out)
{
	const char *close;
	const char *text;
	long        priority = 0;
	size_t      index;
	size_t      digits;
	size_t      length;

	if (!line || !out || line[0] != '<') {
		return 0;
	}
	close = strchr(line, '>');
	if (!close) {
		return 0;
	}
	digits = (size_t)(close - line) - 1u;
	if (digits == 0u) {
		return 0;
	}
	for (index = 0; index < digits; index++) {
		if (!is_digit(line[1u + index])) {
			return 0;
		}
		priority = priority * 10 + (line[1u + index] - '0');
		if (priority > 255) {
			/* The Rust parses this as a `u8` and a value past it is not a
			 * priority; anything else is a line that is not an event. */
			return 0;
		}
	}
	text = close + 1;
	length = strlen(text);
	while (length > 0u && is_space(text[length - 1u])) {
		length--;
	}
	/* **Refused rather than truncated.** A cut event is an event with a field
	 * missing, and the fields are what every caller reads it for; answering
	 * "not an event" is the one wrong answer that cannot be acted on. The
	 * socket already refuses a datagram that filled its buffer, so nothing
	 * reaching here from a supplicant is this long. */
	if (length >= sizeof(out->text)) {
		return 0;
	}
	out->priority = (int)priority;
	if (length) {
		memcpy(out->text, text, length);
	}
	out->text[length] = '\0';
	return 1;
}

/* The `index`-th whitespace-separated word, or NULL. */
static const char *word_at(const char *text, size_t index, size_t *length_out)
{
	size_t at = 0;
	size_t seen = 0;

	for (;;) {
		while (text[at] != '\0' && is_space(text[at])) {
			at++;
		}
		if (text[at] == '\0') {
			return NULL;
		}
		{
			size_t start = at;

			while (text[at] != '\0' && !is_space(text[at])) {
				at++;
			}
			if (seen == index) {
				*length_out = at - start;
				return text + start;
			}
			seen++;
		}
	}
}

const char *ncfg_supplicant_event_name(const ncfg_supplicant_event_t *event, char *out,
    size_t out_size)
{
	const char *word;
	size_t      length = 0;

	if (!out || out_size == 0u) {
		return "";
	}
	out[0] = '\0';
	if (!event) {
		return out;
	}
	word = word_at(event->text, 0u, &length);
	if (!word || length >= out_size) {
		return out;
	}
	memcpy(out, word, length);
	out[length] = '\0';
	return out;
}

int ncfg_supplicant_event_is(const ncfg_supplicant_event_t *event, const char *name)
{
	char found[64];

	return strcmp(ncfg_supplicant_event_name(event, found, sizeof(found)), name) == 0;
}

/* Six colon-separated hex octets, which is the whole assumption the positional
 * read below rests on. */
static int looks_like_bssid(const char *text, size_t length)
{
	size_t index;

	if (length != 17u) {
		return 0;
	}
	for (index = 0; index < 17u; index++) {
		unsigned char ignored;

		if (index % 3u == 2u) {
			if (text[index] != ':') {
				return 0;
			}
		} else if (!hex_value((unsigned char)text[index], &ignored)) {
			return 0;
		}
	}
	return 1;
}

int ncfg_supplicant_event_connected_bssid(const ncfg_supplicant_event_t *event, char *out,
    size_t out_size)
{
	const char *word;
	size_t      length = 0;

	if (!event || !out || out_size == 0u) {
		return 0;
	}
	out[0] = '\0';
	if (!ncfg_supplicant_event_is(event, "CTRL-EVENT-CONNECTED")) {
		return 0;
	}
	word = word_at(event->text, 4u, &length);
	if (!word || !looks_like_bssid(word, length) || length >= out_size) {
		return 0;
	}
	memcpy(out, word, length);
	out[length] = '\0';
	return 1;
}

int ncfg_supplicant_event_network_id(const ncfg_supplicant_event_t *event, uint32_t *out)
{
	static const char prefix[] = "[id=";
	const char       *word;
	size_t            length = 0;
	size_t            index;
	uint64_t          value = 0;

	if (!event || !out) {
		return 0;
	}
	if (!ncfg_supplicant_event_is(event, "CTRL-EVENT-CONNECTED")) {
		return 0;
	}
	word = word_at(event->text, 6u, &length);
	if (!word || length <= sizeof(prefix) - 1u ||
	    strncmp(word, prefix, sizeof(prefix) - 1u) != 0) {
		return 0;
	}
	word += sizeof(prefix) - 1u;
	length -= sizeof(prefix) - 1u;
	for (index = 0; index < length; index++) {
		if (!is_digit(word[index])) {
			/* `-1` is what the supplicant writes when the association has no
			 * configured network behind it. Not a number this returns, and
			 * not a separate case either: it is simply not unsigned. */
			return 0;
		}
		value = value * 10u + (uint64_t)(word[index] - '0');
		if (value > UINT32_MAX) {
			return 0;
		}
	}
	*out = (uint32_t)value;
	return 1;
}

int ncfg_supplicant_event_field(const ncfg_supplicant_event_t *event, const char *key, char *out,
    size_t out_size)
{
	size_t      key_length;
	const char *text;
	size_t      at;

	if (!event || !key || !out || out_size == 0u) {
		return 0;
	}
	out[0] = '\0';
	key_length = strlen(key);
	if (key_length == 0u) {
		return 0;
	}
	text = event->text;
	for (at = 0; text[at] != '\0'; at++) {
		const char *value;
		size_t      length;

		if (strncmp(text + at, key, key_length) != 0) {
			continue;
		}
		/* **At a field boundary, or it is somebody else's key.** `id` is a
		 * suffix of `bssid`, and a reader without this answers a question
		 * about the network id with the tail of an access point's address. */
		if (at != 0u && text[at - 1u] != ' ') {
			continue;
		}
		value = text + at + key_length;
		if (*value != '=') {
			/* The key appeared with nothing assigned to it -- a positional
			 * address, a word of prose. Keep looking rather than answering
			 * with what follows. */
			continue;
		}
		value++;
		if (*value == '"') {
			const char *close;

			value++;
			close = strchr(value, '"');
			length = close ? (size_t)(close - value) : strlen(value);
		} else {
			const char *space = strchr(value, ' ');

			length = space ? (size_t)(space - value) : strlen(value);
		}
		if (length >= out_size) {
			return 0;
		}
		if (length) {
			memcpy(out, value, length);
		}
		out[length] = '\0';
		return 1;
	}
	return 0;
}

/* ------------------------------------------------------------- the escaping */

size_t ncfg_supplicant_printf_decode(const char *text, unsigned char *out, size_t out_size)
{
	const unsigned char *source;
	size_t               length;
	size_t               index = 0;
	size_t               written = 0;

	if (!text) {
		return 0;
	}
	source = (const unsigned char *)text;
	length = strlen(text);
	while (index < length) {
		unsigned char one;

		if (source[index] != '\\') {
			one = source[index];
			index++;
		} else if (index + 1u >= length) {
			/* A trailing backslash is not an escape. Keeping it is what the
			 * supplicant's own decoder does. */
			one = '\\';
			index++;
		} else {
			unsigned char escape = source[index + 1u];

			if (escape == 'x') {
				unsigned char high;
				unsigned char low;

				/* Two hex digits, or it was never an escape. The index only
				 * advances past what was actually consumed, so a malformed
				 * one loses nothing -- `\xzz` is four characters of a name,
				 * not a decode failure. */
				if (index + 3u < length &&
				    hex_value(source[index + 2u], &high) &&
				    hex_value(source[index + 3u], &low)) {
					one = (unsigned char)((high << 4) | low);
					index += 4u;
				} else {
					if (written < out_size) {
						out[written] = '\\';
					}
					written++;
					one = 'x';
					index += 2u;
				}
			} else {
				switch (escape) {
				case 'n':
					one = '\n';
					break;
				case 'r':
					one = '\r';
					break;
				case 't':
					one = '\t';
					break;
				case 'e':
					one = 0x1b;
					break;
				default:
					/* `\\`, `\"`, and anything else: the character itself.
					 * Matching the supplicant's decoder, which passes unknown
					 * escapes through. */
					one = escape;
					break;
				}
				index += 2u;
			}
		}
		if (written < out_size) {
			out[written] = one;
		}
		written++;
	}
	return written;
}

/* A field as an SSID, or 0 where it is longer than one can be. */
static int field_as_ssid(const char *field, size_t length, ncfg_ssid_t *out)
{
	char   *held = own(field, length);
	size_t  decoded;

	if (!held) {
		return 0;
	}
	decoded = ncfg_supplicant_printf_decode(held, out->bytes, sizeof(out->bytes));
	free(held);
	if (decoded > sizeof(out->bytes)) {
		/* An SSID is 0 to 32 octets and this is not one, so the row it came
		 * from is a row netcfgd cannot make sense of. */
		return 0;
	}
	out->has = 1;
	out->length = decoded;
	return 1;
}

/* --------------------------------------------------------------- scan rows */

void ncfg_supplicant_scans_free(ncfg_supplicant_scan_t *scans, size_t count)
{
	size_t index;

	if (!scans) {
		return;
	}
	for (index = 0; index < count; index++) {
		free(scans[index].bssid);
		free(scans[index].flags);
	}
	free(scans);
}

/*
 * Parse one `SCAN_RESULTS` row, or 0 where it is not one.
 *
 * The SSID is the last field and is escaped, so a tab inside a name arrives as
 * `\t` and cannot be confused with a separator. Taking the remainder anyway
 * costs nothing and means a future column added to the end does not silently
 * truncate names.
 */
static int scan_row(const char *line, size_t length, ncfg_supplicant_scan_t *out)
{
	const char *field[4];
	size_t      field_length[4];
	size_t      at = 0;
	size_t      taken;

	memset(out, 0, sizeof(*out));
	for (taken = 0; taken < 4u; taken++) {
		size_t start = at;

		while (at < length && line[at] != '\t') {
			at++;
		}
		field[taken] = line + start;
		field_length[taken] = at - start;
		if (at < length) {
			at++;
		} else if (taken < 3u) {
			/* Fewer than the four columns every row has. */
			return 0;
		}
	}
	if (!exact_number(field[1], field_length[1], &out->frequency) ||
	    !exact_number(field[2], field_length[2], &out->signal)) {
		return 0;
	}
	/* Whatever is left after the fourth tab, which is empty for a hidden
	 * access point -- that is what hiding is, and the row really does arrive
	 * with no name in it. */
	if (!field_as_ssid(line + at, length - at, &out->ssid)) {
		return 0;
	}
	out->bssid = own(field[0], field_length[0]);
	out->flags = own(field[3], field_length[3]);
	if (!out->bssid || !out->flags) {
		free(out->bssid);
		free(out->flags);
		out->bssid = NULL;
		out->flags = NULL;
		return 0;
	}
	return 1;
}

int ncfg_supplicant_parse_scan_results(const char *body, ncfg_supplicant_scan_t **out,
    size_t *count_out, char *err, size_t err_size)
{
	const char             *cursor = body;
	const char             *line;
	size_t                  length;
	ncfg_supplicant_scan_t *rows = NULL;
	size_t                  count = 0;
	size_t                  capacity = 0;

	if (!out || !count_out) {
		ncfg_error_set(err, err_size, "a scan needs somewhere to be put");
		return 0;
	}
	*out = NULL;
	*count_out = 0;
	if (!body) {
		return 1;
	}
	/* The first line is a header and is skipped. */
	(void)next_line(&cursor, &length);
	while ((line = next_line(&cursor, &length)) != NULL) {
		ncfg_supplicant_scan_t one;

		/* **A row netcfgd cannot make sense of is skipped rather than failing
		 * the whole scan**: one malformed entry from a misbehaving access
		 * point should not make a laptop unable to list networks. */
		if (!scan_row(line, length, &one)) {
			continue;
		}
		if (!room_for_one((void **)&rows, count, &capacity,
		    sizeof(ncfg_supplicant_scan_t))) {
			free(one.bssid);
			free(one.flags);
			ncfg_supplicant_scans_free(rows, count);
			ncfg_error_set(err, err_size, "no memory for a scan of %zu rows", count + 1u);
			return 0;
		}
		rows[count++] = one;
	}
	*out = rows;
	*count_out = count;
	return 1;
}

static int flags_contain(const ncfg_supplicant_scan_t *scan, const char *what)
{
	return scan && scan->flags && strstr(scan->flags, what) != NULL;
}

int ncfg_supplicant_scan_is_secured(const ncfg_supplicant_scan_t *scan)
{
	return flags_contain(scan, "WPA") || flags_contain(scan, "WEP") ||
	    flags_contain(scan, "SAE");
}

int ncfg_supplicant_scan_is_enterprise(const ncfg_supplicant_scan_t *scan)
{
	return flags_contain(scan, "EAP");
}

int ncfg_supplicant_scan_is_owe(const ncfg_supplicant_scan_t *scan)
{
	/* **The flags field and not the row.** There is an access point called
	 * `OWNIT_24GHz_8A41A0` in range of the machine this was written on, and a
	 * check that searched the whole row would call it OWE. */
	return flags_contain(scan, "OWE");
}

int ncfg_supplicant_scan_does_fast_transition(const ncfg_supplicant_scan_t *scan)
{
	return flags_contain(scan, "FT/");
}

int ncfg_supplicant_parse_mobility_domain(const char *body, char *out, size_t out_size)
{
	static const char prefix[] = "mdid=";
	const char       *cursor = body;
	const char       *line;
	size_t            length;

	if (!out || out_size == 0u) {
		return 0;
	}
	out[0] = '\0';
	if (!body) {
		return 0;
	}
	while ((line = next_line(&cursor, &length)) != NULL) {
		const char *value;

		if (length < sizeof(prefix) - 1u || strncmp(line, prefix, sizeof(prefix) - 1u) != 0) {
			continue;
		}
		value = line + sizeof(prefix) - 1u;
		length -= sizeof(prefix) - 1u;
		while (length > 0u && is_space(*value)) {
			value++;
			length--;
		}
		while (length > 0u && is_space(value[length - 1u])) {
			length--;
		}
		/* **Absent rather than empty.** An empty id is something a caller
		 * would print, and this is the ordinary case for a BSS that does no
		 * fast transition at all. */
		if (length == 0u || length >= out_size) {
			return 0;
		}
		memcpy(out, value, length);
		out[length] = '\0';
		return 1;
	}
	return 0;
}

/* ------------------------------------------------------------ network lists */

void ncfg_supplicant_entries_free(ncfg_supplicant_entry_t *entries, size_t count)
{
	size_t index;

	if (!entries) {
		return;
	}
	for (index = 0; index < count; index++) {
		free(entries[index].flags);
	}
	free(entries);
}

static int network_row(const char *line, size_t length, ncfg_supplicant_entry_t *out)
{
	const char *field[4];
	size_t      field_length[4];
	size_t      at = 0;
	size_t      taken = 0;
	int64_t     id = 0;

	memset(out, 0, sizeof(*out));
	while (taken < 4u) {
		size_t start = at;

		while (at < length && line[at] != '\t') {
			at++;
		}
		field[taken] = line + start;
		field_length[taken] = at - start;
		taken++;
		if (at >= length) {
			break;
		}
		at++;
	}
	/* id, ssid and bssid are required; **the flags column is not.** An entry
	 * with no flags is normal -- a network that is neither current nor
	 * disabled has nothing there -- and dropping it would hide exactly the
	 * networks that are working. */
	if (taken < 3u) {
		return 0;
	}
	if (!exact_number(field[0], field_length[0], &id) || id < 0 || id > (int64_t)UINT32_MAX) {
		return 0;
	}
	if (!field_as_ssid(field[1], field_length[1], &out->ssid)) {
		return 0;
	}
	out->id = (uint32_t)id;
	out->flags = taken >= 4u ? own(field[3], field_length[3]) : own("", 0u);
	return out->flags != NULL;
}

int ncfg_supplicant_parse_network_list(const char *body, ncfg_supplicant_entry_t **out,
    size_t *count_out, char *err, size_t err_size)
{
	const char              *cursor = body;
	const char              *line;
	size_t                   length;
	ncfg_supplicant_entry_t *rows = NULL;
	size_t                   count = 0;
	size_t                   capacity = 0;

	if (!out || !count_out) {
		ncfg_error_set(err, err_size, "a network list needs somewhere to be put");
		return 0;
	}
	*out = NULL;
	*count_out = 0;
	if (!body) {
		return 1;
	}
	(void)next_line(&cursor, &length);
	while ((line = next_line(&cursor, &length)) != NULL) {
		ncfg_supplicant_entry_t one;

		if (!network_row(line, length, &one)) {
			continue;
		}
		if (!room_for_one((void **)&rows, count, &capacity,
		    sizeof(ncfg_supplicant_entry_t))) {
			free(one.flags);
			ncfg_supplicant_entries_free(rows, count);
			ncfg_error_set(err, err_size, "no memory for a list of %zu networks",
			    count + 1u);
			return 0;
		}
		rows[count++] = one;
	}
	*out = rows;
	*count_out = count;
	return 1;
}

int ncfg_supplicant_entry_is_current(const ncfg_supplicant_entry_t *entry)
{
	return entry && entry->flags && strstr(entry->flags, "CURRENT") != NULL;
}

/* ------------------------------------------------------------------- status */

void ncfg_supplicant_status_free(ncfg_supplicant_status_pair_t *pairs, size_t count)
{
	size_t index;

	if (!pairs) {
		return;
	}
	for (index = 0; index < count; index++) {
		free(pairs[index].key);
		free(pairs[index].value);
	}
	free(pairs);
}

int ncfg_supplicant_parse_status(const char *body, ncfg_supplicant_status_pair_t **out,
    size_t *count_out, char *err, size_t err_size)
{
	const char                    *cursor = body;
	const char                    *line;
	size_t                         length;
	ncfg_supplicant_status_pair_t *pairs = NULL;
	size_t                         count = 0;
	size_t                         capacity = 0;

	if (!out || !count_out) {
		ncfg_error_set(err, err_size, "a status needs somewhere to be put");
		return 0;
	}
	*out = NULL;
	*count_out = 0;
	if (!body) {
		return 1;
	}
	while ((line = next_line(&cursor, &length)) != NULL) {
		const char                   *split = memchr(line, '=', length);
		ncfg_supplicant_status_pair_t one;

		/* A line with no `=` is not a field. `STATUS` has carried banner
		 * lines in some builds, and reading one as a key with no value would
		 * put it in front of whoever asked for the state. */
		if (!split) {
			continue;
		}
		one.key = own(line, (size_t)(split - line));
		one.value = own(split + 1, length - (size_t)(split - line) - 1u);
		if (!one.key || !one.value ||
		    !room_for_one((void **)&pairs, count, &capacity,
		    sizeof(ncfg_supplicant_status_pair_t))) {
			free(one.key);
			free(one.value);
			ncfg_supplicant_status_free(pairs, count);
			ncfg_error_set(err, err_size, "no memory for a status of %zu fields",
			    count + 1u);
			return 0;
		}
		pairs[count++] = one;
	}
	*out = pairs;
	*count_out = count;
	return 1;
}

const char *ncfg_supplicant_status_field(const ncfg_supplicant_status_pair_t *pairs, size_t count,
    const char *key)
{
	size_t index;

	if (!pairs || !key) {
		return NULL;
	}
	for (index = 0; index < count; index++) {
		if (strcmp(pairs[index].key, key) == 0) {
			return pairs[index].value;
		}
	}
	return NULL;
}

/* -------------------------------------------------------------- arguments */

int ncfg_supplicant_ssid_argument(const ncfg_ssid_t *ssid, char *out, size_t out_size)
{
	static const char digits[] = "0123456789abcdef";
	size_t            index;

	if (!out || out_size == 0u) {
		return 0;
	}
	out[0] = '\0';
	if (!ssid || !ssid->has || ssid->length > NCFG_SSID_MAX_LEN) {
		return 0;
	}
	if (ssid->length * 2u + 1u > out_size) {
		return 0;
	}
	for (index = 0; index < ssid->length; index++) {
		out[index * 2u] = digits[ssid->bytes[index] >> 4];
		out[index * 2u + 1u] = digits[ssid->bytes[index] & 0x0fu];
	}
	out[ssid->length * 2u] = '\0';
	return 1;
}

void ncfg_supplicant_quote(ncfg_buf_t *out, const char *value)
{
	size_t index;

	if (!out) {
		return;
	}
	ncfg_buf_add_char(out, '"');
	for (index = 0; value && value[index] != '\0'; index++) {
		/* A quote and a backslash are the two characters `wpa_supplicant`'s
		 * parser reads as syntax inside a quoted value, so they are the two
		 * that must not pass through unaltered -- and a trailing backslash
		 * escaping the closing quote is the shape that turns one value into
		 * two. */
		if (value[index] == '"' || value[index] == '\\') {
			ncfg_buf_add_char(out, '\\');
		}
		ncfg_buf_add_char(out, value[index]);
	}
	ncfg_buf_add_char(out, '"');
}

int ncfg_supplicant_passphrase_is_sendable(const char *passphrase)
{
	size_t index;

	if (!passphrase) {
		return 0;
	}
	for (index = 0; passphrase[index] != '\0'; index++) {
		if (passphrase[index] == '\n' || passphrase[index] == '\r') {
			return 0;
		}
	}
	/* A NUL cannot be reached through a C string, which is the one shape the
	 * Rust also refuses -- so a passphrase carrying one is already shorter
	 * here than it was in the store, and the length check downstream is what
	 * notices. */
	return 1;
}
