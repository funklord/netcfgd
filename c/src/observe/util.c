/*
 * util.c -- the string and list handling the observer's three sources share.
 *
 * Nothing here decides anything. It exists so that `build.c`, `host.c` and
 * `derive.c` do not each grow their own copy of "append a copy of this name",
 * which is how two of them come to disagree about whether a list is sorted.
 */
#include "observe_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *observe_dup(const char *text)
{
	size_t length;
	char  *copy;

	if (!text) {
		text = "";
	}
	length = strlen(text) + 1u;
	copy = malloc(length);
	if (!copy) {
		return NULL;
	}
	memcpy(copy, text, length);
	return copy;
}

int observe_list_add(char ***list, size_t *count, const char *text)
{
	char **grown = realloc(*list, (*count + 1u) * sizeof(*grown));
	char  *copy;

	if (!grown) {
		return 0;
	}
	*list = grown;
	copy = observe_dup(text);
	if (!copy) {
		/* The array has already grown and the count has not, which is
		 * the order that keeps the caller's free correct: an entry that
		 * was never written is never read. */
		return 0;
	}
	(*list)[*count] = copy;
	(*count)++;
	return 1;
}

int observe_list_copy(char ***out, size_t *out_count, char *const *in, size_t count)
{
	size_t at;

	for (at = 0; at < count; at++) {
		if (!observe_list_add(out, out_count, in[at])) {
			return 0;
		}
	}
	return 1;
}

int observe_list_has(char *const *list, size_t count, const char *text)
{
	size_t at;

	for (at = 0; at < count; at++) {
		if (list[at] && text && strcmp(list[at], text) == 0) {
			return 1;
		}
	}
	return 0;
}

static int compare_names(const void *left, const void *right)
{
	const char *const *one = (const char *const *)left;
	const char *const *two = (const char *const *)right;

	return strcmp(*one, *two);
}

void observe_list_sort(char **list, size_t count)
{
	if (list && count > 1u) {
		qsort(list, count, sizeof(*list), compare_names);
	}
}

void observe_names_free(char **names, size_t count)
{
	size_t at;

	for (at = 0; at < count; at++) {
		free(names[at]);
	}
	free(names);
}

int observe_widen(uint64_t value, const char *what, int64_t *out, char *err, size_t err_size)
{
	if (value > (uint64_t)INT64_MAX) {
		ncfg_error_set(err, err_size,
		    "%s is %llu, which is larger than this model can hold", what,
		    (unsigned long long)value);
		return 0;
	}
	*out = (int64_t)value;
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Reading back what netcfgd generated
 * ------------------------------------------------------------------------ */

/*
 * How much of a generated file is read.
 *
 * Generous for what netcfgd writes and a ceiling rather than a growing read,
 * because these run once per running daemon on every observation. Past it the
 * file is treated as unreadable, which leaves the answer absent -- the same as
 * a file that is not there, and for the same reason.
 */
#define GENERATED_FILE_MAX 65536

char *observe_read_generated(const char *path)
{
	FILE  *file = path ? fopen(path, "rb") : NULL;
	char  *body;
	size_t got;

	if (!file) {
		return NULL;
	}
	body = malloc((size_t)GENERATED_FILE_MAX + 1u);
	if (!body) {
		(void)fclose(file);
		return NULL;
	}
	got = fread(body, 1u, (size_t)GENERATED_FILE_MAX, file);
	if (!feof(file) || ferror(file)) {
		(void)fclose(file);
		free(body);
		return NULL;
	}
	(void)fclose(file);
	body[got] = '\0';
	return body;
}

int observe_config_value(const char *text, const char *key, char *out, size_t out_size)
{
	const char *line = text;
	size_t      key_length = key ? strlen(key) : 0u;

	if (!text || !key || !out || out_size == 0u) {
		return 0;
	}
	while (line && *line) {
		const char *end = strchr(line, '\n');
		const char *stop = end ? end : line + strlen(line);
		const char *at = line;

		while (at < stop && (*at == ' ' || *at == '\t')) {
			at++;
		}
		if ((size_t)(stop - at) > key_length && strncmp(at, key, key_length) == 0 &&
		    at[key_length] == '=') {
			size_t length = (size_t)(stop - at) - key_length - 1u;

			if (length + 1u > out_size) {
				return 0;
			}
			memcpy(out, at + key_length + 1u, length);
			out[length] = '\0';
			return 1;
		}
		line = end ? end + 1 : NULL;
	}
	return 0;
}
