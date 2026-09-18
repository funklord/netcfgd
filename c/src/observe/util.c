/*
 * util.c -- the string and list handling the observer's three sources share.
 *
 * Nothing here decides anything. It exists so that `build.c`, `host.c` and
 * `derive.c` do not each grow their own copy of "append a copy of this name",
 * which is how two of them come to disagree about whether a list is sorted.
 */
#include "observe_internal.h"

#include <stdint.h>
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
