/*
 * control.c -- `ncfg control`: who may ask netcfgd for what.
 *
 * THE BOOTSTRAP 0118 DESCRIBES
 *   Every tier defaults to root, so a default install refuses its own GUI --
 *   and the fix cannot go over the socket, because that would be asking the
 *   daemon for permission to ask the daemon. It goes through this, run once by
 *   somebody who is already root.
 *
 * TYPED, LIKE `wifi add` AND FOR THE SAME REASON
 *   The subcommand takes three principals and renders the block itself; it
 *   never accepts config text. A config file may name a hook and a hook's
 *   `run_as` is absent by default, which means root -- so a privileged command
 *   that wrote text a caller supplied would be a way to run anything as root.
 *   There is no field here that could name a hook or a path.
 *
 * ONE FILE, REWRITTEN WHOLE
 *   The policy deciding who may configure the network should be one visible
 *   file an operator can read, diff and delete -- deleting it restores the
 *   root-only default rather than breaking the machine. `00-` so it sorts
 *   first: later files win for scalar keys, so a policy an operator wrote by
 *   hand in their own file overrides this one rather than being silently
 *   overridden by it.
 *
 * WHY THE PRINCIPAL IS PARSED HERE
 *   The Rust has `Principal::parse` and `Principal::render` on the model type
 *   and both halves call them. `document.h` is final and carries neither, and
 *   the two implementations that exist -- the lowerer's and the renderer's --
 *   are `static` inside modules whose context this has none of. So the rule is
 *   spelled once here, in `cli.h`, and the test asserts the round trip against
 *   what `src/compile/render.c` writes into a configuration file: a third
 *   spelling of `group:NAME` is exactly the drift 0263 refuses.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   Both entries are in 0263's list. In short: the scanner that finds a block
 *   skips strings and comments, because the Rust's does not and a `#` comment
 *   containing `control {` inside the `global` block made this command refuse
 *   itself; and the file to splice into is looked for in the writable layer
 *   only, because the Rust searches the layered set and so edits the factory
 *   image where that is what defines `global`.
 */
#include "subcommand_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The longest command the helper will read. A verb and three principals. */
#define NCFG_CLI_CONTROL_COMMAND_MAX 4096

/* ------------------------------------------------------------------------ *
 * Principals
 * ------------------------------------------------------------------------ */

int ncfg_cli_principal_parse(const char *text, ncfg_principal_t *out, char *err, size_t err_size)
{
	const char *name;
	char       *copy;

	if (!text || !out) {
		ncfg_error_set(err, err_size, "a principal was not given");
		return 0;
	}
	if (strcmp(text, "root") == 0) {
		out->kind = NCFG_PRINCIPAL_ROOT;
		out->name = NULL;
		return 1;
	}
	if (strcmp(text, "any") == 0) {
		out->kind = NCFG_PRINCIPAL_ANY;
		out->name = NULL;
		return 1;
	}
	if (strncmp(text, "user:", 5u) == 0) {
		name = text + 5;
		if (name[0] == '\0') {
			ncfg_error_set(err, err_size, "user: needs a name after it");
			return 0;
		}
		out->kind = NCFG_PRINCIPAL_USER;
	} else if (strncmp(text, "group:", 6u) == 0) {
		name = text + 6;
		if (name[0] == '\0') {
			ncfg_error_set(err, err_size, "group: needs a name after it");
			return 0;
		}
		out->kind = NCFG_PRINCIPAL_GROUP;
	} else {
		ncfg_error_set(err, err_size, "`%s` is not root, any, user:NAME or group:NAME",
		    text);
		return 0;
	}
	copy = malloc(strlen(name) + 1u);
	if (!copy) {
		ncfg_error_set(err, err_size, "out of memory reading a principal");
		return 0;
	}
	memcpy(copy, name, strlen(name) + 1u);
	out->name = copy;
	return 1;
}

const char *ncfg_cli_principal_render(const ncfg_principal_t *principal, char *out,
    size_t out_size)
{
	if (!out || out_size == 0) {
		return "";
	}
	if (!principal) {
		(void)snprintf(out, out_size, "root");
		return out;
	}
	switch (principal->kind) {
	case NCFG_PRINCIPAL_ANY:
		(void)snprintf(out, out_size, "any");
		break;
	case NCFG_PRINCIPAL_USER:
		(void)snprintf(out, out_size, "user:%s", principal->name ? principal->name : "");
		break;
	case NCFG_PRINCIPAL_GROUP:
		(void)snprintf(out, out_size, "group:%s", principal->name ? principal->name : "");
		break;
	case NCFG_PRINCIPAL_ROOT:
	default:
		(void)snprintf(out, out_size, "root");
		break;
	}
	return out;
}

/* Back to the default, which is root and no name. */
static void principal_reset(ncfg_principal_t *principal)
{
	free(principal->name);
	principal->name = NULL;
	principal->kind = NCFG_PRINCIPAL_ROOT;
}

static int principal_same(const ncfg_principal_t *one, const ncfg_principal_t *other)
{
	if (one->kind != other->kind) {
		return 0;
	}
	if (!one->name || !other->name) {
		return one->name == other->name;
	}
	return strcmp(one->name, other->name) == 0;
}

static int principal_copy(const ncfg_principal_t *from, ncfg_principal_t *to)
{
	to->kind = from->kind;
	to->name = NULL;
	if (from->name) {
		size_t length = strlen(from->name) + 1u;

		to->name = malloc(length);
		if (!to->name) {
			return 0;
		}
		memcpy(to->name, from->name, length);
	}
	return 1;
}

static void control_reset(ncfg_control_t *control)
{
	principal_reset(&control->observe);
	principal_reset(&control->wifi);
	principal_reset(&control->admin);
}

static int control_copy(const ncfg_control_t *from, ncfg_control_t *to)
{
	memset(to, 0, sizeof(*to));
	return principal_copy(&from->observe, &to->observe) &&
	    principal_copy(&from->wifi, &to->wifi) && principal_copy(&from->admin, &to->admin);
}

static int control_same(const ncfg_control_t *one, const ncfg_control_t *other)
{
	return principal_same(&one->observe, &other->observe) &&
	    principal_same(&one->wifi, &other->wifi) && principal_same(&one->admin, &other->admin);
}

/*
 * Whether reaching any tier requires opening a socket root-only permissions
 * would close.
 *
 * The socket's mode follows this: a policy naming a group is a lie if the
 * socket stays root-only, because the caller cannot connect to be told yes.
 */
static int control_opens_beyond_root(const ncfg_control_t *control)
{
	return control->observe.kind != NCFG_PRINCIPAL_ROOT ||
	    control->wifi.kind != NCFG_PRINCIPAL_ROOT ||
	    control->admin.kind != NCFG_PRINCIPAL_ROOT;
}

/* The three tiers, in the order they are written and printed. */
static const ncfg_principal_t *tier_of(const ncfg_control_t *control, size_t which)
{
	if (which == 0) {
		return &control->observe;
	}
	if (which == 1) {
		return &control->wifi;
	}
	return &control->admin;
}

static const char *const tier_names[] = { "observe", "wifi", "admin" };

/* ------------------------------------------------------------------------ *
 * Rendering
 * ------------------------------------------------------------------------ */

/* Just the `control { ... }` part, for pasting into a block that exists. */
static void render_inner(const ncfg_control_t *control, const char *indent, ncfg_buf_t *out)
{
	size_t which;

	ncfg_buf_addf(out, "%scontrol {\n", indent);
	for (which = 0; which < 3u; which++) {
		char rendered[NCFG_CLI_TEXT_MAX];

		ncfg_buf_addf(out, "%s%s%s = \"%s\"\n", indent, indent, tier_names[which],
		    ncfg_cli_principal_render(tier_of(control, which), rendered,
		    sizeof(rendered)));
	}
	ncfg_buf_addf(out, "%s}\n", indent);
}

void ncfg_cli_control_render(const ncfg_control_t *control, ncfg_buf_t *out)
{
	ncfg_buf_add_text(out,
	    "# Who may ask netcfgd for what. Written by `ncfg control set`.\n"
	    "#\n"
	    "# Ordinary netcfgd configuration: read it, diff it, commit it, or\n"
	    "# delete it. Deleting it restores the default, which is root only.\n"
	    "#\n"
	    "# observe -- ask what the network looks like\n"
	    "# wifi    -- join, leave and scan networks the configuration describes\n"
	    "# admin   -- change anything else, including adding a network\n");
	ncfg_buf_add_text(out, "\nglobal {\n");
	render_inner(control, "\t", out);
	ncfg_buf_add_text(out, "}\n");
}

/* ------------------------------------------------------------------------ *
 * Finding a block in text somebody else wrote
 * ------------------------------------------------------------------------ */

static int is_space(char one)
{
	return one == ' ' || one == '\t' || one == '\n' || one == '\r' || one == '\f' ||
	    one == '\v';
}

/*
 * The end of the block whose opening brace is at `open`.
 *
 * Strings and comments are skipped, because a brace inside either is not a
 * brace: an SSID may be written `"{}"` and a comment may say anything. Hook
 * bodies are the config language's one irregular production and cannot occur
 * here -- they are per-interface, and this only ever walks `global`.
 *
 * `(size_t)-1` where the block does not end.
 */
static size_t matching_brace(const char *text, size_t open, size_t length)
{
	size_t depth = 0;
	size_t at = open;
	int    in_string = 0;
	int    in_comment = 0;

	while (at < length) {
		char byte = text[at];

		if (in_comment) {
			if (byte == '\n') {
				in_comment = 0;
			}
		} else if (in_string) {
			if (byte == '\\') {
				at++;
			} else if (byte == '"') {
				in_string = 0;
			}
		} else if (byte == '"') {
			in_string = 1;
		} else if (byte == '#') {
			in_comment = 1;
		} else if (byte == '{') {
			depth++;
		} else if (byte == '}') {
			if (depth == 0) {
				return (size_t)-1;
			}
			depth--;
			if (depth == 0) {
				return at;
			}
		}
		at++;
	}
	return (size_t)-1;
}

/* A word, not a substring: `controller = ...` is not `control`. */
static int word_starts_at(const char *text, size_t at)
{
	unsigned char before;

	if (at == 0) {
		return 1;
	}
	before = (unsigned char)text[at - 1u];
	if (before == '_') {
		return 0;
	}
	return !((before >= '0' && before <= '9') || (before >= 'A' && before <= 'Z') ||
	    (before >= 'a' && before <= 'z'));
}

/*
 * Where a block with this head begins and ends, searching only `[from, to)`.
 *
 * The span runs from the start of the head word to just past its closing
 * brace, so a caller can replace the whole thing.
 *
 * **It lexes rather than searches**, which is the divergence: the Rust looks
 * for the head with `str::find` and checks only the character before it, so a
 * comment or a string inside the block that happens to contain `control {` or
 * `global {` is found as a block. `matching_brace` then counts from a brace
 * that is not one, and the span runs past the real end -- which, spliced,
 * deletes whatever was between. The invariant in `splice_into` catches the
 * result and puts the file back, so nothing is lost; what is lost is the
 * command, which refuses itself with "this is a bug in `ncfg control set`" on
 * the one machine whose bootstrap needs it.
 */
static int block_span(const char *text, size_t from, size_t to, const char *head,
    size_t *start_out, size_t *end_out)
{
	size_t head_length = strlen(head);
	size_t length = strlen(text);
	size_t at = from;
	int    in_string = 0;
	int    in_comment = 0;

	while (at < to) {
		char byte = text[at];

		if (in_comment) {
			if (byte == '\n') {
				in_comment = 0;
			}
			at++;
			continue;
		}
		if (in_string) {
			if (byte == '\\') {
				at++;
			} else if (byte == '"') {
				in_string = 0;
			}
			at++;
			continue;
		}
		if (byte == '"') {
			in_string = 1;
			at++;
			continue;
		}
		if (byte == '#') {
			in_comment = 1;
			at++;
			continue;
		}
		if (at + head_length <= to && memcmp(text + at, head, head_length) == 0 &&
		    word_starts_at(text, at)) {
			size_t after = at + head_length;
			size_t scan = after;

			/* Nothing but whitespace between the head and its brace. */
			while (scan < to && is_space(text[scan])) {
				scan++;
			}
			if (scan < to && text[scan] == '{') {
				size_t close = matching_brace(text, scan, length);

				if (close != (size_t)-1) {
					*start_out = at;
					*end_out = close + 1u;
					return 1;
				}
			}
			at = after;
			continue;
		}
		at++;
	}
	return 0;
}

/*
 * The indentation of whatever is already inside, so the result looks like the
 * file rather than like this function.
 *
 * The first non-empty line's leading tabs and spaces, and a tab where there is
 * no line to read it from.
 */
static void indent_within(const char *text, size_t from, size_t to, char *out, size_t out_size)
{
	size_t at = from;

	(void)snprintf(out, out_size, "\t");
	while (at < to) {
		size_t end = at;
		size_t lead;
		int    empty = 1;

		while (end < to && text[end] != '\n') {
			end++;
		}
		for (lead = at; lead < end; lead++) {
			if (!is_space(text[lead])) {
				empty = 0;
				break;
			}
		}
		if (!empty) {
			size_t take = 0;

			while (at + take < end && (text[at + take] == '\t' || text[at + take] == ' ') &&
			    take + 1u < out_size) {
				take++;
			}
			memcpy(out, text + at, take);
			out[take] = '\0';
			return;
		}
		at = end + 1u;
	}
}

int ncfg_cli_control_splice(const char *text, const ncfg_control_t *control, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	size_t     length = strlen(text);
	size_t     global_start;
	size_t     global_end;
	size_t     open;
	size_t     close;
	size_t     block_start;
	size_t     block_end;
	char       indent[64];
	ncfg_buf_t inner;

	ncfg_buf_init(out, 0);
	if (!block_span(text, 0, length, "global", &global_start, &global_end)) {
		ncfg_error_set(err, err_size, "that file has no `global` block after all");
		return 0;
	}
	open = global_start;
	while (open < global_end && text[open] != '{') {
		open++;
	}
	if (open >= global_end) {
		ncfg_error_set(err, err_size, "the `global` block has no opening brace");
		return 0;
	}
	close = global_end - 1u;

	indent_within(text, open + 1u, close, indent, sizeof(indent));
	ncfg_buf_init(&inner, 0);
	render_inner(control, indent, &inner);

	if (block_span(text, open + 1u, close, "control", &block_start, &block_end)) {
		const char *block = ncfg_buf_text(&inner);
		size_t      head = 0;
		size_t      tail = strlen(block);

		while (block[head] == '\t' || block[head] == ' ') {
			head++;
		}
		while (tail > head && block[tail - 1u] == '\n') {
			tail--;
		}
		ncfg_buf_add(out, text, block_start);
		ncfg_buf_add(out, block + head, tail - head);
		ncfg_buf_add_text(out, text + block_end);
	} else {
		ncfg_buf_add(out, text, close);
		if (close == 0 || text[close - 1u] != '\n') {
			ncfg_buf_add_char(out, '\n');
		}
		ncfg_buf_add_text(out, ncfg_buf_text(&inner));
		ncfg_buf_add_text(out, text + close);
	}
	ncfg_buf_free(&inner);
	if (ncfg_buf_failed(out)) {
		ncfg_error_set(err, err_size, "that file is too large to edit in one piece");
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Which file defines `global`
 * ------------------------------------------------------------------------ */

/*
 * Whether this line opens a `global` block.
 *
 * Read as text rather than asked of the compiler, because what matters here is
 * *where the block is written*, and a compiled document has already merged
 * everything into one set of globals.
 */
static int opens_global(const char *line, size_t length)
{
	size_t at = 0;

	while (at < length && (line[at] == ' ' || line[at] == '\t')) {
		at++;
	}
	if (at + 8u <= length && memcmp(line + at, "override", 8u) == 0) {
		at += 8u;
		if (at >= length || (line[at] != ' ' && line[at] != '\t')) {
			return 0;
		}
		while (at < length && (line[at] == ' ' || line[at] == '\t')) {
			at++;
		}
	}
	if (at + 6u > length || memcmp(line + at, "global", 6u) != 0) {
		return 0;
	}
	at += 6u;
	/* A word: `globals = 1` is not a `global` block. */
	return at == length || line[at] == ' ' || line[at] == '\t' || line[at] == '{';
}

/* The first file in `sources` that opens a `global` block. */
static int defines_global(const ncfg_config_sources_t *sources, char *out, size_t out_size)
{
	size_t which;

	for (which = 0; which < sources->count; which++) {
		const char *text = sources->at[which].text;
		size_t      at = 0;

		while (text && text[at] != '\0') {
			size_t end = at;

			while (text[end] != '\0' && text[end] != '\n') {
				end++;
			}
			if (opens_global(text + at, end - at)) {
				(void)snprintf(out, out_size, "%s", sources->at[which].name);
				return 1;
			}
			at = text[end] == '\0' ? end : end + 1u;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------------ *
 * Writing the policy
 * ------------------------------------------------------------------------ */

/* The whole of a file, NUL-terminated, or NULL. The caller frees it. */
static char *read_whole(const char *path, size_t *length_out)
{
	FILE      *file = fopen(path, "rb");
	char       chunk[4096];
	char      *text;
	ncfg_buf_t buf;

	if (length_out) {
		*length_out = 0;
	}
	if (!file) {
		return NULL;
	}
	ncfg_buf_init(&buf, NCFG_CONFIG_FILE_MAX);
	for (;;) {
		size_t got = fread(chunk, 1u, sizeof(chunk), file);

		if (got > 0) {
			ncfg_buf_add(&buf, chunk, got);
		}
		if (got < sizeof(chunk) || ncfg_buf_failed(&buf)) {
			break;
		}
	}
	(void)fclose(file);
	if (ncfg_buf_failed(&buf)) {
		ncfg_buf_free(&buf);
		return NULL;
	}
	text = malloc(buf.length + 1u);
	if (text) {
		memcpy(text, ncfg_buf_text(&buf), buf.length + 1u);
		if (length_out) {
			*length_out = buf.length;
		}
	}
	ncfg_buf_free(&buf);
	return text;
}

/*
 * The drop-in this command owns.
 *
 * **Composed here and proved against the writer.** `ncfg_config_install_drop_in`
 * owns the `conf.d/<name>.conf` rule and hands back the path it used, but the
 * previous contents have to be read *before* the install to be put back after
 * it -- so this spelling exists, and `cli_control_test.c` asserts that what the
 * install returns is what this composed. A path rule written twice and checked
 * once is a path rule written once.
 */
#define NCFG_CLI_CONTROL_DROP_IN "00-control"

static int control_path(const char *config_dir, char *out, size_t out_size)
{
	int wrote = snprintf(out, out_size, "%s/conf.d/%s.conf", config_dir,
	    NCFG_CLI_CONTROL_DROP_IN);

	return wrote > 0 && (size_t)wrote < out_size;
}

/*
 * Compile, and check that the policy is the one that was asked for.
 *
 * Compiled back through the loader the daemon uses, for the reason
 * `ncfg_config_install_drop_in` does it: a generated file that does not compile
 * takes the whole directory with it, and this one decides who may talk to the
 * daemon at all.
 */
static int verify(const ncfg_cli_options_t *options, const ncfg_control_t *wanted, char *err,
    size_t err_size)
{
	char             said[NCFG_ERROR_MAX];
	ncfg_document_t *document = ncfg_cli_compile_to_read(options, said, sizeof(said));
	int              same;

	if (!document) {
		ncfg_error_set(err, err_size,
		    "that policy does not compile, so it was put back:\n%s", said);
		return 0;
	}
	same = control_same(&document->globals.control, wanted);
	ncfg_document_free(document);
	if (!same) {
		ncfg_error_set(err, err_size,
		    "the policy was written and compiled to something else, so it was put "
		    "back. This is a bug in `ncfg control set`");
		return 0;
	}
	return 1;
}

/* Put the bytes that were there back, or take the file away where there were
 * none. A command that widens who may configure the network must not be able
 * to leave the machine with a policy nobody chose. */
static void put_back(const char *path, const char *previous, size_t length)
{
	char ignored[NCFG_ERROR_MAX];

	if (previous) {
		(void)ncfg_config_write_atomically(path, previous, length, 0644u, NULL, ignored,
		    sizeof(ignored));
	} else {
		(void)unlink(path);
	}
}

/*
 * Everything but the policy, compared as the compiler sees it.
 *
 * Normalising the one field that is *meant* to differ is what makes this an
 * assertion about the rest rather than a restatement of the edit. Canonical
 * JSON rather than a field walk: `document.h` already has one writer whose
 * output is the document, and a second comparison written by hand is a second
 * thing to keep in step with a model that grows a block every milestone.
 *
 * A document that will not render compares as different, which errs towards
 * putting the file back.
 */
static int same_but_for_the_policy(ncfg_document_t *before, ncfg_document_t *after)
{
	ncfg_buf_t one;
	ncfg_buf_t other;
	char       ignored[NCFG_ERROR_MAX];
	int        same = 0;

	control_reset(&before->globals.control);
	control_reset(&after->globals.control);
	ncfg_buf_init(&one, 0);
	ncfg_buf_init(&other, 0);
	if (ncfg_document_write_canonical(before, &one, ignored, sizeof(ignored)) &&
	    ncfg_document_write_canonical(after, &other, ignored, sizeof(ignored))) {
		same = strcmp(ncfg_buf_text(&one), ncfg_buf_text(&other)) == 0;
	}
	ncfg_buf_free(&one);
	ncfg_buf_free(&other);
	return same;
}

/*
 * Edit the `global` block that exists, and prove nothing else moved.
 *
 * A drop-in cannot do this: section 3 makes `override global` replace the block
 * *whole*, so a policy written that way silently takes every other global
 * setting with it -- measured, and it turned a machine's DNS mode from
 * `write_resolv_conf` into `none`. So the block is edited where it lives.
 *
 * The proof is the point and it is stated as an invariant rather than left to
 * review: **compile before, compile after, and the two documents may differ in
 * `globals.control` and nowhere else.** Splicing text into a file somebody
 * wrote is the kind of change that eats a line and looks fine, and this one
 * happens on the file that decides who may configure the network -- so a
 * result that fails the invariant is put back rather than reported.
 */
static int splice_into(const char *path, const ncfg_control_t *wanted,
    const ncfg_cli_options_t *options, char *err, size_t err_size)
{
	char             said[NCFG_ERROR_MAX];
	char            *text;
	size_t           length = 0;
	ncfg_buf_t       spliced;
	ncfg_document_t *before;
	ncfg_document_t *after;
	int              denied = 0;
	int              kept;

	before = ncfg_cli_compile_to_read(options, err, err_size);
	if (!before) {
		return 0;
	}
	text = read_whole(path, &length);
	if (!text) {
		ncfg_document_free(before);
		ncfg_error_set(err, err_size, "could not read %s", path);
		return 0;
	}
	if (!ncfg_cli_control_splice(text, wanted, &spliced, err, err_size)) {
		ncfg_buf_free(&spliced);
		free(text);
		ncfg_document_free(before);
		return 0;
	}
	if (!ncfg_config_write_atomically(path, ncfg_buf_text(&spliced), spliced.length, 0644u,
	    &denied, said, sizeof(said))) {
		ncfg_buf_free(&spliced);
		free(text);
		ncfg_document_free(before);
		ncfg_cli_refused_locally(denied, said, "", err, err_size);
		return 0;
	}
	ncfg_buf_free(&spliced);

	after = ncfg_cli_compile_to_read(options, said, sizeof(said));
	if (!after) {
		put_back(path, text, length);
		ncfg_error_set(err, err_size,
		    "editing %s produced something that does not compile, so it was put "
		    "back:\n%s", path, said);
		free(text);
		ncfg_document_free(before);
		return 0;
	}
	if (!control_same(&after->globals.control, wanted)) {
		put_back(path, text, length);
		ncfg_error_set(err, err_size,
		    "%s was edited and the policy compiled to something else, so it was put "
		    "back. This is a bug in `ncfg control set`", path);
		free(text);
		ncfg_document_free(before);
		ncfg_document_free(after);
		return 0;
	}
	kept = same_but_for_the_policy(before, after);
	ncfg_document_free(before);
	ncfg_document_free(after);
	if (!kept) {
		put_back(path, text, length);
		ncfg_error_set(err, err_size,
		    "editing %s changed something other than the control policy, so it was "
		    "put back. This is a bug in `ncfg control set`", path);
		free(text);
		return 0;
	}
	free(text);
	return 1;
}

/*
 * Write a policy and prove it compiled back to itself. Returns what it wrote.
 *
 * Split out of `set` so that `ncfg control helper` writes through exactly this
 * code and not a second copy of it. The helper runs as root and this function
 * is everything it is allowed to do, so a second implementation would be a
 * second thing to audit.
 *
 * **A drop-in can only replace a `global` block, never adjust one key of it**:
 * section 3 makes redefining a block a compile error and `override` replace it
 * whole, deliberately, so that last-wins is never silent. Measured rather than
 * assumed, because the failure is quiet and severe: with `override global {
 * control { ... } }` beside a `global` naming a DNS mode, the compiled mode
 * came back `none`. So where a `global` block already exists it is edited
 * where it lives.
 *
 * **The writable layer decides, and the factory layer is refused by name.**
 * The Rust searches the layered source set, which puts the factory files
 * first -- so on an image that ships a `global` block this command edits
 * `/usr/share/netcfgd`, which is part of the image rather than part of the
 * machine's configuration: the edit is lost at the next upgrade, or refused
 * outright on a read-only root, for a policy `ncfg control show` goes on
 * reporting correctly in the meantime.
 */
static int write_policy(const ncfg_control_t *control, const ncfg_cli_options_t *options,
    char *path_out, size_t path_size, char *err, size_t err_size)
{
	char                  config_dir[NCFG_CLI_PATH_MAX];
	char                  factory_dir[NCFG_CLI_PATH_MAX];
	char                  found[NCFG_CLI_PATH_MAX];
	char                  said[NCFG_ERROR_MAX];
	ncfg_config_sources_t sources = { NULL, 0, 0 };
	ncfg_buf_t            text;
	char                 *previous;
	size_t                previous_length = 0;
	char                 *written = NULL;
	int                   denied = 0;

	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
	    sizeof(factory_dir));

	if (!ncfg_config_load(config_dir, &sources, err, err_size)) {
		ncfg_config_sources_free(&sources);
		return 0;
	}
	if (defines_global(&sources, found, sizeof(found))) {
		ncfg_config_sources_free(&sources);
		if (!splice_into(found, control, options, err, err_size)) {
			return 0;
		}
		(void)snprintf(path_out, path_size, "%s", found);
		return 1;
	}
	ncfg_config_sources_free(&sources);

	if (!ncfg_config_load(factory_dir, &sources, said, sizeof(said))) {
		/* A factory layer that cannot be read is not this command's problem:
		 * the loader reports it on the next compile, which `verify` performs
		 * below. Freeing leaves the set usable and empty, so the scan that
		 * follows simply finds nothing. */
		ncfg_config_sources_free(&sources);
	}
	if (defines_global(&sources, found, sizeof(found))) {
		ncfg_config_sources_free(&sources);
		ncfg_error_set(err, err_size,
		    "the `global` block this machine reads is in %s, which is part of the "
		    "image rather than part of its configuration. A drop-in cannot add a key "
		    "to it -- redefining the block is a compile error and `override global` "
		    "replaces it whole, taking every other global setting with it -- so the "
		    "policy belongs in that file", found);
		return 0;
	}
	ncfg_config_sources_free(&sources);

	if (!control_path(config_dir, path_out, path_size)) {
		ncfg_error_set(err, err_size,
		    "%s makes a path too long to write a control policy into", config_dir);
		return 0;
	}
	/* Kept, so a failed verification can put back exactly what was there. */
	previous = read_whole(path_out, &previous_length);

	ncfg_buf_init(&text, 0);
	ncfg_cli_control_render(control, &text);
	if (ncfg_buf_failed(&text)) {
		ncfg_buf_free(&text);
		free(previous);
		ncfg_error_set(err, err_size, "out of memory rendering the control policy");
		return 0;
	}
	if (!ncfg_config_install_drop_in(config_dir, factory_dir, NCFG_CLI_CONTROL_DROP_IN,
	    ncfg_buf_text(&text), 1, &written, &denied, said, sizeof(said))) {
		ncfg_buf_free(&text);
		free(previous);
		ncfg_cli_refused_locally(denied, said, "", err, err_size);
		return 0;
	}
	ncfg_buf_free(&text);
	(void)snprintf(path_out, path_size, "%s", written ? written : path_out);
	free(written);

	if (!verify(options, control, err, err_size)) {
		put_back(path_out, previous, previous_length);
		free(previous);
		return 0;
	}
	free(previous);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * What an operator reads
 * ------------------------------------------------------------------------ */

static void print_tiers(const ncfg_control_t *control)
{
	char rendered[NCFG_CLI_TEXT_MAX];

	ncfg_out_writef("observe  %s\n",
	    ncfg_cli_principal_render(&control->observe, rendered, sizeof(rendered)));
	ncfg_out_writef("wifi     %s\n",
	    ncfg_cli_principal_render(&control->wifi, rendered, sizeof(rendered)));
	ncfg_out_writef("admin    %s\n",
	    ncfg_cli_principal_render(&control->admin, rendered, sizeof(rendered)));
}

static int show(const ncfg_cli_options_t *options, char *err, size_t err_size)
{
	ncfg_document_t *document = ncfg_cli_compile_to_read(options, err, err_size);

	if (!document) {
		return 0;
	}
	print_tiers(&document->globals.control);
	/* The socket's mode follows the policy, and an operator reading this is
	 * nearly always asking why a client was refused. Saying which file decides
	 * is the part that saves the afternoon. */
	if (!control_opens_beyond_root(&document->globals.control)) {
		ncfg_out_line("");
		ncfg_out_line("every tier is root, so the socket is root-only and no client run");
		ncfg_out_line("by an ordinary user can reach it. `ncfg control set` changes that.");
	}
	ncfg_document_free(document);
	return 1;
}

/* What the policy is now, and what an operator still has to do about it. */
static void report(const ncfg_control_t *control)
{
	print_tiers(control);
	if (control_opens_beyond_root(control)) {
		ncfg_out_line("");
		ncfg_out_line("netcfgd applies this when it next reads its configuration. A member of");
		ncfg_out_line("a named group has to log out and back in before the kernel gives their");
		ncfg_out_line("session that membership.");
	}
}

/* Parse `--observe`, `--wifi` and `--admin`, leaving what was not named alone. */
static int set(const ncfg_cli_options_t *options, char *err, size_t err_size)
{
	ncfg_control_t   control;
	ncfg_document_t *document = ncfg_cli_compile_to_read(options, err, err_size);
	const char      *given[3];
	char             path[NCFG_CLI_PATH_MAX];
	size_t           which;
	int              named = 0;

	if (!document) {
		return 0;
	}
	if (!control_copy(&document->globals.control, &control)) {
		ncfg_document_free(document);
		control_reset(&control);
		ncfg_error_set(err, err_size, "out of memory reading the control policy");
		return 0;
	}
	ncfg_document_free(document);

	given[0] = options->control.observe;
	given[1] = options->control.wifi;
	given[2] = options->control.admin;
	for (which = 0; which < 3u; which++) {
		ncfg_principal_t parsed;
		char             why[NCFG_ERROR_MAX];

		if (!given[which]) {
			continue;
		}
		memset(&parsed, 0, sizeof(parsed));
		if (!ncfg_cli_principal_parse(given[which], &parsed, why, sizeof(why))) {
			control_reset(&control);
			ncfg_error_set(err, err_size,
			    "`%s` is not a principal: %s. For example: group:netcfgd, "
			    "user:alice, any, root", given[which], why);
			return 0;
		}
		if (which == 0) {
			principal_reset(&control.observe);
			control.observe = parsed;
		} else if (which == 1) {
			principal_reset(&control.wifi);
			control.wifi = parsed;
		} else {
			principal_reset(&control.admin);
			control.admin = parsed;
		}
		named = 1;
	}
	if (!named) {
		control_reset(&control);
		ncfg_error_set(err, err_size,
		    "`ncfg control set` needs at least one of --observe, --wifi or --admin. "
		    "`ncfg control show` prints the policy now");
		return 0;
	}
	if (!write_policy(&control, options, path, sizeof(path), err, err_size)) {
		control_reset(&control);
		return 0;
	}
	ncfg_out_line(path);
	report(&control);
	control_reset(&control);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The privileged half of the client's administrator mode
 * ------------------------------------------------------------------------ */

/*
 * One command. The whole grammar is here, and it is three principals.
 *
 * [0120]: the red frame around an editor is a claim that something on the
 * other side of a process boundary holds root. This parser is what is on the
 * other side. What matters is not that `set` works -- it is that nothing else
 * does, and that a refusal happens before anything is written.
 */
int ncfg_cli_control_command(const char *line, const ncfg_cli_options_t *options, char *path_out,
    size_t path_size, char *err, size_t err_size)
{
	static const char *const tiers[] = { "observe", "wifi", "admin" };
	ncfg_control_t           control;
	ncfg_principal_t        *into[3];
	const char              *at = line;
	size_t                   which;

	memset(&control, 0, sizeof(control));
	into[0] = &control.observe;
	into[1] = &control.wifi;
	into[2] = &control.admin;

	while (*at != '\0' && is_space(*at)) {
		at++;
	}
	if (*at == '\0') {
		ncfg_error_set(err, err_size, "an empty line is not a command");
		return 0;
	}
	if (strncmp(at, "set", 3u) != 0 || (at[3] != '\0' && !is_space(at[3]))) {
		size_t end = 0;

		while (at[end] != '\0' && !is_space(at[end])) {
			end++;
		}
		ncfg_error_set(err, err_size, "unknown command `%.*s`; it is `set`", (int)end, at);
		return 0;
	}
	at += 3;

	for (which = 0; which < 3u; which++) {
		char   word[NCFG_CLI_TEXT_MAX];
		char   why[NCFG_ERROR_MAX];
		size_t end = 0;

		while (*at != '\0' && is_space(*at)) {
			at++;
		}
		if (*at == '\0') {
			control_reset(&control);
			ncfg_error_set(err, err_size,
			    "`set` needs three principals; %s was not given", tiers[which]);
			return 0;
		}
		while (at[end] != '\0' && !is_space(at[end]) && end + 1u < sizeof(word)) {
			end++;
		}
		memcpy(word, at, end);
		word[end] = '\0';
		at += end;
		if (!ncfg_cli_principal_parse(word, into[which], why, sizeof(why))) {
			control_reset(&control);
			ncfg_error_set(err, err_size, "`%s` is not a principal for %s: %s", word,
			    tiers[which], why);
			return 0;
		}
	}
	while (*at != '\0' && is_space(*at)) {
		at++;
	}
	if (*at != '\0') {
		control_reset(&control);
		ncfg_error_set(err, err_size, "`set` takes exactly three principals");
		return 0;
	}
	if (!write_policy(&control, options, path_out, path_size, err, err_size)) {
		control_reset(&control);
		return 0;
	}
	control_reset(&control);
	return 1;
}

/*
 * The privileged half, speaking its line protocol on standard input.
 *
 * It is started by whatever the desktop has -- `pkexec`, `kdesu`, `sudo -A` --
 * so the authentication happens *before* any editor opens, and the client never
 * handles a password.
 *
 * **Deliberately not a GUI.** 0117 and 0118 both refuse running Qt as root "so
 * that it can write one file", and that refusal stands: a toolkit with a theme
 * engine and a plugin loader is not a thing to hand uid 0. What crosses the
 * boundary is this, which links no toolkit at all.
 *
 * **It cannot outlive the window that authenticated it.** The protocol ends at
 * end of file on standard input, so when the client exits -- cleanly, killed,
 * or crashed -- the pipe closes and this returns. There is no timeout to get
 * wrong and nothing to leave running.
 *
 * The `ready` line reports the uid it actually got, so the client reddens its
 * frame on a *checked* claim rather than on having asked. An elevator that
 * silently did nothing would otherwise produce a red frame around an
 * unprivileged process, which is the one thing the frame must never mean.
 *
 * The Rust reads the uid out of `/proc/self/status`, because `netcfgd-sys` is
 * the crate allowed `unsafe` and reaching for it would be a dependency edge for
 * one integer. C has the call, so it makes it -- and answers on a machine with
 * no `/proc`, where the Rust reports `4294967295`.
 */
static int helper(const ncfg_cli_options_t *options)
{
	ncfg_out_writef("ready uid=%lu\n", (unsigned long)geteuid());
	for (;;) {
		char   line[NCFG_CLI_CONTROL_COMMAND_MAX + 1u];
		char   path[NCFG_CLI_PATH_MAX];
		char   why[NCFG_ERROR_MAX];
		size_t length;
		size_t at;

		/*
		 * Bounded, because this is a root process reading a pipe and a
		 * line-reading loop will take whatever it is sent. `proto.h` bounds
		 * the socket at `NCFG_PROTO_MAX_LINE` for the same reason; the number
		 * here is much smaller because the whole grammar is a verb and three
		 * principals, and a bound that fits the protocol is worth more than
		 * one that merely fits memory.
		 */
		if (!fgets(line, (int)sizeof(line), stdin)) {
			/* End of file: the client that authenticated this is gone. */
			break;
		}
		length = strlen(line);
		if (length == NCFG_CLI_CONTROL_COMMAND_MAX && line[length - 1u] != '\n') {
			/* No resynchronising after this -- whatever follows is the tail of
			 * a command nobody can parse, so say so and stop rather than
			 * treating the remainder as fresh input. */
			ncfg_out_writef("error a command may not exceed %d bytes\n",
			    NCFG_CLI_CONTROL_COMMAND_MAX);
			break;
		}
		while (length > 0 && is_space(line[length - 1u])) {
			length--;
		}
		line[length] = '\0';
		if (ncfg_cli_control_command(line, options, path, sizeof(path), why, sizeof(why))) {
			ncfg_out_writef("ok %s\n", path);
			continue;
		}
		/* One line, because the protocol is one line per reply and a
		 * diagnostic with a newline in it would be read as two. */
		for (at = 0; why[at] != '\0'; at++) {
			if (why[at] == '\n') {
				why[at] = ' ';
			}
		}
		ncfg_out_writef("error %s\n", why);
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * `ncfg control show|set`
 * ------------------------------------------------------------------------ */

int ncfg_cli_control(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size)
{
	if (count == 0) {
		ncfg_error_set(err, err_size, "`ncfg control` takes `show` or `set`");
		return 0;
	}
	if (strcmp(positional[0], "show") == 0) {
		return show(options, err, err_size);
	}
	if (strcmp(positional[0], "set") == 0) {
		return set(options, err, err_size);
	}
	if (strcmp(positional[0], "helper") == 0) {
		return helper(options);
	}
	/*
	 * `helper` is deliberately absent from both this sentence and the usage
	 * text. It is not a command for a person: it speaks a line protocol on
	 * standard input to the client that started it, and naming it here would
	 * invite somebody to run it by hand and wonder why it appears to hang.
	 * 0120 documents it.
	 */
	ncfg_error_set(err, err_size, "unknown control subcommand `%.*s`; it is `show` or `set`",
	    (int)NCFG_CLI_TEXT_MAX, positional[0]);
	return 0;
}
