/*
 * contention.c -- finding out whether something else is already managing an
 * interface.
 *
 * WHAT THIS READS, AND NOTHING ELSE
 *   Two files per interface, both read-only and both somebody else's:
 *
 *     <run>/NetworkManager/devices/<ifindex>
 *     <run>/systemd/netif/links/<ifindex>
 *
 *   one for all of them, `<etc>/config/network`, for OpenWrt's netifd; and, for
 *   liveness, `<proc>/<pid>/comm` for every numeric entry under `<proc>`. It
 *   opens nothing else, writes nothing, and signals nothing: netcfgd reports
 *   here and the operator decides.
 *
 * WHY NETIFD IS READ FROM ITS CONFIGURATION
 *   netifd keeps no state file: it answers over ubus, and section 1 constraint 3
 *   keeps a bus off the core's path. Its configuration says what it was told to
 *   hold, which is the claim. This reads UCI only to answer that, naming no
 *   setting and importing nothing, so 0019 stands (project.md 10.746).
 *
 * WHY A PROCESS NAME IS CONSULTED AT ALL
 *   `process.h` forbids finding a process by name, and is right to: an
 *   operator's own daemons are common and a name would reach them. This is the
 *   other question -- not "which process is netcfgd's" but "is the daemon that
 *   wrote this file still running" -- and it is asked only to *withdraw* a
 *   claim, never to act on one. `process.h` has the same shape under
 *   `ncfg_process_pids_of_programs`; the scan is local here because the root
 *   this walks is an argument and that one's is not.
 *
 * WHY THE LINK FILES ARE PARSED WHEN THEY SAY NOT TO
 *   Every `systemd/netif/links/` file opens with
 *   `# This is private data. Do not parse.` This parses them anyway, which is
 *   a decision and not an oversight: the supported ways to ask are
 *   `networkctl` and networkd's D-Bus API, and section 1 constraint 3 keeps a
 *   message bus off the core's mandatory path. The cost is that a systemd
 *   release can move the format; the mitigation is that this feeds a
 *   *warning*, so what breaks is a diagnostic and not a network.
 */
#include "ncfg/apply.h"

#include "ncfg/process.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * How long a line of one of these files may be before it is not a line.
 *
 * `managed=true` and `ADMIN_STATE=configured` are short, and a file whose
 * lines are longer than this holds something that is not what this is reading
 * for. Bounded rather than grown, because the file is another daemon's and its
 * size is not netcfgd's to trust.
 */
#define LINE_MAX_BYTES 512

/* How many lines are looked at before the answer is no. A device file has
 * fewer than twenty. */
#define LINE_LIMIT 512

/* A namespace link is `net:[4026531840]`. */
#define NAMESPACE_MAX 64

/*
 * The names each daemon runs under.
 *
 * `comm` is **truncated to 15 characters** by the kernel, which is why
 * `systemd-networkd` is listed under its truncation as well as its full name:
 * a name one character too long simply never matches and the check reports
 * nothing. `NetworkManager` is fourteen and needs no second spelling.
 */
static const char *const network_manager_names[] = { "NetworkManager" };
static const char *const networkd_names[] = { "systemd-network", "systemd-networkd" };
static const char *const netifd_names[] = { "netifd" };

/* ------------------------------------------------------------------------ *
 * Small things
 * ------------------------------------------------------------------------ */

/* A copy of `text`, or NULL. Named rather than `strdup` for
 * `backend_internal.h`'s reason: one spelling per module. */
static char *duplicate(const char *text)
{
	size_t length;
	char  *copy;

	if (!text) {
		return NULL;
	}
	length = strlen(text) + 1u;
	copy = malloc(length);
	if (copy) {
		memcpy(copy, text, length);
	}
	return copy;
}

/* Take the leading and trailing whitespace off in place. Returns the start. */
static char *trim(char *text)
{
	size_t length;

	while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') {
		text++;
	}
	length = strlen(text);
	while (length > 0u && (text[length - 1u] == ' ' || text[length - 1u] == '\t' ||
	    text[length - 1u] == '\r' || text[length - 1u] == '\n')) {
		text[--length] = '\0';
	}
	return text;
}

static int compare_names(const void *left, const void *right)
{
	return strcmp(*(const char *const *)left, *(const char *const *)right);
}

/*
 * Whether any whole line of `path`, trimmed, is `wanted`.
 *
 * **Whole lines only.** A line longer than the buffer arrives in pieces, and a
 * piece that happened to end `managed=true` would otherwise read as the claim
 * -- so a split line is skipped to its end rather than compared.
 */
static int file_states(const char *path, const char *wanted)
{
	char  line[LINE_MAX_BYTES];
	FILE *file = fopen(path, "r");
	int   found = 0;
	int   skipping = 0;
	int   lines = 0;

	if (!file) {
		return 0;
	}
	while (!found && lines < LINE_LIMIT && fgets(line, (int)sizeof(line), file)) {
		int whole = strchr(line, '\n') != NULL || feof(file);

		if (skipping) {
			/* Still inside a line too long to be one of these. */
			skipping = !whole;
			continue;
		}
		if (!whole) {
			skipping = 1;
			continue;
		}
		lines++;
		found = strcmp(trim(line), wanted) == 0;
	}
	(void)fclose(file);
	return found;
}

/* ------------------------------------------------------------------------ *
 * Whose namespace wrote these files
 * ------------------------------------------------------------------------ */

/* The target of one namespace link, or 0 where it cannot be read. */
static int namespace_of(const char *proc_root, const char *who, char *out, size_t out_size)
{
	char    path[512];
	ssize_t length;
	int     written;

	written = snprintf(path, sizeof(path), "%s/%s/ns/net", proc_root, who);
	if (written < 0 || (size_t)written >= sizeof(path)) {
		return 0;
	}
	length = readlink(path, out, out_size - 1u);
	if (length < 0) {
		return 0;
	}
	out[length] = '\0';
	return 1;
}

/*
 * Whether the state under `run_root` was written from this network namespace.
 *
 * There is nothing in the files to cross-check against: `NetworkManager`'s
 * device file records neither the interface name nor a permanent MAC. What can
 * be checked is whether we are in the namespace those files were written from.
 * Pid 1 is the machine's init, host daemons write `/run` from its network
 * namespace, and if ours is not that one then their indices are not about our
 * interfaces.
 *
 * **Unreadable is treated as ours, deliberately.** Only a privileged process
 * can read another's namespace link, and being wrong in that direction costs a
 * refusal the operator can override, while being wrong in the other lets
 * netcfgd start a second supplicant on a radio somebody else is holding --
 * which is the failure this whole file exists to prevent.
 */
static int run_root_is_ours(const ncfg_contention_where_t *where)
{
	char ours[NAMESPACE_MAX];
	char init[NAMESPACE_MAX];

	if (!where->run_root_is_the_machines) {
		return 1;
	}
	if (!namespace_of(where->proc_root, "self", ours, sizeof(ours)) ||
	    !namespace_of(where->proc_root, "1", init, sizeof(init))) {
		return 1;
	}
	return strcmp(ours, init) == 0;
}

/* ------------------------------------------------------------------------ *
 * Liveness
 * ------------------------------------------------------------------------ */

/* Whether `name` is one of `names`. */
static int named(const char *const *names, size_t count, const char *name)
{
	size_t at;

	for (at = 0u; at < count; at++) {
		if (strcmp(names[at], name) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * Which of the two daemons has a process running, in one walk of `<proc>`.
 *
 * **An unreadable `/proc` means both**: falling back to believing the files is
 * the direction that keeps the guard, rather than the one that starts a second
 * supplicant on somebody else's radio.
 */
static void running_daemons(const char *proc_root, int *network_manager, int *networkd,
    int *netifd)
{
	DIR                 *entries = opendir(proc_root);
	const struct dirent *found;

	*network_manager = 0;
	*networkd = 0;
	*netifd = 0;
	if (!entries) {
		*network_manager = 1;
		*networkd = 1;
		*netifd = 1;
		return;
	}
	while ((*network_manager == 0 || *networkd == 0 || *netifd == 0) &&
	    (found = readdir(entries)) != NULL) {
		char   path[512];
		char   comm[NCFG_PROGRAM_MAX + 16];
		char  *name;
		FILE  *file;
		size_t at;
		int    written;

		for (at = 0u; found->d_name[at] != '\0'; at++) {
			if (found->d_name[at] < '0' || found->d_name[at] > '9') {
				break;
			}
		}
		if (at == 0u || found->d_name[at] != '\0') {
			continue;
		}
		written = snprintf(path, sizeof(path), "%s/%s/comm", proc_root, found->d_name);
		if (written < 0 || (size_t)written >= sizeof(path)) {
			continue;
		}
		/* A numeric entry with no `comm` is what a process exiting mid-scan
		 * looks like, and is nothing to report. */
		file = fopen(path, "r");
		if (!file) {
			continue;
		}
		if (fgets(comm, (int)sizeof(comm), file)) {
			name = trim(comm);
			if (named(network_manager_names,
			    sizeof(network_manager_names) / sizeof(*network_manager_names), name)) {
				*network_manager = 1;
			}
			if (named(networkd_names, sizeof(networkd_names) / sizeof(*networkd_names),
			    name)) {
				*networkd = 1;
			}
			if (named(netifd_names, sizeof(netifd_names) / sizeof(*netifd_names), name)) {
				*netifd = 1;
			}
		}
		(void)fclose(file);
	}
	(void)closedir(entries);
}

/* ------------------------------------------------------------------------ *
 * The claims
 * ------------------------------------------------------------------------ */

/*
 * Which of `claims` the daemon at `directory` states `wanted` about, sorted.
 *
 * 1 with an owned array in `*names`, or 0 where something could not be
 * allocated. An empty answer is success.
 */
static int claims_under(const char *run_root, const char *directory, const char *wanted,
    const ncfg_interface_claim_t *claims, size_t claim_count, char ***names, size_t *count)
{
	size_t at;

	*names = NULL;
	*count = 0u;
	if (claim_count == 0u) {
		return 1;
	}
	*names = calloc(claim_count, sizeof(**names));
	if (!*names) {
		return 0;
	}
	for (at = 0u; at < claim_count; at++) {
		char path[1024];
		int  written;

		if (!claims[at].name) {
			continue;
		}
		written = snprintf(path, sizeof(path), "%s/%s/%lu", run_root, directory,
		    (unsigned long)claims[at].index);
		if (written < 0 || (size_t)written >= sizeof(path)) {
			continue;
		}
		if (!file_states(path, wanted)) {
			continue;
		}
		(*names)[*count] = duplicate(claims[at].name);
		if (!(*names)[*count]) {
			return 0;
		}
		(*count)++;
	}
	if (*count > 1u) {
		qsort(*names, *count, sizeof(**names), compare_names);
	}
	return 1;
}

/*
 * The next word of a UCI line, quoted or not, or NULL at its end or at a comment.
 * Advances `*at` past it, and writes into the line.
 */
static char *uci_word(char **at)
{
	char *word = *at;
	char *end;
	char  quote = '\0';

	while (*word == ' ' || *word == '\t') {
		word++;
	}
	if (*word == '\0' || *word == '#') {
		*at = word;
		return NULL;
	}
	if (*word == '\'' || *word == '"') {
		quote = *word++;
	}
	end = word;
	while (*end != '\0' && (quote ? *end != quote : *end != ' ' && *end != '\t')) {
		end++;
	}
	*at = *end == '\0' ? end : end + 1;
	*end = '\0';
	return word;
}

/* Whether a value names `wanted`: the older `ifname` lists several in one word. */
static int names_device(char *value, const char *wanted)
{
	char *word;

	while ((word = uci_word(&value)) != NULL) {
		if (strcmp(word, wanted) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * Whether `<etc>/config/network` gives netifd the device `wanted`.
 *
 * An `interface` section's `device` or `ifname`, and a `device` section's `name`
 * or `ports`: a bridge netifd makes and each port of it. Nothing else, as a
 * `rule` or a `route` has an `interface` that is no device, and `@lan` names a
 * section and so matches nothing here. No file means no claim.
 */
static int netifd_configures(const char *etc_root, const char *wanted)
{
	char  path[1024];
	char  line[LINE_MAX_BYTES];
	FILE *file;
	int   lines = 0;
	int   in_interface = 0;
	int   in_device = 0;
	int   found = 0;
	int   written;

	written = snprintf(path, sizeof(path), "%s/config/network", etc_root);
	if (written < 0 || (size_t)written >= sizeof(path)) {
		return 0;
	}
	file = fopen(path, "r");
	if (!file) {
		return 0;
	}
	while (!found && lines++ < LINE_LIMIT && fgets(line, (int)sizeof(line), file)) {
		char *at = trim(line);
		char *kind = uci_word(&at);
		char *key;

		if (!kind) {
			continue;
		}
		key = uci_word(&at);
		if (!key) {
			continue;
		}
		if (strcmp(kind, "config") == 0) {
			in_interface = strcmp(key, "interface") == 0;
			in_device = strcmp(key, "device") == 0;
		} else if (strcmp(kind, "option") == 0 || strcmp(kind, "list") == 0) {
			if ((in_interface && (strcmp(key, "device") == 0 ||
			    strcmp(key, "ifname") == 0)) ||
			    (in_device && (strcmp(key, "name") == 0 ||
			    strcmp(key, "ports") == 0))) {
				char *value = uci_word(&at);

				found = value && names_device(value, wanted);
			}
		}
	}
	(void)fclose(file);
	return found;
}

/* Which of `claims` netifd is configured to hold, as `claims_under` answers. */
static int netifd_claims(const char *etc_root, const ncfg_interface_claim_t *claims,
    size_t claim_count, char ***names, size_t *count)
{
	size_t at;

	*names = NULL;
	*count = 0u;
	if (claim_count == 0u) {
		return 1;
	}
	*names = calloc(claim_count, sizeof(**names));
	if (!*names) {
		return 0;
	}
	for (at = 0u; at < claim_count; at++) {
		if (!claims[at].name || !netifd_configures(etc_root, claims[at].name)) {
			continue;
		}
		(*names)[*count] = duplicate(claims[at].name);
		if (!(*names)[*count]) {
			return 0;
		}
		(*count)++;
	}
	if (*count > 1u) {
		qsort(*names, *count, sizeof(**names), compare_names);
	}
	return 1;
}

/* Put one contender into the answer, taking the names with it. */
static int push(ncfg_contenders_t *out, const char *name, const char *remedy, char **names,
    size_t count)
{
	ncfg_contender_t *grown = realloc(out->at, (out->count + 1u) * sizeof(*grown));

	if (!grown) {
		return 0;
	}
	out->at = grown;
	out->at[out->count].name = name;
	out->at[out->count].remedy = remedy;
	out->at[out->count].interfaces = names;
	out->at[out->count].interface_count = count;
	out->count++;
	return 1;
}

static void release_names(char **names, size_t count)
{
	size_t at;

	if (!names) {
		return;
	}
	for (at = 0u; at < count; at++) {
		free(names[at]);
	}
	free(names);
}

void ncfg_contention_machine(ncfg_contention_where_t *out)
{
	if (!out) {
		return;
	}
	out->run_root = "/run";
	out->proc_root = "/proc";
	out->run_root_is_the_machines = 1;
	out->etc_root = "/etc";
}

void ncfg_contenders_free(ncfg_contenders_t *found)
{
	size_t at;

	if (!found) {
		return;
	}
	for (at = 0u; at < found->count; at++) {
		release_names(found->at[at].interfaces, found->at[at].interface_count);
	}
	free(found->at);
	found->at = NULL;
	found->count = 0u;
}

int ncfg_contenders_find(const ncfg_contention_where_t *where,
    const ncfg_interface_claim_t *claims, size_t claim_count, ncfg_contenders_t *out, char *err,
    size_t err_size)
{
	char **names = NULL;
	size_t count = 0u;
	int    network_manager = 0;
	int    networkd = 0;
	int    netifd = 0;

	if (!out) {
		ncfg_error_set(err, err_size, "there is nowhere to put what was found");
		return 0;
	}
	out->at = NULL;
	out->count = 0u;
	if (!where || !where->run_root || !where->proc_root) {
		ncfg_error_set(err, err_size,
		    "a contention check has to be told where to read `/run` and `/proc`");
		return 0;
	}
	if (!run_root_is_ours(where)) {
		return 1;
	}
	running_daemons(where->proc_root, &network_manager, &networkd, &netifd);

	/*
	 * `NetworkManager` writes `<run>/NetworkManager/devices/<ifindex>`. The
	 * file exists for every device NM knows about, so its presence proves
	 * nothing -- an unmanaged device has one too. `managed=true` is the claim,
	 * and checking for the file alone would report a contest with a daemon
	 * that has already stepped aside.
	 */
	if (network_manager) {
		if (!claims_under(where->run_root, "NetworkManager/devices", "managed=true", claims,
		    claim_count, &names, &count)) {
			release_names(names, count);
			ncfg_error_set(err, err_size,
			    "there was no memory to read what NetworkManager claims");
			return 0;
		}
		if (count > 0u) {
			if (!push(out, "NetworkManager", "nmcli device set {} managed no", names,
			    count)) {
				release_names(names, count);
				ncfg_contenders_free(out);
				ncfg_error_set(err, err_size,
				    "there was no memory to record what NetworkManager claims");
				return 0;
			}
		} else {
			release_names(names, count);
		}
	}

	/*
	 * `systemd-networkd` writes `<run>/systemd/netif/links/<ifindex>`.
	 * `ADMIN_STATE=configured` is the equivalent claim: networkd writes a file
	 * for every link it can see, and one it was given no `.network` for
	 * reports `unmanaged`.
	 *
	 * A running networkd showed a third state the documentation does not
	 * mention. `pending` is a link networkd has seen and not yet decided
	 * about, and it persisted for the whole run rather than flickering past.
	 * It is deliberately not a claim: networkd has configured nothing on such
	 * a link, and warning about a contest there is the false alarm that gets a
	 * warning ignored.
	 */
	names = NULL;
	count = 0u;
	if (networkd) {
		if (!claims_under(where->run_root, "systemd/netif/links",
		    "ADMIN_STATE=configured", claims, claim_count, &names, &count)) {
			release_names(names, count);
			ncfg_contenders_free(out);
			ncfg_error_set(err, err_size,
			    "there was no memory to read what systemd-networkd claims");
			return 0;
		}
		if (count > 0u) {
			if (!push(out, "systemd-networkd",
			    "remove the .network file matching {}, or set Unmanaged=yes for it",
			    names, count)) {
				release_names(names, count);
				ncfg_contenders_free(out);
				ncfg_error_set(err, err_size,
				    "there was no memory to record what systemd-networkd claims");
				return 0;
			}
		} else {
			release_names(names, count);
		}
	}

	/*
	 * OpenWrt's netifd, on every stock router. Its file says what it holds and
	 * has no way of saying it has stepped aside, so a stopped netifd is the
	 * withdrawal: `/etc/init.d/network stop`, or the device taken out of it.
	 */
	names = NULL;
	count = 0u;
	if (netifd && where->etc_root) {
		if (!netifd_claims(where->etc_root, claims, claim_count, &names, &count)) {
			release_names(names, count);
			ncfg_contenders_free(out);
			ncfg_error_set(err, err_size,
			    "there was no memory to read what netifd claims");
			return 0;
		}
		if (count > 0u) {
			if (!push(out, "netifd", "take {} out of /etc/config/network, then "
			    "`/etc/init.d/network reload`", names, count)) {
				release_names(names, count);
				ncfg_contenders_free(out);
				ncfg_error_set(err, err_size,
				    "there was no memory to record what netifd claims");
				return 0;
			}
		} else {
			release_names(names, count);
		}
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * What to tell the operator
 * ------------------------------------------------------------------------ */

int ncfg_contender_remedy_for(const ncfg_contender_t *contender, const char *interface, char *out,
    size_t out_size)
{
	const char *placeholder;
	size_t      before;
	int         written;

	if (!out || out_size == 0u) {
		return 0;
	}
	out[0] = '\0';
	if (!contender || !contender->remedy || !interface) {
		return 0;
	}
	placeholder = strstr(contender->remedy, "{}");
	if (!placeholder) {
		written = snprintf(out, out_size, "%s", contender->remedy);
		return written >= 0 && (size_t)written < out_size;
	}
	before = (size_t)(placeholder - contender->remedy);
	written = snprintf(out, out_size, "%.*s%s%s", (int)before, contender->remedy, interface,
	    placeholder + 2);
	if (written < 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		return 0;
	}
	return 1;
}

int ncfg_contender_describe(const ncfg_contender_t *contender, ncfg_buf_t *buf, char *err,
    size_t err_size)
{
	size_t at;

	if (!contender || !buf) {
		ncfg_error_set(err, err_size, "there is nothing to describe, or nowhere to put it");
		return 0;
	}
	ncfg_buf_addf(buf, "%s also manages ", contender->name);
	for (at = 0u; at < contender->interface_count; at++) {
		ncfg_buf_add_text(buf, at > 0u ? ", " : "");
		ncfg_buf_add_text(buf, contender->interfaces[at]);
	}
	ncfg_buf_add_text(buf,
	    ". Two daemons on one interface will fight, and whichever applied last wins until "
	    "the other notices -- so this will look like the config working intermittently."
	    "\n\nHand over just this device with `");
	for (at = 0u; at < contender->interface_count; at++) {
		char command[NCFG_REMEDY_MAX];

		if (!ncfg_contender_remedy_for(contender, contender->interfaces[at], command,
		    sizeof(command))) {
			ncfg_error_set(err, err_size,
			    "the command for handing over `%s` does not fit in a message",
			    contender->interfaces[at]);
			return 0;
		}
		ncfg_buf_add_text(buf, at > 0u ? "` and `" : "");
		ncfg_buf_add_text(buf, command);
	}
	ncfg_buf_add_text(buf,
	    "`, or set `managed = false` on the device here."
	    "\n\nTo make netcfgd the only network daemon on the machine instead:\n\n"
	    "    mkdir -p /etc/systemd/system/netcfgd.service.d\n"
	    "    cp /usr/share/doc/netcfgd/netcfgd-exclusive.conf \\\n"
	    "        /etc/systemd/system/netcfgd.service.d/\n"
	    "    systemctl daemon-reload && systemctl restart netcfgd\n\n"
	    "That drop-in conflicts with NetworkManager, systemd-networkd, connman, "
	    "wpa_supplicant and ModemManager, so the init system stops them rather than "
	    "netcfgd killing anything itself.");
	if (ncfg_buf_failed(buf)) {
		ncfg_error_set(err, err_size,
		    "the message about %s did not fit in the buffer it was being built in",
		    contender->name);
		return 0;
	}
	return 1;
}
