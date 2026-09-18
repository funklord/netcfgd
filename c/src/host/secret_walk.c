/*
 * secret_walk.c -- every `@secret:` reference a document makes, and who makes it.
 *
 * ONE WALK, IN ONE PLACE
 *   `ncfg secret set` reports which blocks refer to a name, and the socket
 *   needs the same knowledge inverted -- every name and who refers to it. Two
 *   walks would be two chances to miss a shape when the model grows one, and
 *   the model has grown three since this was written: stored certificates, a
 *   WireGuard peer's preshared key, and 802.1X on a wired port.
 *
 * WHAT REPLACES THE COMPILER HERE
 *   The Rust destructures `Document`, so a block list added to the model is a
 *   compile error in the walk rather than a walk that quietly does not cover
 *   it. That is not available in C, and the defect it was put there for is
 *   real: the walk was written against field accesses and `access_points` was
 *   never walked at all, so a stored hostapd passphrase was reported as used
 *   by nothing -- in a document that named it, which invites deleting a live
 *   credential. The same shape had already happened to an OpenVPN password.
 *
 *   What stands in for it is a fixture rather than a comment.
 *   `secrets_test.c` builds one document carrying a credential in **every**
 *   shape the model has and asserts the whole result, name by name and user by
 *   user; a shape added to the model and not added here fails that assertion
 *   instead of being missing from a list nobody compares.
 *
 * NOTHING HERE READS A SECRET'S CONTENTS
 *   The store is consulted only for whether a file exists, which is what makes
 *   "referenced but not stored" -- a network that will never join -- answerable
 *   without handling the value.
 */
#include "ncfg/secrets.h"

#include "host_internal.h"
#include "ncfg/base.h"

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

/* A model string that a hand-built document may have left NULL. `%s` with one
 * is undefined behaviour, and this walk is handed documents from tests as well
 * as from the compiler. */
static const char *text(const char *maybe)
{
	return maybe ? maybe : "";
}

typedef struct {
	char  *name;
	char **users;
	size_t user_count;
	size_t user_capacity;
} entry_t;

typedef struct {
	entry_t *at;
	size_t   count;
	size_t   capacity;
	/* Sticky, like `ncfg_buf_t`'s: the walk is forty calls and a caller that
	 * checked each would be a caller that stopped checking. */
	int      failed;
} references_t;

static void references_free(references_t *refs)
{
	size_t i;

	for (i = 0; i < refs->count; i++) {
		free(refs->at[i].name);
		ncfg_host_strings_free(refs->at[i].users, refs->at[i].user_count);
	}
	free(refs->at);
	memset(refs, 0, sizeof(*refs));
}

static entry_t *entry_for(references_t *refs, const char *name)
{
	size_t i;

	for (i = 0; i < refs->count; i++) {
		if (strcmp(refs->at[i].name, name) == 0) {
			return &refs->at[i];
		}
	}
	if (refs->count == refs->capacity) {
		size_t want = refs->capacity ? refs->capacity * 2u : 8u;
		entry_t *grown = realloc(refs->at, want * sizeof(*grown));

		if (!grown) {
			refs->failed = 1;
			return NULL;
		}
		refs->at = grown;
		refs->capacity = want;
	}
	memset(&refs->at[refs->count], 0, sizeof(refs->at[refs->count]));
	refs->at[refs->count].name = strdup(name);
	if (!refs->at[refs->count].name) {
		refs->failed = 1;
		return NULL;
	}
	return &refs->at[refs->count++];
}

/*
 * Record that `what` refers to `reference`.
 *
 * An empty `what` records the name alone, which is what `ncfg_secret_named_by`
 * wants: it asks which credentials a block names, not who names them, and
 * sharing this function is what keeps the two answers from diverging.
 */
static void note(references_t *refs, const char *what, const ncfg_secret_ref_t *reference)
{
	entry_t *entry;

	if (refs->failed || !reference || !reference->name) {
		return;
	}
	entry = entry_for(refs, reference->name);
	if (!entry || !what || !what[0]) {
		return;
	}
	if (!ncfg_host_strings_add(&entry->users, &entry->user_count, &entry->user_capacity, what)) {
		refs->failed = 1;
	}
}

/* `note`, with the description built from a format. */
static void notef(references_t *refs, const ncfg_secret_ref_t *reference, const char *format, ...)
{
	char what[256];
	va_list args;

	if (refs->failed) {
		return;
	}
	va_start(args, format);
	(void)vsnprintf(what, sizeof(what), format, args);
	va_end(args);
	note(refs, what, reference);
}

/*
 * Every secret one `security` block refers to, however the block that holds it
 * is spelled.
 *
 * Shared by `network` and `access_point` because they carry the same type, and
 * a second copy of this decision is a second chance to miss a case when the
 * model grows one -- which is exactly how access points came to be left out of
 * the walk in the first place.
 */
static void note_security(references_t *refs, const char *what, const ncfg_security_t *security)
{
	switch (security->kind) {
	case NCFG_SECURITY_PSK:
		note(refs, what, &security->psk.passphrase);
		break;
	case NCFG_SECURITY_EAP:
		if (security->eap.password) {
			note(refs, what, security->eap.password);
		}
		if (security->eap.private_key.has &&
		    security->eap.private_key.kind == NCFG_CERT_SOURCE_STORED) {
			notef(refs, &security->eap.private_key.stored, "%s (client key)", what);
		}
		/* The certificates too, now that they can be stored content: a client
		 * sends `ca_cert = "@secret:corp-ca"` and this is what tells the
		 * operator the store has it. */
		if (security->eap.ca_cert.has &&
		    security->eap.ca_cert.kind == NCFG_CERT_SOURCE_STORED) {
			notef(refs, &security->eap.ca_cert.stored, "%s (CA certificate)", what);
		}
		if (security->eap.client_cert.has &&
		    security->eap.client_cert.kind == NCFG_CERT_SOURCE_STORED) {
			notef(refs, &security->eap.client_cert.stored, "%s (client certificate)", what);
		}
		break;
	case NCFG_SECURITY_OPEN:
	case NCFG_SECURITY_OWE:
	default:
		break;
	}
}

static void references_of(references_t *refs, const ncfg_document_t *document)
{
	size_t i;
	size_t j;

	if (!document) {
		return;
	}
	/*
	 * What is deliberately **not** walked, so that a reader can see it was
	 * considered rather than forgotten: a schema version and a provenance
	 * string cannot name a secret; globals hold policy and not credentials; a
	 * Bluetooth device is an address and a profile, with no pairing key in the
	 * model; a routing rule is selectors and a table; a linkset is a name and
	 * a list of names.
	 */

	/* Devices: a WireGuard key belongs to the thing being created (0155). */
	for (i = 0; i < document->device_count; i++) {
		const ncfg_device_t *device = &document->devices[i];

		if (device->kind.kind == NCFG_KIND_WIREGUARD) {
			notef(refs, &device->kind.wireguard.private_key, "interface %s (private key)",
			    text(device->name));
			for (j = 0; j < device->kind.wireguard.peer_count; j++) {
				const ncfg_wg_peer_t *peer = &device->kind.wireguard.peers[j];

				if (peer->preshared_key) {
					notef(refs, peer->preshared_key, "interface %s (peer %s)",
					    text(device->name), text(peer->name));
				}
			}
		}
		if (device->kind.kind == NCFG_KIND_PPPOE) {
			notef(refs, &device->kind.pppoe.password, "interface %s", text(device->name));
		}
		/* And an OpenVPN tunnel's, which was missed for as long as the field
		 * existed: a stored `.ovpn` password reported as used by nothing, in a
		 * document that named it, which invites deleting a live credential. */
		if (device->kind.kind == NCFG_KIND_OPENVPN && device->kind.openvpn.password) {
			notef(refs, device->kind.openvpn.password, "interface %s", text(device->name));
		}
	}

	for (i = 0; i < document->interface_count; i++) {
		const ncfg_interface_t *interface = &document->interfaces[i];

		if (!interface->dot1x) {
			continue;
		}
		if (interface->dot1x->password) {
			notef(refs, interface->dot1x->password, "interface %s (802.1X)",
			    text(interface->name));
		}
		/* **Only a stored key is a secret this command put there.** One given
		 * as a path is a file the operator manages, and reporting it as an
		 * unused secret would be wrong in both directions -- it is not this
		 * store's, and `ncfg secret set` cannot create it. */
		if (interface->dot1x->private_key.has &&
		    interface->dot1x->private_key.kind == NCFG_CERT_SOURCE_STORED) {
			notef(refs, &interface->dot1x->private_key.stored,
			    "interface %s (802.1X client key)", text(interface->name));
		}
	}

	for (i = 0; i < document->network_count; i++) {
		char what[160];

		(void)snprintf(what, sizeof(what), "network %s", text(document->networks[i].id));
		note_security(refs, what, &document->networks[i].security);
	}
	/* Access points too. The list was walked for networks only, so a hostapd
	 * passphrase this command had stored was reported as used by nothing. */
	for (i = 0; i < document->access_point_count; i++) {
		char what[160];

		(void)snprintf(what, sizeof(what), "access point %s", text(document->access_points[i].id));
		note_security(refs, what, &document->access_points[i].security);
	}

	for (i = 0; i < refs->count; i++) {
		ncfg_host_strings_sort_unique(refs->at[i].users, &refs->at[i].user_count);
	}
}

void ncfg_secret_names_free(char **names, size_t count)
{
	ncfg_host_strings_free(names, count);
}

void ncfg_secret_entries_free(ncfg_secret_entry_t *entries, size_t count)
{
	size_t i;

	if (!entries) {
		return;
	}
	for (i = 0; i < count; i++) {
		free(entries[i].name);
		ncfg_host_strings_free(entries[i].used_by, entries[i].used_by_count);
	}
	free(entries);
}

int ncfg_secret_named_by(const ncfg_security_t *security, char ***out, size_t *count_out,
    char *err, size_t err_size)
{
	references_t refs;
	char **names = NULL;
	size_t count = 0;
	size_t capacity = 0;
	size_t i;
	int failed;

	if (!out || !count_out) {
		ncfg_error_set(err, err_size, "the names were asked for with nowhere to put them");
		return 0;
	}
	*out = NULL;
	*count_out = 0;
	memset(&refs, 0, sizeof(refs));
	if (!security) {
		return 1;
	}
	/* The same walk as the document's, pointed at one block: `""` records the
	 * name and nothing about who named it. */
	note_security(&refs, "", security);
	for (i = 0; i < refs.count && !refs.failed; i++) {
		if (!ncfg_host_strings_add(&names, &count, &capacity, refs.at[i].name)) {
			refs.failed = 1;
		}
	}
	failed = refs.failed;
	references_free(&refs);
	if (failed) {
		ncfg_host_strings_free(names, count);
		ncfg_error_set(err, err_size, "out of memory walking a block for credentials");
		return 0;
	}
	ncfg_host_strings_sort_unique(names, &count);
	*out = names;
	*count_out = count;
	return 1;
}

int ncfg_secret_referring_to(const ncfg_document_t *document, const char *name, char ***out,
    size_t *count_out, char *err, size_t err_size)
{
	references_t refs;
	char **users = NULL;
	size_t count = 0;
	size_t capacity = 0;
	size_t i;
	int failed;

	if (!out || !count_out) {
		ncfg_error_set(err, err_size, "the blocks were asked for with nowhere to put them");
		return 0;
	}
	*out = NULL;
	*count_out = 0;
	memset(&refs, 0, sizeof(refs));
	references_of(&refs, document);
	for (i = 0; i < refs.count && !refs.failed && name; i++) {
		size_t j;

		if (strcmp(refs.at[i].name, name) != 0) {
			continue;
		}
		for (j = 0; j < refs.at[i].user_count; j++) {
			if (!ncfg_host_strings_add(&users, &count, &capacity, refs.at[i].users[j])) {
				refs.failed = 1;
				break;
			}
		}
	}
	failed = refs.failed;
	references_free(&refs);
	if (failed) {
		ncfg_host_strings_free(users, count);
		ncfg_error_set(err, err_size, "out of memory walking the document for credentials");
		return 0;
	}
	/* A missing name is an empty list, which is the honest answer for a stored
	 * secret nothing uses. */
	*out = users;
	*count_out = count;
	return 1;
}

int ncfg_secret_list(const char *config_dir, const ncfg_document_t *document,
    ncfg_secret_entry_t **out, size_t *count_out, char *err, size_t err_size)
{
	references_t refs;
	char **names = NULL;
	size_t name_count = 0;
	size_t name_capacity = 0;
	char *dir = NULL;
	DIR *open_dir;
	ncfg_secret_entry_t *entries = NULL;
	size_t i;
	int ok = 1;

	if (!out || !count_out) {
		ncfg_error_set(err, err_size, "the secrets were asked for with nowhere to put them");
		return 0;
	}
	*out = NULL;
	*count_out = 0;
	memset(&refs, 0, sizeof(refs));
	references_of(&refs, document);
	for (i = 0; i < refs.count && !refs.failed; i++) {
		if (!ncfg_host_strings_add(&names, &name_count, &name_capacity, refs.at[i].name)) {
			refs.failed = 1;
		}
	}
	if (config_dir) {
		dir = ncfg_host_join(config_dir, "secrets", err, err_size);
		if (!dir) {
			refs.failed = 1;
		}
	}
	/* A directory that is not there is a machine with nothing stored, which is
	 * every machine before the first `ncfg secret set`. */
	open_dir = dir ? opendir(dir) : NULL;
	if (open_dir) {
		const struct dirent *found;

		while (!refs.failed && (found = readdir(open_dir)) != NULL) {
			char *path;
			struct stat about;

			/* A directory in there is not a secret, and neither is a name
			 * that is not a plain file -- `@secret:` cannot spell either. */
			if (strcmp(found->d_name, ".") == 0 || strcmp(found->d_name, "..") == 0) {
				continue;
			}
			path = ncfg_host_join(dir, found->d_name, err, err_size);
			if (!path) {
				refs.failed = 1;
				break;
			}
			if (lstat(path, &about) == 0 && S_ISREG(about.st_mode) &&
			    !ncfg_host_strings_add(&names, &name_count, &name_capacity,
			    found->d_name)) {
				refs.failed = 1;
			}
			free(path);
		}
		(void)closedir(open_dir);
	}
	ncfg_host_strings_sort_unique(names, &name_count);

	if (!refs.failed && name_count) {
		entries = calloc(name_count, sizeof(*entries));
		if (!entries) {
			refs.failed = 1;
		}
	}
	for (i = 0; i < name_count && !refs.failed; i++) {
		size_t which;

		entries[i].name = names[i];
		names[i] = NULL;
		if (dir) {
			char *path = ncfg_host_join(dir, entries[i].name, err, err_size);
			struct stat about;

			if (!path) {
				refs.failed = 1;
				break;
			}
			/* `stat` rather than `lstat`: a symlink to a 0600 file in the
			 * operator's own tree is a stored secret as far as everything
			 * that reads one is concerned. */
			entries[i].stored = stat(path, &about) == 0 && S_ISREG(about.st_mode);
			free(path);
		}
		for (which = 0; which < refs.count; which++) {
			size_t j;
			size_t capacity = 0;

			if (strcmp(refs.at[which].name, entries[i].name) != 0) {
				continue;
			}
			for (j = 0; j < refs.at[which].user_count; j++) {
				if (!ncfg_host_strings_add(&entries[i].used_by,
				    &entries[i].used_by_count, &capacity,
				    refs.at[which].users[j])) {
					refs.failed = 1;
					break;
				}
			}
			break;
		}
	}

	if (refs.failed) {
		ncfg_secret_entries_free(entries, name_count);
		entries = NULL;
		ncfg_error_set(err, err_size, "out of memory listing the credentials");
		ok = 0;
	}
	ncfg_host_strings_free(names, name_count);
	free(dir);
	references_free(&refs);
	if (!ok) {
		return 0;
	}
	*out = entries;
	*count_out = name_count;
	return 1;
}
