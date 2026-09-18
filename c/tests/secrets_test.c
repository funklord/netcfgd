/*
 * secrets_test.c -- the rule the whole design exists for, proved rather than asserted.
 *
 * THE PROOF, AND WHY IT IS SHAPED LIKE THIS
 *   `secrets.h` says no secret material ever reaches a diagnostic, a log line
 *   or a rendered document. A comment saying so is worth nothing, and so is a
 *   test that checks one message: the leak, when it comes, will be in the
 *   *next* failure path somebody adds.
 *
 *   So: one value, `CANARY`, is the material for every provider this module
 *   has, and every failure this module can produce is driven with it. Three
 *   channels are then read back for that value:
 *
 *     * **every `err` buffer**, which is where a netcfgd failure is a sentence
 *       an operator reads;
 *     * **this process' whole standard error**, redirected to a file for the
 *       length of the run, which is where a log line would land -- and where a
 *       secret helper's own diagnostics would land if the exec provider let
 *       them through, which is the case `secrets.c` sends to `/dev/null`;
 *     * **a rendered document** that refers to the credential, because the
 *       document is written to `/run`, read by adapters and may eventually be
 *       transmitted.
 *
 *   **And the proof is checked for being vacuous.** A sweep that never handled
 *   the canary would pass exactly as loudly as one that handled it and kept
 *   quiet, so `ncfg_secret_expose` is asserted to return the canary first:
 *   the material really was in this process, and the channels really are
 *   empty.
 *
 * THE WALK
 *   `a_credential_in_every_shape_is_found` is what replaces the Rust's
 *   destructuring. There, a block list added to the model is a compile error
 *   in the walk; here it is a fixture carrying a credential in every shape the
 *   model has, asserted whole. Two of those shapes are in it because they were
 *   missed for as long as the field existed: an OpenVPN password and an access
 *   point's passphrase were each reported as used by nothing, in a document
 *   that named them -- which invites deleting a live credential.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY
 *   This machine has a real `/etc/netcfgd/secrets` with real credentials in
 *   it. Every path here is under one `mkdtemp` directory and the default is
 *   never reached: see `testdir.h`.
 */
#include "ncfg/base.h"
#include "ncfg/document.h"
#include "ncfg/secrets.h"

#include "testdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The value nothing may repeat. Distinctive enough that finding it in a buffer
 * is never a coincidence. */
#define CANARY "zq7-CANARY-passphrase-must-never-be-printed-4f1e"

static int failures;
/* Every `err` buffer this file has filled, end to end, swept at the end. */
static char every_message[64u * 1024u];
static size_t every_message_length;

static void check(int condition, const char *what)
{
	printf("%-64s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* Keep a diagnostic for the sweep, and hand it back for a caller that wants to
 * look at it now. */
static const char *kept(const char *message)
{
	size_t length = strlen(message);

	if (every_message_length + length + 2u < sizeof(every_message)) {
		memcpy(every_message + every_message_length, message, length);
		every_message_length += length;
		every_message[every_message_length++] = '\n';
		every_message[every_message_length] = '\0';
	}
	return message;
}

static char *join(const char *dir, const char *leaf)
{
	static char out[512];

	(void)snprintf(out, sizeof(out), "%s/%s", dir, leaf);
	return out;
}

/* ------------------------------------------------------------- the store */

static void a_name_has_to_be_usable_three_ways(void)
{
	char message[NCFG_ERROR_MAX];
	struct {
		const char *name;
		const char *why;
	} refused[] = {
		{ "", "it is empty" },
		{ "../../../etc/cron.d/x", "path separator" },
		{ "with/slash", "path separator" },
		{ ".hidden", "hidden file" },
		{ "two..dots", "hidden file" },
		{ "say \"what\"", "quote or a backslash" },
		{ "back\\slash", "quote or a backslash" },
		{ "bell\7here", "control character" },
		{ "0123456789012345678901234567890123456789012345678901234567890123456789",
		    "longer than 64 bytes" }
	};
	size_t i;
	int all = 1;

	for (i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
		message[0] = '\0';
		if (ncfg_secret_name_usable(refused[i].name, message, sizeof(message)) ||
		    !strstr(kept(message), refused[i].why)) {
			printf("  `%s` was not refused for being %s: %s\n", refused[i].name,
			    refused[i].why, message);
			all = 0;
		}
	}
	/* A name that reaches two `join`s from a socket request is the reason this
	 * is inside the store rather than left to a caller (0117): a validation a
	 * caller may skip is a validation a caller will skip. */
	check(all, "a name that cannot be a label, a filename and a secret name is refused");
	check(ncfg_secret_name_usable("corp-ca", message, sizeof(message)),
	    "and an ordinary one is not");
}

static void the_store_writes_tightly_and_never_reads_back(const char *config_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	char *path = NULL;

	check(!ncfg_secret_store_put(config_dir, "empty-one", "", 0, NULL, message,
	    sizeof(message)) && strstr(kept(message), "fails at the moment it is used"),
	    "an empty secret is refused now rather than at association time");

	check(ncfg_secret_store_put(config_dir, "wifi-canary", CANARY, 0, &path, message,
	    sizeof(message)) && path,
	    "a credential is stored");
	check(testdir_mode(path) == 0600, "at 0600, from the moment the file exists");
	check(testdir_mode(join(config_dir, "secrets")) == 0700,
	    "under a directory at 0700, from the moment it exists");

	message[0] = '\0';
	check(!ncfg_secret_store_put(config_dir, "wifi-canary", "something-else", 0, NULL,
	    message, sizeof(message)) && strstr(kept(message), "already exists"),
	    "replacing is refused unless it was asked for (0042)");
	check(ncfg_secret_store_put(config_dir, "wifi-canary", CANARY, 1, NULL, message,
	    sizeof(message)),
	    "and allowed when it was");

	check(ncfg_secret_store_remove(config_dir, "not-there-at-all", message, sizeof(message)),
	    "removing one that is not there is success: the caller asked for it to be gone");
	message[0] = '\0';
	check(!ncfg_secret_store_remove(config_dir, "../etc/passwd", message, sizeof(message)) &&
	    strstr(kept(message), "path separator"),
	    "and a name that would escape the directory is refused by the same rule");
	free(path);
}

/* ---------------------------------------------------------- the providers */

static void the_file_provider(const char *config_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_secret_resolver_t resolver;
	ncfg_secret_ref_t reference;
	ncfg_secret_error_t why = NCFG_SECRET_OK;
	ncfg_secret_t *secret;
	char *secrets_dir = strdup(join(config_dir, "secrets"));

	memset(&resolver, 0, sizeof(resolver));
	resolver.secrets_dir = secrets_dir;
	memset(&reference, 0, sizeof(reference));
	reference.provider = NCFG_SECRET_PROVIDER_FILE;
	reference.name = (char *)"wifi-canary";

	secret = ncfg_secret_resolve(&resolver, &reference, &why, message, sizeof(message));
	/*
	 * **The check that stops this whole file being vacuous.** If the material
	 * never reached this process, every sweep below would pass while proving
	 * nothing.
	 */
	check(secret && strcmp(ncfg_secret_expose(secret), CANARY) == 0,
	    "the file provider hands back exactly what was stored");
	check(secret && ncfg_secret_length(secret) == strlen(CANARY) &&
	    !ncfg_secret_is_empty(secret),
	    "and its length is safe to say, which a zero-length passphrase needs");
	/* What a format string is given when somebody reaches for the value: the
	 * word, never the material. */
	check(strcmp(ncfg_secret_redacted(), "<redacted>") == 0,
	    "and what a diagnostic may say about one is `<redacted>`");
	ncfg_secret_free(secret);

	/* One trailing newline is what an editor or `echo` leaves behind; a
	 * passphrase that silently included it fails to associate with no
	 * indication why. Anything further is the operator's. */
	check(testdir_write(join(config_dir, "secrets/trailing"), CANARY "\n\n", strlen(CANARY) + 2u),
	    "a credential an editor left two newlines on");
	(void)chmod(join(config_dir, "secrets/trailing"), (mode_t)0600);
	reference.name = (char *)"trailing";
	secret = ncfg_secret_resolve(&resolver, &reference, &why, message, sizeof(message));
	check(secret && strcmp(ncfg_secret_expose(secret), CANARY "\n") == 0,
	    "has exactly one newline taken off it");
	ncfg_secret_free(secret);

	message[0] = '\0';
	reference.name = (char *)"never-stored";
	secret = ncfg_secret_resolve(&resolver, &reference, &why, message, sizeof(message));
	check(!secret && why == NCFG_SECRET_NOT_FOUND &&
	    strstr(kept(message), "ncfg secret set never-stored"),
	    "a credential the machine does not have names the command that stores one");

	/* **Not there and cannot be looked at are different sentences.** Every
	 * failure used to become "not found", whose message tells the operator to
	 * run `ncfg secret set` -- advice that is destructive if taken for a secret
	 * sitting right there behind a permission error. */
	check(testdir_write(join(config_dir, "secrets/exposed"), CANARY, strlen(CANARY)),
	    "a credential in a world-readable file");
	(void)chmod(join(config_dir, "secrets/exposed"), (mode_t)0644);
	message[0] = '\0';
	reference.name = (char *)"exposed";
	secret = ncfg_secret_resolve(&resolver, &reference, &why, message, sizeof(message));
	check(!secret && why == NCFG_SECRET_EXPOSED && strstr(kept(message), "0644") &&
	    strstr(message, "chmod 600"),
	    "is refused rather than read, and the remedy is named");

	message[0] = '\0';
	reference.name = (char *)"../../etc/shadow";
	secret = ncfg_secret_resolve(&resolver, &reference, &why, message, sizeof(message));
	check(!secret && strstr(kept(message), "path separator"),
	    "a name that escapes the directory cannot read a file as root");

	free(secrets_dir);
}

static void the_other_providers(const char *work_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	char command[512];
	ncfg_secret_resolver_t resolver;
	ncfg_secret_ref_t reference;
	ncfg_secret_error_t why = NCFG_SECRET_OK;
	ncfg_secret_t *secret;
	static const char leaky[] = "#!/bin/sh\n"
	    "echo " CANARY "\n"
	    "echo " CANARY " 1>&2\n"
	    "exit 3\n";

	memset(&resolver, 0, sizeof(resolver));
	memset(&reference, 0, sizeof(reference));

	/* The command is the name, run through no shell: a shell would make the
	 * secrets directory a place where a configuration file becomes arbitrary
	 * code with word splitting and globbing attached. */
	reference.provider = NCFG_SECRET_PROVIDER_EXEC;
	(void)snprintf(command, sizeof(command), "/bin/echo %s", CANARY);
	reference.name = command;
	secret = ncfg_secret_resolve(&resolver, &reference, &why, message, sizeof(message));
	check(secret && strcmp(ncfg_secret_expose(secret), CANARY) == 0,
	    "the exec provider takes what the command printed, newline off");
	ncfg_secret_free(secret);

	/* A helper that prints the credential and then fails. Its own output is
	 * the thing most likely to carry the value it could not deliver. */
	check(testdir_write(join(work_dir, "leaky.sh"), leaky, sizeof(leaky) - 1u) &&
	    chmod(join(work_dir, "leaky.sh"), (mode_t)0700) == 0,
	    "a secret helper that prints what it failed to deliver");
	message[0] = '\0';
	reference.name = join(work_dir, "leaky.sh");
	secret = ncfg_secret_resolve(&resolver, &reference, &why, message, sizeof(message));
	check(!secret && why == NCFG_SECRET_FAILED && strstr(kept(message), "exited with 3"),
	    "is reported by its exit status and nothing it said");

	message[0] = '\0';
	reference.name = (char *)"/nonexistent/not-a-program-anywhere";
	secret = ncfg_secret_resolve(&resolver, &reference, &why, message, sizeof(message));
	check(!secret && why == NCFG_SECRET_FAILED, "a command that is not there is a failure");

	/* `pass` takes a store path, and a name that looks like a flag or carries
	 * a second word would become an argument to `pass` itself. Refused before
	 * anything runs, so this needs no `pass` on the machine. */
	reference.provider = NCFG_SECRET_PROVIDER_PASS;
	reference.name = (char *)"--help";
	message[0] = '\0';
	check(!ncfg_secret_resolve(&resolver, &reference, &why, message, sizeof(message)) &&
	    strstr(kept(message), "one word naming an entry"),
	    "a pass name that looks like a flag is refused before pass runs");
	reference.name = (char *)"work wifi";
	message[0] = '\0';
	check(!ncfg_secret_resolve(&resolver, &reference, &why, message, sizeof(message)) &&
	    strstr(kept(message), "one word naming an entry"),
	    "and so is one carrying a second word");

	reference.provider = NCFG_SECRET_PROVIDER_KEYRING;
	reference.name = (char *)"anything";
	message[0] = '\0';
	check(!ncfg_secret_resolve(&resolver, &reference, &why, message, sizeof(message)) &&
	    why == NCFG_SECRET_UNSUPPORTED && !strstr(kept(message), "M1"),
	    "the keyring says it is not implemented and names no milestone it will not meet");
}

static void the_first_line_rule(void)
{
	char message[NCFG_ERROR_MAX] = "";
	char command[512];
	ncfg_secret_resolver_t resolver;
	ncfg_secret_ref_t reference;
	ncfg_secret_t *whole;
	ncfg_secret_t *first;

	memset(&resolver, 0, sizeof(resolver));
	memset(&reference, 0, sizeof(reference));
	reference.provider = NCFG_SECRET_PROVIDER_EXEC;
	/* A store entry conventionally holds the secret on line one and notes
	 * below it. Taking the whole thing would hand a supplicant a passphrase
	 * with somebody's recovery codes appended, and the failure is an
	 * association that does not work for a reason nobody can see, because
	 * nothing will print the value. */
	(void)snprintf(command, sizeof(command), "/bin/printf %s\\n%s", CANARY,
	    "recovery-code-1234");
	reference.name = command;
	whole = ncfg_secret_resolve(&resolver, &reference, NULL, message, sizeof(message));
	first = ncfg_secret_first_line(whole);
	check(first && strcmp(ncfg_secret_expose(first), CANARY) == 0,
	    "a password-store entry gives up its first line and not its notes");
	ncfg_secret_free(first);
	ncfg_secret_free(whole);
}

static void a_stored_certificate_is_written_where_the_supplicant_can_read_it(const char *work_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_secret_resolver_t resolver;
	ncfg_cert_source_t source;
	ncfg_secret_error_t why = NCFG_SECRET_OK;
	char *first;
	char *second;
	char *certs_dir = strdup(join(work_dir, "certs"));
	char *secrets_dir = strdup(join(work_dir, "config/secrets"));

	memset(&resolver, 0, sizeof(resolver));
	resolver.secrets_dir = secrets_dir;
	memset(&source, 0, sizeof(source));
	source.has = 1;
	source.kind = NCFG_CERT_SOURCE_PATH;
	source.path = (char *)"/etc/ssl/certs/ca-certificates.crt";
	first = ncfg_secret_path_for(&resolver, &source, "ca.pem", &why, message, sizeof(message));
	check(first && strcmp(first, source.path) == 0,
	    "a certificate given as a path is handed back as it stands");
	free(first);

	source.kind = NCFG_CERT_SOURCE_STORED;
	source.stored.provider = NCFG_SECRET_PROVIDER_FILE;
	source.stored.name = (char *)"corp-ca";
	(void)ncfg_secret_store_put(join(work_dir, "config"), "corp-ca", CANARY "-ca", 1, NULL,
	    message, sizeof(message));
	(void)ncfg_secret_store_put(join(work_dir, "config"), "uni-ca", CANARY "-uni", 1, NULL,
	    message, sizeof(message));

	message[0] = '\0';
	first = ncfg_secret_path_for(&resolver, &source, "ca.pem", &why, message, sizeof(message));
	check(!first && strstr(kept(message), "nowhere to materialise"),
	    "a resolver with nowhere to write refuses rather than choosing a directory");

	resolver.materialise_dir = certs_dir;
	first = ncfg_secret_path_for(&resolver, &source, "ca.pem", &why, message, sizeof(message));
	source.stored.name = (char *)"uni-ca";
	second = ncfg_secret_path_for(&resolver, &source, "ca.pem", &why, message, sizeof(message));
	/*
	 * **The file is named after the credential, not after its role.** The role
	 * alone is a literal, so every network with a stored CA wrote one
	 * `ca.pem`; one supplicant is given every network in one loop, so the last
	 * rendered won for all of them and a machine with a work network and a
	 * university network validated **both** servers against whichever CA was
	 * written last. That is the corporate network trusting an authority it was
	 * never configured to trust.
	 */
	check(first && second && strcmp(first, second) != 0,
	    "two networks with different stored CAs get different files");
	check(first && testdir_mode(first) == 0600, "written at 0600, by the open");
	check(testdir_mode(certs_dir) == 0700, "under a directory at 0700");
	{
		char *body = first ? testdir_read(first, NULL) : NULL;

		check(body && strcmp(body, CANARY "-ca") == 0,
		    "and holding what the store says now, rewritten every time");
		free(body);
	}
	free(first);
	free(second);
	free(certs_dir);
	free(secrets_dir);
}

/* ---------------------------------------------------------------- the walk */

static char *own(const char *text)
{
	char *copy = strdup(text);

	if (!copy) {
		printf("out of memory building the fixture\n");
		exit(1);
	}
	return copy;
}

static ncfg_secret_ref_t *ref_to(const char *name)
{
	ncfg_secret_ref_t *reference = calloc(1u, sizeof(*reference));

	if (!reference) {
		printf("out of memory building the fixture\n");
		exit(1);
	}
	reference->provider = NCFG_SECRET_PROVIDER_FILE;
	reference->name = own(name);
	return reference;
}

static void stored_cert(ncfg_cert_source_t *source, const char *name)
{
	source->has = 1;
	source->kind = NCFG_CERT_SOURCE_STORED;
	source->stored.provider = NCFG_SECRET_PROVIDER_FILE;
	source->stored.name = own(name);
}

/*
 * One document carrying a credential in **every** shape the model has.
 *
 * Built rather than parsed, because what is being tested is the walk over the
 * structure and a fixture in text would prove the reader as well.
 */
static ncfg_document_t *every_shape(void)
{
	char message[NCFG_ERROR_MAX];
	ncfg_document_t *document = ncfg_document_new(message, sizeof(message));
	ncfg_device_t *device;
	ncfg_interface_t *interface;
	ncfg_wifi_network_t *network;
	ncfg_access_point_t *access_point;

	if (!document) {
		printf("could not make a document: %s\n", message);
		exit(1);
	}
	document->devices = calloc(3u, sizeof(*document->devices));
	document->interfaces = calloc(1u, sizeof(*document->interfaces));
	document->networks = calloc(2u, sizeof(*document->networks));
	document->access_points = calloc(1u, sizeof(*document->access_points));
	if (!document->devices || !document->interfaces || !document->networks ||
	    !document->access_points) {
		printf("out of memory building the fixture\n");
		exit(1);
	}
	document->device_count = 3u;
	document->interface_count = 1u;
	document->network_count = 2u;
	document->access_point_count = 1u;

	/* A WireGuard key belongs to the thing being created (0155), and a peer
	 * may have a preshared one. */
	device = &document->devices[0];
	device->name = own("wg0");
	device->kind.kind = NCFG_KIND_WIREGUARD;
	device->kind.wireguard.private_key.provider = NCFG_SECRET_PROVIDER_FILE;
	device->kind.wireguard.private_key.name = own("wg-key");
	device->kind.wireguard.peers = calloc(1u, sizeof(*device->kind.wireguard.peers));
	if (!device->kind.wireguard.peers) {
		exit(1);
	}
	device->kind.wireguard.peer_count = 1u;
	device->kind.wireguard.peers[0].name = own("hub");
	device->kind.wireguard.peers[0].preshared_key = ref_to("wg-preshared");

	device = &document->devices[1];
	device->name = own("ppp0");
	device->kind.kind = NCFG_KIND_PPPOE;
	device->kind.pppoe.parent = own("eth0");
	device->kind.pppoe.username = own("someone");
	device->kind.pppoe.password.provider = NCFG_SECRET_PROVIDER_FILE;
	device->kind.pppoe.password.name = own("pppoe-password");

	/* Missed for as long as the field existed: a stored `.ovpn` password
	 * reported as used by nothing, in a document that named it. */
	device = &document->devices[2];
	device->name = own("vpn0");
	device->kind.kind = NCFG_KIND_OPENVPN;
	device->kind.openvpn.config = own("/etc/openvpn/work.ovpn");
	device->kind.openvpn.password = ref_to("openvpn-password");

	interface = &document->interfaces[0];
	interface->name = own("eth0");
	interface->enabled = 1;
	interface->dot1x = calloc(1u, sizeof(*interface->dot1x));
	if (!interface->dot1x) {
		exit(1);
	}
	interface->dot1x->method = NCFG_EAP_METHOD_PEAP;
	interface->dot1x->identity = own("someone@example.com");
	interface->dot1x->password = ref_to("wired-8021x");
	/* Only a **stored** key is a secret this command put there. One given as a
	 * path is a file the operator manages. */
	stored_cert(&interface->dot1x->private_key, "wired-client-key");

	network = &document->networks[0];
	network->id = own("Cafe");
	network->security.kind = NCFG_SECURITY_PSK;
	network->security.psk.passphrase.provider = NCFG_SECRET_PROVIDER_FILE;
	network->security.psk.passphrase.name = own("cafe-psk");

	network = &document->networks[1];
	network->id = own("Work");
	network->security.kind = NCFG_SECURITY_EAP;
	network->security.eap.method = NCFG_EAP_METHOD_TLS;
	network->security.eap.password = ref_to("work-password");
	stored_cert(&network->security.eap.ca_cert, "corp-ca");
	stored_cert(&network->security.eap.client_cert, "corp-cert");
	stored_cert(&network->security.eap.private_key, "corp-key");

	/* The list was walked for networks only, so a hostapd passphrase this
	 * command had stored was reported as used by nothing. */
	access_point = &document->access_points[0];
	access_point->id = own("Guest");
	access_point->security.kind = NCFG_SECURITY_PSK;
	access_point->security.psk.passphrase.provider = NCFG_SECRET_PROVIDER_FILE;
	access_point->security.psk.passphrase.name = own("guest-psk");
	return document;
}

static int entry_says(const ncfg_secret_entry_t *entries, size_t count, const char *name,
    const char *user)
{
	size_t i;
	size_t j;

	for (i = 0; i < count; i++) {
		if (strcmp(entries[i].name, name) != 0) {
			continue;
		}
		if (!user) {
			return 1;
		}
		for (j = 0; j < entries[i].used_by_count; j++) {
			if (strcmp(entries[i].used_by[j], user) == 0) {
				return 1;
			}
		}
		printf("  `%s` is not used by `%s` but by %zu other block(s)\n", name, user,
		    entries[i].used_by_count);
		for (j = 0; j < entries[i].used_by_count; j++) {
			printf("    %s\n", entries[i].used_by[j]);
		}
		return 0;
	}
	printf("  `%s` is not in the list at all\n", name);
	return 0;
}

static void a_credential_in_every_shape_is_found(const char *config_dir)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_document_t *document = every_shape();
	ncfg_secret_entry_t *entries = NULL;
	size_t count = 0;
	struct {
		const char *name;
		const char *user;
	} expected[] = {
		{ "wg-key", "interface wg0 (private key)" },
		{ "wg-preshared", "interface wg0 (peer hub)" },
		{ "pppoe-password", "interface ppp0" },
		{ "openvpn-password", "interface vpn0" },
		{ "wired-8021x", "interface eth0 (802.1X)" },
		{ "wired-client-key", "interface eth0 (802.1X client key)" },
		{ "cafe-psk", "network Cafe" },
		{ "work-password", "network Work" },
		{ "corp-ca", "network Work (CA certificate)" },
		{ "corp-cert", "network Work (client certificate)" },
		{ "corp-key", "network Work (client key)" },
		{ "guest-psk", "access point Guest" }
	};
	size_t i;
	int all = 1;

	check(ncfg_secret_list(config_dir, document, &entries, &count, message, sizeof(message)),
	    "the document is walked for credentials");
	for (i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
		all = entry_says(entries, count, expected[i].name, expected[i].user) && all;
	}
	check(all, "a credential in every shape the model has is found, and named for its block");

	/* The union of two sets rather than either alone: a stored name nothing
	 * refers to is a credential still on the machine after whatever wanted it
	 * was deleted. */
	check(entry_says(entries, count, "wifi-canary", NULL),
	    "a stored credential nothing refers to is listed too");
	for (i = 0; i < count; i++) {
		if (strcmp(entries[i].name, "wifi-canary") == 0) {
			check(entries[i].stored && entries[i].used_by_count == 0u,
			    "as stored, and used by nothing");
		}
		if (strcmp(entries[i].name, "cafe-psk") == 0) {
			/* A referenced name with no file is a network that will never
			 * join, and it fails at association time with an error about the
			 * radio rather than about the missing passphrase. */
			check(!entries[i].stored, "and a referenced one with no file is not stored");
		}
	}
	for (i = 1; i < count; i++) {
		all = all && strcmp(entries[i - 1u].name, entries[i].name) < 0;
	}
	check(all, "and the list is sorted by name, with no repeats");

	{
		char **users = NULL;
		size_t user_count = 0;

		check(ncfg_secret_referring_to(document, "corp-ca", &users, &user_count, message,
		    sizeof(message)) && user_count == 1u &&
		    strcmp(users[0], "network Work (CA certificate)") == 0,
		    "and one name can be asked about on its own");
		ncfg_secret_names_free(users, user_count);

		check(ncfg_secret_referring_to(document, "nothing-uses-this", &users, &user_count,
		    message, sizeof(message)) && user_count == 0u,
		    "a name nothing uses is an empty list, which is the honest answer");
		ncfg_secret_names_free(users, user_count);

		/* The same walk pointed at one block, through the same function, so a
		 * model growing a fifth place to keep a credential cannot be covered
		 * there and missed here. */
		check(ncfg_secret_named_by(&document->networks[1].security, &users, &user_count,
		    message, sizeof(message)) && user_count == 4u,
		    "one block names every credential it refers to and no more");
		ncfg_secret_names_free(users, user_count);
	}
	ncfg_secret_entries_free(entries, count);
	ncfg_document_free(document);
}

/* -------------------------------------------------- the rule, swept for */

static void the_document_carries_the_reference_and_never_the_material(void)
{
	char message[NCFG_ERROR_MAX] = "";
	ncfg_document_t *document = every_shape();
	ncfg_buf_t buf;

	ncfg_buf_init(&buf, 0);
	check(ncfg_document_write(document, &buf, message, sizeof(message)),
	    "a document naming every credential is rendered");
	/* The document is written to `/run`, read by adapters and may eventually
	 * be transmitted. Making the type incapable of carrying a passphrase
	 * closes that door structurally rather than by policy. */
	check(!strstr(ncfg_buf_text(&buf), CANARY),
	    "and carries no secret material, only the names");
	check(strstr(ncfg_buf_text(&buf), "cafe-psk") != NULL,
	    "the names being there is what makes that a real check");
	ncfg_buf_free(&buf);
	ncfg_document_free(document);
}

int main(void)
{
	const char *work_dir = testdir_make("secrets");
	char *config_dir = strdup(join(work_dir, "config"));
	int saved_stderr = dup(STDERR_FILENO);
	char *log_path = strdup(join(work_dir, "stderr.log"));
	int log = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	printf("== secrets_test in %s\n", work_dir);
	/* Everything netcfgd would log goes here for the length of the run, and is
	 * swept at the end. A leak into a log line is the one this module's whole
	 * design exists to stop: a passphrase in a log is a passphrase in every
	 * log aggregator downstream. */
	if (log >= 0) {
		(void)dup2(log, STDERR_FILENO);
		(void)close(log);
	}

	a_name_has_to_be_usable_three_ways();
	the_store_writes_tightly_and_never_reads_back(config_dir);
	the_file_provider(config_dir);
	the_other_providers(work_dir);
	the_first_line_rule();
	a_stored_certificate_is_written_where_the_supplicant_can_read_it(work_dir);
	a_credential_in_every_shape_is_found(config_dir);
	the_document_carries_the_reference_and_never_the_material();

	if (saved_stderr >= 0) {
		(void)dup2(saved_stderr, STDERR_FILENO);
		(void)close(saved_stderr);
	}
	{
		size_t length = 0;
		char *said = testdir_read(log_path, &length);

		check(said && !strstr(said, CANARY),
		    "nothing this module said on stderr carries the material");
		if (said && length) {
			printf("    (it said %zu bytes, none of them the value)\n", length);
		}
		free(said);
	}
	check(every_message_length > 0u && !strstr(every_message, CANARY),
	    "and neither does any of the diagnostics it handed back");
	printf("    (%zu bytes of diagnostics were swept)\n", every_message_length);

	free(config_dir);
	free(log_path);
	testdir_remove(work_dir);

	if (failures == 0) {
		printf("secrets_test: all checks passed\n");
	} else {
		printf("secrets_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
