/*
 * wifi_profile_test.c -- the `network` block writer, and what it refuses.
 *
 * WHAT THESE CASES ARE FOR
 *   Most of them are `crates/netcfgd-host/src/wifi_profile.rs`'s own, carried
 *   across with the defect each names, because the case is the expensive half
 *   to rediscover: an id that would leave the directory, a round trip that
 *   catches a field which did not survive, a credential that must not be
 *   clobbered. Three groups beyond those:
 *
 *   * **Every field the block can carry is written and read back.** section 10.160
 *     records five fields `ncfg profile save` drops with nothing comparing
 *     what went in against what came out; the answer here is that the install
 *     *is* that comparison, so a renderer that stops writing a key makes the
 *     install fail rather than producing a file that quietly means something
 *     else. Sabotaging any one `add_key` call is what that check is measured
 *     against.
 *   * **Nothing is left behind by a refusal**, in either direction: a block
 *     that would not compile takes its credential with it, and a credential
 *     that was already there is never overwritten.
 *   * **The credential reaches the file and nothing else.** One canary value
 *     is the passphrase of every secured network below, and three channels are
 *     read back for it at the end: every `err` buffer this file filled, the
 *     whole of this process' standard error, and every `network` block that
 *     was written. The sweep is checked for being vacuous -- the canary must
 *     be in the secret file, byte for byte, or the write never happened and
 *     the absence everywhere else proves nothing.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY
 *   The real daemon runs on this machine with its real configuration in
 *   `/etc/netcfgd` and its real credentials in `/etc/netcfgd/secrets`. Every
 *   path here is under one `mkdtemp` directory and is passed explicitly;
 *   nothing falls back to a default.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/daemon.h"
#include "ncfg/document.h"
#include "ncfg/hooks.h"
#include "ncfg/lower.h"
#include "ncfg/secrets.h"
#include "ncfg/wifi_profile.h"

#include "testdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Distinctive enough that finding it in a buffer is never a coincidence, and a
 * legal WPA2 passphrase so that a length check is not what refuses it. */
#define CANARY "vq2-CANARY-network-credential-never-printed-8a3d"

static int failures;

static void check(int condition, const char *what)
{
	printf("%-72s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static void detail(const char *label, const char *body)
{
	printf("    %s: %s\n", label, body ? body : "(nothing)");
}

/* Every `err` buffer this file has filled, end to end, swept at the end. */
static char   every_message[64u * 1024u];
static size_t every_message_length;

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

/* ------------------------------------------------------------------------ *
 * A tree to work in
 * ------------------------------------------------------------------------ */

static char base[256];
static char config_dir[320];
static char factory_dir[320];

/* `<dir>/<leaf>` in one of a few rotating buffers, because half the cases
 * below join twice in one expression and a single buffer would quietly make
 * the two arguments the same string. */
static const char *in(const char *dir, const char *leaf)
{
	static char   buffers[8][512];
	static size_t next;
	char         *out = buffers[next];

	next = (next + 1u) % 8u;
	(void)snprintf(out, sizeof(buffers[0]), "%s/%s", dir, leaf);
	return out;
}

static void make_directory(const char *path)
{
	if (mkdir(path, 0755) != 0) {
		/* Already there is what every caller means. */
	}
}

/* A fresh, empty configuration directory for one case. */
static void fresh_tree(void)
{
	char command[1024];

	/*
	 * Removed by name through the tree this process made, and refused for
	 * anything else: `testdir_remove` will not touch a path that is not the
	 * one `mkdtemp` handed back, and this rebuilds inside it.
	 */
	(void)snprintf(command, sizeof(command), "%s/conf.d", config_dir);
	{
		DIR *open_dir = opendir(command);
		const struct dirent *found;

		if (open_dir) {
			while ((found = readdir(open_dir)) != NULL) {
				if (found->d_name[0] == '.') {
					continue;
				}
				(void)unlink(in(command, found->d_name));
			}
			(void)closedir(open_dir);
		}
	}
	(void)snprintf(command, sizeof(command), "%s/secrets", config_dir);
	{
		DIR *open_dir = opendir(command);
		const struct dirent *found;

		if (open_dir) {
			while ((found = readdir(open_dir)) != NULL) {
				if (found->d_name[0] == '.') {
					continue;
				}
				(void)unlink(in(command, found->d_name));
			}
			(void)closedir(open_dir);
		}
	}
	(void)unlink(in(config_dir, "netcfgd.conf"));
	(void)testdir_write(in(config_dir, "netcfgd.conf"), "", 0);
	make_directory(in(config_dir, "conf.d"));
}

/* What the machine compiles to now, or NULL. The unwritten sink, because this
 * is a question rather than an application and there is nowhere to put a
 * script. */
static ncfg_document_t *compiled(void)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *document;
	char                  err[NCFG_ERROR_MAX];

	if (!ncfg_config_load_with_profile(factory_dir, config_dir, &sources, err, sizeof(err))) {
		ncfg_config_sources_free(&sources);
		return NULL;
	}
	document = ncfg_config_compile(&sources, ncfg_hook_sink_unwritten(), NULL, err,
	    sizeof(err));
	ncfg_config_sources_free(&sources);
	return document;
}

static const ncfg_wifi_network_t *network_of(const ncfg_document_t *document, const char *id)
{
	size_t at;

	for (at = 0; document && at < document->network_count; at++) {
		if (document->networks[at].id && strcmp(document->networks[at].id, id) == 0) {
			return &document->networks[at];
		}
	}
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * Names and paths
 * ------------------------------------------------------------------------ */

static void a_name_is_three_things_at_once(void)
{
	char err[NCFG_ERROR_MAX];
	char name[NCFG_WIFI_PROFILE_NAME_MAX];
	char longest[NCFG_WIFI_PROFILE_ID_MAX + 2u];
	char *path;
	size_t at;
	static const char *const refused[] = { "", "../escape", "with/slash", ".hidden",
		"we\"ird", "back\\slash", "new\nline" };

	printf("\n-- an id is a block label, a filename and a credential's name\n");
	for (at = 0; at < sizeof(refused) / sizeof(refused[0]); at++) {
		check(!ncfg_wifi_profile_usable_id(refused[at], err, sizeof(err)),
		    at == 0 ? "an empty id is refused" : "  and so is one that is not a name");
		(void)kept(err);
	}
	for (at = 0; at < NCFG_WIFI_PROFILE_ID_MAX; at++) {
		longest[at] = 'a';
	}
	longest[NCFG_WIFI_PROFILE_ID_MAX] = '\0';
	check(ncfg_wifi_profile_usable_id(longest, err, sizeof(err)),
	    "exactly the bound is usable, and the bound is read from the header");
	longest[NCFG_WIFI_PROFILE_ID_MAX] = 'a';
	longest[NCFG_WIFI_PROFILE_ID_MAX + 1u] = '\0';
	check(!ncfg_wifi_profile_usable_id(longest, err, sizeof(err)), "  one past it is not");
	(void)kept(err);

	check(ncfg_wifi_profile_drop_in("home", name, sizeof(name), err, sizeof(err)) &&
	    strcmp(name, "wifi-home") == 0,
	    "the drop-in name is `wifi-<id>`, which is what a forget asks for");
	path = ncfg_wifi_profile_path("/etc/netcfgd", "home", err, sizeof(err));
	check(path && strcmp(path, "/etc/netcfgd/conf.d/wifi-home.conf") == 0,
	    "  and the file is that name under conf.d, where the loader reads");
	free(path);
	path = ncfg_wifi_profile_secret_path("/etc/netcfgd", "home", err, sizeof(err));
	check(path && strcmp(path, "/etc/netcfgd/secrets/home") == 0,
	    "  and the credential is under secrets, by the network's own label");
	free(path);
	path = ncfg_wifi_profile_secret_path("/etc/netcfgd", "../../shadow", err, sizeof(err));
	check(path == NULL, "a traversing id never becomes a path at all");
	(void)kept(err);
}

/* ------------------------------------------------------------------------ *
 * The block, as text
 * ------------------------------------------------------------------------ */

static void what_a_block_looks_like(void)
{
	ncfg_wifi_profile_t profile;
	ncfg_buf_t          text;
	char                err[NCFG_ERROR_MAX];

	printf("\n-- the block, kept to what was asked for\n");
	memset(&profile, 0, sizeof(profile));
	profile.id = "home";
	profile.ssid.has = 1;
	profile.ssid.length = 4u;
	memcpy(profile.ssid.bytes, "home", 4u);
	profile.security = NCFG_WIFI_SECURITY_PSK;

	ncfg_buf_init(&text, 0);
	check(ncfg_wifi_profile_render(&profile, &text, err, sizeof(err)), "a psk block renders");
	check(strstr(ncfg_buf_text(&text), "wifi { psk = \"@secret:home\" }") != NULL,
	    "  as one line, with the credential by reference and never by value");
	check(strstr(ncfg_buf_text(&text), "ssid =") == NULL,
	    "  with no `ssid` key, because the label is the ssid exactly");
	check(strstr(ncfg_buf_text(&text), "autoconnect") == NULL &&
	    strstr(ncfg_buf_text(&text), "metered") == NULL,
	    "  and nothing that was not asked for");
	ncfg_buf_free(&text);

	/* An ssid that is not the label is kept as hex, which is what makes a
	 * separate id lossless. */
	profile.id = "cafe";
	profile.ssid.length = 5u;
	memcpy(profile.ssid.bytes, "Caf\xc3\xa9", 5u);
	profile.hidden = 1;
	profile.proto = "wpa3";
	profile.metric.has = 1;
	profile.metric.value = 120;
	ncfg_buf_init(&text, 0);
	check(ncfg_wifi_profile_render(&profile, &text, err, sizeof(err)), "a pinned one renders");
	check(strstr(ncfg_buf_text(&text), "ssid = \"436166c3a9\"") != NULL,
	    "  with the ssid as lowercase hex when it is not the label");
	check(strstr(ncfg_buf_text(&text), "hidden = true") != NULL, "  with `hidden`");
	check(strstr(ncfg_buf_text(&text), "proto = \"wpa3\"") != NULL, "  with the generation");
	check(strstr(ncfg_buf_text(&text), "\tmetric = 120\n") != NULL,
	    "  and the metric beside the wifi block, which is where the parser reads it");
	ncfg_buf_free(&text);

	/* An enterprise network is seven keys, which reads badly on one line. */
	memset(&profile, 0, sizeof(profile));
	profile.id = "Corp";
	profile.ssid.has = 1;
	profile.ssid.length = 4u;
	memcpy(profile.ssid.bytes, "Corp", 4u);
	profile.security = NCFG_WIFI_SECURITY_EAP;
	profile.method = "peap";
	profile.identity = "you@example.ac.uk";
	profile.anonymous_identity = "anonymous@example.ac.uk";
	profile.ca_cert = "@secret:corp-ca";
	profile.phase2 = "mschapv2";
	ncfg_buf_init(&text, 0);
	check(ncfg_wifi_profile_render(&profile, &text, err, sizeof(err)), "an eap block renders");
	check(strstr(ncfg_buf_text(&text), "\twifi {\n") != NULL,
	    "  one key per line, because seven on one line is unreadable");
	check(strstr(ncfg_buf_text(&text), "password = \"@secret:Corp\"") != NULL,
	    "  with a password for peap");
	ncfg_buf_free(&text);

	profile.method = "tls";
	profile.client_cert = "@secret:corp-client";
	ncfg_buf_init(&text, 0);
	(void)ncfg_wifi_profile_render(&profile, &text, err, sizeof(err));
	check(strstr(ncfg_buf_text(&text), "private_key = \"@secret:Corp\"") != NULL &&
	    strstr(ncfg_buf_text(&text), "password") == NULL,
	    "  and a private key for tls, which is the other branch the prompt took");
	ncfg_buf_free(&text);

	/* A value that ended its own string would produce a file that does not
	 * compile, which takes every other interface on the machine with it. */
	profile.method = "ttls";
	profile.client_cert = NULL;
	profile.identity = "we\"ird\\one";
	ncfg_buf_init(&text, 0);
	(void)ncfg_wifi_profile_render(&profile, &text, err, sizeof(err));
	check(strstr(ncfg_buf_text(&text), "identity = \"we\\\"ird\\\\one\"") != NULL,
	    "a quote or a backslash in a value is escaped rather than ending the string");
	ncfg_buf_free(&text);
}

/* ------------------------------------------------------------------------ *
 * Installing
 * ------------------------------------------------------------------------ */

/* The profile every install case below starts from: open, and named after its
 * own ssid. */
static void plain(ncfg_wifi_profile_t *profile, const char *id)
{
	memset(profile, 0, sizeof(*profile));
	profile->id = id;
	profile->ssid.has = 1;
	profile->ssid.length = strlen(id);
	memcpy(profile->ssid.bytes, id, profile->ssid.length);
	profile->security = NCFG_WIFI_SECURITY_OPEN;
}

static void what_an_install_writes(void)
{
	ncfg_wifi_profile_t   profile;
	ncfg_wifi_installed_t written = { NULL, NULL };
	ncfg_document_t      *document;
	char                  err[NCFG_ERROR_MAX];
	char                 *body;
	int                   ok;

	printf("\n-- what an install writes, and what it proves afterwards\n");
	fresh_tree();
	plain(&profile, "Cafe");
	err[0] = '\0';
	ok = ncfg_wifi_profile_install(config_dir, factory_dir, &profile, NULL, 0u, &written,
	    NULL, err, sizeof(err));
	check(ok, kept(err[0] ? err : "an open network installs"));
	check(written.file && testdir_exists(written.file), "  the block is on disk");
	check(written.secret == NULL, "  and an open network stored nothing");
	check(written.file && testdir_mode(written.file) == 0644,
	    "  at 0644, which is a configuration file");
	document = compiled();
	check(network_of(document, "Cafe") != NULL,
	    "  and the machine compiles to a configuration with that network in it");
	ncfg_document_free(document);
	ncfg_wifi_installed_free(&written);

	/* Refused rather than overwritten: this does not clobber what it did not
	 * write, and the message names the file. */
	check(!ncfg_wifi_profile_install(config_dir, factory_dir, &profile, NULL, 0u, &written,
	        NULL, err, sizeof(err)) &&
	    strstr(kept(err), "refusing to overwrite a file this did not write") != NULL,
	    "a second install over the same block is refused");

	fresh_tree();
	plain(&profile, "Office");
	profile.security = NCFG_WIFI_SECURITY_PSK;
	err[0] = '\0';
	ok = ncfg_wifi_profile_install(config_dir, factory_dir, &profile, CANARY, strlen(CANARY),
	    &written, NULL, err, sizeof(err));
	check(ok, kept(err[0] ? err : "a secured network installs with its credential"));
	check(written.secret && testdir_mode(written.secret) == 0600,
	    "  the credential is 0600 from the moment the file exists");
	check(testdir_mode(in(config_dir, "secrets")) == 0700,
	    "  under a 0700 directory, made at that mode rather than tightened after");
	body = testdir_read(written.secret, NULL);
	check(body && strlen(body) == strlen(CANARY) && strcmp(body, CANARY) == 0,
	    "  and it holds exactly the bytes it was handed, with nothing added");
	free(body);
	body = testdir_read(written.file, NULL);
	check(body && strstr(body, "@secret:Office") != NULL && strstr(body, CANARY) == NULL,
	    "  while the block carries a reference and never the value");
	free(body);
	ncfg_wifi_installed_free(&written);

	/* A stored credential is never overwritten either -- and the block is not
	 * written over it, so nothing is half done. */
	(void)unlink(in(in(config_dir, "conf.d"), "wifi-Office.conf"));
	check(!ncfg_wifi_profile_install(config_dir, factory_dir, &profile, "another-one-8",
	        13u, &written, NULL, err, sizeof(err)) &&
	    strstr(kept(err), "refusing to overwrite a stored credential") != NULL,
	    "an existing credential is refused before anything is written");
	body = testdir_read(in(in(config_dir, "secrets"), "Office"), NULL);
	check(body && strcmp(body, CANARY) == 0, "  and the one that was there is untouched");
	free(body);
	check(!testdir_exists(in(in(config_dir, "conf.d"), "wifi-Office.conf")),
	    "  and no block was written beside it");
}

static void a_credential_that_cannot_be_one(void)
{
	ncfg_wifi_profile_t profile;
	char                err[NCFG_ERROR_MAX];
	char                with_nul[8];

	printf("\n-- a credential nothing downstream could carry\n");
	fresh_tree();
	plain(&profile, "Psk");
	profile.security = NCFG_WIFI_SECURITY_PSK;
	check(!ncfg_wifi_profile_install(config_dir, factory_dir, &profile, NULL, 0u, NULL, NULL,
	        err, sizeof(err)) &&
	    strstr(kept(err), "needs a credential") != NULL,
	    "a secured network with no credential is refused");
	check(!ncfg_wifi_profile_install(config_dir, factory_dir, &profile, "", 0u, NULL, NULL,
	        err, sizeof(err)) &&
	    strstr(kept(err), "empty credential") != NULL,
	    "  and an empty one is, because it fails when it is used rather than now");
	memcpy(with_nul, "ab\0cdefg", 8u);
	check(!ncfg_wifi_profile_install(config_dir, factory_dir, &profile, with_nul, 8u, NULL,
	        NULL, err, sizeof(err)) &&
	    strstr(kept(err), "NUL") != NULL,
	    "  and one carrying a NUL is, rather than being silently cut at it");
	check(!testdir_exists(in(in(config_dir, "conf.d"), "wifi-Psk.conf")) &&
	    !testdir_exists(in(in(config_dir, "secrets"), "Psk")),
	    "  and none of the three left a file behind");
}

static void an_id_that_escapes_the_directory(void)
{
	ncfg_wifi_profile_t profile;
	char                err[NCFG_ERROR_MAX];
	size_t              at;
	static const char *const bad[] = { "../escape", "with/slash", ".hidden", "", "we\"ird" };

	printf("\n-- an id is checked inside the install, not by a caller remembering\n");
	fresh_tree();
	for (at = 0; at < sizeof(bad) / sizeof(bad[0]); at++) {
		plain(&profile, bad[at]);
		check(!ncfg_wifi_profile_install(config_dir, factory_dir, &profile, NULL, 0u, NULL,
		        NULL, err, sizeof(err)) &&
		    strstr(kept(err), "cannot be used as") != NULL,
		    at == 0 ? "an id that would leave the directory is refused here"
		            : "  and so is every other name that is not one");
	}
	check(!testdir_exists(in(base, "escape")) && !testdir_exists(in(base, "escape.conf")),
	    "  and nothing was written anywhere above the configuration directory");
}

/*
 * Every field the block can carry, written and read back.
 *
 * **This is the answer to section 10.160 for this writer.** There, five fields are
 * dropped by a renderer with nothing comparing what went in against what came
 * out. Here the install *is* that comparison: the round trip inside it
 * compares the ssid, the hidden flag, the metric, the security kind, the
 * credential reference, the generation and all five enterprise fields against
 * the profile it was asked for, so a renderer that stops writing one makes the
 * install fail rather than producing a file that quietly means something else.
 *
 * Measured by sabotage: removing any one `add_key` call from `render` -- or
 * the `ssid`, `hidden` or `metric` line -- turns this from a pass into "did
 * not survive being written and read back", naming the field.
 */
static void every_field_survives_being_written(void)
{
	ncfg_wifi_profile_t   profile;
	ncfg_wifi_installed_t written = { NULL, NULL };
	ncfg_document_t      *document;
	const ncfg_wifi_network_t *network;
	char                  err[NCFG_ERROR_MAX];
	int                   ok;

	printf("\n-- every field goes in and comes back, which is the install's own check\n");
	fresh_tree();
	memset(&profile, 0, sizeof(profile));
	profile.id = "Corp";
	profile.ssid.has = 1;
	profile.ssid.length = 5u;
	memcpy(profile.ssid.bytes, "C\xc3\xb6rp", 5u);
	profile.hidden = 1;
	profile.metric.has = 1;
	profile.metric.value = 42;
	profile.security = NCFG_WIFI_SECURITY_EAP;
	profile.method = "ttls";
	profile.identity = "you@example.ac.uk";
	profile.anonymous_identity = "anonymous@example.ac.uk";
	profile.ca_cert = "@secret:corp-ca";
	profile.phase2 = "mschapv2";
	err[0] = '\0';
	ok = ncfg_wifi_profile_install(config_dir, factory_dir, &profile, CANARY, strlen(CANARY),
	    &written, NULL, err, sizeof(err));
	check(ok, kept(err[0] ? err : "a network with every field this can express installs"));

	document = compiled();
	network = network_of(document, "Corp");
	check(network != NULL, "  and the configuration has it");
	if (network) {
		check(network->ssid.length == 5u &&
		    memcmp(network->ssid.bytes, "C\xc3\xb6rp", 5u) == 0,
		    "  the ssid survived as the octets it was, not as text");
		check(network->hidden == 1, "  the hidden flag survived");
		check(network->metric.has && network->metric.value == 42, "  the metric survived");
		check(network->security.kind == NCFG_SECURITY_EAP, "  the security kind survived");
		check(network->security.eap.method == NCFG_EAP_METHOD_TTLS,
		    "  the eap method survived");
		check(network->security.eap.identity &&
		    strcmp(network->security.eap.identity, "you@example.ac.uk") == 0,
		    "  the identity survived a quoted string");
		check(network->security.eap.anonymous_identity &&
		    strcmp(network->security.eap.anonymous_identity,
		        "anonymous@example.ac.uk") == 0,
		    "  the anonymous identity survived");
		check(network->security.eap.ca_cert.has &&
		    network->security.eap.ca_cert.kind == NCFG_CERT_SOURCE_STORED &&
		    network->security.eap.ca_cert.stored.name &&
		    strcmp(network->security.eap.ca_cert.stored.name, "corp-ca") == 0,
		    "  the CA reference lowered to a stored source and never to a path");
		check(network->security.eap.phase2 &&
		    strcmp(network->security.eap.phase2, "mschapv2") == 0,
		    "  the phase 2 method survived");
		check(network->security.eap.password &&
		    network->security.eap.password->name &&
		    strcmp(network->security.eap.password->name, "Corp") == 0,
		    "  and the credential is referred to by the network's own label");
	}
	ncfg_document_free(document);
	ncfg_wifi_installed_free(&written);
}

/*
 * A block that would not compile takes its credential with it.
 *
 * The compile-back is not a formality: a generated file that does not compile
 * is worse than no file at all, because the loader compiles the directory as
 * one document and takes every other interface on the machine with it. The
 * collision here is a second `network` block with the same label, written by
 * hand -- which is exactly what a caller that skipped the duplicate check
 * would produce.
 */
static void nothing_is_left_behind_by_a_refusal(void)
{
	ncfg_wifi_profile_t profile;
	char                err[NCFG_ERROR_MAX];

	printf("\n-- a file that would not compile is taken back out, credential included\n");
	fresh_tree();
	(void)testdir_write(in(in(config_dir, "conf.d"), "10-theirs.conf"),
	    "network \"Clash\" { wifi { open = true } }\n", 41u);
	plain(&profile, "Clash");
	profile.security = NCFG_WIFI_SECURITY_PSK;
	check(!ncfg_wifi_profile_install(config_dir, factory_dir, &profile, CANARY,
	        strlen(CANARY), NULL, NULL, err, sizeof(err)) &&
	    strstr(kept(err), "does not compile") != NULL,
	    "a block colliding with one already there is refused by the compile-back");
	check(!testdir_exists(in(in(config_dir, "conf.d"), "wifi-Clash.conf")),
	    "  the block it wrote is gone again");
	check(!testdir_exists(in(in(config_dir, "secrets"), "Clash")),
	    "  and so is the credential, which is the half that would have been stranded");
}

/* ------------------------------------------------------------------------ *
 * Forgetting
 * ------------------------------------------------------------------------ */

static void forgetting_a_network(void)
{
	ncfg_wifi_profile_t   profile;
	ncfg_wifi_forgotten_t forgotten = { NULL, 0, NULL, 0 };
	ncfg_document_t      *document;
	char                  err[NCFG_ERROR_MAX];
	int                   ok;

	printf("\n-- taking one away, credential included\n");
	fresh_tree();
	plain(&profile, "Office");
	profile.security = NCFG_WIFI_SECURITY_PSK;
	if (!ncfg_wifi_profile_install(config_dir, factory_dir, &profile, CANARY, strlen(CANARY),
	        NULL, NULL, err, sizeof(err))) {
		check(0, kept(err));
		return;
	}
	document = compiled();
	err[0] = '\0';
	ok = ncfg_wifi_profile_forget(config_dir, factory_dir, document, "Office", &forgotten, NULL,
	    err, sizeof(err));
	check(ok, kept(err[0] ? err : "a network netcfgd wrote is forgotten"));
	check(!testdir_exists(in(in(config_dir, "conf.d"), "wifi-Office.conf")),
	    "  the block is gone");
	check(forgotten.removed_count == 1u && forgotten.removed[0] &&
	    strcmp(forgotten.removed[0], "Office") == 0,
	    "  and the credential went with it, by name");
	check(!testdir_exists(in(in(config_dir, "secrets"), "Office")),
	    "  which is to say the file is actually gone");
	check(forgotten.kept_count == 0u, "  and nothing was kept");
	ncfg_wifi_forgotten_free(&forgotten);
	ncfg_document_free(document);

	/* A credential something else still refers to stays, and the caller is
	 * told which -- a passphrase shared with an access point is still in use. */
	fresh_tree();
	(void)testdir_write(in(in(config_dir, "secrets"), "shared"), CANARY "\n",
	    strlen(CANARY) + 1u);
	(void)chmod(in(in(config_dir, "secrets"), "shared"), 0600);
	(void)testdir_write(in(in(config_dir, "conf.d"), "10-mine.conf"),
	    "network \"keepit\" { wifi { psk = \"@secret:shared\" } }\n", 52u);
	(void)testdir_write(in(in(config_dir, "conf.d"), "wifi-Guest.conf"),
	    "network \"Guest\" { wifi { psk = \"@secret:shared\" } }\n", 51u);
	document = compiled();
	err[0] = '\0';
	ok = ncfg_wifi_profile_forget(config_dir, factory_dir, document, "Guest", &forgotten, NULL,
	    err, sizeof(err));
	check(ok, kept(err[0] ? err : "a shared credential's network stops being configured"));
	check(forgotten.kept_count == 1u && forgotten.kept[0] &&
	    strcmp(forgotten.kept[0], "shared") == 0 && forgotten.removed_count == 0u,
	    "  and the credential stays, because something else still refers to it");
	check(testdir_exists(in(in(config_dir, "secrets"), "shared")),
	    "  which is to say the file is still there");
	ncfg_wifi_forgotten_free(&forgotten);
	ncfg_document_free(document);
}

static void what_a_forget_refuses(void)
{
	ncfg_wifi_forgotten_t forgotten = { NULL, 0, NULL, 0 };
	ncfg_document_t      *document;
	char                  err[NCFG_ERROR_MAX];

	printf("\n-- and what it will not take away\n");
	fresh_tree();
	/* Secured, and sharing its credential with nothing, so that the order the
	 * header promises is checkable: the drop-in goes first, and a refusal
	 * therefore leaves the credential exactly where it was. */
	(void)testdir_write(in(in(config_dir, "conf.d"), "10-theirs.conf"),
	    "network \"Theirs\" { wifi { psk = \"@secret:Theirs\" } }\n", 53u);
	(void)mkdir(in(config_dir, "secrets"), 0700);
	(void)testdir_write(in(in(config_dir, "secrets"), "Theirs"), CANARY, strlen(CANARY));
	(void)chmod(in(in(config_dir, "secrets"), "Theirs"), 0600);
	document = compiled();
	check(!ncfg_wifi_profile_forget(config_dir, factory_dir, document, "Theirs", &forgotten,
	        NULL, err, sizeof(err)) &&
	    strstr(kept(err), "not in a file netcfgd wrote") != NULL,
	    "a network somebody wrote themselves is not netcfgd's to remove");
	check(testdir_exists(in(in(config_dir, "conf.d"), "10-theirs.conf")),
	    "  and their file is still there");
	check(testdir_exists(in(in(config_dir, "secrets"), "Theirs")),
	    "  and so is its credential, which is what the drop-in-first order buys");
	check(!ncfg_wifi_profile_forget(config_dir, factory_dir, document, "Nope", &forgotten,
	        NULL, err, sizeof(err)) && strstr(kept(err), "Theirs") != NULL,
	    "an id that is not configured is refused, naming what there is");
	check(!ncfg_wifi_profile_forget(config_dir, factory_dir, NULL, "Theirs", &forgotten,
	        NULL, err, sizeof(err)) &&
	    strstr(kept(err), "no compiled configuration") != NULL,
	    "and a machine whose configuration does not compile is told so, not guessed at");
	check(!ncfg_wifi_profile_forget(config_dir, factory_dir, document, "../escape",
	        &forgotten, NULL, err, sizeof(err)),
	    "an id that is not a name never reaches a path here either");
	(void)kept(err);
	ncfg_document_free(document);
}

/* ------------------------------------------------------------------------ *
 * The seam the daemon installs
 * ------------------------------------------------------------------------ */

/*
 * `ncfg_wifi_configure_network` refused every caller for want of this.
 *
 * Driven here with the request the socket carries, so that the one path 0117
 * opened -- a client with no permission to write the file -- is exercised end
 * to end rather than up to the seam.
 */
static void the_daemon_s_seam_writes_the_same_file(void)
{
	ncfg_wifi_installer_t installer;
	ncfg_proto_wifi_add_t wanted;
	ncfg_buf_t            out;
	ncfg_document_t      *document;
	char                  err[NCFG_ERROR_MAX];
	char                 *body;
	int                   ok;

	printf("\n-- the seam `ncfg_wifi_configure_network` had no implementation for\n");
	fresh_tree();
	memset(&installer, 0, sizeof(installer));
	installer.config_dir = config_dir;
	installer.factory_dir = factory_dir;
	memset(&wanted, 0, sizeof(wanted));
	wanted.ssid = ncfg_proto_str("43616665");
	wanted.passphrase = ncfg_proto_str(CANARY);
	ncfg_buf_init(&out, 0);
	err[0] = '\0';
	ok = ncfg_wifi_configure_network(NULL, &wanted, ncfg_wifi_profile_installer, &installer,
	    &out, err, sizeof(err));
	check(ok, kept(err[0] ? err : "a request the socket carries reaches a file on disk"));
	check(installer.installed.file && testdir_exists(installer.installed.file),
	    "  the block is where the loader reads");
	body = testdir_read(in(in(config_dir, "secrets"), "Cafe"), NULL);
	check(body && strcmp(body, CANARY) == 0,
	    "  and the credential arrived byte for byte, never copied on the way");
	free(body);
	document = compiled();
	check(network_of(document, "Cafe") != NULL, "  and the machine compiles with it");
	ncfg_document_free(document);
	ncfg_wifi_installed_free(&installer.installed);
	ncfg_buf_free(&out);

	/* A caller with no directories is refused by name rather than writing
	 * somewhere this module chose. */
	ncfg_buf_init(&out, 0);
	check(!ncfg_wifi_profile_installer(NULL, NULL, NULL, 0u, err, sizeof(err)) &&
	    strstr(kept(err), "no default") != NULL,
	    "an installer with nowhere to write refuses rather than choosing");
	ncfg_buf_free(&out);
}

/* ------------------------------------------------------------------------ *
 * The canary
 * ------------------------------------------------------------------------ */

/*
 * Every channel a credential could leave by, read back for one value.
 *
 * **Checked for being vacuous first.** A sweep over a run that never wrote the
 * credential proves nothing at all, so the secret file has to hold the canary
 * byte for byte before its absence anywhere else means anything.
 */
static void no_credential_reaches_a_message(const char *stderr_text)
{
	char *body;
	const char *found;

	printf("\n-- the canary, swept through every channel a value could leave by\n");
	fresh_tree();
	{
		ncfg_wifi_profile_t profile;
		char                err[NCFG_ERROR_MAX];

		plain(&profile, "Sweep");
		profile.security = NCFG_WIFI_SECURITY_PSK;
		(void)ncfg_wifi_profile_install(config_dir, factory_dir, &profile, CANARY,
		    strlen(CANARY), NULL, NULL, err, sizeof(err));
		(void)kept(err);
	}
	body = testdir_read(in(in(config_dir, "secrets"), "Sweep"), NULL);
	check(body != NULL && strcmp(body, CANARY) == 0,
	    "the write landed: the credential is in the file, byte for byte");
	free(body);
	body = testdir_read(in(in(config_dir, "conf.d"), "wifi-Sweep.conf"), NULL);
	check(body != NULL && strstr(body, CANARY) == NULL,
	    "  and the block beside it carries a reference rather than the value");
	free(body);

	found = strstr(every_message, CANARY);
	check(found == NULL, "no `err` buffer this file filled carries the credential");
	if (found) {
		detail("in", found - 200 > every_message ? found - 200 : every_message);
	}
	check(!stderr_text || strstr(stderr_text, CANARY) == NULL,
	    "and nothing this process wrote to standard error carries it either");
}

/* ================================================================== main */

int main(void)
{
	char  stderr_path[384];
	char *sweep;
	int   stderr_copy;

	(void)testdir_make("wifi-profile");
	(void)snprintf(base, sizeof(base), "%s", testdir_path);
	(void)snprintf(config_dir, sizeof(config_dir), "%s/etc", base);
	(void)snprintf(factory_dir, sizeof(factory_dir), "%s/factory", base);
	(void)snprintf(stderr_path, sizeof(stderr_path), "%s/stderr.log", base);
	make_directory(config_dir);
	make_directory(factory_dir);
	make_directory(in(config_dir, "conf.d"));

	/* Everything this process writes to standard error, kept so the sweep can
	 * read it back. Restored before anything is printed about it. */
	stderr_copy = dup(STDERR_FILENO);
	{
		int redirected = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		if (redirected >= 0) {
			(void)dup2(redirected, STDERR_FILENO);
			(void)close(redirected);
		}
	}

	a_name_is_three_things_at_once();
	what_a_block_looks_like();
	what_an_install_writes();
	a_credential_that_cannot_be_one();
	an_id_that_escapes_the_directory();
	every_field_survives_being_written();
	nothing_is_left_behind_by_a_refusal();
	forgetting_a_network();
	what_a_forget_refuses();
	the_daemon_s_seam_writes_the_same_file();

	(void)fflush(stderr);
	sweep = testdir_read(stderr_path, NULL);
	if (stderr_copy >= 0) {
		(void)dup2(stderr_copy, STDERR_FILENO);
		(void)close(stderr_copy);
	}
	no_credential_reaches_a_message(sweep);
	free(sweep);

	testdir_remove(testdir_path);
	if (failures) {
		printf("\n%d check(s) failed\n", failures);
		return 1;
	}
	printf("\nthe `network` block writer: every check passed\n");
	return 0;
}
