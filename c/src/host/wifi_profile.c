/*
 * wifi_profile.c -- the `network` block, written once for both writers.
 *
 * `crates/netcfgd-host/src/wifi_profile.rs`. The header says why it is one
 * module rather than one per caller; what is worth saying beside the code is
 * the order things happen in, because that order is the whole of the safety
 * property: refuse, then the credential, then the block, then prove the
 * machine can use what was written -- and remove both files where it cannot.
 *
 * NOTHING HERE PUTS A CREDENTIAL ANYWHERE BUT THE FILE
 *   The bytes arrive borrowed and are written once. No message in this file
 *   formats them, no path is derived from them, and the only length that
 *   reaches a sentence is a bound this file chose. `wifi_profile_test.c`
 *   sweeps a canary through every `err` buffer and through the whole of
 *   standard error, and checks the sweep is not vacuous by requiring the write
 *   to have landed the canary in the secret file and nowhere else.
 */
#include "ncfg/wifi_profile.h"

#include "config_internal.h"
#include "host_internal.h"

#include "ncfg/base.h"
#include "ncfg/config.h"
#include "ncfg/secrets.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * The EAP methods, spelled once.
 *
 * The text is what goes in the file and the enum is what comes back out of the
 * compiler, so the round trip needs both directions of one table. A second
 * spelling of `peap` is how a port comes to write a key the language does not
 * take -- 0263 names `wire_guard` and `open_vpn` as the two that already
 * happened.
 */
static const struct {
	const char *text;
	int         method;
} eap_methods[] = {
	{ "peap", NCFG_EAP_METHOD_PEAP },
	{ "ttls", NCFG_EAP_METHOD_TTLS },
	{ "tls", NCFG_EAP_METHOD_TLS },
	{ "pwd", NCFG_EAP_METHOD_PWD },
};

/* The generations, the same way. NULL is "negotiate both", which is what the
 * language means by leaving `proto` out. */
static const struct {
	const char *text;
	int         proto;
} psk_protos[] = {
	{ "wpa2", NCFG_PSK_PROTO_WPA2 },
	{ "wpa3", NCFG_PSK_PROTO_WPA3 },
};

/* What the document's method is called, or NULL for one this does not know --
 * which cannot happen from a block this wrote and is not assumed away. */
static const char *method_text(int method)
{
	size_t at;

	for (at = 0; at < sizeof(eap_methods) / sizeof(eap_methods[0]); at++) {
		if (eap_methods[at].method == method) {
			return eap_methods[at].text;
		}
	}
	return NULL;
}

static const char *proto_text(int proto)
{
	size_t at;

	for (at = 0; at < sizeof(psk_protos) / sizeof(psk_protos[0]); at++) {
		if (psk_protos[at].proto == proto) {
			return psk_protos[at].text;
		}
	}
	/* `NCFG_PSK_PROTO_WPA2_WPA3` is the one with no spelling, because leaving
	 * the key out is how the language says it. */
	return NULL;
}

/* ------------------------------------------------------------------------ *
 * Names and paths
 * ------------------------------------------------------------------------ */

int ncfg_wifi_profile_usable_id(const char *id, char *err, size_t err_size)
{
	/*
	 * Asked rather than restated. `ncfg_secret_name_usable` already refuses an
	 * empty name, one longer than 64 bytes, a quote or a backslash, a path
	 * separator, `..`, a leading dot and a control character -- which is every
	 * rule an id has to satisfy to be a block label, a filename and a
	 * credential's name at once. Writing the list again here would be a second
	 * copy to keep in step, and the one that drifted would be the one nothing
	 * tested.
	 */
	return ncfg_config_name_usable(id, "a network id here", err, err_size);
}

int ncfg_wifi_profile_drop_in(const char *id, char *out, size_t out_size, char *err,
    size_t err_size)
{
	int wrote;

	if (!out || out_size == 0) {
		ncfg_error_set(err, err_size, "there is nowhere to put a drop-in name");
		return 0;
	}
	out[0] = '\0';
	if (!ncfg_wifi_profile_usable_id(id, err, err_size)) {
		return 0;
	}
	wrote = snprintf(out, out_size, "wifi-%s", id);
	if (wrote < 0 || (size_t)wrote >= out_size) {
		ncfg_error_set(err, err_size,
		    "`%s` makes a drop-in name longer than the %u bytes this holds", id,
		    (unsigned)NCFG_WIFI_PROFILE_NAME_MAX);
		return 0;
	}
	return 1;
}

char *ncfg_wifi_profile_path(const char *config_dir, const char *id, char *err, size_t err_size)
{
	char name[NCFG_WIFI_PROFILE_NAME_MAX];

	if (!ncfg_wifi_profile_drop_in(id, name, sizeof(name), err, err_size)) {
		return NULL;
	}
	/* The loader's own path rule rather than a second spelling of `conf.d`:
	 * a writer and a loader that spell one directory differently is a file
	 * written where nothing reads it. */
	return ncfg_config_drop_in_path(config_dir, name, err, err_size);
}

char *ncfg_wifi_profile_secret_path(const char *config_dir, const char *id, char *err,
    size_t err_size)
{
	char *dir;
	char *path;

	if (!ncfg_wifi_profile_usable_id(id, err, err_size)) {
		return NULL;
	}
	dir = ncfg_host_join(config_dir, "secrets", err, err_size);
	if (!dir) {
		return NULL;
	}
	path = ncfg_host_join(dir, id, err, err_size);
	free(dir);
	return path;
}

/* ------------------------------------------------------------------------ *
 * The block, as text
 * ------------------------------------------------------------------------ */

/*
 * A value going into a quoted string in generated configuration.
 *
 * An identity or a certificate reference arrives from outside and goes into a
 * file the compiler reads back. A quote or a backslash in one would end the
 * string early and produce a file that does not compile -- which takes every
 * other interface on the machine with it, since the loader compiles the
 * directory as one document.
 */
static void add_escaped(ncfg_buf_t *out, const char *value)
{
	size_t at;

	for (at = 0; value[at] != '\0'; at++) {
		if (value[at] == '\\' || value[at] == '"') {
			ncfg_buf_add_char(out, '\\');
		}
		ncfg_buf_add_char(out, value[at]);
	}
}

/* One `key = "value"` of a `wifi` block, into the caller's list. */
static void add_key(ncfg_buf_t *keys, size_t *count, const char *key, const char *value)
{
	if (!value) {
		return;
	}
	ncfg_buf_add_text(&keys[*count], key);
	ncfg_buf_add_text(&keys[*count], " = \"");
	add_escaped(&keys[*count], value);
	ncfg_buf_add_char(&keys[*count], '"');
	(*count)++;
}

/* The most keys a `wifi` block this writes can carry: `eap`, five fields, and
 * the credential. A `psk` block has two. */
#define WIFI_KEYS_MAX 7u

/* The SSID as lowercase hex, which is its canonical encoding. */
static void add_ssid_hex(ncfg_buf_t *out, const ncfg_ssid_t *ssid)
{
	static const char digits[] = "0123456789abcdef";
	size_t            at;

	for (at = 0; at < ssid->length; at++) {
		ncfg_buf_add_char(out, digits[ssid->bytes[at] >> 4]);
		ncfg_buf_add_char(out, digits[ssid->bytes[at] & 0x0fu]);
	}
}

/* Whether the SSID's octets are exactly the label's, which is what decides
 * whether the block needs an `ssid` key at all. */
static int ssid_is_the_label(const ncfg_wifi_profile_t *profile)
{
	size_t length = strlen(profile->id);

	return length == profile->ssid.length &&
	    memcmp(profile->ssid.bytes, profile->id, length) == 0;
}

int ncfg_wifi_profile_render(const ncfg_wifi_profile_t *profile, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_buf_t  keys[WIFI_KEYS_MAX];
	size_t      count = 0;
	size_t      at;
	char        reference[NCFG_WIFI_PROFILE_NAME_MAX + 16u];
	int         failed;

	if (!profile || !profile->id || !out) {
		ncfg_error_set(err, err_size, "there is no network to render");
		return 0;
	}
	for (at = 0; at < WIFI_KEYS_MAX; at++) {
		/* The same ceiling the block itself has. A key that did not fit is a
		 * failed buffer, and a failed buffer hands out the empty string
		 * rather than the part that fitted. */
		ncfg_buf_init(&keys[at], NCFG_CONFIG_FILE_MAX);
	}
	(void)snprintf(reference, sizeof(reference), "@secret:%s", profile->id);

	switch (profile->security) {
	case NCFG_WIFI_SECURITY_OPEN:
		ncfg_buf_add_text(&keys[count++], "open = true");
		break;
	case NCFG_WIFI_SECURITY_EAP:
		add_key(keys, &count, "eap", profile->method);
		/*
		 * Every value is quoted rather than interpolated bare: an identity is
		 * `you@example.ac.uk` and a certificate reference is `@secret:name`,
		 * and neither is guaranteed to be a bare word the lexer reads back as
		 * itself. The round trip below proves it for each one.
		 */
		add_key(keys, &count, "identity", profile->identity);
		add_key(keys, &count, "anonymous_identity", profile->anonymous_identity);
		add_key(keys, &count, "ca_cert", profile->ca_cert);
		add_key(keys, &count, "client_cert", profile->client_cert);
		add_key(keys, &count, "phase2", profile->phase2);
		/*
		 * TLS presents a certificate and the other three present a password,
		 * and the supplicant refuses the network outright if given the other
		 * -- so which key the stored credential goes under is the same branch
		 * the caller prompted through.
		 */
		add_key(keys, &count,
		    (profile->method && strcmp(profile->method, "tls") == 0) ? "private_key"
		                                                            : "password",
		    reference);
		break;
	default:
		add_key(keys, &count, "psk", reference);
		add_key(keys, &count, "proto", profile->proto);
		break;
	}

	ncfg_buf_add_text(out,
	    "# Written by netcfgd. This file is ordinary netcfgd configuration:\n"
	    "# edit it, diff it, commit it, or delete it. Deleting it is how the\n"
	    "# machine forgets this network.\n\nnetwork \"");
	ncfg_buf_add_text(out, profile->id);
	ncfg_buf_add_text(out, "\" {\n");
	/*
	 * The SSID as hex whenever it is not exactly the label, which is what
	 * makes a separate id lossless: an SSID is 32 arbitrary octets and a label
	 * is text, so a network whose name is not usable as a label still keeps
	 * its exact name.
	 */
	if (!ssid_is_the_label(profile)) {
		ncfg_buf_add_text(out, "\tssid = \"");
		add_ssid_hex(out, &profile->ssid);
		ncfg_buf_add_text(out, "\"\n");
	}
	if (profile->hidden) {
		ncfg_buf_add_text(out, "\thidden = true\n");
	}
	/* One key per line for an enterprise network. The single-line form reads
	 * well for `psk` alone and badly for seven keys, and this file is meant to
	 * be edited by hand afterwards. */
	if (count > 3u) {
		ncfg_buf_add_text(out, "\twifi {\n");
		for (at = 0; at < count; at++) {
			ncfg_buf_add_text(out, "\t\t");
			ncfg_buf_add_text(out, ncfg_buf_text(&keys[at]));
			ncfg_buf_add_char(out, '\n');
		}
		ncfg_buf_add_text(out, "\t}\n");
	} else {
		ncfg_buf_add_text(out, "\twifi { ");
		for (at = 0; at < count; at++) {
			if (at > 0) {
				ncfg_buf_add_text(out, "; ");
			}
			ncfg_buf_add_text(out, ncfg_buf_text(&keys[at]));
		}
		ncfg_buf_add_text(out, " }\n");
	}
	/* Beside the `wifi` block rather than inside it, because that is where the
	 * parser reads it: a metric ranks this network against every link on the
	 * machine, wired ones included, so it is not a property of the radio. */
	if (profile->metric.has) {
		ncfg_buf_addf(out, "\tmetric = %lld\n", (long long)profile->metric.value);
	}
	ncfg_buf_add_text(out, "}\n");

	failed = ncfg_buf_failed(out);
	for (at = 0; at < WIFI_KEYS_MAX; at++) {
		failed = failed || ncfg_buf_failed(&keys[at]);
		ncfg_buf_free(&keys[at]);
	}
	if (failed) {
		ncfg_error_set(err, err_size,
		    "that network does not fit in a configuration file this will write");
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * The round trip
 * ------------------------------------------------------------------------ */

/* Whether two optional strings say the same thing, absence included. */
static int same_text(const char *wrote, const char *got)
{
	if (!wrote) {
		return 1; /* nothing was asked for, so nothing can have been lost */
	}
	return got && strcmp(wrote, got) == 0;
}

/*
 * A certificate reference as it was written, for comparing against the file.
 *
 * The round trip compares what was rendered with what the compiler read back,
 * so it has to undo the lowering rather than look at the meaning: a stored
 * reference was written as `@secret:name`, which is the only form this writer
 * can produce. Comparing the lowered source against the text would fail for
 * every stored certificate -- and the failure would say netcfgd has a bug,
 * which is what that message means and exactly why it must not fire for a
 * working case.
 */
static int cert_as_written(const ncfg_cert_source_t *source, char *out, size_t out_size)
{
	out[0] = '\0';
	if (!source || !source->has) {
		return 0;
	}
	if (source->kind == NCFG_CERT_SOURCE_PATH) {
		(void)snprintf(out, out_size, "%s", source->path ? source->path : "");
		return 1;
	}
	(void)snprintf(out, out_size, "@secret:%s",
	    source->stored.name ? source->stored.name : "");
	return 1;
}

/* The network a compiled document has under this label, or NULL. */
static const ncfg_wifi_network_t *network_named(const ncfg_document_t *document, const char *id)
{
	size_t at;

	for (at = 0; document && at < document->network_count; at++) {
		if (document->networks[at].id && strcmp(document->networks[at].id, id) == 0) {
			return &document->networks[at];
		}
	}
	return NULL;
}

/* The credential name a compiled network's security refers to, or NULL. */
static const char *credential_name(const ncfg_security_t *security)
{
	if (security->kind == NCFG_SECURITY_PSK) {
		return security->psk.passphrase.name;
	}
	if (security->kind == NCFG_SECURITY_EAP) {
		if (security->eap.private_key.has &&
		    security->eap.private_key.kind == NCFG_CERT_SOURCE_STORED) {
			return security->eap.private_key.stored.name;
		}
		return security->eap.password ? security->eap.password->name : NULL;
	}
	return NULL;
}

/*
 * Whether the enterprise half came back as it went in.
 *
 * Field by field, because every one of its values went through a quoted string
 * on the way in: an identity with a realm, a certificate reference. `secured`
 * is true for a `psk` network too, so without this an `--eap` run that
 * compiled to a passphrase network would pass -- and the operator would find
 * out at association time, from a supplicant log.
 */
static int eap_survived(const ncfg_wifi_profile_t *profile, const ncfg_eap_config_t *eap,
    const char **what)
{
	char ca[NCFG_ERROR_MAX];
	char client[NCFG_ERROR_MAX];

	*what = NULL;
	if (!same_text(profile->method, method_text(eap->method))) {
		*what = "method";
	} else if (!same_text(profile->identity, eap->identity)) {
		*what = "identity";
	} else if (!same_text(profile->anonymous_identity, eap->anonymous_identity)) {
		*what = "anonymous identity";
	} else if (!same_text(profile->phase2, eap->phase2)) {
		*what = "phase 2 method";
	} else if (profile->ca_cert &&
	    (!cert_as_written(&eap->ca_cert, ca, sizeof(ca)) ||
	    strcmp(profile->ca_cert, ca) != 0)) {
		*what = "CA certificate";
	} else if (profile->client_cert &&
	    (!cert_as_written(&eap->client_cert, client, sizeof(client)) ||
	    strcmp(profile->client_cert, client) != 0)) {
		*what = "client certificate";
	}
	return *what == NULL;
}

/*
 * Compile the directory again and check the network arrived as asked.
 *
 * **Through the loader that reads the profile**, which is the half the Rust
 * does not do here: `install_drop_in` was fixed to verify with the selected
 * profile folded in and this second writer of the same directory was not, so
 * on a machine with a profile the check compiles a configuration the machine
 * never loads. 0263's list has it.
 *
 * **Every field is compared, not the enterprise five.** The Rust's own comment
 * says the check covers "an SSID whose hex form did not round-trip" and
 * nothing in it looks at the SSID; section 10.160 is the same shape one layer up,
 * where five fields are dropped by a renderer with nothing comparing what went
 * in against what came out. A check that names the fields it does not check is
 * worse than one that checks them.
 */
static int compiles_back(const char *config_dir, const char *factory_dir,
    const ncfg_wifi_profile_t *profile, char *err, size_t err_size)
{
	ncfg_config_sources_t     sources = { 0 };
	ncfg_document_t          *document;
	const ncfg_wifi_network_t *network;
	const char               *reason = NULL;
	const char               *name;
	char                      reference[NCFG_WIFI_PROFILE_NAME_MAX + 16u];
	int                       secured;

	if (!ncfg_config_load_with_profile(factory_dir, config_dir, &sources, err, err_size)) {
		return 0;
	}
	document = ncfg_config_compile_for_reading(&sources, err, err_size);
	ncfg_config_sources_free(&sources);
	if (!document) {
		char said[NCFG_ERROR_MAX];

		(void)snprintf(said, sizeof(said), "%s", err ? err : "");
		ncfg_error_set(err, err_size,
		    "what that would have written does not compile, so it was removed "
		    "again: %s", said);
		return 0;
	}
	network = network_named(document, profile->id);
	if (!network) {
		ncfg_error_set(err, err_size,
		    "the file was written and compiled, and the configuration still has no "
		    "network `%s`, so it was removed again. This is a bug in netcfgd",
		    profile->id);
		ncfg_document_free(document);
		return 0;
	}
	(void)snprintf(reference, sizeof(reference), "@secret:%s", profile->id);
	name = credential_name(&network->security);
	secured = network->security.kind != NCFG_SECURITY_OPEN;

	if (network->ssid.length != profile->ssid.length ||
	    memcmp(network->ssid.bytes, profile->ssid.bytes, profile->ssid.length) != 0) {
		reason = "ssid";
	} else if (network->hidden != (profile->hidden ? 1 : 0)) {
		reason = "hidden flag";
	} else if (profile->metric.has &&
	    (!network->metric.has || network->metric.value != profile->metric.value)) {
		reason = "metric";
	} else if (secured != (profile->security != NCFG_WIFI_SECURITY_OPEN)) {
		reason = "security";
	} else if (secured && (!name || strcmp(name, profile->id) != 0)) {
		/* The credential is referred to by the network's own label and by
		 * nothing else, so a reference that came back under another name is a
		 * network pointing at somebody else's passphrase. */
		reason = "credential reference";
	} else if (profile->security == NCFG_WIFI_SECURITY_PSK) {
		if (network->security.kind != NCFG_SECURITY_PSK) {
			reason = "security";
		} else if (!same_text(profile->proto, proto_text(network->security.psk.proto))) {
			reason = "generation";
		}
	} else if (profile->security == NCFG_WIFI_SECURITY_EAP) {
		if (network->security.kind != NCFG_SECURITY_EAP) {
			reason = "method";
		} else {
			(void)eap_survived(profile, &network->security.eap, &reason);
		}
	}
	ncfg_document_free(document);
	if (reason) {
		ncfg_error_set(err, err_size,
		    "network `%s`'s %s did not survive being written and read back, so it "
		    "was removed again. This is a bug in netcfgd", profile->id, reason);
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Installing
 * ------------------------------------------------------------------------ */

void ncfg_wifi_installed_free(ncfg_wifi_installed_t *installed)
{
	if (!installed) {
		return;
	}
	free(installed->file);
	free(installed->secret);
	installed->file = NULL;
	installed->secret = NULL;
}

/* Whether this network has to have a credential with it. */
static int wants_credential(const ncfg_wifi_profile_t *profile)
{
	return profile->security != NCFG_WIFI_SECURITY_OPEN;
}

/* The bytes are a credential and every refusal about them says only how many
 * there are or that there is a NUL: never what they were. */
static int credential_is_usable(const ncfg_wifi_profile_t *profile, const char *credential,
    size_t length, char *err, size_t err_size)
{
	if (!wants_credential(profile)) {
		return 1;
	}
	if (!credential) {
		ncfg_error_set(err, err_size, "this network needs a credential and none was given");
		return 0;
	}
	if (length == 0) {
		/* `ncfg_secret_store_put`'s rule at the other door into the same
		 * directory: an empty credential is one that fails at the moment it is
		 * used rather than now. */
		ncfg_error_set(err, err_size,
		    "nothing was given for `%s`, and an empty credential is one that fails at "
		    "the moment it is used rather than now", profile->id);
		return 0;
	}
	if (memchr(credential, '\0', length) != NULL) {
		/*
		 * **A divergence.** Nothing downstream can carry a NUL: the
		 * supplicant's control socket is lines, hostapd's configuration is
		 * lines, and anything treating the value as a C string stores the part
		 * before it -- silently, and with no way to tell afterwards which half
		 * is on the machine. The Rust's `&str` may hold one and its checks let
		 * it through for every method but PSK.
		 */
		ncfg_error_set(err, err_size,
		    "that credential contains a NUL, which nothing netcfgd hands it to can "
		    "carry -- and a value silently cut at one is a credential nobody can tell "
		    "is wrong");
		return 0;
	}
	return 1;
}

int ncfg_wifi_profile_install(const char *config_dir, const char *factory_dir,
    const ncfg_wifi_profile_t *profile, const char *credential, size_t credential_length,
    ncfg_wifi_installed_t *out, int *denied, char *err, size_t err_size)
{
	ncfg_buf_t  text;
	char       *file = NULL;
	char       *secret = NULL;
	char       *secrets_dir = NULL;
	struct stat about;
	int         stored = 0;
	int         ok = 0;

	if (out) {
		out->file = NULL;
		out->secret = NULL;
	}
	if (denied) {
		*denied = 0;
	}
	if (!config_dir || !factory_dir || !profile || !profile->id) {
		ncfg_error_set(err, err_size, "there is no network to write");
		return 0;
	}
	/* First, and inside rather than above: everything below joins this onto a
	 * directory twice. */
	if (!ncfg_wifi_profile_usable_id(profile->id, err, err_size)) {
		return 0;
	}
	file = ncfg_wifi_profile_path(config_dir, profile->id, err, err_size);
	if (!file) {
		return 0;
	}
	secret = ncfg_wifi_profile_secret_path(config_dir, profile->id, err, err_size);
	if (!secret) {
		free(file);
		return 0;
	}
	ncfg_buf_init(&text, NCFG_CONFIG_FILE_MAX);

	/*
	 * Refused before anything is written, and `lstat` rather than `stat`: a
	 * symlink where the block goes is a file this did not write, and following
	 * it would edit whatever owns the target.
	 */
	if (lstat(file, &about) == 0) {
		ncfg_error_set(err, err_size,
		    "%s already exists -- refusing to overwrite a file this did not write",
		    file);
		goto done;
	}
	if (!credential_is_usable(profile, credential, credential_length, err, err_size)) {
		goto done;
	}
	if (wants_credential(profile) && lstat(secret, &about) == 0) {
		ncfg_error_set(err, err_size,
		    "%s already exists -- refusing to overwrite a stored credential. Remove "
		    "it first if it is stale", secret);
		goto done;
	}
	if (!ncfg_wifi_profile_render(profile, &text, err, err_size)) {
		goto done;
	}

	if (wants_credential(profile)) {
		/*
		 * 0700 from the moment it exists rather than created and then
		 * tightened: a directory that is briefly world-readable is briefly
		 * world-readable, and the file about to go in it is a passphrase.
		 */
		secrets_dir = ncfg_host_join(config_dir, "secrets", err, err_size);
		if (!secrets_dir) {
			goto done;
		}
		if (!ncfg_host_make_directory(secrets_dir, (mode_t)0700, err, err_size)) {
			goto done;
		}
		/* The borrowed bytes, written once. 0600 from the moment the file
		 * exists, which is what `ncfg_config_write_atomically` promises by
		 * putting the mode on the temporary. */
		if (!ncfg_config_write_atomically(secret, credential, credential_length,
		        0600u, denied, err, err_size)) {
			goto done;
		}
		stored = 1;
	}

	if (!ncfg_config_write_atomically(file, ncfg_buf_text(&text), strlen(ncfg_buf_text(&text)),
	        0644u, denied, err, err_size)) {
		if (stored) {
			(void)unlink(secret);
		}
		goto done;
	}
	if (!compiles_back(config_dir, factory_dir, profile, err, err_size)) {
		(void)unlink(file);
		if (stored) {
			(void)unlink(secret);
		}
		goto done;
	}
	if (out) {
		out->file = file;
		out->secret = stored ? secret : NULL;
		file = NULL;
		if (stored) {
			secret = NULL;
		}
	}
	ok = 1;
done:
	ncfg_buf_free(&text);
	free(secrets_dir);
	free(file);
	free(secret);
	return ok;
}

int ncfg_wifi_profile_installer(void *context, const ncfg_wifi_profile_t *profile,
    const char *credential, size_t credential_length, char *err, size_t err_size)
{
	ncfg_wifi_installer_t *where = context;

	if (!where) {
		ncfg_error_set(err, err_size,
		    "the installer was given no directories to write in, and there is no "
		    "default for either of them");
		return 0;
	}
	return ncfg_wifi_profile_install(where->config_dir, where->factory_dir, profile,
	    credential, credential_length, &where->installed, &where->denied, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * Forgetting
 * ------------------------------------------------------------------------ */

void ncfg_wifi_forgotten_free(ncfg_wifi_forgotten_t *forgotten)
{
	if (!forgotten) {
		return;
	}
	ncfg_secret_names_free(forgotten->removed, forgotten->removed_count);
	ncfg_secret_names_free(forgotten->kept, forgotten->kept_count);
	forgotten->removed = NULL;
	forgotten->removed_count = 0;
	forgotten->kept = NULL;
	forgotten->kept_count = 0;
}

/* Naming what there is, for the reason `profile set` does: the id is usually a
 * typo away from a real one, and a bare refusal sends somebody to look for a
 * file. */
static void no_such_network(const ncfg_document_t *document, const char *id, char *err,
    size_t err_size)
{
	ncfg_buf_t names;
	size_t     at;

	ncfg_buf_init(&names, NCFG_ERROR_MAX);
	for (at = 0; at < document->network_count; at++) {
		if (!document->networks[at].id) {
			continue;
		}
		if (names.length > 0) {
			ncfg_buf_add_text(&names, ", ");
		}
		ncfg_buf_add_text(&names, document->networks[at].id);
	}
	if (names.length == 0) {
		ncfg_error_set(err, err_size,
		    "no network `%s` is configured, and there are none to forget", id);
	} else {
		ncfg_error_set(err, err_size, "no network `%s` is configured. There is: %s", id,
		    ncfg_buf_text(&names));
	}
	ncfg_buf_free(&names);
}

/* The configuration as it stands now, or NULL -- which this reads as "cannot
 * tell", and every credential is kept. */
static ncfg_document_t *compile_now(const char *config_dir, const char *factory_dir)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *document;
	char                  ignored[NCFG_ERROR_MAX];

	if (!ncfg_config_load_with_profile(factory_dir, config_dir, &sources, ignored,
	        sizeof(ignored))) {
		ncfg_config_sources_free(&sources);
		return NULL;
	}
	document = ncfg_config_compile_for_reading(&sources, ignored, sizeof(ignored));
	ncfg_config_sources_free(&sources);
	return document;
}

int ncfg_wifi_profile_forget(const char *config_dir, const char *factory_dir,
    const ncfg_document_t *document, const char *id, ncfg_wifi_forgotten_t *out, int *denied,
    char *err, size_t err_size)
{
	ncfg_wifi_forgotten_t forgotten = { NULL, 0, NULL, 0 };
	ncfg_document_t      *after;
	const ncfg_wifi_network_t *network;
	char                **named = NULL;
	size_t                named_count = 0;
	size_t                capacity_removed = 0;
	size_t                capacity_kept = 0;
	size_t                at;
	char                  name[NCFG_WIFI_PROFILE_NAME_MAX];
	int                   removed = 0;
	int                   ok = 1;

	if (out) {
		out->removed = NULL;
		out->removed_count = 0;
		out->kept = NULL;
		out->kept_count = 0;
	}
	if (denied) {
		*denied = 0;
	}
	if (!ncfg_wifi_profile_drop_in(id, name, sizeof(name), err, err_size)) {
		return 0;
	}
	if (!document) {
		ncfg_error_set(err, err_size,
		    "there is no compiled configuration, so there is no network to forget");
		return 0;
	}
	network = network_named(document, id);
	if (!network) {
		no_such_network(document, id, err, err_size);
		return 0;
	}
	if (!ncfg_secret_named_by(&network->security, &named, &named_count, err, err_size)) {
		return 0;
	}
	/*
	 * **The drop-in first**, so that a refusal leaves the credential where it
	 * was. The other order would take a passphrase away from a network that is
	 * still configured, which is the one outcome here nobody can undo.
	 */
	if (!ncfg_config_remove_drop_in(config_dir, factory_dir, name, &removed, denied, err,
	        err_size)) {
		ncfg_secret_names_free(named, named_count);
		return 0;
	}
	if (!removed) {
		/* Configured and not by a file netcfgd wrote. Whatever defines it is
		 * somebody's own file, and editing it is theirs. */
		ncfg_error_set(err, err_size,
		    "`%s` is configured, but not in a file netcfgd wrote -- so netcfgd cannot "
		    "take it away. Whatever defines it is somebody's own file, and editing it "
		    "is theirs", id);
		ncfg_secret_names_free(named, named_count);
		return 0;
	}

	/* Asked *after* the removal, because what matters is whether anything
	 * still refers to the credential -- and asked of the whole document rather
	 * than of the other networks, since a passphrase shared with an access
	 * point block is still in use. */
	after = compile_now(config_dir, factory_dir);
	for (at = 0; at < named_count; at++) {
		char  **users = NULL;
		size_t  user_count = 0;
		int     still_used = 1;
		char    said[NCFG_ERROR_MAX];

		if (after && ncfg_secret_referring_to(after, named[at], &users, &user_count, said,
		        sizeof(said))) {
			still_used = user_count > 0;
			ncfg_secret_names_free(users, user_count);
		}
		if (still_used) {
			/* Fails closed: a configuration that cannot be read back keeps
			 * every credential. Removing one on a guess is unrecoverable
			 * (0042) and leaving one behind is visible in a listing. */
			if (!ncfg_host_strings_add(&forgotten.kept, &forgotten.kept_count,
			        &capacity_kept, named[at])) {
				ok = 0;
			}
			continue;
		}
		{
			char       *path = ncfg_wifi_profile_secret_path(config_dir, named[at], said,
			    sizeof(said));
			struct stat about;
			int         there = path && lstat(path, &about) == 0;

			free(path);
			if (!there) {
				/* Referred to and never stored is one of the two faults a
				 * credential listing exists to name, and it is not this
				 * call's to complain about: there was nothing to remove and
				 * the network is gone. */
				continue;
			}
		}
		if (!ncfg_secret_store_remove(config_dir, named[at], said, sizeof(said))) {
			ncfg_error_set(err, err_size, "%s", said);
			ok = 0;
			continue;
		}
		if (!ncfg_host_strings_add(&forgotten.removed, &forgotten.removed_count,
		        &capacity_removed, named[at])) {
			ok = 0;
		}
	}
	if (after) {
		ncfg_document_free(after);
	}
	ncfg_secret_names_free(named, named_count);
	if (out && ok) {
		*out = forgotten;
	} else {
		ncfg_wifi_forgotten_free(&forgotten);
	}
	return ok;
}
