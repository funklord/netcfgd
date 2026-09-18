/*
 * wifi_write.c -- `ncfg wifi add` and `ncfg wifi forget`: the two verbs under
 * `ncfg wifi` that write a file.
 *
 * WHY THEY ARE NOT IN `wifi.c`
 *   That file's own header says it: nothing in it compiles or applies
 *   anything, and nothing in it reads a file. These two do both. They are
 *   `crates/netcfgd-cli/src/wifi.rs`'s writing half, and they belong beside
 *   `drop_in.c`, `profile.c` and `secret.c` -- the verbs that change the
 *   configuration -- rather than beside the renderers.
 *
 * THE ORDER IS THE DESIGN, AND IT IS ONE RULE
 *   **A refusal that was going to happen anyway must not happen after somebody
 *   has typed a passphrase.** Every check in `add` is before the prompt for
 *   that reason: the flags that contradict each other, the id that cannot be a
 *   name, the network that is already configured, the certificate given as a
 *   path where the block has to go to the daemon, the directory that cannot be
 *   written with no daemon to ask, and which radio this is for. The credential
 *   is read last, and the install refuses an existing file or credential
 *   before it writes either -- so nothing after the prompt can clobber what
 *   somebody else wrote.
 *
 * WHERE THIS DIVERGES FROM THE RUST
 *   `--json` is answered rather than accepted and ignored at both verbs, which
 *   is `subcommand_internal.h`'s rule. `add` prints what it wrote, whether the
 *   network is secured and which radio it took; `forget` prints which
 *   credentials went and which stayed -- and both leave out, on the daemon
 *   route, every member the daemon's `ok` does not answer.
 *
 *   0263's list has the whole of each. In short: the configuration is loaded
 *   once rather than twice; the block's every field is compared after the
 *   write rather than the enterprise five; and `forget` says how many
 *   credentials it kept as well as which, because a network that shared its
 *   passphrase with an access point is the case an operator has to be told
 *   about rather than left to infer from silence.
 */
#include "subcommand_internal.h"

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/daemon.h"
#include "ncfg/log.h"
#include "ncfg/radio.h"
#include "ncfg/secrets.h"
#include "ncfg/wifi_profile.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ------------------------------------------------------------------------ *
 * What the flags may say together
 * ------------------------------------------------------------------------ */

/*
 * What an enterprise network needs, per method, before anything is written.
 *
 * **This is the form part.** A flag list cannot express "TLS wants a client
 * certificate and PEAP wants a password", so the alternative to refusing here
 * is a file that compiles and a network that never joins -- which is 0017's
 * distinction between refusing what would work and refusing what cannot.
 *
 * Each refusal names the flag to add rather than the field that is missing,
 * because the reader is at a command line and not in the model.
 */
static int check_enterprise(const ncfg_cli_wifi_t *wanted, char *err, size_t err_size)
{
	static const char *const flags[] = { "--identity", "--anonymous-identity", "--ca-cert",
		"--client-cert", "--phase2" };
	const char *const given[] = { wanted->identity, wanted->anonymous_identity,
		wanted->ca_cert, wanted->client_cert, wanted->phase2 };
	size_t at;

	if (!wanted->eap) {
		/* The enterprise flags mean nothing without a method, and silently
		 * ignoring them would write a personal network for somebody who
		 * believed they had written a corporate one. */
		for (at = 0; at < sizeof(given) / sizeof(given[0]); at++) {
			if (given[at]) {
				ncfg_error_set(err, err_size,
				    "%s is for an enterprise network and this one has no method. "
				    "Add `--eap peap`, `--eap ttls`, `--eap tls` or `--eap pwd`",
				    flags[at]);
				return 0;
			}
		}
		return 1;
	}
	if (wanted->open) {
		ncfg_error_set(err, err_size,
		    "--open and --eap contradict each other: one says there is no "
		    "authentication and the other says which kind");
		return 0;
	}
	if (wanted->proto) {
		ncfg_error_set(err, err_size,
		    "--wpa2/--wpa3 name a generation for a passphrase, and --eap says there is "
		    "no passphrase. An enterprise network negotiates its own");
		return 0;
	}
	if (!wanted->identity) {
		ncfg_error_set(err, err_size,
		    "--eap %s needs `--identity`, which is who you are to the authentication "
		    "server -- often your username, and often with a realm: `--identity "
		    "you@example.ac.uk`", wanted->eap);
		return 0;
	}
	/*
	 * TLS authenticates with a certificate and no password; the other three
	 * authenticate with a password and no certificate of their own. Getting
	 * this wrong is a network that will not join, and wpa_supplicant says so
	 * only in its log.
	 */
	if (strcmp(wanted->eap, "tls") == 0 && !wanted->client_cert) {
		ncfg_error_set(err, err_size,
		    "--eap tls authenticates with a certificate, so it needs `--client-cert "
		    "PATH`. The private key is asked for, not passed");
		return 0;
	}
	if (strcmp(wanted->eap, "tls") != 0 && wanted->client_cert) {
		ncfg_error_set(err, err_size,
		    "--client-cert is for `--eap tls`, which authenticates with a certificate. "
		    "`--eap %s` authenticates with a password", wanted->eap);
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------------------ *
 * Whether this process could write there
 * ------------------------------------------------------------------------ */

/*
 * The probe itself, on a directory that exists.
 *
 * **Asked by writing, because that is the only answer that is true**: a mode
 * and an owner have to be read against this process' uid and every
 * supplementary group, and a filesystem may be read-only or refuse for a
 * reason neither mentions.
 *
 * **The name carries the pid and a counter**, which is 0121's rule and a
 * defect the Rust's own test names: a fixed `.ncfg-write-probe` left behind by
 * a process killed between the create and the remove made `O_CREAT|O_EXCL`
 * answer "not writable" about a writable directory, for ever. A dotfile, which
 * the config loader ignores.
 */
static int can_write_dir(const char *directory)
{
	static unsigned sequence;
	char            probe[NCFG_CLI_PATH_MAX];
	int             wrote;
	int             fd;

	wrote = snprintf(probe, sizeof(probe), "%s/.ncfg-write-probe.%ld.%u", directory,
	    (long)getpid(), sequence++);
	if (wrote < 0 || (size_t)wrote >= sizeof(probe)) {
		return 0;
	}
	fd = open(probe, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		return 0;
	}
	(void)close(fd);
	(void)unlink(probe);
	return 1;
}

/* The directory `path` sits in, into `out`. */
static int parent_of(const char *path, char *out, size_t out_size)
{
	const char *slash = strrchr(path, '/');
	size_t      length;

	if (!slash) {
		return 0;
	}
	length = (size_t)(slash - path);
	if (length == 0) {
		length = 1u; /* directly under the root */
	}
	if (length + 1u > out_size) {
		return 0;
	}
	memcpy(out, path, length);
	out[length] = '\0';
	return 1;
}

/*
 * Whether this process could create `target`.
 *
 * It probes the directory `target` would sit in, not `target` itself and not
 * the config directory: the block goes in `conf.d`, and asking about the
 * parent of that is how the first version of this got a wrong answer. Where
 * `conf.d` is not there the install would create it, so the question becomes
 * whether *its* parent allows that.
 */
static int can_write(const char *target)
{
	char        directory[NCFG_CLI_PATH_MAX];
	char        above[NCFG_CLI_PATH_MAX];
	struct stat about;

	if (!parent_of(target, directory, sizeof(directory))) {
		return 0;
	}
	if (stat(directory, &about) == 0 && S_ISDIR(about.st_mode)) {
		return can_write_dir(directory);
	}
	if (!parent_of(directory, above, sizeof(above))) {
		return 0;
	}
	return stat(above, &about) == 0 && S_ISDIR(about.st_mode) && can_write_dir(above);
}

/* ------------------------------------------------------------------------ *
 * The configuration as it stands
 * ------------------------------------------------------------------------ */

/*
 * The document this machine compiles to, or NULL where there is not one yet.
 *
 * **The distinction matters here and nowhere else in `ncfg`**: every other
 * command has nothing to do without a configuration, and this one is what a
 * machine with no configuration at all runs first. Refusing to add the first
 * network because there is no network to add it to would be a fine joke and a
 * useless tool.
 *
 * **Loaded once**, where the Rust loads twice -- once to ask whether there is
 * anything and once inside `compile` to compile it -- and with the profile
 * either way, which its emptiness probe does not use. One walk cannot disagree
 * with itself about what the configuration is.
 *
 * Returns 1 with `*out` set or left NULL; 0 with a sentence where the
 * directory cannot be read or what is in it does not compile. A configuration
 * that was already broken must be reported *before* this writes a file, or the
 * operator spends the evening blaming the command that told them.
 */
static int current(const ncfg_cli_options_t *options, ncfg_document_t **out, char *err,
    size_t err_size)
{
	char                  config_dir[NCFG_CLI_PATH_MAX];
	char                  factory_dir[NCFG_CLI_PATH_MAX];
	ncfg_config_sources_t sources = { 0 };

	*out = NULL;
	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
	    sizeof(factory_dir));
	if (!ncfg_config_load_with_profile(factory_dir, config_dir, &sources, err, err_size)) {
		ncfg_config_sources_free(&sources);
		return 0;
	}
	if (sources.count == 0) {
		ncfg_config_sources_free(&sources);
		return 1;
	}
	*out = ncfg_cli_compile_to_read(options, err, err_size);
	ncfg_config_sources_free(&sources);
	return *out != NULL;
}

/* ------------------------------------------------------------------------ *
 * Which radio
 * ------------------------------------------------------------------------ */

/* Where `/sys/class/net` is, from `--sys-class-net`, the environment, or the
 * kernel's own path. Never guessed past that: a test that read the machine's
 * own would pass on a laptop and do something else on a build host. */
static int class_net_of(const ncfg_cli_options_t *options, char *out, size_t out_size,
    char *err, size_t err_size)
{
	if (options->sys_class_net) {
		int wrote = snprintf(out, out_size, "%s", options->sys_class_net);

		if (wrote < 0 || (size_t)wrote >= out_size) {
			ncfg_error_set(err, err_size, "that --sys-class-net path is too long");
			return 0;
		}
		return 1;
	}
	return ncfg_radio_class_net(out, out_size, err, err_size);
}

/* The radios netcfgd has already been given: the document's answer **and** the
 * kernel's. A `device` block naming an interface that is not a radio says
 * nothing about hardware that is here, and a radio with no block is not
 * netcfgd's yet. */
static int already_activated(const char *root, const ncfg_document_t *document,
    const char *name)
{
	size_t at;

	for (at = 0; document && at < document->device_count; at++) {
		const ncfg_device_t *device = &document->devices[at];

		if (!device->name || !device->managed || !device->wifi) {
			continue;
		}
		if (name && strcmp(device->name, name) != 0) {
			continue;
		}
		if (ncfg_radio_is_wireless(root, device->name)) {
			return 1;
		}
	}
	return 0;
}

/* Interface names as a person reads them, into `out`. */
static void list_radios(const ncfg_radio_links_t *links, ncfg_buf_t *out)
{
	size_t at;

	if (links->count == 0) {
		ncfg_buf_add_text(out, "none");
		return;
	}
	for (at = 0; at < links->count; at++) {
		if (at > 0) {
			ncfg_buf_add_text(out, ", ");
		}
		ncfg_buf_add_text(out, links->items[at]);
	}
}

/*
 * Which radio this network needs handed over, if any.
 *
 * **Adding a network to a machine whose radio nobody activated writes a
 * configuration that does nothing**, which is what this exists to stop: a
 * `network` block alone plans nothing at all, and with only an `interface`
 * block it plans a DHCP client on a radio that never associates. Both were
 * measured, and the second is the worse of the two because it looks
 * configured.
 *
 * **Decides and writes nothing**, so that it can run before the credential
 * prompt. Refusing to choose between two radios is exactly the kind of refusal
 * that must not arrive after somebody has typed a passphrase.
 *
 * `out` receives the interface to activate, or is left empty where there is
 * nothing to do -- which includes a machine with no radio at all, since that
 * is a machine being prepared before the hardware arrives and is the case this
 * command was written for.
 */
static int choose_radio(const char *root, const ncfg_document_t *document,
    const ncfg_cli_wifi_t *wanted, char *out, size_t out_size, char *err, size_t err_size)
{
	ncfg_radio_links_t links = { 0 };
	ncfg_buf_t         names;
	char               said[NCFG_ERROR_MAX];
	int                ok = 1;

	out[0] = '\0';
	if (wanted->interface) {
		/* Sized from both halves rather than from the shorter one: a sysfs
		 * root is `NCFG_RADIO_ROOT_MAX` and an interface name comes from
		 * `argv`, and a join that truncated would `stat` a path nobody named
		 * and read "not present" from it. */
		char path[NCFG_RADIO_ROOT_MAX + NCFG_CLI_TEXT_MAX + 2u];
		struct stat about;

		/*
		 * Present and not a radio is a mistake worth refusing: somebody named
		 * the wrong interface. **Absent is not**, and the difference matters
		 * here more than anywhere else in this command -- writing
		 * configuration for hardware that is not plugged in yet is what `ncfg
		 * wifi add` on a machine being prepared is for, and the planner skips
		 * an interface that is not there.
		 */
		(void)snprintf(path, sizeof(path), "%s/%.*s", root, (int)NCFG_CLI_TEXT_MAX,
		    wanted->interface);
		if (stat(path, &about) == 0 && !ncfg_radio_is_wireless(root, wanted->interface)) {
			ncfg_buf_init(&names, NCFG_ERROR_MAX);
			if (ncfg_radio_links(root, &links, said, sizeof(said))) {
				list_radios(&links, &names);
			} else {
				ncfg_buf_add_text(&names, "none this could list");
			}
			ncfg_error_set(err, err_size,
			    "`%.*s` is an interface on this machine and is not a radio. The "
			    "radios are: %s", (int)NCFG_CLI_TEXT_MAX, wanted->interface,
			    ncfg_buf_text(&names));
			ncfg_buf_free(&names);
			ncfg_radio_links_free(&links);
			return 0;
		}
		if (already_activated(root, document, wanted->interface)) {
			return 1;
		}
		if ((size_t)snprintf(out, out_size, "%s", wanted->interface) >= out_size) {
			ncfg_error_set(err, err_size, "that interface name is too long");
			return 0;
		}
		return 1;
	}

	/* Something is already netcfgd's, so this command has no reason to
	 * choose. That matters most on the machine that would otherwise be
	 * refused: two radios, one already activated, and nothing ambiguous. */
	if (already_activated(root, document, NULL)) {
		return 1;
	}
	if (!ncfg_radio_links(root, &links, err, err_size)) {
		return 0;
	}
	if (links.count == 1u) {
		if ((size_t)snprintf(out, out_size, "%s", links.items[0]) >= out_size) {
			ncfg_error_set(err, err_size, "that interface name is too long");
			ok = 0;
		}
	} else if (links.count > 1u) {
		/* Refused rather than guessed: one of two radios is often somebody
		 * else's, and picking it would take hardware nobody offered. */
		ncfg_buf_init(&names, NCFG_ERROR_MAX);
		list_radios(&links, &names);
		ncfg_error_set(err, err_size,
		    "this machine has %zu radios (%s), and none of them is netcfgd's yet -- "
		    "so this cannot tell which one the network is for. Say which with "
		    "`--interface`, or hand one over first with `ncfg wifi activate <radio>`",
		    links.count, ncfg_buf_text(&names));
		ncfg_buf_free(&names);
		ok = 0;
	}
	ncfg_radio_links_free(&links);
	return ok;
}

/*
 * Hand a radio to netcfgd, by whichever route is open.
 *
 * The daemon where one is listening, because 0127 makes it the writer; the
 * files directly where none is, because that is the machine `ncfg wifi add`
 * was written for -- somebody at a console, as root, with no network. Both
 * write the same two blocks, from `ncfg_wifi_radio_blocks`, so the two routes
 * cannot drift.
 */
static int activate(const char *interface, const ncfg_cli_options_t *options, char *err,
    size_t err_size)
{
	char       socket_path[NCFG_CLI_PATH_MAX];
	char       config_dir[NCFG_CLI_PATH_MAX];
	char       factory_dir[NCFG_CLI_PATH_MAX];
	char       name[NCFG_WIFI_DROP_IN_MAX];
	char       said[NCFG_ERROR_MAX];
	ncfg_buf_t blocks;
	int        denied = 0;
	int        ok;

	if (!ncfg_cli_daemon_socket(options, socket_path, sizeof(socket_path))) {
		ncfg_error_set(err, err_size,
		    "the run directory makes a socket path too long to connect to");
		return 0;
	}
	if (ncfg_cli_daemon_listening(socket_path)) {
		ncfg_proto_request_t request;

		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_RADIO_SET;
		request.u.radio_set.interface = ncfg_proto_str(interface);
		request.u.radio_set.activate = 1u;
		return ncfg_cli_ask_ok(socket_path, &request, err, err_size);
	}

	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
	    sizeof(factory_dir));
	ncfg_buf_init(&blocks, 0);
	if (!ncfg_wifi_radio_drop_in(interface, name, sizeof(name), err, err_size) ||
	    !ncfg_wifi_radio_blocks(interface, &blocks, err, err_size)) {
		ncfg_buf_free(&blocks);
		return 0;
	}
	/* Replacing is right: this is a switch, so turning on something already
	 * on is the state being asked for rather than a collision. */
	ok = ncfg_config_install_drop_in(config_dir, factory_dir, name, ncfg_buf_text(&blocks), 1,
	    NULL, &denied, said, sizeof(said));
	ncfg_buf_free(&blocks);
	if (!ok) {
		ncfg_cli_refused_locally(denied, said, socket_path, err, err_size);
	}
	return ok;
}

/* ------------------------------------------------------------------------ *
 * The credential
 * ------------------------------------------------------------------------ */

/* Wipe before freeing. A credential that has been used is still a credential
 * until the bytes are gone. */
static void forget_value(char *value)
{
	if (value) {
		memset(value, 0, strlen(value));
		free(value);
	}
}

/*
 * The passphrase rules, refused here rather than by the supplicant.
 *
 * The same checks `ncfg_supplicant_*` makes before it sends one, made where
 * the operator can still fix it: at association time the failure is a bare
 * `FAIL`, half an hour after the file was written.
 *
 * **The length is safe to report and the value is not**, which is the rule
 * `secrets.h` keeps everywhere.
 */
static int check_passphrase(const char *passphrase, char *err, size_t err_size)
{
	size_t length = strlen(passphrase);
	size_t at;

	/* Octets, which is what the supplicant and hostapd both count (0229). */
	if (length < 8u || length > 63u) {
		ncfg_error_set(err, err_size,
		    "a WPA passphrase is 8 to 63 octets and that one is %zu -- a character "
		    "outside ASCII counts as more than one. A 64-digit hex key -- a "
		    "pre-computed PMK rather than a passphrase -- is not something netcfgd "
		    "can send", length);
		return 0;
	}
	for (at = 0; at < length; at++) {
		unsigned char one = (unsigned char)passphrase[at];

		if (one < 0x20u || one == 0x7fu) {
			ncfg_error_set(err, err_size,
			    "that passphrase contains a control character, which cannot be sent "
			    "to the supplicant at all");
			return 0;
		}
	}
	return 1;
}

/*
 * The one credential this network needs, asked for by its own name.
 *
 * Three different things live at `@secret:<id>` depending on the network, and
 * the prompt has to say which or the operator types the wrong one: a WPA
 * passphrase, an EAP password, or the private key an EAP-TLS certificate goes
 * with. Only the first has length rules -- an EAP password is whatever the
 * authentication server says it is, and checking it against WPA's 8-to-63 rule
 * would refuse valid credentials.
 *
 * **Never an argument**, for the reason `ncfg secret set` exists (0075): an
 * argument is in the process table and in the shell's history.
 */
static int read_credential(const char *id, const ncfg_cli_wifi_t *wanted, char **out, char *err,
    size_t err_size)
{
	char prompt[NCFG_CLI_TEXT_MAX];

	if (!wanted->eap) {
		(void)snprintf(prompt, sizeof(prompt), "passphrase for `%.*s`",
		    (int)NCFG_WIFI_PROFILE_ID_MAX, id);
		if (!ncfg_cli_read_secret(prompt, out, err, err_size)) {
			return 0;
		}
		if (!check_passphrase(*out, err, err_size)) {
			forget_value(*out);
			*out = NULL;
			return 0;
		}
		return 1;
	}
	if (strcmp(wanted->eap, "tls") == 0) {
		/* **A path, and not the key.** `wpa_supplicant`'s `private_key` names
		 * a file it opens, so key material there is a filename that does not
		 * exist -- and a PEM is multi-line, which terminates the control
		 * socket's command in the middle. Offering an option that cannot work
		 * is worse than not offering it. */
		(void)snprintf(prompt, sizeof(prompt),
		    "path to the private key for `%.*s`, which wpa_supplicant will open",
		    (int)NCFG_WIFI_PROFILE_ID_MAX, id);
	} else {
		(void)snprintf(prompt, sizeof(prompt), "EAP password for `%.*s`",
		    (int)NCFG_WIFI_PROFILE_ID_MAX, id);
	}
	return ncfg_cli_read_secret(prompt, out, err, err_size);
}

/* ------------------------------------------------------------------------ *
 * Saying what happened
 * ------------------------------------------------------------------------ */

/*
 * What activating a radio did, said the same way by both routes.
 *
 * **Said rather than done quietly.** Adding a network can hand a radio to
 * netcfgd, which is a change to what hardware netcfgd owns -- a bigger thing
 * than the network that prompted it, and not what somebody typing `ncfg wifi
 * add` asked for in so many words. A command that takes hardware silently is
 * one whose next surprise is worse.
 */
static void say_activated(const ncfg_cli_options_t *options, const char *interface)
{
	if (!options->json && interface && interface[0]) {
		ncfg_out_writef("activated `%s`: netcfgd manages that radio now, which is what "
		    "lets it join anything. `ncfg wifi deactivate %s` hands it back\n",
		    interface, interface);
	}
}

/* Whether the document has a radio at all, which is what decides the "nothing
 * will use it yet" line. */
static int any_radio_block(const ncfg_document_t *document)
{
	size_t at;

	for (at = 0; document && at < document->device_count; at++) {
		if (document->devices[at].wifi) {
			return 1;
		}
	}
	return 0;
}

/*
 * What `ncfg wifi add` did, as one object.
 *
 * `id` is the handle every other `ncfg wifi` verb takes, so it is the member a
 * script keeps. `secured` is the socket's own word for the fact the open-network
 * warning is about -- a scan entry carries it -- so the flag and the scan agree
 * on what to call it.
 *
 * `file` and `secret` are the two paths this process wrote, named as
 * `ncfg_wifi_installed_t` names them, and both are **absent on the daemon
 * route**: netcfgd chose where its copies went and 0127's rule is that handing
 * a path back invites a client to keep it. `secret` is a path and never a
 * value; the credential this command read is in that file and in nothing this
 * program prints.
 *
 * `activated` is the radio that was handed over, absent where none was -- a
 * bigger change than the network that prompted it, and the text says so for
 * that reason.
 *
 * `usable` is the "nothing will use it yet" line: whether anything in this
 * configuration can join what was just added. It is **absent on the daemon
 * route**, where this process never compiled the document and so never looked;
 * `false` there would be a finding nobody made.
 */
static int say_added(const ncfg_wifi_installed_t *written, const char *id,
    const ncfg_cli_wifi_t *wanted, const int *usable, const char *activated, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;
	ncfg_buf_t         out;
	int                ok;

	ncfg_buf_init(&out, 0);
	ncfg_json_write_init(&writer, &out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "id", id);
	ncfg_json_write_member_bool(&writer, "secured", !wanted->open);
	ncfg_json_write_member_bool(&writer, "daemon", written == NULL);
	if (written && written->file) {
		ncfg_json_write_member_string(&writer, "file", written->file);
	}
	if (written && written->secret) {
		ncfg_json_write_member_string(&writer, "secret", written->secret);
	}
	if (activated && activated[0]) {
		ncfg_json_write_member_string(&writer, "activated", activated);
	}
	if (usable) {
		ncfg_json_write_member_bool(&writer, "usable", *usable);
	}
	ncfg_json_write_object_end(&writer);
	ok = ncfg_cli_say_json(&writer, "the network that was added", err, err_size);
	ncfg_buf_free(&out);
	return ok;
}

static void report(const ncfg_wifi_installed_t *written, const char *id,
    const ncfg_cli_wifi_t *wanted, const ncfg_document_t *before, const char *activated,
    const ncfg_cli_options_t *options)
{
	ncfg_out_writef("wrote %s\n", written->file ? written->file : "");
	if (written->secret) {
		ncfg_out_writef("wrote %s (mode 0600)\n", written->secret);
	}
	if (wanted->open) {
		ncfg_out_writef("`%s` has no security: anything sent over it is readable by "
		    "anybody in range\n", id);
	}
	/*
	 * A network profile is not bound to a device, so a configuration with no
	 * radio in it compiles perfectly and joins nothing. 0061's rule -- a thing
	 * that compiles either does something or says it does not -- applied to
	 * the file this just wrote.
	 */
	say_activated(options, activated);
	if (!any_radio_block(before) && !(activated && activated[0])) {
		ncfg_out_line("nothing will use it yet: no device in this configuration has a "
		    "`wifi` block, and no radio was activated for it");
	}
	/* Quoted when it needs to be, because a copied line that does not run is
	 * worse than no suggestion, and an SSID with a space in it is ordinary. */
	if (strpbrk(id, " \t\n")) {
		ncfg_out_writef("`ncfg plan` shows what it changes; `ncfg wifi connect \"%s\"` "
		    "joins it now\n", id);
	} else {
		ncfg_out_writef("`ncfg plan` shows what it changes; `ncfg wifi connect %s` "
		    "joins it now\n", id);
	}
}

/* ------------------------------------------------------------------------ *
 * Over the socket
 * ------------------------------------------------------------------------ */

/* A `@secret:name` reference reduced to the name the socket carries.
 *
 * The two spellings exist for a reason rather than by accident: a
 * configuration file says `@secret:corp-ca` because that is the language's
 * syntax for an indirection, and the socket carries `corp-ca` because a
 * request that could hold the other spelling could hold a path. The prefix
 * goes back on in the daemon, which is the only place it can. */
static const char *stored_name(const char *reference)
{
	if (reference && strncmp(reference, "@secret:", 8u) == 0) {
		return reference + 8u;
	}
	return reference;
}

/*
 * A certificate given as a path cannot cross the socket.
 *
 * The socket carries the *names* of stored certificates and has no field a
 * path fits in, which is what makes accepting an enterprise network safe at
 * all: a path is an instruction to open a file as root. The way to use a file
 * already on the machine is to store its contents first.
 */
static int certs_can_cross(const ncfg_cli_wifi_t *wanted, const char *why, char *err,
    size_t err_size)
{
	static const char *const flags[] = { "--ca-cert", "--client-cert" };
	const char *const given[] = { wanted->ca_cert, wanted->client_cert };
	size_t at;

	for (at = 0; at < 2u; at++) {
		if (given[at] && strncmp(given[at], "@secret:", 8u) != 0) {
			ncfg_error_set(err, err_size,
			    "%s, and `%s %.*s` names a file, which the socket does not accept: "
			    "a path is an instruction to open a file as root. Store the "
			    "contents instead --\n  ncfg secret set NAME < %.*s\nand pass "
			    "`%s @secret:NAME`", why, flags[at], (int)NCFG_CLI_TEXT_MAX,
			    given[at], (int)NCFG_CLI_TEXT_MAX, given[at], flags[at]);
			return 0;
		}
	}
	return 1;
}

/* The ssid as lowercase hex, which is the only form the request carries. */
static void ssid_hex(const ncfg_ssid_t *ssid, char *out, size_t out_size)
{
	static const char digits[] = "0123456789abcdef";
	size_t            at;

	out[0] = '\0';
	if (ssid->length * 2u + 1u > out_size) {
		return;
	}
	for (at = 0; at < ssid->length; at++) {
		out[at * 2u] = digits[ssid->bytes[at] >> 4];
		out[at * 2u + 1u] = digits[ssid->bytes[at] & 0x0fu];
	}
	out[ssid->length * 2u] = '\0';
}

/*
 * Add the network through the daemon, for a caller who cannot write the file.
 *
 * The credential travels inbound in the request, is written by the daemon
 * through the secret provider at 0600, and the block keeps an `@secret:`
 * reference -- so the desired-state document stays free of secret material
 * exactly as it does when this command writes the file itself (0117).
 */
static int add_over_socket(const char *socket_path, const ncfg_wifi_profile_t *profile,
    const char *credential, const ncfg_cli_wifi_t *wanted, const char *activated,
    const ncfg_cli_options_t *options, char *err, size_t err_size)
{
	ncfg_proto_request_t request;
	char                 hex[NCFG_SSID_MAX_LEN * 2u + 1u];

	if (!certs_can_cross(wanted, "the configuration is root's, so this has to go to "
	        "netcfgd", err, err_size)) {
		return 0;
	}
	ssid_hex(&profile->ssid, hex, sizeof(hex));
	memset(&request, 0, sizeof(request));
	request.kind = NCFG_PROTO_REQ_WIFI_ADD;
	request.u.wifi_add.ssid = ncfg_proto_str(hex);
	request.u.wifi_add.id = ncfg_proto_str(profile->id);
	if (credential) {
		request.u.wifi_add.passphrase = ncfg_proto_str(credential);
	}
	if (profile->proto) {
		request.u.wifi_add.proto = ncfg_proto_str(profile->proto);
	}
	request.u.wifi_add.hidden = (unsigned char)(profile->hidden ? 1 : 0);
	if (profile->metric.has) {
		request.u.wifi_add.metric.present = 1;
		request.u.wifi_add.metric.value = profile->metric.value;
	}
	if (profile->method) {
		request.u.wifi_add.eap.present = 1;
		request.u.wifi_add.eap.method = ncfg_proto_str(profile->method);
		request.u.wifi_add.eap.identity = ncfg_proto_str(profile->identity);
		if (profile->anonymous_identity) {
			request.u.wifi_add.eap.anonymous_identity =
			    ncfg_proto_str(profile->anonymous_identity);
		}
		if (profile->phase2) {
			request.u.wifi_add.eap.phase2 = ncfg_proto_str(profile->phase2);
		}
		/* Already checked above to be `@secret:` references; the socket
		 * carries the bare name and the daemon puts the prefix back. */
		if (profile->ca_cert) {
			request.u.wifi_add.eap.ca_cert = ncfg_proto_str(stored_name(profile->ca_cert));
		}
		if (profile->client_cert) {
			request.u.wifi_add.eap.client_cert =
			    ncfg_proto_str(stored_name(profile->client_cert));
		}
	}
	if (!ncfg_cli_ask_ok(socket_path, &request, err, err_size)) {
		return 0;
	}
	say_activated(options, activated);
	if (options->json) {
		/* No paths and no `usable`: netcfgd chose where both files went and
		 * this process never compiled the document to see what could join. */
		return say_added(NULL, profile->id, wanted, NULL, activated, err, err_size);
	}
	ncfg_out_writef("added `%s` through netcfgd\n", profile->id);
	ncfg_out_line("the configuration is root's, so this went to the daemon rather than "
	    "straight to a file");
	ncfg_out_writef("`ncfg wifi connect \"%s\"` joins it now\n", profile->id);
	return 1;
}

/* ------------------------------------------------------------------------ *
 * `ncfg wifi add`
 * ------------------------------------------------------------------------ */

int ncfg_cli_wifi_add(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size)
{
	const ncfg_cli_wifi_t *wanted = &options->wifi;
	ncfg_wifi_profile_t    profile;
	ncfg_wifi_installed_t  written = { NULL, NULL };
	ncfg_document_t       *document = NULL;
	char                   config_dir[NCFG_CLI_PATH_MAX];
	char                   factory_dir[NCFG_CLI_PATH_MAX];
	char                   socket_path[NCFG_CLI_PATH_MAX];
	char                   class_net[NCFG_RADIO_ROOT_MAX];
	char                   hand_over[NCFG_CLI_TEXT_MAX];
	char                   said[NCFG_ERROR_MAX];
	char                  *credential = NULL;
	char                  *profile_file = NULL;
	const char            *id;
	size_t                 ssid_length;
	size_t                 at;
	int                    listening;
	int                    denied = 0;
	int                    ok = 0;

	if (count != 1u) {
		ncfg_error_set(err, err_size,
		    "`ncfg wifi add` takes one SSID: `ncfg wifi add \"Cafe Wifi\"`. The "
		    "passphrase is asked for, or read from standard input");
		return 0;
	}
	if (wanted->open && wanted->proto) {
		ncfg_error_set(err, err_size,
		    "--open and --wpa2/--wpa3 contradict each other: one says there is no "
		    "passphrase and the other says which generation protects it");
		return 0;
	}
	if (!check_enterprise(wanted, err, err_size)) {
		return 0;
	}

	memset(&profile, 0, sizeof(profile));
	ssid_length = strlen(positional[0]);
	if (ssid_length > NCFG_SSID_MAX_LEN) {
		ncfg_error_set(err, err_size,
		    "that is not a usable ssid: it is %zu octets and an ssid is at most %u",
		    ssid_length, (unsigned)NCFG_SSID_MAX_LEN);
		return 0;
	}
	profile.ssid.has = 1;
	profile.ssid.length = ssid_length;
	memcpy(profile.ssid.bytes, positional[0], ssid_length);
	id = wanted->id ? wanted->id : positional[0];
	if (!ncfg_wifi_profile_usable_id(id, said, sizeof(said))) {
		ncfg_error_set(err, err_size,
		    "%s Pass `--id` with a plainer one -- the SSID itself is kept exactly, as "
		    "hex", said);
		return 0;
	}
	profile.id = id;
	profile.hidden = wanted->hidden ? 1 : 0;
	profile.metric = wanted->metric;
	profile.proto = wanted->proto;
	if (wanted->open) {
		profile.security = NCFG_WIFI_SECURITY_OPEN;
	} else if (wanted->eap) {
		profile.security = NCFG_WIFI_SECURITY_EAP;
		profile.method = wanted->eap;
		profile.identity = wanted->identity;
		profile.anonymous_identity = wanted->anonymous_identity;
		profile.ca_cert = wanted->ca_cert;
		profile.client_cert = wanted->client_cert;
		profile.phase2 = wanted->phase2;
	} else {
		profile.security = NCFG_WIFI_SECURITY_PSK;
	}

	/*
	 * Before anything is written. A second block with the same label is a
	 * compile error, so writing it would break the whole configuration --
	 * every interface on the machine -- to add one network.
	 */
	if (!current(options, &document, err, err_size)) {
		return 0;
	}
	for (at = 0; document && at < document->network_count; at++) {
		if (document->networks[at].id &&
		    strcmp(document->networks[at].id, id) == 0) {
			ncfg_error_set(err, err_size,
			    "a network `%s` is already configured. Change it by editing the "
			    "configuration, or remove it and add it again", id);
			goto done;
		}
	}

	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
	    sizeof(factory_dir));
	if (!ncfg_cli_daemon_socket(options, socket_path, sizeof(socket_path))) {
		ncfg_error_set(err, err_size,
		    "the run directory makes a socket path too long to connect to");
		goto done;
	}
	listening = ncfg_cli_daemon_listening(socket_path);
	profile_file = ncfg_wifi_profile_path(config_dir, id, err, err_size);
	if (!profile_file) {
		goto done;
	}
	/*
	 * **Nowhere to send it is a refusal, and it belongs before the prompt.**
	 * Found in the Rust by a test that hung rather than failed: a network with
	 * a stored certificate reached the credential prompt on a machine with an
	 * unwritable config directory and no daemon, and would have asked for a
	 * password before saying it had nowhere to put the answer.
	 */
	if (!listening && !can_write(profile_file)) {
		ncfg_error_set(err, err_size,
		    "cannot write %s and nothing is listening on %s -- so there is nowhere to "
		    "put this network. Start netcfgd, or run this as somebody who can write "
		    "the configuration", config_dir, socket_path);
		goto done;
	}
	/* A certificate given as a path cannot cross the socket, and finding that
	 * out after somebody has typed a password is the thing to avoid. */
	if (wanted->eap && !listening && !can_write(profile_file) &&
	    !certs_can_cross(wanted, "this cannot write the configuration", err, err_size)) {
		goto done;
	}
	if (wanted->eap && listening &&
	    !certs_can_cross(wanted, "the configuration is root's, so this has to go to "
	        "netcfgd", err, err_size)) {
		goto done;
	}

	/* Which radio, before the prompt and for the same reason as the refusal
	 * above. Nothing is written yet. */
	if (!class_net_of(options, class_net, sizeof(class_net), err, err_size) ||
	    !choose_radio(class_net, document, wanted, hand_over, sizeof(hand_over), err,
	        err_size)) {
		goto done;
	}

	/* The credential last, because it is the only step that stops and waits
	 * for a person. */
	if (!wanted->open && !read_credential(id, wanted, &credential, err, err_size)) {
		goto done;
	}

	/*
	 * **The radio before the network, because it is the prerequisite.** Where
	 * this fails there is an unactivated radio and no network, which is the
	 * state the machine was already in; the other order would leave a network
	 * nothing can join, which looks configured and is not.
	 */
	if (hand_over[0] && !activate(hand_over, options, err, err_size)) {
		goto done;
	}
	if (listening) {
		ok = add_over_socket(socket_path, &profile, credential, wanted, hand_over, options,
		    err, err_size);
		goto done;
	}
	if (!ncfg_wifi_profile_install(config_dir, factory_dir, &profile, credential,
	        credential ? strlen(credential) : 0u, &written, &denied, said, sizeof(said))) {
		ncfg_cli_refused_locally(denied, said, socket_path, err, err_size);
		goto done;
	}
	if (options->json) {
		int usable = any_radio_block(document) || (hand_over[0] != '\0');

		ok = say_added(&written, id, wanted, &usable, hand_over, err, err_size);
		goto done;
	}
	report(&written, id, wanted, document, hand_over, options);
	ncfg_out_writef("nothing is listening on %s, so this was written directly\n",
	    socket_path);
	ok = 1;
done:
	forget_value(credential);
	free(profile_file);
	ncfg_wifi_installed_free(&written);
	if (document) {
		ncfg_document_free(document);
	}
	return ok;
}

/* ------------------------------------------------------------------------ *
 * `ncfg wifi forget`
 * ------------------------------------------------------------------------ */

/*
 * What `ncfg wifi forget` did, as one object.
 *
 * `removed` and `kept` are the credentials, by name, and they are the reason
 * this verb says more than "forgotten": a credential outliving what wanted it
 * is a fault an operator cannot see from here, and one shared with an access
 * point stays behind. The names are `ncfg_wifi_forgotten_t`'s own.
 *
 * **Both are absent on the daemon route, never empty.** The daemon answers
 * `ok` and says nothing about credentials, so an empty list there would be
 * this command reporting that none went when it has no idea -- which is
 * project.md section 10.175's shape in a document rather than in a sentence. An
 * empty list on the local route means the loop ran and found none.
 */
static int say_forgotten(const char *id, const ncfg_wifi_forgotten_t *forgotten, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;
	ncfg_buf_t         out;
	size_t             at;
	int                ok;

	ncfg_buf_init(&out, 0);
	ncfg_json_write_init(&writer, &out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "id", id);
	ncfg_json_write_member_bool(&writer, "daemon", forgotten == NULL);
	if (forgotten) {
		ncfg_json_write_key(&writer, "removed");
		ncfg_json_write_array_begin(&writer);
		for (at = 0; at < forgotten->removed_count; at++) {
			ncfg_json_write_string(&writer,
			    forgotten->removed[at] ? forgotten->removed[at] : "");
		}
		ncfg_json_write_array_end(&writer);
		ncfg_json_write_key(&writer, "kept");
		ncfg_json_write_array_begin(&writer);
		for (at = 0; at < forgotten->kept_count; at++) {
			ncfg_json_write_string(&writer,
			    forgotten->kept[at] ? forgotten->kept[at] : "");
		}
		ncfg_json_write_array_end(&writer);
	}
	ncfg_json_write_object_end(&writer);
	ok = ncfg_cli_say_json(&writer, "the network that was forgotten", err, err_size);
	ncfg_buf_free(&out);
	return ok;
}

int ncfg_cli_wifi_forget(const ncfg_cli_options_t *options, const char **positional,
    size_t count, char *err, size_t err_size)
{
	ncfg_wifi_forgotten_t forgotten = { NULL, 0, NULL, 0 };
	ncfg_document_t      *document = NULL;
	char                  config_dir[NCFG_CLI_PATH_MAX];
	char                  factory_dir[NCFG_CLI_PATH_MAX];
	char                  socket_path[NCFG_CLI_PATH_MAX];
	char                  said[NCFG_ERROR_MAX];
	size_t                at;
	int                   denied = 0;
	int                   ok = 0;

	if (count != 1u) {
		ncfg_error_set(err, err_size,
		    "`ncfg wifi forget` takes one network id: `ncfg wifi forget home`. `ncfg "
		    "wifi status` and the configuration list them");
		return 0;
	}
	if (!ncfg_cli_daemon_socket(options, socket_path, sizeof(socket_path))) {
		ncfg_error_set(err, err_size,
		    "the run directory makes a socket path too long to connect to");
		return 0;
	}
	/* Socket first and the directory second, like every other write verb
	 * (0127): `/etc/netcfgd` is root's and a client is not. */
	if (ncfg_cli_daemon_listening(socket_path)) {
		ncfg_proto_request_t request;

		memset(&request, 0, sizeof(request));
		request.kind = NCFG_PROTO_REQ_WIFI_FORGET;
		request.u.name = ncfg_proto_str(positional[0]);
		if (!ncfg_cli_ask_ok(socket_path, &request, err, err_size)) {
			return 0;
		}
		if (options->json) {
			return say_forgotten(positional[0], NULL, err, err_size);
		}
		ncfg_out_writef("netcfgd forgot `%s`\n", positional[0]);
		return 1;
	}

	(void)ncfg_config_resolve_dir(options->config_dir, config_dir, sizeof(config_dir));
	(void)ncfg_config_resolve_factory_dir(options->factory_dir, factory_dir,
	    sizeof(factory_dir));
	if (!current(options, &document, err, err_size)) {
		return 0;
	}
	if (!ncfg_wifi_profile_forget(config_dir, factory_dir, document, positional[0], &forgotten,
	        &denied, said, sizeof(said))) {
		ncfg_cli_refused_locally(denied, said, socket_path, err, err_size);
		goto done;
	}
	if (options->json) {
		ok = say_forgotten(positional[0], &forgotten, err, err_size);
		goto done;
	}
	ncfg_out_writef("forgot `%s`\n", positional[0]);
	/* Said, because a credential outliving what wanted it is a fault this
	 * project names elsewhere and an operator cannot see it from here. */
	for (at = 0; at < forgotten.removed_count; at++) {
		ncfg_out_writef("and removed the credential `%s`, which nothing refers to now\n",
		    forgotten.removed[at]);
	}
	for (at = 0; at < forgotten.kept_count; at++) {
		ncfg_out_writef("the credential `%s` stays: something else still refers to it\n",
		    forgotten.kept[at]);
	}
	ok = 1;
done:
	ncfg_wifi_forgotten_free(&forgotten);
	if (document) {
		ncfg_document_free(document);
	}
	return ok;
}
