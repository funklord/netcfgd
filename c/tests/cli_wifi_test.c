/*
 * cli_wifi_test.c -- `ncfg wifi add` and `ncfg wifi forget` end to end.
 *
 * WHAT THESE CASES ARE FOR
 *   `crates/netcfgd-cli/src/wifi.rs`'s writing half, driven through the entry
 *   points the dispatch calls, against a fixture tree. Four groups:
 *
 *   * **Every refusal happens before the prompt.** That is the one rule the
 *     Rust's own comments repeat at each check, and the reason is a person
 *     standing at a terminal: a refusal that was going to happen anyway must
 *     not happen after they have typed a passphrase. Each case below points
 *     standard input at a valid passphrase and asserts the refusal is about
 *     the flags, the name or the radio -- so a check that moved after the
 *     prompt would consume the input and change what these say.
 *   * **What it writes is asked of the configuration**, not compared against
 *     expected text: the broken version wrote perfectly good text too. The
 *     network has to come back out of a compile with its fields intact, and
 *     the radio that was handed over has to be in the document as a managed
 *     device with a `wifi` block.
 *   * **`forget` is the same write backwards**, credential included, and it
 *     refuses what netcfgd did not write.
 *   * **The passphrase reaches the file and nothing else.** One canary is the
 *     credential of every secured network here, and it is swept at the end
 *     through every `err` buffer this file filled, everything the commands
 *     printed on standard output, and this process' whole standard error. The
 *     sweep is checked for being vacuous: the canary has to be in the secret
 *     file byte for byte, or nothing was written and its absence elsewhere
 *     proves nothing.
 *
 * NOTHING OUTSIDE ITS OWN DIRECTORY, AND NOTHING ON THE MACHINE
 *   The configuration, factory and run directories are all under one `mkdtemp`
 *   tree and are passed explicitly. `--sys-class-net` points at a fixture, so
 *   the radios here are two empty directories rather than whatever this
 *   machine has -- a test that read `/sys/class/net` would pass on a laptop
 *   and do something else on a build host. Nothing here opens the daemon's
 *   socket: the run directory has none, which is the local route these verbs
 *   exist to serve.
 */
#include "ncfg/base.h"
#include "ncfg/cli.h"
#include "ncfg/config.h"
#include "ncfg/document.h"
#include "ncfg/hooks.h"
#include "ncfg/wifi_profile.h"

#include "testdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* A legal WPA2 passphrase, distinctive enough that finding it anywhere is
 * never a coincidence. */
#define CANARY "kx4-CANARY-wifi-add-passphrase-never-printed-77b"

static int failures;

/*
 * Where a result goes, which is deliberately not `stdout`.
 *
 * The cases below point descriptor 1 at a file to read back what the command
 * printed, and a check that reported into *that* would be counted and never
 * seen. So the real standard output is duplicated once, before any capture.
 */
static FILE *report;

static void check(int condition, const char *what)
{
	(void)fprintf(report, "%-72s %s\n", what, condition ? "ok" : "FAILED");
	(void)fflush(report);
	if (!condition) {
		failures++;
	}
}

static void detail(const char *label, const char *text)
{
	(void)fprintf(report, "       %s: %s\n", label, text ? text : "(none)");
	(void)fflush(report);
}

/* ------------------------------------------------------------------------ *
 * The tree, the capture and the prompt
 * ------------------------------------------------------------------------ */

static char root[256];
static char config_dir[320];
static char factory_dir[320];
static char run_dir[320];
static char class_net[320];
static char capture_file[384];
static char input_file[384];

static ncfg_cli_options_t options;

/* Everything any command here printed on standard output, and every `err`
 * buffer this file filled: both swept at the end. */
static char   everything[128u * 1024u];
static size_t everything_length;

static const char *kept(const char *text)
{
	size_t length = text ? strlen(text) : 0u;

	if (text && everything_length + length + 2u < sizeof(everything)) {
		memcpy(everything + everything_length, text, length);
		everything_length += length;
		everything[everything_length++] = '\n';
		everything[everything_length] = '\0';
	}
	return text;
}

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
	(void)mkdir(path, 0755);
}

/* A radio the fixture has, or an interface that is not one. `phy80211` is what
 * `ncfg_radio_is_wireless` asks for first (0231). */
static void make_link(const char *name, int wireless)
{
	make_directory(in(class_net, name));
	if (wireless) {
		(void)testdir_write(in(in(class_net, name), "phy80211"), "", 0);
	}
}

static int   saved_stdout = -1;
static char *captured;

static void capture_begin(void)
{
	int fd;

	(void)fflush(stdout);
	saved_stdout = dup(STDOUT_FILENO);
	fd = open(capture_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || saved_stdout < 0) {
		(void)fprintf(report, "could not redirect stdout to %s\n", capture_file);
		exit(1);
	}
	(void)dup2(fd, STDOUT_FILENO);
	(void)close(fd);
}

static const char *capture_end(void)
{
	(void)fflush(stdout);
	(void)dup2(saved_stdout, STDOUT_FILENO);
	(void)close(saved_stdout);
	saved_stdout = -1;
	free(captured);
	captured = testdir_read(capture_file, NULL);
	return kept(captured ? captured : "");
}

/*
 * Point standard input at a file holding `text`.
 *
 * `freopen` rather than a `dup2` onto descriptor 0, because the reader goes
 * through `stdin` and a descriptor swapped underneath a stream leaves whatever
 * the stream had already buffered in front of it.
 */
static void stdin_is(const char *text)
{
	(void)testdir_write(input_file, text, strlen(text));
	if (!freopen(input_file, "rb", stdin)) {
		(void)fprintf(report, "could not point standard input at %s\n", input_file);
		exit(1);
	}
}

/* Everything a case here can have written, taken away by name. */
static void fresh_tree(void)
{
	static const char *const files[] = { "wifi-Cafe.conf", "wifi-Office.conf",
		"wifi-Corp.conf", "wifi-Hidden.conf", "10-theirs.conf", "50-wifi-wlan0.conf",
		"50-wifi-wlan1.conf" };
	static const char *const secrets[] = { "Cafe", "Office", "Corp", "Hidden", "shared" };
	size_t at;

	for (at = 0; at < sizeof(files) / sizeof(files[0]); at++) {
		(void)unlink(in(in(config_dir, "conf.d"), files[at]));
	}
	for (at = 0; at < sizeof(secrets) / sizeof(secrets[0]); at++) {
		(void)unlink(in(in(config_dir, "secrets"), secrets[at]));
	}
	(void)testdir_write(in(config_dir, "netcfgd.conf"), "", 0);
}

/* What the machine compiles to now, or NULL. */
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

/* One `ncfg wifi add SSID`, with whatever `options.wifi` currently says. */
static int add(const char *ssid, char *err, size_t err_size)
{
	const char *positional[1];
	int         ok;

	positional[0] = ssid;
	err[0] = '\0';
	capture_begin();
	ok = ncfg_cli_wifi_add(&options, positional, 1u, err, err_size);
	(void)capture_end();
	(void)kept(err);
	return ok;
}

static int forget(const char *id, char *err, size_t err_size)
{
	const char *positional[1];
	int         ok;

	positional[0] = id;
	err[0] = '\0';
	capture_begin();
	ok = ncfg_cli_wifi_forget(&options, positional, 1u, err, err_size);
	(void)capture_end();
	(void)kept(err);
	return ok;
}

/*
 * Whether the passphrase is still where the prompt would have taken it from.
 *
 * **This is what makes "before the prompt" a check rather than a claim.** A
 * refusal that moved after the credential read would have drained standard
 * input, so a case that asserts a flag refusal *and* this is asserting the
 * order as well as the sentence.
 */
static int the_prompt_was_not_reached(void)
{
	char line[256];

	if (!fgets(line, (int)sizeof(line), stdin)) {
		return 0;
	}
	return strncmp(line, CANARY, strlen(CANARY)) == 0;
}

/* The flags back to nothing, and standard input holding a usable passphrase --
 * so that a refusal which happened *after* the prompt would be a length
 * complaint rather than the sentence each case asserts. */
static void nothing_asked_for(void)
{
	memset(&options.wifi, 0, sizeof(options.wifi));
	stdin_is(CANARY "\n");
}

/* ------------------------------------------------------------------------ *
 * What the flags may say together
 * ------------------------------------------------------------------------ */

static void the_flags_that_contradict_each_other(void)
{
	char err[NCFG_ERROR_MAX];

	(void)fprintf(report, "\n-- what the flags may say together, all of it before the "
	    "prompt\n");
	fresh_tree();
	nothing_asked_for();
	options.wifi.open = 1;
	options.wifi.proto = "wpa2";
	check(!add("Cafe", err, sizeof(err)) && strstr(err, "contradict") != NULL,
	    "`--open --wpa2` is refused: one says no passphrase, the other which kind");

	nothing_asked_for();
	options.wifi.identity = "you@example.ac.uk";
	check(!add("Cafe", err, sizeof(err)) && strstr(err, "no method") != NULL,
	    "an enterprise flag with no `--eap` is refused rather than ignored");

	nothing_asked_for();
	options.wifi.eap = "tls";
	options.wifi.identity = "you@example.ac.uk";
	check(!add("Cafe", err, sizeof(err)) && strstr(err, "--client-cert") != NULL,
	    "`--eap tls` with no certificate is refused, naming the flag to add");

	nothing_asked_for();
	options.wifi.eap = "peap";
	options.wifi.identity = "you@example.ac.uk";
	options.wifi.client_cert = "@secret:c";
	check(!add("Cafe", err, sizeof(err)) && strstr(err, "authenticates with a password") != NULL,
	    "  and a certificate with a method that uses a password is refused too");

	nothing_asked_for();
	options.wifi.eap = "peap";
	check(!add("Cafe", err, sizeof(err)) && strstr(err, "--identity") != NULL,
	    "an enterprise network with nobody to be is refused");

	nothing_asked_for();
	options.wifi.eap = "peap";
	options.wifi.identity = "you@example.ac.uk";
	options.wifi.open = 1;
	check(!add("Cafe", err, sizeof(err)) && strstr(err, "contradict") != NULL,
	    "`--open --eap` is refused: one says no authentication, the other which kind");

	nothing_asked_for();
	check(!ncfg_cli_wifi_add(&options, NULL, 0u, err, sizeof(err)) &&
	    strstr(kept(err), "takes one SSID") != NULL,
	    "`ncfg wifi add` with no ssid says what it wanted");
	{
		const char *two[2] = { "Cafe", "extra" };

		check(!ncfg_cli_wifi_add(&options, two, 2u, err, sizeof(err)) &&
		    strstr(kept(err), "takes one SSID") != NULL,
		    "  and so does one with a second argument it cannot place");
	}
	check(!testdir_exists(in(in(config_dir, "conf.d"), "wifi-Cafe.conf")),
	    "and none of those wrote anything");

	/*
	 * The order, not just the sentence. **Secured, deliberately**: an
	 * `--open` network is never asked for a credential at all, so the same
	 * assertion made with one would pass whatever the order was -- which is a
	 * check that inspected nothing. This one refuses on the flags of a network
	 * that *does* want a passphrase, so standard input still holding it is
	 * evidence that the refusal came first.
	 */
	nothing_asked_for();
	options.wifi.identity = "you@example.ac.uk";
	check(!add("Cafe", err, sizeof(err)) && strstr(err, "no method") != NULL,
	    "a secured network is refused on its flags");
	check(the_prompt_was_not_reached(),
	    "  and before the prompt: the passphrase is still there, unread");
}

static void a_name_that_cannot_be_one(void)
{
	char err[NCFG_ERROR_MAX];
	char long_ssid[64];

	(void)fprintf(report, "\n-- a name that cannot be a label, a file and a credential\n");
	fresh_tree();
	nothing_asked_for();
	options.wifi.open = 1;
	options.wifi.id = "../escape";
	check(!add("Cafe", err, sizeof(err)) && strstr(err, "--id") != NULL,
	    "an id that would leave the directory is refused, and says to pass a plainer one");

	memset(long_ssid, 'a', sizeof(long_ssid));
	long_ssid[NCFG_SSID_MAX_LEN + 1u] = '\0';
	nothing_asked_for();
	options.wifi.open = 1;
	check(!add(long_ssid, err, sizeof(err)) && strstr(err, "not a usable ssid") != NULL,
	    "an ssid past 32 octets is refused, because that is what an ssid is");
	check(!testdir_exists(in(in(config_dir, "conf.d"), "wifi-Cafe.conf")),
	    "and neither wrote a file");
}

/* ------------------------------------------------------------------------ *
 * Which radio
 * ------------------------------------------------------------------------ */

static void which_radio_this_is_for(void)
{
	char err[NCFG_ERROR_MAX];

	(void)fprintf(report, "\n-- which radio, decided before the prompt and never guessed\n");
	fresh_tree();
	nothing_asked_for();
	options.wifi.open = 1;
	options.wifi.interface = "eth0";
	check(!add("Cafe", err, sizeof(err)) && strstr(err, "is not a radio") != NULL &&
	    strstr(err, "wlan0") != NULL,
	    "an interface that is here and is not a radio is refused, naming the ones that are");

	/* Secured, for the reason the flag cases are: an open network is never
	 * prompted for anything, so the order could not be seen through one. */
	nothing_asked_for();
	check(!add("Cafe", err, sizeof(err)) && strstr(err, "2 radios") != NULL &&
	    strstr(err, "--interface") != NULL,
	    "two radios and none of them netcfgd's yet is refused rather than chosen between");
	check(the_prompt_was_not_reached(),
	    "  and that refusal too came before anybody was asked to type anything");
	check(!testdir_exists(in(in(config_dir, "conf.d"), "wifi-Cafe.conf")),
	    "  and nothing was written while it could not tell");
}

/* ------------------------------------------------------------------------ *
 * What it writes
 * ------------------------------------------------------------------------ */

static void what_adding_an_open_network_writes(void)
{
	ncfg_document_t *document;
	char             err[NCFG_ERROR_MAX];
	const char      *printed;
	size_t           at;
	int              radio_is_managed = 0;
	int              ok;

	(void)fprintf(report, "\n-- what it writes, asked of the configuration rather than "
	    "of the text\n");
	fresh_tree();
	nothing_asked_for();
	options.wifi.open = 1;
	options.wifi.interface = "wlan0";
	ok = add("Cafe", err, sizeof(err));
	check(ok, err[0] ? err : "an open network is added");
	printed = captured ? captured : "";
	check(strstr(printed, "wrote ") != NULL, "  it says which file it wrote");
	check(strstr(printed, "activated `wlan0`") != NULL,
	    "  and says it took a radio, which is a bigger thing than the network");
	check(strstr(printed, "no security") != NULL,
	    "  and says an open network is readable by anybody in range");

	document = compiled();
	check(network_of(document, "Cafe") != NULL, "  the network is in the configuration");
	for (at = 0; document && at < document->device_count; at++) {
		if (document->devices[at].name &&
		    strcmp(document->devices[at].name, "wlan0") == 0 &&
		    document->devices[at].managed && document->devices[at].wifi) {
			radio_is_managed = 1;
		}
	}
	check(radio_is_managed,
	    "  and the radio is a managed device with a `wifi` block, so something will use it");
	ncfg_document_free(document);

	/* A second block with the same label is a compile error, so it is refused
	 * before anything is written rather than found afterwards. */
	nothing_asked_for();
	options.wifi.open = 1;
	options.wifi.interface = "wlan0";
	check(!add("Cafe", err, sizeof(err)) && strstr(err, "already configured") != NULL,
	    "adding the same network twice is refused, naming what to do instead");
}

static void what_adding_a_secured_network_writes(void)
{
	ncfg_document_t *document;
	const ncfg_wifi_network_t *network;
	char             err[NCFG_ERROR_MAX];
	const char      *printed;
	char            *body;
	int              ok;

	(void)fprintf(report, "\n-- a secured network, and where the passphrase goes\n");
	fresh_tree();
	nothing_asked_for();
	options.wifi.interface = "wlan0";
	options.wifi.hidden = 1;
	options.wifi.proto = "wpa3";
	options.wifi.metric.has = 1;
	options.wifi.metric.value = 120;
	ok = add("Office", err, sizeof(err));
	check(ok, err[0] ? err : "a secured network is added");
	printed = captured ? captured : "";
	check(strstr(printed, "(mode 0600)") != NULL,
	    "  it says the credential was written, and at what mode");
	check(strstr(printed, CANARY) == NULL,
	    "  and what it printed does not contain the passphrase");

	body = testdir_read(in(in(config_dir, "secrets"), "Office"), NULL);
	check(body && strcmp(body, CANARY) == 0,
	    "  the credential is on disk, byte for byte, with the newline taken off");
	free(body);
	body = testdir_read(in(in(config_dir, "conf.d"), "wifi-Office.conf"), NULL);
	check(body && strstr(body, "@secret:Office") != NULL && strstr(body, CANARY) == NULL,
	    "  and the block refers to it rather than holding it");
	free(body);

	document = compiled();
	network = network_of(document, "Office");
	check(network && network->hidden, "  `--hidden` reached the file");
	check(network && network->metric.has && network->metric.value == 120,
	    "  and so did `--metric`, which ranks it against every other link");
	check(network && network->security.kind == NCFG_SECURITY_PSK &&
	    network->security.psk.proto == NCFG_PSK_PROTO_WPA3,
	    "  and so did `--wpa3`, which pins the generation");
	ncfg_document_free(document);
}

static void a_passphrase_the_supplicant_would_refuse(void)
{
	char err[NCFG_ERROR_MAX];

	(void)fprintf(report, "\n-- a passphrase refused here rather than at association "
	    "time\n");
	fresh_tree();
	nothing_asked_for();
	options.wifi.interface = "wlan0";
	stdin_is("short\n");
	check(!add("Office", err, sizeof(err)) && strstr(err, "8 to 63 octets") != NULL,
	    "a passphrase outside WPA's length is refused where it can still be fixed");
	check(strstr(err, "short") == NULL || strstr(err, "that one is 5") != NULL,
	    "  and the message carries the length rather than the value");
	check(!testdir_exists(in(in(config_dir, "secrets"), "Office")),
	    "  and nothing was stored");
}

/* ------------------------------------------------------------------------ *
 * Forgetting
 * ------------------------------------------------------------------------ */

static void forgetting_what_was_added(void)
{
	char        err[NCFG_ERROR_MAX];
	const char *printed;
	int         ok;

	(void)fprintf(report, "\n-- and taking it away again\n");
	fresh_tree();
	nothing_asked_for();
	options.wifi.interface = "wlan0";
	if (!add("Office", err, sizeof(err))) {
		check(0, err);
		return;
	}
	ok = forget("Office", err, sizeof(err));
	check(ok, err[0] ? err : "a network netcfgd wrote is forgotten");
	printed = captured ? captured : "";
	check(strstr(printed, "forgot `Office`") != NULL, "  it says so");
	check(strstr(printed, "removed the credential `Office`") != NULL,
	    "  and says the credential went with it, which nothing else would show");
	check(!testdir_exists(in(in(config_dir, "conf.d"), "wifi-Office.conf")) &&
	    !testdir_exists(in(in(config_dir, "secrets"), "Office")),
	    "  and both files are gone");

	check(!forget("Office", err, sizeof(err)) && strstr(err, "no network") != NULL,
	    "forgetting it twice is refused rather than reported as a removal");
	check(!ncfg_cli_wifi_forget(&options, NULL, 0u, err, sizeof(err)) &&
	    strstr(kept(err), "takes one network id") != NULL,
	    "and `ncfg wifi forget` with no id says what it wanted");

	/* A network somebody wrote themselves is not netcfgd's to remove. */
	(void)testdir_write(in(in(config_dir, "conf.d"), "10-theirs.conf"),
	    "network \"Theirs\" { wifi { open = true } }\n", 42u);
	check(!forget("Theirs", err, sizeof(err)) &&
	    strstr(err, "not in a file netcfgd wrote") != NULL,
	    "a network in somebody's own file is refused, and the file is theirs to edit");
	check(testdir_exists(in(in(config_dir, "conf.d"), "10-theirs.conf")),
	    "  and it is still there");
	(void)unlink(in(in(config_dir, "conf.d"), "10-theirs.conf"));
}

/* ------------------------------------------------------------------------ *
 * The canary
 * ------------------------------------------------------------------------ */

static void no_passphrase_reaches_a_message(const char *stderr_text)
{
	char       *body;
	const char *found;

	(void)fprintf(report, "\n-- the canary, swept through every channel it could leave "
	    "by\n");
	/*
	 * Non-vacuity first. A sweep over a run that never wrote the credential
	 * proves nothing at all, so one is written here and read back byte for
	 * byte before its absence anywhere else means anything.
	 */
	fresh_tree();
	nothing_asked_for();
	options.wifi.interface = "wlan0";
	{
		char err[NCFG_ERROR_MAX];

		int ok = add("Sweep", err, sizeof(err));

		check(ok, err[0] ? err : "the sweep's own write landed");
	}
	body = testdir_read(in(in(config_dir, "secrets"), "Sweep"), NULL);
	check(body && strcmp(body, CANARY) == 0,
	    "the passphrase is in the file it was meant for, byte for byte");
	free(body);

	found = strstr(everything, CANARY);
	check(found == NULL,
	    "and in no `err` buffer and nothing any of these commands printed");
	if (found) {
		detail("in", found - 200 > everything ? found - 200 : everything);
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
	int   fd = dup(STDOUT_FILENO);

	report = fd >= 0 ? fdopen(fd, "w") : NULL;
	if (!report) {
		printf("could not keep a handle on the real standard output\n");
		return 1;
	}

	(void)testdir_make("cli-wifi");
	(void)snprintf(root, sizeof(root), "%s", testdir_path);
	(void)snprintf(config_dir, sizeof(config_dir), "%s/etc", root);
	(void)snprintf(factory_dir, sizeof(factory_dir), "%s/factory", root);
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", root);
	(void)snprintf(class_net, sizeof(class_net), "%s/sys", root);
	(void)snprintf(capture_file, sizeof(capture_file), "%s/stdout.log", root);
	(void)snprintf(input_file, sizeof(input_file), "%s/stdin", root);
	(void)snprintf(stderr_path, sizeof(stderr_path), "%s/stderr.log", root);
	make_directory(config_dir);
	make_directory(in(config_dir, "conf.d"));
	make_directory(factory_dir);
	make_directory(run_dir);
	make_directory(class_net);
	/* Two radios and one interface that is not one, so that "which radio" is a
	 * real question here and the answer never comes from this machine. */
	make_link("wlan0", 1);
	make_link("wlan1", 1);
	make_link("eth0", 0);

	memset(&options, 0, sizeof(options));
	options.config_dir = config_dir;
	options.factory_dir = factory_dir;
	options.run_dir = run_dir;
	options.sys_class_net = class_net;

	stderr_copy = dup(STDERR_FILENO);
	{
		int redirected = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		if (redirected >= 0) {
			(void)dup2(redirected, STDERR_FILENO);
			(void)close(redirected);
		}
	}

	the_flags_that_contradict_each_other();
	a_name_that_cannot_be_one();
	which_radio_this_is_for();
	what_adding_an_open_network_writes();
	what_adding_a_secured_network_writes();
	a_passphrase_the_supplicant_would_refuse();
	forgetting_what_was_added();

	(void)fflush(stderr);
	sweep = testdir_read(stderr_path, NULL);
	if (stderr_copy >= 0) {
		(void)dup2(stderr_copy, STDERR_FILENO);
		(void)close(stderr_copy);
	}
	no_passphrase_reaches_a_message(sweep);
	free(sweep);
	free(captured);

	(void)freopen("/dev/null", "rb", stdin);
	testdir_remove(testdir_path);
	if (failures) {
		(void)fprintf(report, "\n%d check(s) failed\n", failures);
		return 1;
	}
	(void)fprintf(report, "\n`ncfg wifi add` and `ncfg wifi forget`: every check passed\n");
	return 0;
}
