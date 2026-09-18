/*
 * cli_profile_test.c -- `ncfg profile` and `ncfg config`, which is one story.
 *
 * WHY THE TWO VERBS ARE IN ONE FILE
 *   0151's rule ties them together: **a settings write by a person takes the
 *   machine off its profile**, with the profile folded into `conf.d` so that
 *   what is running does not move. `ncfg config put` is the settings write and
 *   `ncfg profile get` is how anybody can tell what it did, so a test for
 *   either one alone can only assert half of the rule.
 *
 * WHAT IS ASSERTED, AND WHY IT IS THE FILES
 *   The fold is a claim about three things at once -- the selection, the files
 *   in `conf.d`, and what the machine compiles to -- and only the third of
 *   those is what anybody cares about. So the workflow cases compile the
 *   result and read a value out of it, rather than asserting that a particular
 *   file appeared.
 *
 * WHAT THIS DOES NOT DO
 *   **Nothing talks to the running daemon.** Every fixture names its own
 *   config, factory and run directories; the one case that needs a listener
 *   binds an `AF_UNIX` socket in a directory this test made and forks a child
 *   that answers one line.
 */
#include "ncfg/cli.h"

#include "ncfg/base.h"
#include "ncfg/config.h"
#include "ncfg/document.h"
#include "ncfg/hooks.h"

#include "testdir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

/*
 * Where a result goes, which is deliberately not `stdout`.
 *
 * The cases below point descriptor 1 at a file to read back what the command
 * printed, and a check that reported into *that* would be counted and never
 * seen -- a failure inside a capture would raise the count with no line saying
 * which. So the real standard output is duplicated once, before any capture,
 * and every result is written there.
 */
static FILE *report;

static void report_opens_before_any_capture(void)
{
	int fd = dup(STDOUT_FILENO);

	report = fd >= 0 ? fdopen(fd, "w") : NULL;
	if (!report) {
		printf("could not keep a handle on the real standard output\n");
		exit(1);
	}
}

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
 * Capturing what the program printed
 * ------------------------------------------------------------------------ */

static int   saved_stdout = -1;
static char  capture_file[512];
static char *captured;

static void capture_begin(void)
{
	int fd;

	(void)fflush(stdout);
	saved_stdout = dup(STDOUT_FILENO);
	fd = open(capture_file, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || saved_stdout < 0) {
		printf("could not redirect stdout to %s\n", capture_file);
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
	return captured ? captured : "";
}

static int has_line(const char *text, const char *wanted)
{
	size_t      length = strlen(wanted);
	const char *at = text;

	while (at && *at) {
		const char *end = strchr(at, '\n');
		size_t      run = end ? (size_t)(end - at) : strlen(at);

		if (run == length && memcmp(at, wanted, length) == 0) {
			return 1;
		}
		if (!end) {
			return 0;
		}
		at = end + 1;
	}
	return 0;
}

static void line(const char *text, const char *wanted, const char *what)
{
	int found = has_line(text, wanted);

	check(found, what);
	if (!found) {
		detail("wanted", wanted);
	}
}

/* ------------------------------------------------------------------------ *
 * The fixture
 * ------------------------------------------------------------------------ *
 *
 * A config tree with two profiles, and a run directory with no socket -- so
 * every write below takes the local route, which is the machine being
 * configured before netcfgd runs on it.
 */

/* The directory this test made; every path below is under it. */
static const char *root;
static char config_dir[320];
static char factory_dir[320];
static char run_dir[320];
static ncfg_cli_options_t options;

static const char *base_config =
    "interface eth0 {\n\tconfig = \"dhcp\"\n}\ndevice eth0 { mtu = 1500 }\n";
static const char *office_profile =
    "override interface eth0 {\n\tconfig = \"dhcp\"\n}\noverride device eth0 { mtu = 9000 }\n";

static void fixture(void)
{
	char path[512];

	(void)snprintf(config_dir, sizeof(config_dir), "%s/etc", root);
	(void)snprintf(factory_dir, sizeof(factory_dir), "%s/factory", root);
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", root);
	(void)mkdir(config_dir, 0755);
	(void)mkdir(run_dir, 0755);
	(void)snprintf(path, sizeof(path), "%s/conf.d", config_dir);
	(void)mkdir(path, 0755);
	(void)snprintf(path, sizeof(path), "%s/profile", config_dir);
	(void)mkdir(path, 0755);
	(void)snprintf(path, sizeof(path), "%s/profile/office", config_dir);
	(void)mkdir(path, 0755);
	(void)snprintf(path, sizeof(path), "%s/profile/offline", config_dir);
	(void)mkdir(path, 0755);

	(void)snprintf(path, sizeof(path), "%s/netcfgd.conf", config_dir);
	(void)testdir_write(path, base_config, strlen(base_config));
	(void)snprintf(path, sizeof(path), "%s/profile/office/10-office.conf", config_dir);
	(void)testdir_write(path, office_profile, strlen(office_profile));

	memset(&options, 0, sizeof(options));
	options.config_dir = config_dir;
	options.factory_dir = factory_dir;
	options.run_dir = run_dir;
}

/*
 * Put the tree back to what `fixture` made, by name.
 *
 * Every file a case here can produce is listed. A pattern would be shorter and
 * would also delete whatever else happened to be in a directory this test did
 * not create -- which is the rule `~/.claude/guidelines` sets for a removal
 * whose names are knowable, and these are.
 */
static void reset(void)
{
	static const char *const drop_ins[] = { "90-profile.conf", "05-profile-office.conf",
		"05-profile-offline.conf", "zz-profile-office.conf", "zz-profile-offline.conf",
		"50-mine.conf", "50-bad.conf", "site.conf" };
	static const char *const saved[] = { "office-v2", "fresh" };
	char                     path[512];
	size_t                   which;

	for (which = 0; which < sizeof(drop_ins) / sizeof(drop_ins[0]); which++) {
		(void)snprintf(path, sizeof(path), "%s/conf.d/%s", config_dir, drop_ins[which]);
		(void)unlink(path);
	}
	for (which = 0; which < sizeof(saved) / sizeof(saved[0]); which++) {
		(void)snprintf(path, sizeof(path), "%s/profile/%s/00-saved.conf", config_dir,
		    saved[which]);
		(void)unlink(path);
		(void)snprintf(path, sizeof(path), "%s/profile/%s", config_dir, saved[which]);
		(void)rmdir(path);
	}
	(void)snprintf(path, sizeof(path), "%s/netcfgd.conf", config_dir);
	(void)testdir_write(path, base_config, strlen(base_config));
	(void)snprintf(path, sizeof(path), "%s/profile/office/10-office.conf", config_dir);
	(void)testdir_write(path, office_profile, strlen(office_profile));
}

/* Everything the fixture made, taken away by name. */
static void fixture_remove(void)
{
	static const char *const dirs[] = { "%s/etc/profile/office", "%s/etc/profile/offline",
		"%s/etc/profile", "%s/etc/conf.d", "%s/factory/profile/shipped",
		"%s/factory/profile/office", "%s/factory/profile", "%s/factory" };
	char   path[512];
	size_t which;

	reset();
	(void)snprintf(path, sizeof(path), "%s/etc/profile/office/10-office.conf", root);
	(void)unlink(path);
	(void)snprintf(path, sizeof(path), "%s/etc/netcfgd.conf", root);
	(void)unlink(path);
	for (which = 0; which < sizeof(dirs) / sizeof(dirs[0]); which++) {
		(void)snprintf(path, sizeof(path), dirs[which], root);
		(void)rmdir(path);
	}
}

/* Run one verb, with whatever it printed thrown away. */
static int run_profile(const char **positional, size_t count, char *err, size_t err_size)
{
	int ok;

	err[0] = '\0';
	capture_begin();
	ok = ncfg_cli_profile(&options, positional, count, err, err_size);
	(void)capture_end();
	return ok;
}

static int run_config(const char **positional, size_t count, char *err, size_t err_size)
{
	int ok;

	err[0] = '\0';
	capture_begin();
	ok = ncfg_cli_config(&options, positional, count, err, err_size);
	(void)capture_end();
	return ok;
}

/* A drop-in to hand `ncfg config put`, written where this test can read it. */
static const char *drop_in_file(const char *name, const char *text, char *out, size_t out_size)
{
	(void)snprintf(out, out_size, "%s/%s", root, name);
	(void)testdir_write(out, text, strlen(text));
	return out;
}

/* What the machine compiles to now, or NULL. */
static ncfg_document_t *running(void)
{
	char err[NCFG_ERROR_MAX];
	ncfg_config_sources_t sources = { NULL, 0, 0 };
	ncfg_document_t      *document;

	if (!ncfg_config_load_with_profile(factory_dir, config_dir, &sources, err, sizeof(err))) {
		ncfg_config_sources_free(&sources);
		return NULL;
	}
	document = ncfg_config_compile(&sources, ncfg_hook_sink_unwritten(), NULL, err,
	    sizeof(err));
	ncfg_config_sources_free(&sources);
	return document;
}

/* The profile in effect, as a freshly compiled document reports it. */
static int chosen_is(const char *name)
{
	ncfg_document_t *document = running();
	int              same;

	if (!document) {
		return 0;
	}
	if (!name) {
		same = document->globals.profile == NULL;
	} else {
		same = document->globals.profile != NULL &&
		    strcmp(document->globals.profile, name) == 0;
	}
	ncfg_document_free(document);
	return same;
}

/* ------------------------------------------------------------------------ *
 * The round trip
 * ------------------------------------------------------------------------ */

/* Nothing chosen, choose one, read it back, take it away again. */
static void set_get_and_unset_round_trip(void)
{
	const char *positional[2];
	const char *printed;
	char        err[NCFG_ERROR_MAX];
	char        written[512];

	reset();
	check(chosen_is(NULL), "nothing is chosen to begin with");

	positional[0] = "get";
	err[0] = '\0';
	capture_begin();
	(void)ncfg_cli_profile(&options, positional, 1u, err, sizeof(err));
	printed = capture_end();
	line(printed, "no profile chosen",
	    "and `get` says so rather than naming a profile called `none`");

	positional[0] = "set";
	positional[1] = "office";
	check(run_profile(positional, 2u, err, sizeof(err)), "`profile set office` runs");
	if (err[0] != '\0') {
		detail("said", err);
	}
	check(chosen_is("office"), "and the machine is on it");

	/* The fixed name of 0151: switching twice must edit one file rather than
	 * leaving the previous choice behind for the loader to argue with. */
	(void)snprintf(written, sizeof(written), "%s/conf.d/90-profile.conf", config_dir);
	check(testdir_exists(written), "the drop-in it owns is there");

	positional[1] = "offline";
	check(run_profile(positional, 2u, err, sizeof(err)), "`profile set offline` runs");
	check(chosen_is("offline"), "and switching twice moves the selection");
	check(testdir_exists(written), "into the same one file");

	positional[0] = "unset";
	check(run_profile(positional, 1u, err, sizeof(err)), "`profile unset` runs");
	check(chosen_is(NULL), "and the machine is back on none");
	check(!testdir_exists(written), "with the drop-in gone");
	reset();
}

/*
 * A settings write takes the machine off its profile, folding it in so that
 * what is running does not move -- early enough that the edit which caused it
 * actually wins.
 */
static void a_settings_write_takes_the_machine_off_its_profile(void)
{
	const char      *positional[3];
	char             err[NCFG_ERROR_MAX];
	char             source[512];
	ncfg_document_t *document;

	reset();
	positional[0] = "set";
	positional[1] = "office";
	check(run_profile(positional, 2u, err, sizeof(err)), "on a profile to begin with");

	positional[0] = "put";
	positional[1] = "50-mine";
	positional[2] = drop_in_file("mine.conf", "override device eth0 { mtu = 1400 }\n", source,
	    sizeof(source));
	check(run_config(positional, 3u, err, sizeof(err)), "a settings write is accepted");
	if (err[0] != '\0') {
		detail("said", err);
	}
	check(chosen_is(NULL), "and the machine is on none now");

	document = running();
	check(document != NULL && document->device_count > 0 &&
	    document->devices[0].mtu.has && document->devices[0].mtu.value == 1400,
	    "and the edit won, which is what folding early rather than late is for");
	ncfg_document_free(document);
	reset();
}

/*
 * A settings write that is refused changed no setting, so it must not have
 * taken the machine off its profile either.
 */
static void a_refused_write_leaves_the_profile_alone(void)
{
	const char *positional[3];
	char        err[NCFG_ERROR_MAX];
	char        source[512];
	char        path[512];

	reset();
	positional[0] = "set";
	positional[1] = "office";
	check(run_profile(positional, 2u, err, sizeof(err)), "on a profile to begin with");

	positional[0] = "put";
	positional[1] = "50-bad";
	positional[2] = drop_in_file("bad.conf", "override interface eth0 { nonsense = 1 }\n",
	    source, sizeof(source));
	check(!run_config(positional, 3u, err, sizeof(err)),
	    "a drop-in that does not compile is refused");
	check(strstr(err, "nonsense") != NULL, "and the diagnostic names what is wrong");

	check(chosen_is("office"), "and the machine is still on its profile");
	(void)snprintf(path, sizeof(path), "%s/conf.d/05-profile-office.conf", config_dir);
	check(!testdir_exists(path), "with no fold left behind");
	(void)snprintf(path, sizeof(path), "%s/conf.d/zz-profile-office.conf", config_dir);
	check(!testdir_exists(path), "at either position the fold can take");
	reset();
}

/*
 * **A removal that removed nothing leaves the profile alone.**
 *
 * The Rust folds the profile into `conf.d` before every settings write and
 * undoes the fold only when the write *fails*. `ncfg config rm` of a name that
 * was never written neither fails nor writes -- `remove_drop_in` answers
 * "absent is success" -- so the fold stood: a command that changed nothing
 * reported success, took the machine off its profile, and left a folded copy
 * of it in `conf.d`. Nothing that is running moves, which is what made it
 * quiet; what moves is the answer `ncfg profile get` gives afterwards, and the
 * profile an operator would then have to choose again.
 */
static void a_removal_that_removed_nothing_leaves_the_profile_alone(void)
{
	const char *positional[2];
	const char *printed;
	char        err[NCFG_ERROR_MAX];
	char        path[512];

	reset();
	positional[0] = "set";
	positional[1] = "office";
	check(run_profile(positional, 2u, err, sizeof(err)), "on a profile to begin with");

	positional[0] = "rm";
	positional[1] = "never-existed";
	err[0] = '\0';
	capture_begin();
	check(ncfg_cli_config(&options, positional, 2u, err, sizeof(err)),
	    "removing a drop-in that is not there is success, since that is the state asked for");
	printed = capture_end();
	check(strstr(printed, "is not in") != NULL,
	    "and it says so rather than reporting a removal");

	check(chosen_is("office"), "and the machine is still on its profile");
	(void)snprintf(path, sizeof(path), "%s/conf.d/05-profile-office.conf", config_dir);
	check(!testdir_exists(path), "with no fold left behind by a command that changed nothing");
	(void)snprintf(path, sizeof(path), "%s/conf.d/zz-profile-office.conf", config_dir);
	check(!testdir_exists(path), "at either position the fold can take");

	/* And the removal that does remove something still takes it off. */
	{
		const char *put[3];
		char        source[512];

		put[0] = "put";
		put[1] = "50-mine";
		put[2] = drop_in_file("mine.conf", "override device eth0 { mtu = 1400 }\n",
		    source, sizeof(source));
		check(run_config(put, 3u, err, sizeof(err)), "a real settings write is accepted");
		check(chosen_is(NULL), "and that one does take the machine off its profile");
	}
	reset();
}

/* ------------------------------------------------------------------------ *
 * Names
 * ------------------------------------------------------------------------ */

static void a_name_with_no_directory_is_refused(void)
{
	const char *positional[2];
	char        err[NCFG_ERROR_MAX];
	char        path[512];

	reset();
	positional[0] = "set";
	positional[1] = "nosuch";
	check(!run_profile(positional, 2u, err, sizeof(err)),
	    "a profile with no directory is refused rather than written");
	check(strstr(err, "no profile called `nosuch`") != NULL, "and the sentence names it");
	check(strstr(err, "office") != NULL, "and says what this machine does have");
	(void)snprintf(path, sizeof(path), "%s/conf.d/90-profile.conf", config_dir);
	check(!testdir_exists(path), "and nothing was written");
	reset();
}

static void a_name_that_is_a_path_is_refused(void)
{
	static const char *const bad[] = { "../elsewhere", "office/inner", ".hidden", "" };
	const char              *positional[2];
	char                     err[NCFG_ERROR_MAX];
	size_t                   which;

	reset();
	positional[0] = "set";
	for (which = 0; which < sizeof(bad) / sizeof(bad[0]); which++) {
		positional[1] = bad[which];
		check(!run_profile(positional, 2u, err, sizeof(err)),
		    "a name that is a path, or hidden, or empty, is refused");
		check(strstr(err, "cannot be a profile name") != NULL,
		    "before the compiler sees it, so the message says which part was wrong");
		if (strstr(err, "cannot be a profile name") == NULL) {
			detail("said", err);
		}
	}
	reset();
}

/* A name that is a path is refused on the local route too, not only by the
 * daemon -- a client that only ever met the daemon's refusal would be a client
 * somebody ran without one. */
static void a_drop_in_name_that_is_a_path_is_refused_locally(void)
{
	const char *positional[3];
	char        err[NCFG_ERROR_MAX];
	char        source[512];

	reset();
	positional[0] = "put";
	positional[1] = "../escape";
	positional[2] = drop_in_file("x.conf", "interface eth1 {\n\tconfig = \"dhcp\"\n}\n",
	    source, sizeof(source));
	check(!run_config(positional, 3u, err, sizeof(err)),
	    "a drop-in name that is a path is refused locally");
	detail("said", err);
	reset();
}

/* ------------------------------------------------------------------------ *
 * `ncfg config put` and `rm`
 * ------------------------------------------------------------------------ */

static void with_no_daemon_the_drop_in_is_written_locally(void)
{
	const char *positional[3];
	const char *printed;
	char        err[NCFG_ERROR_MAX];
	char        source[512];
	char        path[512];

	reset();
	positional[0] = "put";
	positional[1] = "site";
	positional[2] = drop_in_file("site.conf", "interface eth1 {\n\tconfig = \"dhcp\"\n}\n",
	    source, sizeof(source));
	err[0] = '\0';
	capture_begin();
	check(ncfg_cli_config(&options, positional, 3u, err, sizeof(err)),
	    "with no daemon the drop-in is written locally");
	printed = capture_end();
	if (err[0] != '\0') {
		detail("said", err);
	}
	(void)snprintf(path, sizeof(path), "%s/conf.d/site.conf", config_dir);
	check(testdir_exists(path), "into the directory netcfgd reads");
	check(strstr(printed, "wrote ") != NULL, "and it says what it wrote");
	check(strstr(printed, "nothing is listening on ") != NULL,
	    "and that it took the local route, which is the half a reader needs");
	reset();
}

static void an_empty_drop_in_is_refused(void)
{
	const char *positional[3];
	char        err[NCFG_ERROR_MAX];
	char        source[512];

	reset();
	positional[0] = "put";
	positional[1] = "gone";
	positional[2] = drop_in_file("nothing.conf", "\n   \n", source, sizeof(source));
	check(!run_config(positional, 3u, err, sizeof(err)),
	    "an empty drop-in configures nothing and is refused");
	check(strstr(err, "ncfg config rm") != NULL, "and the sentence says what to use instead");
	reset();
}

static void put_takes_a_name_and_at_most_one_file(void)
{
	const char *positional[5];
	char        err[NCFG_ERROR_MAX];
	char        source[512];

	reset();
	positional[0] = "put";
	check(!run_config(positional, 1u, err, sizeof(err)), "`config put` needs a name");
	check(strstr(err, "The name is not a path") != NULL,
	    "and the sentence says what a name is");

	positional[1] = "site";
	positional[2] = drop_in_file("site.conf", "interface eth1 { config = \"dhcp\" }\n",
	    source, sizeof(source));
	positional[3] = "extra";
	check(!run_config(positional, 4u, err, sizeof(err)),
	    "and it takes at most one file, counting what it got");
	detail("said", err);
	reset();
}

/*
 * With a daemon listening, the text goes to it and no file is written.
 *
 * The property this command exists for: 0127 makes netcfgd the writer, so what
 * proves the route is that `conf.d` is empty afterwards. The request carries
 * the text and not the path -- a request naming a path would be a request to
 * read a file as root.
 */
static void with_a_daemon_listening_the_text_goes_to_it(void)
{
	struct sockaddr_un address;
	const char        *positional[3];
	char               socket_path[512];
	char               sent_path[512];
	char               source[512];
	char               path[512];
	char               err[NCFG_ERROR_MAX];
	char              *sent;
	pid_t              child;
	int                listener;

	reset();
	(void)snprintf(socket_path, sizeof(socket_path), "%s/netcfgd.sock", run_dir);
	(void)snprintf(sent_path, sizeof(sent_path), "%s/sent", root);

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (strlen(socket_path) >= sizeof(address.sun_path)) {
		check(0, "the fixture's socket path fits in a unix address");
		return;
	}
	memcpy(address.sun_path, socket_path, strlen(socket_path));
	listener = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listener < 0 ||
	    bind(listener, (const struct sockaddr *)&address, sizeof(address)) < 0 ||
	    listen(listener, 1) < 0) {
		check(0, "a fake daemon can be bound");
		if (listener >= 0) {
			(void)close(listener);
		}
		return;
	}
	child = fork();
	if (child == 0) {
		int fd = accept(listener, NULL, NULL);

		if (fd >= 0) {
			char    got[8192];
			ssize_t read_in = recv(fd, got, sizeof(got), 0);

			if (read_in > 0) {
				(void)testdir_write(sent_path, got, (size_t)read_in);
			}
			(void)send(fd, "{\"response\":\"ok\"}\n", 18u, MSG_NOSIGNAL);
			(void)close(fd);
		}
		(void)close(listener);
		_exit(0);
	}
	if (child < 0) {
		check(0, "a fake daemon can be started");
		(void)close(listener);
		(void)unlink(socket_path);
		return;
	}

	positional[0] = "put";
	positional[1] = "site";
	positional[2] = drop_in_file("site.conf", "interface eth1 {\n\tconfig = \"dhcp\"\n}\n",
	    source, sizeof(source));
	check(run_config(positional, 3u, err, sizeof(err)), "the daemon answers ok");
	if (err[0] != '\0') {
		detail("said", err);
	}
	(void)waitpid(child, NULL, 0);
	(void)close(listener);
	(void)unlink(socket_path);

	sent = testdir_read(sent_path, NULL);
	check(sent != NULL && strstr(sent, "config_put") != NULL, "and it was asked to store one");
	check(sent != NULL && strstr(sent, "interface eth1") != NULL,
	    "the text crossed the socket");
	check(sent != NULL && strstr(sent, "site.conf") == NULL,
	    "and the path it was read from did not, which is 0127 in one assertion");
	free(sent);
	(void)unlink(sent_path);

	(void)snprintf(path, sizeof(path), "%s/conf.d/site.conf", config_dir);
	check(!testdir_exists(path), "and nothing was written locally");
	reset();
}

/* ------------------------------------------------------------------------ *
 * Listing and saving
 * ------------------------------------------------------------------------ */

static void list_reports_both_layers_and_who_owns_a_name(void)
{
	const char *positional[1];
	const char *printed;
	char        err[NCFG_ERROR_MAX];
	char        path[512];

	reset();
	(void)mkdir(factory_dir, 0755);
	(void)snprintf(path, sizeof(path), "%s/profile", factory_dir);
	(void)mkdir(path, 0755);
	(void)snprintf(path, sizeof(path), "%s/profile/shipped", factory_dir);
	(void)mkdir(path, 0755);
	(void)snprintf(path, sizeof(path), "%s/profile/office", factory_dir);
	(void)mkdir(path, 0755);

	positional[0] = "list";
	err[0] = '\0';
	capture_begin();
	check(ncfg_cli_profile(&options, positional, 1u, err, sizeof(err)), "`profile list` runs");
	printed = capture_end();
	line(printed, "  office  (yours)",
	    "a name in both layers is reported as the operator's, since theirs layers on top");
	line(printed, "  offline  (yours)", "and one only they have is theirs");
	line(printed, "  shipped  (shipped)", "and one only the image has is the image's");

	/* And the chosen one is marked. */
	{
		const char *set_it[2];

		set_it[0] = "set";
		set_it[1] = "office";
		check(run_profile(set_it, 2u, err, sizeof(err)), "choose one");
	}
	capture_begin();
	(void)ncfg_cli_profile(&options, positional, 1u, err, sizeof(err));
	printed = capture_end();
	line(printed, "* office  (yours)", "and the chosen one is marked with a star");
	reset();
}

/*
 * The workflow of 0151 end to end: choose a profile, change a setting, save it.
 *
 * What the machine runs must not move at any step, and the profile that was
 * chosen at the start must come out of it untouched -- which is the whole
 * reason saving is a separate explicit act.
 */
static void the_set_change_save_workflow_keeps_what_is_running(void)
{
	const char      *positional[3];
	char             err[NCFG_ERROR_MAX];
	char             source[512];
	char             crafted[512];
	char             path[512];
	char            *before;
	char            *after_text;
	ncfg_document_t *document;

	reset();
	(void)snprintf(crafted, sizeof(crafted), "%s/profile/office/10-office.conf", config_dir);
	before = testdir_read(crafted, NULL);

	positional[0] = "set";
	positional[1] = "office";
	check(run_profile(positional, 2u, err, sizeof(err)), "choose a profile");

	positional[0] = "put";
	positional[1] = "50-mine";
	positional[2] = drop_in_file("mine.conf", "override device eth0 { mtu = 1400 }\n", source,
	    sizeof(source));
	check(run_config(positional, 3u, err, sizeof(err)), "change a setting");

	document = running();
	check(document && document->device_count > 0 && document->devices[0].mtu.has &&
	    document->devices[0].mtu.value == 1400, "the edit is what is running");
	ncfg_document_free(document);

	positional[0] = "save";
	positional[1] = "office-v2";
	check(run_profile(positional, 2u, err, sizeof(err)), "save it into a profile");
	if (err[0] != '\0') {
		detail("said", err);
	}

	document = running();
	check(document && document->device_count > 0 && document->devices[0].mtu.has &&
	    document->devices[0].mtu.value == 1400, "and nothing moved");
	check(document && document->globals.profile &&
	    strcmp(document->globals.profile, "office-v2") == 0, "the new profile is selected");
	ncfg_document_free(document);

	(void)snprintf(path, sizeof(path), "%s/profile/office-v2/00-saved.conf", config_dir);
	check(testdir_exists(path), "and the snapshot is where a profile is read from");

	/* The crafted profile is byte-identical. Nothing here may rewrite it. */
	after_text = testdir_read(crafted, NULL);
	check(before && after_text && strcmp(before, after_text) == 0,
	    "the profile that was chosen at the start is untouched");
	free(before);
	free(after_text);

	/* And the fold moved into the profile rather than being copied, so
	 * switching away later does not leave the old profile in the base. */
	(void)snprintf(path, sizeof(path), "%s/conf.d/05-profile-office.conf", config_dir);
	check(!testdir_exists(path), "with no folded copy of the old profile left in `conf.d`");
	(void)snprintf(path, sizeof(path), "%s/conf.d/zz-profile-office.conf", config_dir);
	check(!testdir_exists(path), "at either position");
	reset();
}

static void saving_over_a_profile_needs_saying_so(void)
{
	const char *positional[2];
	char        err[NCFG_ERROR_MAX];

	reset();
	positional[0] = "save";
	positional[1] = "office";
	check(!run_profile(positional, 2u, err, sizeof(err)),
	    "saving over an existing profile is refused");
	check(strstr(err, "already exists") != NULL, "and says it is already there");
	check(strstr(err, "--replace") != NULL,
	    "and names the flag in this caller's vocabulary rather than a button's");

	/* And a hand-written profile is refused even with `--replace`, since
	 * saving cannot reproduce files it did not write. */
	options.replace = 1;
	check(!run_profile(positional, 2u, err, sizeof(err)),
	    "and one written by hand is refused even then");
	check(strstr(err, "written by hand") != NULL, "saying why");
	detail("said", err);
	options.replace = 0;

	positional[1] = "save";
	check(!run_profile(positional, 1u, err, sizeof(err)), "`profile save` needs a name");
	reset();
}

static void an_unknown_subcommand_is_named(void)
{
	const char *positional[1];
	char        err[NCFG_ERROR_MAX];

	positional[0] = "wibble";
	check(!run_profile(positional, 1u, err, sizeof(err)),
	    "an unknown profile subcommand is refused");
	check(strstr(err, "wibble") != NULL && strstr(err, "`get`") != NULL,
	    "and the sentence quotes it and lists what there is");

	positional[0] = "wobble";
	check(!run_config(positional, 1u, err, sizeof(err)),
	    "and so is an unknown config subcommand");
	check(strstr(err, "`put` or `rm`") != NULL, "naming the two there are");
}

int main(void)
{
	report_opens_before_any_capture();
	(void)testdir_make("cli-profile");
	root = testdir_path;
	(void)snprintf(capture_file, sizeof(capture_file), "%s/out", testdir_path);
	fixture();

	set_get_and_unset_round_trip();
	a_settings_write_takes_the_machine_off_its_profile();
	a_refused_write_leaves_the_profile_alone();
	a_removal_that_removed_nothing_leaves_the_profile_alone();

	a_name_with_no_directory_is_refused();
	a_name_that_is_a_path_is_refused();
	a_drop_in_name_that_is_a_path_is_refused_locally();

	with_no_daemon_the_drop_in_is_written_locally();
	an_empty_drop_in_is_refused();
	put_takes_a_name_and_at_most_one_file();
	with_a_daemon_listening_the_text_goes_to_it();

	list_reports_both_layers_and_who_owns_a_name();
	the_set_change_save_workflow_keeps_what_is_running();
	saving_over_a_profile_needs_saying_so();
	an_unknown_subcommand_is_named();

	fixture_remove();
	free(captured);
	testdir_remove(testdir_path);

	if (failures == 0) {
		(void)fprintf(report, "cli_profile_test: all checks passed\n");
	} else {
		(void)fprintf(report, "cli_profile_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
