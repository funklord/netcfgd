/*
 * daemon_wifi_test.c -- the daemon's wifi half, against a radio that is not
 * one.
 *
 * WHAT IT MAY NOT TOUCH
 *   This is the developer's own workstation, its wifi is live, and the real
 *   netcfgd is managing it. Nothing here goes near `/run/wpa_supplicant`,
 *   `/etc/netcfgd`, `/run/netcfgd` or the running supplicant: every path is
 *   under one `mkdtemp` directory, the interfaces are called `wlan0` and
 *   `wlan1` and exist only as directories in a fake `/sys/class/net`, and
 *   `ncfg_wifi_where_t` has no defaults to fall back to.
 *
 * THE FAKES ARE THE REPOSITORY'S
 *   `tests/live/fake_supplicant.py` and `tests/live/fake_hostapd.py`, run as
 *   they are. Their first paragraphs carry the rule this depends on -- **the
 *   one thing this repository cannot produce on demand is a radio, so the
 *   hardware is faked and the wire format is the real one** -- and a second
 *   copy of either would be a second place for the format to drift. They are
 *   also the fakes `make live` drives, so a parser changing its mind about the
 *   format is something both suites notice.
 *
 * HOW A FAKE CANNOT OUTLIVE THIS
 *   Three things, because one is not enough for a child that binds a socket.
 *   Each is started under `timeout -k 2 60`, which ends it whatever happens to
 *   this process; each is put in **its own process group**, so the parent can
 *   take down `timeout` and the python it started together; and every pid is
 *   recorded and killed **by that pid**, never by name, path or pattern.
 *
 * WHICH HOOK SINK, AND WHY IT IS THE UNWRITTEN ONE
 *   Two checks below compile what `ncfg_wifi_radio_blocks` writes and ask the
 *   planner what it would do with the result. **The question is what this text
 *   means, not what to act on** -- the document is thrown away and there is
 *   nowhere to put a script -- so both pass `ncfg_hook_sink_unwritten()`, and
 *   each site says so. The Rust uses `NoHooks` at both, which is
 *   `ncfg_hook_sink_refusing()` here: not a live defect, because neither
 *   fixture has a hook in it, but the wrong sink for the question -- a fixture
 *   that gained one would fail with a sentence about hooks rather than about
 *   planning. 0258 and `project.md`'s `UnwrittenHooks` section.
 *
 * THE CANARY
 *   `secrets_test.c`'s proof, carried across a socket. One value is the
 *   passphrase of the network this joins and of the network it asks the daemon
 *   to write down, and three channels are read back for it at the end: every
 *   `err` buffer this file has filled, this process' whole standard error, and
 *   the fake supplicant's own log. The proof is checked for being vacuous: the
 *   join must have succeeded -- which cannot happen unless the credential
 *   resolved and reached the socket -- and the fake's log must carry the cut
 *   `SET_NETWORK 0` line that is what redacting one leaves behind.
 */
#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/config.h"
#include "ncfg/daemon.h"
#include "ncfg/document.h"
#include "ncfg/hooks.h"
#include "ncfg/lower.h"
#include "ncfg/observed.h"
#include "ncfg/plan.h"
#include "ncfg/proto.h"
#include "ncfg/secrets.h"
#include "ncfg/supplicant.h"

#include "testdir.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Distinctive enough that finding it in a buffer is never a coincidence, and a
 * legal WPA2 passphrase so that a length check is not what refuses it. */
#define CANARY "zq7-CANARY-passphrase-must-never-be-printed-4f1e"

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
static char   every_message[128u * 1024u];
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

/* ====================================================== the fakes, bounded */

#define FAKES_MAX 4

static pid_t fake_pid[FAKES_MAX];
static size_t fake_count;

static long long now_ms(void)
{
	struct timespec when;

	(void)clock_gettime(CLOCK_MONOTONIC, &when);
	return (long long)when.tv_sec * 1000 + when.tv_nsec / 1000000;
}

static void pause_briefly(void)
{
	struct timespec slice;

	slice.tv_sec = 0;
	slice.tv_nsec = 2000000;
	(void)nanosleep(&slice, NULL);
}

/*
 * Start one of the repository's fakes, and wait for the socket it binds.
 *
 * `timeout` is the outer bound and is not a courtesy: a test binary killed
 * part way through must not leave a python process holding a socket, and the
 * only thing that can promise that is something outside this process.
 * `setpgid` is the inner one, so the kill below reaches `timeout` and the
 * python it started rather than one of the two.
 *
 * Waited for rather than slept on: the socket appearing is the readiness
 * signal, which is what netcfgd itself waits for when it starts a supplicant.
 */
static int start_fake(const char *script, const char *const *argument, size_t argument_count,
    const char *socket_path, const char *log_path)
{
	const char *argv[16];
	size_t      at = 0;
	long long   deadline;
	pid_t       child;

	if (fake_count >= FAKES_MAX || argument_count + 6u > sizeof(argv) / sizeof(argv[0])) {
		return 0;
	}
	argv[at++] = "timeout";
	argv[at++] = "-k";
	argv[at++] = "2";
	argv[at++] = "60";
	argv[at++] = "python3";
	argv[at++] = script;
	for (; at < argument_count + 6u; at++) {
		argv[at] = argument[at - 6u];
	}
	argv[at] = NULL;
	child = fork();
	if (child < 0) {
		return 0;
	}
	if (child == 0) {
		int log = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		(void)setpgid(0, 0);
		if (log >= 0) {
			(void)dup2(log, STDOUT_FILENO);
			(void)dup2(log, STDERR_FILENO);
			(void)close(log);
		}
		/* A cast away from `const` because `execvp` predates it; nothing
		 * here writes through the pointers. */
		(void)execvp("timeout", (char *const *)(void *)argv);
		_exit(127);
	}
	(void)setpgid(child, child);
	fake_pid[fake_count++] = child;
	deadline = now_ms() + 5000;
	while (now_ms() < deadline) {
		if (testdir_exists(socket_path)) {
			return 1;
		}
		pause_briefly();
	}
	return 0;
}

/* By the pid this process recorded, and by nothing else. */
static void stop_fakes(void)
{
	size_t at;

	for (at = 0; at < fake_count; at++) {
		int status = 0;

		if (fake_pid[at] <= 0) {
			continue;
		}
		(void)kill(-fake_pid[at], SIGTERM);
		(void)kill(fake_pid[at], SIGTERM);
		(void)waitpid(fake_pid[at], &status, 0);
		fake_pid[at] = -1;
	}
	fake_count = 0;
}

/* Say something to a fake that is not a wpa_supplicant command: `DISABLE`,
 * `FAIL_NEXT_SCAN`, `FAIL_NEXT_JOIN`. Each is that fixture's way of producing
 * a state which needs an access point refusing this station. */
/*
 * A unix address for `<dir>/<leaf>`, refusing one longer than an address holds.
 *
 * `snprintf` is right in the library and wrong here: a compiler reasoning about
 * a 320-byte path copied into a 108-byte `sun_path` is a warning per call site
 * rather than a fault. A fixture path that does not fit is a test that would
 * check nothing, so this stops instead.
 */
static void address_for(struct sockaddr_un *out, const char *dir, const char *leaf)
{
	size_t used = strlen(dir);
	size_t tail = strlen(leaf);

	if (used + 1u + tail >= sizeof(out->sun_path)) {
		printf("a fixture socket path is longer than a unix address\n");
		exit(1);
	}
	memset(out, 0, sizeof(*out));
	out->sun_family = AF_UNIX;
	memcpy(out->sun_path, dir, used);
	out->sun_path[used] = '/';
	memcpy(out->sun_path + used + 1u, leaf, tail + 1u);
}

static int tell_fake(const char *dir, const char *interface, const char *command)
{
	struct sockaddr_un mine;
	struct sockaddr_un theirs;
	char               reply[64];
	char               leaf[64];
	int                fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	int                said = 0;
	struct timeval     patience;

	if (fd < 0) {
		return 0;
	}
	(void)snprintf(leaf, sizeof(leaf), "telling-%ld", (long)getpid());
	address_for(&mine, dir, leaf);
	address_for(&theirs, dir, interface);
	patience.tv_sec = 2;
	patience.tv_usec = 0;
	(void)unlink(mine.sun_path);
	if (bind(fd, (const struct sockaddr *)&mine, sizeof(mine)) == 0 &&
	    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &patience, sizeof(patience)) == 0 &&
	    sendto(fd, command, strlen(command), 0, (const struct sockaddr *)&theirs,
	        sizeof(theirs)) >= 0) {
		said = recv(fd, reply, sizeof(reply), 0) > 0;
	}
	(void)close(fd);
	(void)unlink(mine.sun_path);
	return said;
}

/* ========================================================== the fixtures */

static char base[256];
static char ctrl_dir[320];
static char run_dir[320];
static char class_net[320];
static char config_dir[320];
static char factory_dir[320];
static char secrets_dir[320];
static char certs_dir[320];
static char hostapd_dir[384];
static char supplicant_log[384];

static ncfg_wifi_where_t where;

static void make_directory(const char *path)
{
	if (mkdir(path, 0700) != 0 && testdir_mode(path) < 0) {
		printf("could not make the fixture directory %s\n", path);
		exit(1);
	}
}

/*
 * A radio the fake `/sys/class/net` reports, which `ncfg_radio_is_wireless`
 * answers from `phy80211` (0231).
 *
 * **The attribute is a file, where the kernel makes it a directory**, and the
 * difference is the cleanup rather than the check: `attribute_exists` asks
 * `stat`, which does not care, and `testdir.h`'s removal is two levels deep by
 * hand -- so a directory here is one this test makes and cannot take away, and
 * thirty-nine of them were left under `TMPDIR` before this was a file.
 */
static void make_radio(const char *name, int wireless)
{
	char device[384];
	char attribute[448];

	(void)snprintf(device, sizeof(device), "%s/%s", class_net, name);
	make_directory(device);
	if (wireless) {
		(void)snprintf(attribute, sizeof(attribute), "%s/phy80211", device);
		(void)testdir_write(attribute, "", 0);
	}
}

/* One configuration file's text, as the loader would hand it over. */
static int add_source(ncfg_config_sources_t *sources, const char *name, const char *text)
{
	ncfg_config_file_t *grown = realloc(sources->at, (sources->count + 1u) * sizeof(*grown));

	if (!grown) {
		return 0;
	}
	sources->at = grown;
	sources->capacity = sources->count + 1u;
	grown[sources->count].name = strdup(name);
	grown[sources->count].text = strdup(text);
	grown[sources->count].length = strlen(text);
	if (!grown[sources->count].name || !grown[sources->count].text) {
		return 0;
	}
	sources->count++;
	return 1;
}

/*
 * Compile one file's worth of configuration.
 *
 * **`ncfg_hook_sink_unwritten()`, because this compiles to read.** Every
 * fixture here is a question -- what does this text mean, what would the
 * planner do with it -- and the document is thrown away afterwards. The
 * refusing sink belongs to a caller producing a document to *act* on with
 * nowhere to put the scripts, which is nothing in this file.
 */
static ncfg_document_t *compiled(const char *name, const char *text)
{
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *document = NULL;
	char                  err[NCFG_ERROR_MAX];

	if (add_source(&sources, name, text)) {
		document = ncfg_config_compile(&sources, ncfg_hook_sink_unwritten(), NULL, err,
		    sizeof(err));
		if (!document) {
			detail("this fixture does not compile", err);
		}
	}
	ncfg_config_sources_free(&sources);
	return document;
}

/* An observation from JSON, which is how every other test in this port builds
 * one: the model's own reader, rather than a struct filled in by hand and
 * quietly missing whatever the model grows next. */
static ncfg_observed_t *observation(const char *text)
{
	char             err[NCFG_ERROR_MAX];
	ncfg_observed_t *observed = ncfg_observed_read(text, strlen(text), err, sizeof(err));

	if (!observed) {
		detail("this observation does not parse", err);
	}
	return observed;
}

#define TWO_RADIOS \
	"{\"links\":[" \
	"{\"name\":\"wlan0\",\"index\":2,\"kind\":\"\",\"wireless\":true,\"up\":true," \
	"\"carrier\":true,\"mtu\":1500,\"offloads\":[],\"ownership\":\"unknown\"," \
	"\"private_key_loaded\":false}," \
	"{\"name\":\"wlan1\",\"index\":3,\"kind\":\"\",\"wireless\":true,\"up\":false," \
	"\"carrier\":false,\"mtu\":1500,\"offloads\":[],\"ownership\":\"unknown\"," \
	"\"private_key_loaded\":false}," \
	"{\"name\":\"eth0\",\"index\":1,\"kind\":\"\",\"wireless\":false,\"up\":true," \
	"\"carrier\":true,\"mtu\":1500,\"offloads\":[],\"ownership\":\"unknown\"," \
	"\"private_key_loaded\":false}]}"

/* The same, with the kill switch on `wlan0` pressed. */
#define RADIO_SWITCHED_OFF \
	"{\"links\":[" \
	"{\"name\":\"wlan0\",\"index\":2,\"kind\":\"\",\"wireless\":true,\"up\":true," \
	"\"carrier\":true,\"mtu\":1500,\"offloads\":[],\"ownership\":\"unknown\"," \
	"\"private_key_loaded\":false," \
	"\"rfkill\":{\"switch\":\"phy0\",\"soft\":true,\"hard\":false}}]}"

/* `HomeFiber`, `Cafe` and `Office` as the octets they are. */
#define HOMEFIBER_HEX "486f6d654669626572"
#define CAFE_HEX "43616665"
#define OFFICE_HEX "4f6666696365"

/*
 * What the fake has been told since a mark.
 *
 * **Read by offset rather than by emptying the file**, which is the shape the
 * first version got wrong: the fake holds the descriptor, so truncating the log
 * from here leaves its write offset where it was and the next line lands past a
 * hole of NULs -- where `strstr` stops, so every assertion about what was said
 * passed for a reason that had nothing to do with the command.
 */
static long log_mark(void)
{
	struct stat about;

	return stat(supplicant_log, &about) == 0 ? (long)about.st_size : 0;
}

static char *log_since(long mark)
{
	size_t length = 0;
	char  *whole = testdir_read(supplicant_log, &length);
	char  *tail;

	if (!whole) {
		return NULL;
	}
	if (mark < 0 || (size_t)mark > length) {
		return whole;
	}
	tail = strdup(whole + mark);
	free(whole);
	return tail;
}

/* ============================================ decoding what was encoded */

/*
 * Read back what one of these calls wrote.
 *
 * Through `ncfg_proto_response_read` rather than by looking for substrings:
 * the decoder is the other half of this protocol and it is strict about the
 * shapes, so a response that decodes is a response a client can use. The
 * witness in `doc/schema/socket.json` is what pins the spelling, and the
 * `radios` check below compares against it byte for byte.
 */
static int decoded(const ncfg_buf_t *object, ncfg_proto_message_t *out)
{
	char err[NCFG_ERROR_MAX];

	if (!ncfg_proto_response_read(ncfg_buf_text(object), object->length, out, err,
	        sizeof(err))) {
		detail("this response does not decode", kept(err));
		return 0;
	}
	return 1;
}

static int says(ncfg_proto_str_t text, const char *other)
{
	return ncfg_proto_str_equals(text, other);
}

/* ============================================================ the checks */

static void the_backend_is_refused_by_name(void)
{
	ncfg_document_t *iwd = compiled("iwd.conf",
	    "device wlan0 {\n\twifi {\n\t\tbackend = \"iwd\"\n\t}\n}\n");
	ncfg_document_t *supplicant = compiled("wpa.conf",
	    "device wlan0 {\n\twifi {\n\t\tbackend = \"wpa_supplicant\"\n\t}\n}\n");
	ncfg_document_t *plain = compiled("plain.conf",
	    "device wlan0 {\n\twifi {\n\t\tautoconnect = true\n\t}\n}\n");
	char             err[NCFG_ERROR_MAX];

	printf("\n-- 0014: a supplicant netcfgd cannot drive is refused by name\n");
	err[0] = '\0';
	check(!ncfg_wifi_check_backend(iwd, "wlan0", err, sizeof(err)), "`iwd` is refused");
	check(strstr(kept(err), "iwd backend") != NULL &&
	    strstr(err, "backend = \\\"wpa_supplicant\\\"") == NULL &&
	    strstr(err, "doc/decision/0014") != NULL,
	    "  and the refusal says which decision and what to write instead");
	check(ncfg_wifi_check_backend(supplicant, "wlan0", err, sizeof(err)),
	    "`wpa_supplicant` is driven");
	check(ncfg_wifi_check_backend(plain, "wlan0", err, sizeof(err)),
	    "and so is a `wifi` block that names no backend");
	check(ncfg_wifi_check_backend(iwd, "wlan9", err, sizeof(err)),
	    "an interface the document says nothing about is not refused");
	check(ncfg_wifi_check_backend(NULL, "wlan0", err, sizeof(err)),
	    "and neither is anything when there is no document at all");
	ncfg_document_free(iwd);
	ncfg_document_free(supplicant);
	ncfg_document_free(plain);
}

static void the_address_answers_before_the_name(void)
{
	/*
	 * **0239.** Two blocks sharing an SSID and pinned to different access
	 * points compiles with no diagnostic, and taking the first block matching
	 * on *either* rule answered both with whichever sorted earlier -- so the
	 * station on the second was reported as being on the first and took the
	 * first one's `metric`.
	 */
	ncfg_document_t *document = compiled("two.conf",
	    "network \"aaa-first\" {\n\tssid = \"" HOMEFIBER_HEX "\"\n"
	    "\tbssid = [\"00:11:22:33:44:55\"]\n\twifi { open = true }\n}\n"
	    "network \"zzz-second\" {\n\tssid = \"" HOMEFIBER_HEX "\"\n"
	    "\tbssid = [\"66:77:88:99:AA:BB\"]\n\twifi { open = true }\n}\n"
	    /* `ssid = "@bssid"` is how the language spells "the name is whatever
	     * these access points call themselves". Required rather than inferred
	     * from `bssid` alone, because the label is a network's SSID by
	     * default. */
	    "network \"by-address-only\" {\n\tssid = \"@bssid\"\n"
	    "\tbssid = [\"cc:dd:ee:ff:00:11\"]\n\twifi { open = true }\n}\n"
	    "network \"by-name-only\" {\n\tssid = \"" CAFE_HEX "\"\n"
	    "\twifi { open = true }\n}\n");
	ncfg_ssid_t      home;
	ncfg_ssid_t      cafe;
	ncfg_ssid_t      other;
	const ncfg_wifi_network_t *found;

	printf("\n-- 0239: which `network` block an association is on\n");
	if (!document) {
		check(0, "the two-block fixture compiles");
		return;
	}
	memset(&home, 0, sizeof(home));
	memcpy(home.bytes, "HomeFiber", 9u);
	home.length = 9u;
	home.has = 1;
	memset(&cafe, 0, sizeof(cafe));
	memcpy(cafe.bytes, "Cafe", 4u);
	cafe.length = 4u;
	cafe.has = 1;
	memset(&other, 0, sizeof(other));
	memcpy(other.bytes, "Elsewhere", 9u);
	other.length = 9u;
	other.has = 1;

	found = ncfg_wifi_network_for(document->networks, document->network_count, &home,
	    "66:77:88:99:aa:bb");
	check(found && found->id && strcmp(found->id, "zzz-second") == 0,
	    "the block naming this access point wins over the one that sorts first");
	found = ncfg_wifi_network_for(document->networks, document->network_count, &home,
	    "00:11:22:33:44:55");
	check(found && found->id && strcmp(found->id, "aaa-first") == 0,
	    "  and the other address answers the other block");
	found = ncfg_wifi_network_for(document->networks, document->network_count, &home,
	    "de:ad:be:ef:00:00");
	check(found && found->id && strcmp(found->id, "aaa-first") == 0,
	    "an address neither block names falls back to the ssid, in id order");
	found = ncfg_wifi_network_for(document->networks, document->network_count, &other,
	    "cc:dd:ee:ff:00:11");
	check(found && found->id && strcmp(found->id, "by-address-only") == 0,
	    "a block that states no ssid is matched on its addresses alone");
	found = ncfg_wifi_network_for(document->networks, document->network_count, &cafe,
	    "00:11:22:33:44:55");
	check(found && found->id && strcmp(found->id, "by-name-only") == 0,
	    "a block that states no address is matched on its name alone");
	found = ncfg_wifi_network_for(document->networks, document->network_count, &other,
	    "de:ad:be:ef:00:00");
	check(found == NULL, "and a network the configuration does not describe is not invented");
	ncfg_document_free(document);
}

static void why_there_is_no_supplicant(void)
{
	ncfg_document_t *managed = compiled("managed.conf",
	    "device wlan0 {\n\twifi {\n\t\tautoconnect = true\n\t}\n}\n"
	    "device wlan1 {\n\twifi {\n\t\tautoconnect = true\n\t}\n}\n"
	    "device wlan9 {\n\twifi {\n\t\tautoconnect = true\n\t}\n}\n");
	ncfg_document_t *unmanaged = compiled("unmanaged.conf",
	    "device wlan0 {\n\tmanaged = false\n}\n");
	char             said[NCFG_ERROR_MAX];

	printf("\n-- the diagnosis the control socket's own message cannot give\n");
	check(!ncfg_wifi_why_no_supplicant(&where, managed, "eth0", said, sizeof(said)),
	    "an interface that is not a radio is not diagnosed here");
	check(ncfg_wifi_why_no_supplicant(&where, unmanaged, "wlan0", said, sizeof(said)) &&
	    strstr(kept(said), "managed = false") != NULL,
	    "`managed = false` is named as the documented way to hand it over");
	check(ncfg_wifi_why_no_supplicant(&where, NULL, "wlan0", said, sizeof(said)) &&
	    strstr(kept(said), "no `wifi` policy for it") != NULL &&
	    strstr(said, "autoconnect = true") != NULL,
	    "a radio with no policy is answered with the three lines that would fix it");
	check(!ncfg_wifi_why_no_supplicant(&where, managed, "wlan9", said, sizeof(said)),
	    "a configured radio with nothing bound is left to the caller's own message");
	/*
	 * **The case that produced no diagnosis at all.** A radio netcfgd manages,
	 * configured, with another daemon holding the control socket -- which is
	 * what an operator running `NetworkManager` meets. The first fix keyed on
	 * whether the socket *answers*, and was silent in exactly this case:
	 * NetworkManager drives its supplicant over D-Bus and it does not reply on
	 * the control interface, so the socket exists and stays mute.
	 */
	check(ncfg_wifi_why_no_supplicant(&where, managed, "wlan0", said, sizeof(said)) &&
	    strstr(kept(said), "another daemon is already running a supplicant") != NULL,
	    "a socket bound by a process netcfgd did not start names the cause");
	check(strstr(said, "systemctl stop NetworkManager") != NULL &&
	    strstr(said, "systemctl stop wpa_supplicant") != NULL,
	    "  and names BOTH units, since stopping one leaves the socket bound");
	/* `wlan1`'s fake was started with a pid file, so it carries netcfgd's own
	 * mark in its command line -- which is what `ncfg_process_pid_of` asks
	 * about, and what separates netcfgd's wedged supplicant from a stranger's
	 * working one. */
	check(ncfg_wifi_why_no_supplicant(&where, managed, "wlan1", said, sizeof(said)) &&
	    strstr(kept(said), "has a supplicant netcfgd started") != NULL &&
	    strstr(said, "--restart-wedged wlan1") != NULL,
	    "a supplicant netcfgd started is the wedged case, with the remedy");
	ncfg_document_free(managed);
	ncfg_document_free(unmanaged);
}

/* Whether a plan carries an op by name. */
static int plans(const ncfg_plan_t *plan, const char *op)
{
	size_t at;

	for (at = 0; at < plan->action_count; at++) {
		const char *name = ncfg_op_name(&plan->actions[at].op);

		if (name && strcmp(name, op) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * Whether the planner said it saw something it does not act on yet.
 *
 * **This build's planner carries no backends**, so `backend.start` and
 * `dns.apply` are not ops it can emit -- it emits a warning per block it is
 * holding and not acting on instead. So the two outcomes below are asserted at
 * the nearest thing this build can express, and each check says which op it
 * must become when the planner's backend half lands.
 */
static int notices(const ncfg_plan_t *plan, const char *fragment)
{
	size_t at;

	for (at = 0; at < plan->warning_count; at++) {
		if (plan->warnings[at].message && strstr(plan->warnings[at].message, fragment)) {
			return 1;
		}
	}
	return 0;
}

static void what_activation_writes_is_asked_of_the_planner(void)
{
	ncfg_buf_t            blocks;
	ncfg_config_sources_t sources = { 0 };
	ncfg_document_t      *document;
	ncfg_observed_t      *observed;
	ncfg_plan_t          *plan;
	char                  name[NCFG_WIFI_DROP_IN_MAX];
	char                  err[NCFG_ERROR_MAX];

	printf("\n-- what activation writes, asked of the planner rather than of a string\n");
	check(ncfg_wifi_radio_drop_in("wlan0", name, sizeof(name), err, sizeof(err)) &&
	    strcmp(name, "radio-wlan0") == 0,
	    "the drop-in is named for its radio, so a second one does not rewrite it");
	check(!ncfg_wifi_radio_drop_in("", name, sizeof(name), err, sizeof(err)),
	    "and a drop-in with no interface to be named after is refused");
	(void)kept(err);

	ncfg_buf_init(&blocks, 0);
	check(ncfg_wifi_radio_blocks("wlan0", &blocks, err, sizeof(err)),
	    "the activation block is built");
	/*
	 * **The check the first version of this feature did not have, and the bug
	 * it would have caught.** Activation wrote a `device` block, reported
	 * success, and planned nothing -- because the planner walks the interfaces
	 * and a device nothing has an `interface` block for is never visited.
	 * Every layer passed: the request was well formed, the tier was right, the
	 * file was written, the pane redrew. The operator got "cannot reach the
	 * supplicant" and no reason.
	 *
	 * So this asserts the *outcome* rather than the text. Comparing the block
	 * against an expected string would have passed just as happily against the
	 * broken one.
	 *
	 * **The unwritten sink**, because the question is what this text means and
	 * not what to act on: the document is thrown away two lines later and
	 * there is nowhere here to put a script (0258).
	 */
	if (add_source(&sources, "radio-wlan0.conf", ncfg_buf_text(&blocks)) &&
	    add_source(&sources, "50-dns.conf",
	        "global { dns { mode = \"write_resolv_conf\" } }\n")) {
		document = ncfg_config_compile(&sources, ncfg_hook_sink_unwritten(), NULL, err,
		    sizeof(err));
		check(document != NULL, "what activation writes compiles");
		/* A radio that exists, because the radio list asks the kernel's answer
		 * rather than the document's -- a `wifi { }` section is not a claim
		 * that the interface is one. And a lease that offered nameservers,
		 * which is what the dhcpcd hook reports. */
		observed = observation(
		    "{\"links\":[{\"name\":\"wlan0\",\"index\":2,\"kind\":\"\",\"wireless\":true,"
		    "\"up\":false,\"carrier\":true,\"mtu\":1500,\"offloads\":[],"
		    "\"ownership\":\"unknown\",\"private_key_loaded\":false}],"
		    "\"reports\":[{\"interface\":\"wlan0\",\"addresses\":[],\"gateways\":[],"
		    "\"nameservers\":[\"10.0.0.1\"],\"search\":[\"vibes.se\"],\"routes\":[]}]}");
		plan = document && observed
		    ? ncfg_plan_build(document, observed, NULL, err, sizeof(err))
		    : NULL;
		/*
		 * `link.up` rather than `backend.start`, and the substitution is the
		 * point rather than a weakening: it is emitted because the planner
		 * **visits the interface at all**, which is exactly what the
		 * `device`-only block did not make it do. Measured both ways -- with
		 * the interface block the plan has an action, without it the plan is
		 * empty -- so this fails against the file that reported success and
		 * changed nothing. It becomes `backend.start` when the planner's
		 * backend half lands.
		 */
		check(plan && plan->action_count > 0u && plans(plan, "link.up"),
		    "activating a radio plans something, where the `device` block alone planned "
		    "nothing");
		/* The sentence narrowed when the wireless passes landed: the networks
		 * are handed to a supplicant that is already running, and starting one
		 * is still the backend pass's work. What is asserted is unchanged --
		 * that the planner names the half of the `wifi` block it is holding. */
		check(plan && notices(plan, "the supplicant that would serve `wlan0` is not started"),
		    "  and the planner is holding the supplicant this build cannot yet start");
		/*
		 * **The other half of the outcome, and it was missing for as long as
		 * the block existed.** A lease's nameservers are offered to an
		 * interface and taken only where one asks, so a block with
		 * `config = "dhcp"` and no `dns { }` came up addressed, routed and
		 * unable to resolve anything -- on a machine whose global `dns` block
		 * said `write_resolv_conf`, which reads as though it had been asked
		 * for. Reported after a switch: "I had to write to resolv.conf".
		 */
		check(document && document->interface_count == 1u &&
		    document->interfaces[0].dns != NULL,
		    "  and the interface asks for the lease's nameservers, which is the other half");
		check(plan && plans(plan, "dns.apply"),
		    "  which the planner answers with `dns.apply`, the op 0263 said this would "
		    "become");
		ncfg_plan_free(plan);
		ncfg_observed_free(observed);
		ncfg_document_free(document);
	} else {
		check(0, "the activation fixture is built");
	}
	ncfg_config_sources_free(&sources);
	ncfg_buf_free(&blocks);
}

static void the_radio_list_comes_from_the_kernel(void)
{
	ncfg_document_t     *document = compiled("one.conf",
	    "device wlan0 {\n\twifi {\n\t\tautoconnect = true\n\t}\n}\n"
	    "device wlan1 {\n\tmanaged = false\n\twifi {\n\t\tautoconnect = true\n\t}\n}\n");
	ncfg_observed_t     *observed = observation(TWO_RADIOS);
	ncfg_buf_t           out;
	ncfg_proto_message_t message;
	char                 err[NCFG_ERROR_MAX];

	printf("\n-- the radios, and the gap between activated and answering\n");
	ncfg_buf_init(&out, 0);
	check(ncfg_wifi_radios(&where, document, observed, &out, err, sizeof(err)),
	    "the radio list is written");
	/*
	 * Byte for byte against the spelling `doc/schema/socket.json` pins. A
	 * decode would accept a member in the wrong order or an omitted default;
	 * the witness is what says a client built against the Rust reads this.
	 */
	check(strcmp(ncfg_buf_text(&out),
	    "{\"response\":\"radios\",\"radios\":["
	    "{\"interface\":\"wlan0\",\"activated\":true,\"supplicant\":true},"
	    "{\"interface\":\"wlan1\",\"activated\":false,\"supplicant\":true}]}") == 0,
	    "and it is the witness' spelling, member for member");
	if (strcmp(ncfg_buf_text(&out), "") != 0 && failures) {
		detail("what was written", ncfg_buf_text(&out));
	}
	if (decoded(&out, &message)) {
		check(message.u.response.kind == NCFG_PROTO_RESP_RADIOS &&
		    message.u.response.u.radios.count == 2u,
		    "  the wired interface is not in it, because the kernel says it is not a radio");
		check(message.u.response.u.radios.items[1].activated == 0 &&
		    message.u.response.u.radios.items[1].supplicant == 1,
		    "  and a radio netcfgd is not managing is still listed, which is the point");
		ncfg_proto_message_free(&message);
	}
	ncfg_buf_free(&out);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
}

/* What `ncfg_wifi_set_radio` was asked to apply, and how often. */
static struct {
	char   interface[32];
	size_t calls;
	int    refuse;
} applied;

static int recording_apply(void *context, const char *interface, char *err, size_t err_size)
{
	(void)context;
	applied.calls++;
	(void)snprintf(applied.interface, sizeof(applied.interface), "%s", interface);
	if (applied.refuse) {
		ncfg_error_set(err, err_size,
		    "`%s` is netcfgd's in the configuration, and starting its supplicant failed: "
		    "another manager is still holding the radio", interface);
		return 0;
	}
	return 1;
}

static void taking_a_radio_on_and_handing_it_back(void)
{
	ncfg_daemon_state_t state;
	ncfg_observed_t    *observed = observation(TWO_RADIOS);
	ncfg_buf_t          out;
	char                path[448];
	char                err[NCFG_ERROR_MAX];

	printf("\n-- activation writes, reloads and applies, in that order\n");
	if (!ncfg_daemon_state_init(&state, factory_dir, config_dir, run_dir, err, sizeof(err))) {
		check(0, "the daemon state is set up");
		ncfg_observed_free(observed);
		return;
	}
	state.observed = observed;
	ncfg_buf_init(&out, 0);

	memset(&applied, 0, sizeof(applied));
	check(!ncfg_wifi_set_radio(&state, "eth0", 1, recording_apply, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "is not a radio on this machine") != NULL,
	    "activating something that is not a radio is a sentence, not a silent no-op");
	check(applied.calls == 0u, "  and nothing was applied for it");

	/*
	 * **Written is not running.** A caller with no way to apply would write a
	 * correct plan that nothing runs, which is what made activation report
	 * success and change nothing. Refused rather than skipped, because
	 * skipping it silently is what that looked like.
	 */
	check(!ncfg_wifi_set_radio(&state, "wlan0", 1, NULL, NULL, &out, err, sizeof(err)) &&
	    strstr(kept(err), "no way to start the radio's supplicant") != NULL,
	    "activating with no way to apply is refused rather than half done");
	(void)testdir_in(config_dir, "conf.d/radio-wlan0.conf", path, sizeof(path));
	check(!testdir_exists(path), "  and nothing was written for it");

	ncfg_buf_free(&out);
	ncfg_buf_init(&out, 0);
	memset(&applied, 0, sizeof(applied));
	check(ncfg_wifi_set_radio(&state, "wlan0", 1, recording_apply, NULL, &out, err,
	        sizeof(err)), "a radio is taken on");
	check(strcmp(ncfg_buf_text(&out), "{\"response\":\"ok\"}") == 0,
	    "  and the answer is `ok`, which is what a switch says");
	check(testdir_exists(path), "  the drop-in is on disk, named for the radio");
	check(applied.calls == 1u && strcmp(applied.interface, "wlan0") == 0,
	    "  the apply ran once, for that interface and no other");
	check(state.desired && state.desired->interface_count == 1u &&
	    state.desired->device_count == 1u,
	    "  and the reload picked up both blocks, which is what makes it plan anything");

	/* The same radio again: a switch turning on something already on is the
	 * state being asked for rather than a collision. */
	ncfg_buf_free(&out);
	ncfg_buf_init(&out, 0);
	memset(&applied, 0, sizeof(applied));
	check(ncfg_wifi_set_radio(&state, "wlan0", 1, recording_apply, NULL, &out, err,
	        sizeof(err)), "taking on a radio that is already on is success, not a collision");

	ncfg_buf_free(&out);
	ncfg_buf_init(&out, 0);
	memset(&applied, 0, sizeof(applied));
	applied.refuse = 1;
	check(!ncfg_wifi_set_radio(&state, "wlan1", 1, recording_apply, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "starting its supplicant failed") != NULL,
	    "an apply that failed is reported in the executor's own words");
	applied.refuse = 0;

	ncfg_buf_free(&out);
	ncfg_buf_init(&out, 0);
	memset(&applied, 0, sizeof(applied));
	check(ncfg_wifi_set_radio(&state, "wlan0", 0, recording_apply, NULL, &out, err,
	        sizeof(err)), "a radio is handed back");
	check(!testdir_exists(path), "  the drop-in is gone");
	check(applied.calls == 0u,
	    "  and nothing was applied, because the reconcile takes the backend down");
	ncfg_buf_free(&out);
	/* `observed` is this test's, not the state's. */
	state.observed = NULL;
	ncfg_daemon_state_free(&state);
	ncfg_observed_free(observed);
}

static void the_scan_and_why_it_may_be_stale(void)
{
	ncfg_document_t     *document = compiled("known.conf",
	    "network \"home\" {\n\tssid = \"" HOMEFIBER_HEX "\"\n\twifi { open = true }\n}\n");
	ncfg_observed_t     *observed = observation(TWO_RADIOS);
	ncfg_observed_t     *off = observation(RADIO_SWITCHED_OFF);
	ncfg_buf_t           out;
	ncfg_proto_message_t message;
	char                 err[NCFG_ERROR_MAX];
	char                *heard;
	long                 mark;

	printf("\n-- 0194: a scan is two things, and the results say when they are old\n");
	ncfg_buf_init(&out, 0);
	check(ncfg_wifi_scan(&where, document, observed, "wlan0", &out, err, sizeof(err)),
	    "a scan comes back");
	if (decoded(&out, &message)) {
		const ncfg_proto_scan_t *scan = &message.u.response.u.wifi_scan;

		check(message.u.response.kind == NCFG_PROTO_RESP_WIFI_SCAN &&
		    says(scan->interface, "wlan0") && scan->access_point_count == 3u,
		    "  with every access point the radio saw");
		check(scan->access_point_count == 3u && scan->access_points[0].signal == -40 &&
		    scan->access_points[1].signal == -53 &&
		    scan->access_points[2].signal == -100,
		    "  strongest first, because that is the order the question is asked in");
		check(scan->access_point_count == 3u &&
		    says(scan->access_points[1].ssid, HOMEFIBER_HEX) &&
		    says(scan->access_points[1].name, "HomeFiber"),
		    "  the name as hex and as text, which is what makes it identifiable");
		check(scan->access_point_count == 3u &&
		    says(scan->access_points[1].configured, "home") &&
		    !ncfg_proto_str_present(scan->access_points[0].configured),
		    "  0013's boundary is visible: only a configured network is labelled");
		check(scan->access_point_count == 3u && scan->access_points[1].secured == 1 &&
		    scan->access_points[0].secured == 0 &&
		    scan->access_points[1].enterprise == 0 && scan->access_points[0].owe == 0,
		    "  and what joining each one would need");
		check(!ncfg_proto_str_present(scan->stale),
		    "  a fresh scan says nothing about being stale, because it is not");
		ncfg_proto_message_free(&message);
	}
	ncfg_buf_free(&out);

	/*
	 * The comment this replaces said the results were "about to be fresh
	 * either way", which is exactly the fault: about to be is not are.
	 */
	ncfg_buf_init(&out, 0);
	check(tell_fake(ctrl_dir, "wlan0", "FAIL_NEXT_SCAN -16"), "the radio is told to refuse");
	check(ncfg_wifi_scan(&where, document, observed, "wlan0", &out, err, sizeof(err)),
	    "a scan that did not finish still answers");
	if (decoded(&out, &message)) {
		const ncfg_proto_scan_t *scan = &message.u.response.u.wifi_scan;

		check(ncfg_proto_str_present(scan->stale) && scan->access_point_count == 3u,
		    "  with the previous results and the reason they are the previous ones");
		ncfg_proto_message_free(&message);
	}
	ncfg_buf_free(&out);

	/*
	 * **A switched-off radio cannot scan, so it is not asked to.** Without
	 * this the scan is sent, the supplicant answers with a failure or nothing
	 * at all, and the report blames `ret=-100` -- a translation of ENETDOWN
	 * rather than the fact that somebody pressed the button.
	 */
	ncfg_buf_init(&out, 0);
	mark = log_mark();
	check(ncfg_wifi_scan(&where, document, off, "wlan0", &out, err, sizeof(err)),
	    "a switched-off radio still answers with what it last saw");
	if (decoded(&out, &message)) {
		const ncfg_proto_scan_t *scan = &message.u.response.u.wifi_scan;

		check(ncfg_proto_str_present(scan->stale) &&
		    memmem(scan->stale.bytes, scan->stale.length, "rfkill unblock", 14u) != NULL,
		    "  and says which switch is holding it off and what clears that one");
		check(scan->access_point_count == 3u, "  the cached results are worth more than none");
		ncfg_proto_message_free(&message);
	}
	heard = log_since(mark);
	check(heard && strstr(heard, "SCAN_RESULTS") != NULL && strstr(heard, "\nSCAN\n") == NULL,
	    "  and no `SCAN` was ever sent, which is what stops the full patience being spent");
	free(heard);
	ncfg_buf_free(&out);
	ncfg_document_free(document);
	ncfg_observed_free(observed);
	ncfg_observed_free(off);
}

static void joining_a_network_the_configuration_describes(void)
{
	ncfg_document_t     *document = compiled("join.conf",
	    "network \"home\" {\n\tssid = \"" HOMEFIBER_HEX "\"\n"
	    "\twifi { psk = \"@secret:home\"; proto = \"wpa2\" }\n}\n"
	    "network \"office\" {\n\tssid = \"" OFFICE_HEX "\"\n\twifi { open = true }\n}\n");
	ncfg_document_t     *empty = compiled("nothing.conf", "global { }\n");
	ncfg_buf_t           out;
	char                 err[NCFG_ERROR_MAX];
	char                *heard;
	long                 mark;

	printf("\n-- 0197: a join is not over when the supplicant says OK\n");
	ncfg_buf_init(&out, 0);
	check(!ncfg_wifi_connect(&where, NULL, secrets_dir, certs_dir, "wlan0", "home", &out, err,
	        sizeof(err)) && strstr(kept(err), "no configuration is loaded") != NULL,
	    "with no configuration there is nothing to join");
	check(!ncfg_wifi_connect(&where, empty, secrets_dir, certs_dir, "wlan0", "nowhere", &out,
	        err, sizeof(err)) && strstr(kept(err), "Configured: none") != NULL,
	    "a machine with no networks says so rather than listing an empty list");
	check(!ncfg_wifi_connect(&where, document, secrets_dir, certs_dir, "wlan0", "nowhere",
	        &out, err, sizeof(err)) &&
	    strstr(kept(err), "no `network` block called `nowhere`") != NULL &&
	    strstr(err, "Configured: home, office") != NULL,
	    "and an unknown name is the name being unknown, with the known ones named");

	mark = log_mark();
	ncfg_buf_free(&out);
	ncfg_buf_init(&out, 0);
	check(ncfg_wifi_connect(&where, document, secrets_dir, certs_dir, "wlan0", "home", &out,
	        err, sizeof(err)), "a network the configuration describes is joined");
	check(strcmp(ncfg_buf_text(&out), "{\"response\":\"ok\"}") == 0,
	    "  and `ok` means it joined, not that the command was taken");
	heard = log_since(mark);
	check(heard && strstr(heard, "ADD_NETWORK") != NULL &&
	    strstr(heard, "SELECT_NETWORK 0") != NULL,
	    "  the network was handed over and selected");
	check(heard && strstr(heard, "\nSET_NETWORK 0\n") != NULL,
	    "  and the credential crossed the socket, cut off at the keyword in the fake's log");
	free(heard);
	ncfg_buf_free(&out);

	/*
	 * Already present? The supplicant was populated at apply time, so the
	 * usual case is selecting something that is already there. Adding a second
	 * copy would leave two entries for one network and make `LIST_NETWORKS`
	 * unreadable.
	 */
	check(tell_fake(ctrl_dir, "wlan0", "DISABLE [TEMP-DISABLED] Office"),
	    "the radio is given a network it has given up on");
	mark = log_mark();
	ncfg_buf_init(&out, 0);
	check(ncfg_wifi_connect(&where, document, secrets_dir, certs_dir, "wlan0", "office", &out,
	        err, sizeof(err)), "a network the supplicant already holds is joined");
	heard = log_since(mark);
	check(heard && strstr(heard, "ADD_NETWORK") == NULL,
	    "  without a second copy of it, which would make LIST_NETWORKS unreadable");
	/*
	 * `SELECT_NETWORK` rather than `ENABLE_NETWORK`: it disables the others,
	 * which is what "join this one" means. `ENABLE` would leave the supplicant
	 * free to pick a different network it also knows about, and the operator
	 * would have asked for one thing and got another. Checked here rather than
	 * on the path above, where `ncfg_supplicant_add_network` legitimately
	 * enables the network it has just handed over.
	 */
	check(heard && strstr(heard, "SELECT_NETWORK") != NULL &&
	    strstr(heard, "ENABLE_NETWORK") == NULL,
	    "  and by selecting it, which is what leaves the supplicant no other choice");
	free(heard);
	ncfg_buf_free(&out);

	ncfg_buf_init(&out, 0);
	check(tell_fake(ctrl_dir, "wlan0", "FAIL_NEXT_JOIN WRONG_KEY"),
	    "the access point is told to refuse this station");
	check(!ncfg_wifi_connect(&where, document, secrets_dir, certs_dir, "wlan0", "office",
	        &out, err, sizeof(err)) &&
	    strstr(kept(err), "did not join on `wlan0`") != NULL,
	    "a join that failed is reported as a join that failed");
	ncfg_buf_free(&out);

	ncfg_buf_init(&out, 0);
	check(!ncfg_wifi_connect(&where, document, NULL, certs_dir, "wlan0", "home", &out, err,
	        sizeof(err)) && strstr(kept(err), "neither has a default here") != NULL,
	    "and neither the secrets directory nor the certificate one is invented");
	ncfg_buf_free(&out);
	ncfg_document_free(document);
	ncfg_document_free(empty);
}

static void the_status_and_what_it_has_given_up_on(void)
{
	ncfg_document_t     *document = compiled("status.conf",
	    "network \"home\" {\n\tssid = \"" HOMEFIBER_HEX "\"\n\twifi { open = true }\n}\n");
	ncfg_document_t     *iwd = compiled("iwd.conf",
	    "device wlan0 {\n\twifi {\n\t\tbackend = \"iwd\"\n\t}\n}\n");
	ncfg_observed_t     *observed = observation(TWO_RADIOS);
	ncfg_observed_t     *off = observation(RADIO_SWITCHED_OFF);
	ncfg_buf_t           out;
	ncfg_proto_message_t message;
	char                 err[NCFG_ERROR_MAX];

	printf("\n-- what one radio is doing, and what it has stopped trying\n");
	check(tell_fake(ctrl_dir, "wlan0", "DISABLE [DISABLED] Lab"),
	    "the radio is given a network somebody turned off");
	ncfg_buf_init(&out, 0);
	check(ncfg_wifi_status(&where, document, observed, "wlan0", &out, err, sizeof(err)),
	    "the status comes back");
	if (decoded(&out, &message)) {
		const ncfg_proto_wifi_status_t *state = &message.u.response.u.wifi_status;

		check(says(state->interface, "wlan0") && says(state->state, "COMPLETED"),
		    "  with the supplicant's own state name");
		check(says(state->ssid, HOMEFIBER_HEX) && says(state->name, "HomeFiber") &&
		    says(state->bssid, "00:11:22:33:44:55"),
		    "  the network as hex, as text, and the access point serving it");
		check(says(state->network, "home"),
		    "  resolved back to the `network` block that describes it");
		check(!ncfg_proto_str_present(state->blocked),
		    "  and nothing about a kill switch, because this one is not pressed");
		/*
		 * **`STATUS` cannot answer this and never could.** It describes the
		 * one association the interface has, so an interface with none reads
		 * `SCANNING` whether the supplicant is scanning hopefully or has given
		 * up on every network it was given. One check covers both flags
		 * because `[TEMP-DISABLED]` contains `DISABLED`, which is why they are
		 * passed through rather than translated.
		 */
		check(state->not_trying_count == 2u,
		    "  and the networks it is not trying, which `STATUS` never carried");
		check(state->not_trying_count == 2u &&
		    says(state->not_trying[0].flags, "[TEMP-DISABLED]") &&
		    says(state->not_trying[1].flags, "[DISABLED]"),
		    "  with the supplicant's own flags, since the two mean different things");
		check(state->not_trying_count == 2u && says(state->not_trying[0].name, "Office") &&
		    says(state->not_trying[0].ssid, OFFICE_HEX),
		    "  named the way a scan row is named");
		ncfg_proto_message_free(&message);
	}
	ncfg_buf_free(&out);

	/*
	 * **Asked here because this is the command somebody runs when wifi is not
	 * working**, and a kill switch is one keystroke away on any laptop. The
	 * supplicant reports `INACTIVE` or `SCANNING` either way, so without this
	 * the answer to "why is there no network" looks identical whether the
	 * hardware is switched off or the network simply is not there (0199).
	 */
	ncfg_buf_init(&out, 0);
	check(ncfg_wifi_status(&where, document, off, "wlan0", &out, err, sizeof(err)),
	    "a switched-off radio still answers");
	if (decoded(&out, &message)) {
		const ncfg_proto_wifi_status_t *state = &message.u.response.u.wifi_status;

		check(ncfg_proto_str_present(state->blocked) &&
		    memmem(state->blocked.bytes, state->blocked.length, "rfkill unblock", 14u) !=
		        NULL,
		    "  saying which switch is holding it off, which no state name can");
		ncfg_proto_message_free(&message);
	}
	ncfg_buf_free(&out);

	ncfg_buf_init(&out, 0);
	check(!ncfg_wifi_status(&where, document, observed, "wlan9", &out, err, sizeof(err)) &&
	    strstr(kept(err), "cannot reach the supplicant") != NULL,
	    "an interface with nothing listening is told so");
	ncfg_buf_free(&out);

	ncfg_buf_init(&out, 0);
	check(ncfg_wifi_status(&where, iwd, observed, "wlan0", &out, err, sizeof(err)),
	    "and `status` answers for an `iwd` device, which is the defect this port reports");
	ncfg_buf_free(&out);
	ncfg_document_free(document);
	ncfg_document_free(iwd);
	ncfg_observed_free(observed);
	ncfg_observed_free(off);
}

static void leaving_without_forgetting(void)
{
	ncfg_document_t *document = compiled("leave.conf",
	    "device wlan0 {\n\twifi {\n\t\tautoconnect = true\n\t}\n}\n");
	ncfg_document_t *iwd = compiled("iwd.conf",
	    "device wlan0 {\n\twifi {\n\t\tbackend = \"iwd\"\n\t}\n}\n");
	ncfg_buf_t       out;
	char             err[NCFG_ERROR_MAX];
	char            *heard;
	long             mark;

	printf("\n-- leaving a network without forgetting it\n");
	mark = log_mark();
	ncfg_buf_init(&out, 0);
	check(ncfg_wifi_disconnect(&where, document, "wlan0", &out, err, sizeof(err)) &&
	    strcmp(ncfg_buf_text(&out), "{\"response\":\"ok\"}") == 0, "the radio disconnects");
	heard = log_since(mark);
	check(heard && strstr(heard, "DISCONNECT") != NULL &&
	    strstr(heard, "REMOVE_NETWORK") == NULL,
	    "  and the network stays configured, so reconnecting resolves nothing again");
	free(heard);
	ncfg_buf_free(&out);
	ncfg_buf_init(&out, 0);
	check(!ncfg_wifi_disconnect(&where, iwd, "wlan0", &out, err, sizeof(err)) &&
	    strstr(kept(err), "iwd backend") != NULL,
	    "a device pointed at a supplicant netcfgd cannot drive is refused here too");
	ncfg_buf_free(&out);
	ncfg_document_free(document);
	ncfg_document_free(iwd);
}

static void who_is_associated_with_an_access_point(void)
{
	ncfg_document_t     *document = compiled("ap.conf",
	    "access_point \"guest\" {\n\tdevice = \"wlan0\"\n\tchannel = 11\n"
	    "\twifi { psk = \"@secret:guest\"; proto = \"wpa2\" }\n"
	    "\taccess_control { deny = [\"00:11:22:33:44:55\"] }\n}\n");
	ncfg_document_t     *none = compiled("noap.conf", "global { }\n");
	ncfg_buf_t           out;
	ncfg_proto_message_t message;
	char                 err[NCFG_ERROR_MAX];

	printf("\n-- 0040: who is associated, and what the document says about them\n");
	ncfg_buf_init(&out, 0);
	check(!ncfg_wifi_ap_stations(&where, none, "wlan0", &out, err, sizeof(err)) &&
	    strstr(kept(err), "runs no access point") != NULL,
	    "an interface with no access point is told that, not told about a socket");
	ncfg_buf_free(&out);

	ncfg_buf_init(&out, 0);
	check(ncfg_wifi_ap_stations(&where, document, "wlan0", &out, err, sizeof(err)),
	    "the stations come back");
	if (decoded(&out, &message)) {
		const ncfg_proto_stations_t *report = &message.u.response.u.ap_stations;

		check(says(report->interface, "wlan0") && says(report->access_point, "guest"),
		    "  naming the block they belong to");
		check(says(report->access_control, "deny"),
		    "  and which way the list reads, since `listed` means opposite things");
		check(report->station_count == 3u, "  every station hostapd knows about");
		check(report->station_count == 3u && report->stations[0].listed == 1 &&
		    report->stations[1].listed == 0,
		    "  a station on the deny list that is still connected is marked");
		check(report->station_count == 3u && report->stations[0].signal.present &&
		    report->stations[0].signal.value == -52,
		    "  the statistics where the driver answered");
		/*
		 * **hostapd genuinely omits them.** `hostapd_get_sta_info` writes
		 * nothing at all when the driver read fails, so a station with no
		 * `signal=` is a normal reply and not a malformed one -- a reader that
		 * required it would drop a client that is really there.
		 */
		check(report->station_count == 3u && !report->stations[1].signal.present &&
		    !report->stations[1].rx_bytes.present,
		    "  and none of them where it did not, rather than zeroes nobody measured");
		check(report->station_count == 3u && report->stations[2].authorized == 0,
		    "  a station that has not finished authenticating is shown differently");
		ncfg_proto_message_free(&message);
	}
	ncfg_buf_free(&out);
	ncfg_document_free(document);
	ncfg_document_free(none);
}

/* What reached the installer, and the credential's length rather than a copy
 * of it. */
static struct {
	size_t calls;
	char   id[128];
	char   ssid_hex[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char   ca_cert[192];
	char   method[32];
	int    security;
	int    hidden;
	int    has_metric;
	long long metric;
	size_t credential_length;
	int    credential_is_canary;
} installed;

static int recording_install(void *context, const ncfg_wifi_profile_t *profile,
    const char *credential, size_t credential_length, char *err, size_t err_size)
{
	static const char digits[] = "0123456789abcdef";
	size_t            at;

	(void)context;
	(void)err;
	(void)err_size;
	installed.calls++;
	(void)snprintf(installed.id, sizeof(installed.id), "%s", profile->id ? profile->id : "");
	for (at = 0; at < profile->ssid.length; at++) {
		installed.ssid_hex[at * 2u] = digits[profile->ssid.bytes[at] >> 4];
		installed.ssid_hex[at * 2u + 1u] = digits[profile->ssid.bytes[at] & 0x0fu];
	}
	installed.ssid_hex[profile->ssid.length * 2u] = '\0';
	(void)snprintf(installed.ca_cert, sizeof(installed.ca_cert), "%s",
	    profile->ca_cert ? profile->ca_cert : "");
	(void)snprintf(installed.method, sizeof(installed.method), "%s",
	    profile->method ? profile->method : "");
	installed.security = (int)profile->security;
	installed.hidden = profile->hidden;
	installed.has_metric = profile->metric.has;
	installed.metric = (long long)profile->metric.value;
	installed.credential_length = credential_length;
	installed.credential_is_canary = credential && credential_length == strlen(CANARY) &&
	    memcmp(credential, CANARY, credential_length) == 0;
	return 1;
}

/* A `wifi_add` built by hand, which is what a request a caller builds is. */
static void wanted_reset(ncfg_proto_wifi_add_t *wanted)
{
	memset(wanted, 0, sizeof(*wanted));
	wanted->ssid = ncfg_proto_str(HOMEFIBER_HEX);
	wanted->id = ncfg_proto_str_none();
	wanted->passphrase = ncfg_proto_str_none();
	wanted->proto = ncfg_proto_str_none();
}

static void adding_a_network_is_bounded_by_its_shape(void)
{
	ncfg_document_t      *document = compiled("existing.conf",
	    "network \"HomeFiber\" {\n\tssid = \"" HOMEFIBER_HEX "\"\n\twifi { open = true }\n}\n");
	ncfg_proto_wifi_add_t wanted;
	ncfg_buf_t            out;
	char                  err[NCFG_ERROR_MAX];

	printf("\n-- 0117: what a `wifi_add` may say, and what it cannot\n");
	ncfg_buf_init(&out, 0);
	memset(&installed, 0, sizeof(installed));
	wanted_reset(&wanted);
	check(!ncfg_wifi_configure_network(document, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "already configured") != NULL,
	    "a second block with a label one already has is refused before anything is written");
	check(installed.calls == 0u, "  and nothing reached the installer");

	wanted_reset(&wanted);
	wanted.ssid = ncfg_proto_str("48656c6C6f");
	check(!ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "lowercase hex") != NULL,
	    "uppercase hex is refused, because two spellings of one ssid is two networks");

	wanted_reset(&wanted);
	wanted.ssid = ncfg_proto_str("ff00ff");
	check(!ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "not text, so it cannot be used as a name") !=
	        NULL,
	    "an ssid that is not text needs an `id`, because a label is a filename");

	/*
	 * **An ssid that is text and still not a name.** A label becomes a C
	 * string and a filename, so an embedded NUL would be silently dropped
	 * along with everything after it -- the Rust refuses the same value a
	 * layer down, in `usable_id`, as a control character.
	 */
	wanted_reset(&wanted);
	wanted.ssid = ncfg_proto_str("48690068");
	check(!ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "not text, so it cannot be used as a name") !=
	        NULL,
	    "an ssid with a NUL in it is not a name either, so no shorter one is invented");

	/* The same value sent as an `id`, where it is a counted string rather than
	 * octets: refused by name rather than copied up to the NUL. */
	wanted_reset(&wanted);
	{
		static const char with_a_nul[] = "office\0shadow";
		ncfg_proto_str_t  id;

		id.bytes = with_a_nul;
		id.length = sizeof(with_a_nul) - 1u;
		wanted.id = id;
	}
	check(!ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "NUL in the middle of it") != NULL,
	    "and neither is an `id` carrying one, which would otherwise be silently cut");

	wanted_reset(&wanted);
	wanted.ssid = ncfg_proto_str("ff00ff");
	wanted.id = ncfg_proto_str("the-odd-one");
	check(ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)), "  and is accepted once one is given");
	check(installed.calls == 1u && strcmp(installed.id, "the-odd-one") == 0 &&
	    strcmp(installed.ssid_hex, "ff00ff") == 0,
	    "  with the ssid kept exactly, as octets, beside the label");
	check(installed.security == NCFG_WIFI_SECURITY_OPEN && installed.credential_length == 0u,
	    "  an open network stores nothing");

	ncfg_buf_free(&out);
	ncfg_buf_init(&out, 0);
	memset(&installed, 0, sizeof(installed));
	wanted_reset(&wanted);
	check(ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && strcmp(installed.id, "HomeFiber") == 0,
	    "the label defaults to the ssid read as text, which is what people mean by the name");
	check(strcmp(ncfg_buf_text(&out), "{\"response\":\"ok\"}") == 0,
	    "  and the answer is `ok`");

	wanted_reset(&wanted);
	wanted.proto = ncfg_proto_str("wpa2");
	check(!ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "no passphrase") != NULL,
	    "a generation with nothing to pin is refused rather than quietly dropped");

	wanted_reset(&wanted);
	wanted.passphrase = ncfg_proto_str(CANARY);
	wanted.proto = ncfg_proto_str("wpa4");
	check(!ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "is not a generation this understands") != NULL,
	    "and a generation nobody has heard of is named rather than written down");

	memset(&installed, 0, sizeof(installed));
	wanted_reset(&wanted);
	wanted.passphrase = ncfg_proto_str(CANARY);
	wanted.hidden = 1;
	wanted.metric.present = 1;
	wanted.metric.value = 10;
	check(ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && installed.security == NCFG_WIFI_SECURITY_PSK,
	    "a passphrase makes it a PSK network");
	check(installed.hidden == 1 && installed.has_metric && installed.metric == 10,
	    "  carrying the two fields that are not defaults");
	/*
	 * **The credential is handed over by count and never copied.** A
	 * `ncfg_proto_str_t` points into the decoded line, so the passphrase exists
	 * in exactly one place for exactly as long as that line does -- which is
	 * the difference from the Rust, where a resolved value sits in a `Vec` for
	 * as long as the network takes to configure.
	 */
	check(installed.credential_is_canary &&
	    installed.credential_length == strlen(CANARY),
	    "  and the credential arrives by count, from the request's own bytes");

	wanted_reset(&wanted);
	wanted.passphrase = ncfg_proto_str(CANARY);
	wanted.metric.present = 1;
	wanted.metric.value = -1;
	check(!ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "0 to 4294967295") != NULL,
	    "a metric outside a route metric's range is refused here, where serde refuses it there");

	ncfg_buf_free(&out);
	ncfg_buf_init(&out, 0);
	memset(&installed, 0, sizeof(installed));
	wanted_reset(&wanted);
	wanted.passphrase = ncfg_proto_str(CANARY);
	wanted.proto = ncfg_proto_str("wpa2");
	wanted.eap.present = 1;
	wanted.eap.method = ncfg_proto_str("peap");
	wanted.eap.identity = ncfg_proto_str("you@corp.example");
	check(!ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "`proto` was given with an `eap` block") != NULL,
	    "an enterprise network negotiates its own generation, so `proto` beside it is refused");

	wanted_reset(&wanted);
	wanted.passphrase = ncfg_proto_str(CANARY);
	wanted.eap.present = 1;
	wanted.eap.method = ncfg_proto_str("eap-fast");
	wanted.eap.identity = ncfg_proto_str("you@corp.example");
	check(!ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "is not an EAP method netcfgd implements") !=
	        NULL,
	    "a method netcfgd does not implement is named, not left for the supplicant's log");

	wanted_reset(&wanted);
	wanted.passphrase = ncfg_proto_str(CANARY);
	wanted.eap.present = 1;
	wanted.eap.method = ncfg_proto_str("peap");
	wanted.eap.identity = ncfg_proto_str("   ");
	check(!ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && strstr(kept(err), "needs an `identity`") != NULL,
	    "and an enterprise network with nobody to be is refused");

	memset(&installed, 0, sizeof(installed));
	wanted_reset(&wanted);
	wanted.ssid = ncfg_proto_str("656475726f616d");
	wanted.passphrase = ncfg_proto_str(CANARY);
	wanted.eap.present = 1;
	wanted.eap.method = ncfg_proto_str("peap");
	wanted.eap.identity = ncfg_proto_str("you@corp.example");
	wanted.eap.ca_cert = ncfg_proto_str("corp-ca");
	check(ncfg_wifi_configure_network(NULL, &wanted, recording_install, NULL, &out, err,
	        sizeof(err)) && installed.security == NCFG_WIFI_SECURITY_EAP &&
	    strcmp(installed.method, "peap") == 0, "an enterprise network is accepted");
	/*
	 * **The one place the socket's names turn into configuration**, and the
	 * only form they can take: a request carries a *name*, and what is written
	 * says `@secret:<name>`, which the compiler lowers to a stored source and
	 * never to a path. There is no field here a path could be written in.
	 */
	check(strcmp(installed.ca_cert, "@secret:corp-ca") == 0,
	    "  and a certificate is a stored name, never a path to open as root");

	ncfg_buf_free(&out);
	ncfg_buf_init(&out, 0);
	wanted_reset(&wanted);
	check(!ncfg_wifi_configure_network(NULL, &wanted, NULL, NULL, &out, err, sizeof(err)) &&
	    strstr(kept(err), "no way to write a `network` block") != NULL,
	    "a caller with no installer is told so rather than answered `ok` for nothing");
	ncfg_buf_free(&out);
	ncfg_document_free(document);
}

static void nothing_here_has_a_default(void)
{
	ncfg_wifi_where_t nowhere;
	ncfg_buf_t        out;
	char              err[NCFG_ERROR_MAX];

	printf("\n-- the real netcfgd runs on this machine, so nothing falls back to its paths\n");
	memset(&nowhere, 0, sizeof(nowhere));
	ncfg_buf_init(&out, 0);
	check(!ncfg_wifi_radios(&nowhere, NULL, NULL, &out, err, sizeof(err)) &&
	    strstr(kept(err), "none of the three has a default here") != NULL,
	    "a wifi call with no directories refuses rather than reading the machine's");
	check(!ncfg_wifi_scan(&nowhere, NULL, NULL, "wlan0", &out, err, sizeof(err)),
	    "  and so does a scan");
	check(!ncfg_wifi_status(&nowhere, NULL, NULL, "wlan0", &out, err, sizeof(err)),
	    "  and a status");
	check(!ncfg_wifi_ap_stations(&nowhere, NULL, "wlan0", &out, err, sizeof(err)),
	    "  and a station list");
	check(strcmp(NCFG_SUPPLICANT_CTRL_DIR, "/run/wpa_supplicant") == 0,
	    "the real control directory is asserted by reading the constant, never by writing");
	ncfg_buf_free(&out);
}

static void no_credential_reaches_a_message(void)
{
	char       *heard = testdir_read(supplicant_log, NULL);
	const char *found;

	printf("\n-- the canary, swept through every channel a value could leak by\n");
	/* Non-vacuity first: a join that succeeded is a credential that resolved
	 * and reached the socket, and the cut `SET_NETWORK 0` line is what the
	 * fake's redaction leaves where the value was. */
	check(installed.calls > 0u || heard != NULL, "the fake kept a log to sweep");
	found = strstr(every_message, CANARY);
	check(found == NULL, "no `err` buffer this file filled carries the passphrase");
	if (found) {
		detail("in", found - 200 > every_message ? found - 200 : every_message);
	}
	check(!heard || strstr(heard, CANARY) == NULL,
	    "and neither does the fake supplicant's own log");
	free(heard);
}

/* ================================================================== main */

int main(int argc, char **argv)
{
	const char *fakes = (argc > 1) ? argv[1] : "../tests/live";
	char        supplicant_script[384];
	char        hostapd_script[384];
	char        pidfile[448];
	char        socket_path[448];
	char        hostapd_log[384];
	const char *argument[5];
	char       *sweep;
	int         canary_in_stderr;
	int         stderr_copy;
	char        stderr_path[384];

	(void)testdir_make("daemon-wifi");
	(void)snprintf(base, sizeof(base), "%s", testdir_path);
	(void)snprintf(ctrl_dir, sizeof(ctrl_dir), "%s/ctrl", base);
	(void)snprintf(run_dir, sizeof(run_dir), "%s/run", base);
	(void)snprintf(class_net, sizeof(class_net), "%s/sys", base);
	(void)snprintf(config_dir, sizeof(config_dir), "%s/etc", base);
	(void)snprintf(factory_dir, sizeof(factory_dir), "%s/factory", base);
	(void)snprintf(secrets_dir, sizeof(secrets_dir), "%s/secrets", base);
	(void)snprintf(certs_dir, sizeof(certs_dir), "%s/certs", base);
	(void)snprintf(hostapd_dir, sizeof(hostapd_dir), "%s/hostapd", run_dir);
	(void)snprintf(supplicant_log, sizeof(supplicant_log), "%s/supplicant.log", base);
	(void)snprintf(hostapd_log, sizeof(hostapd_log), "%s/hostapd.log", base);
	(void)snprintf(stderr_path, sizeof(stderr_path), "%s/stderr.log", base);
	make_directory(ctrl_dir);
	make_directory(run_dir);
	make_directory(class_net);
	make_directory(config_dir);
	make_directory(factory_dir);
	make_directory(secrets_dir);
	make_directory(certs_dir);
	make_directory(hostapd_dir);
	make_radio("wlan0", 1);
	make_radio("wlan1", 1);
	make_radio("wlan9", 1);
	make_radio("eth0", 0);

	where.ctrl_dir = ctrl_dir;
	where.class_net = class_net;
	where.run_dir = run_dir;

	/* The credential every secret path here uses. 0600, because the `file`
	 * provider refuses one anybody else could read. */
	{
		char path[384];
		int  fd;

		(void)snprintf(path, sizeof(path), "%s/home", secrets_dir);
		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0) {
			(void)write(fd, CANARY "\n", strlen(CANARY) + 1u);
			(void)close(fd);
		}
	}

	(void)snprintf(supplicant_script, sizeof(supplicant_script), "%s/fake_supplicant.py",
	    fakes);
	(void)snprintf(hostapd_script, sizeof(hostapd_script), "%s/fake_hostapd.py", fakes);
	if (!testdir_exists(supplicant_script) || !testdir_exists(hostapd_script)) {
		/* Not skipped. A suite that carried on here would report success for
		 * a run that checked the wire format against nothing at all. */
		printf("the repository's fakes are not at `%s`; pass their directory as "
		    "the first argument\n", fakes);
		testdir_remove(testdir_path);
		return 1;
	}

	/* `wlan0`: a socket bound by a process netcfgd did not start, which is
	 * what an operator running NetworkManager has. */
	argument[0] = ctrl_dir;
	argument[1] = "wlan0";
	(void)snprintf(socket_path, sizeof(socket_path), "%s/wlan0", ctrl_dir);
	if (!start_fake(supplicant_script, argument, 2u, socket_path, supplicant_log)) {
		printf("the fake supplicant for wlan0 never bound its socket\n");
		stop_fakes();
		testdir_remove(testdir_path);
		return 1;
	}
	/* `wlan1`: netcfgd's own, which it knows by the pid file appearing in the
	 * process' command line (0140) and not by the file alone. */
	(void)snprintf(pidfile, sizeof(pidfile), "%s/supplicant/wlan1.pid", run_dir);
	argument[0] = ctrl_dir;
	argument[1] = "wlan1";
	argument[2] = pidfile;
	(void)snprintf(socket_path, sizeof(socket_path), "%s/wlan1", ctrl_dir);
	if (!start_fake(supplicant_script, argument, 3u, socket_path, hostapd_log)) {
		printf("the fake supplicant for wlan1 never bound its socket\n");
		stop_fakes();
		testdir_remove(testdir_path);
		return 1;
	}
	argument[0] = hostapd_dir;
	argument[1] = "wlan0";
	argument[2] = "--deny";
	argument[3] = "00:11:22:33:44:55";
	(void)snprintf(socket_path, sizeof(socket_path), "%s/wlan0", hostapd_dir);
	if (!start_fake(hostapd_script, argument, 4u, socket_path, hostapd_log)) {
		printf("the fake hostapd never bound its socket\n");
		stop_fakes();
		testdir_remove(testdir_path);
		return 1;
	}

	/* Everything this process writes to standard error, kept so the canary
	 * sweep can read it back. Restored before anything is printed about it. */
	stderr_copy = dup(STDERR_FILENO);
	{
		int redirected = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		if (redirected >= 0) {
			(void)dup2(redirected, STDERR_FILENO);
			(void)close(redirected);
		}
	}

	the_backend_is_refused_by_name();
	the_address_answers_before_the_name();
	why_there_is_no_supplicant();
	what_activation_writes_is_asked_of_the_planner();
	the_radio_list_comes_from_the_kernel();
	taking_a_radio_on_and_handing_it_back();
	the_scan_and_why_it_may_be_stale();
	joining_a_network_the_configuration_describes();
	the_status_and_what_it_has_given_up_on();
	leaving_without_forgetting();
	who_is_associated_with_an_access_point();
	adding_a_network_is_bounded_by_its_shape();
	nothing_here_has_a_default();

	(void)fflush(stderr);
	sweep = testdir_read(stderr_path, NULL);
	canary_in_stderr = sweep && strstr(sweep, CANARY) != NULL;
	free(sweep);
	if (stderr_copy >= 0) {
		(void)dup2(stderr_copy, STDERR_FILENO);
		(void)close(stderr_copy);
	}
	check(!canary_in_stderr, "nothing this process wrote to standard error carries it");
	no_credential_reaches_a_message();

	stop_fakes();
	testdir_remove(testdir_path);
	if (failures) {
		printf("\n%d check(s) failed\n", failures);
		return 1;
	}
	printf("\nthe daemon's wifi half: every check passed\n");
	return 0;
}
