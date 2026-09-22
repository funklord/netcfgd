/*
 * wifi.c -- the wireless requests, and the supplicant behind them.
 *
 * Every handler here opens a control socket, uses it and drops it. That is
 * deliberate rather than lazy: decision 0015 says the supplicant holds no
 * state, and a daemon holding a long-lived connection to it would start
 * caching what it last saw. A datagram socket and a `PING` cost a round trip
 * on a local socket, which is nothing next to the scan they precede.
 *
 * The one rule that shapes all of this: a caller in the `wifi` tier can join a
 * network the configuration already describes, and nothing else. Nothing in
 * this file can create a network, so the tier cannot be talked into writing
 * config (0013).
 *
 * WHAT A REFUSAL IS HERE
 *   The Rust returns `Response::error(...)`, which is an answer. So does a 0
 *   from these calls: `daemon.h`'s handler contract is "return 0 with a
 *   sentence in `err` and the server answers `error` with that sentence", so
 *   every sentence below is the Rust's, unchanged, and nothing is translated
 *   on the way out.
 *
 * WHAT MUST NOT REACH A MESSAGE
 *   A passphrase, a key, an EAP password. `ncfg_supplicant_add_network`
 *   already quotes the **redacted** form of a failing command, and nothing
 *   here resolves a credential or copies one: `ncfg_wifi_configure_network`
 *   hands the installer the request's own bytes by count rather than a copy of
 *   them. `daemon_wifi_test.c` sweeps one canary through every `err` buffer
 *   and through standard error for that reason.
 */
#include "ncfg/daemon.h"

#include "ncfg/config.h"
#include "ncfg/hostapd.h"
#include "ncfg/json_write.h"
#include "ncfg/process.h"
#include "ncfg/radio.h"
#include "ncfg/secrets.h"
#include "ncfg/supplicant.h"
#include "ncfg/wifi_profile.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* ------------------------------------------------------------- the pieces */

/* Finish a writer into `out`, turning its own complaint into this module's
 * sentence. The buffer is failed rather than merely reported on: half a
 * message is the one that gets sent by accident. */
static int finish(ncfg_json_writer_t *writer, ncfg_buf_t *out, const char *what, char *err,
    size_t err_size)
{
	if (!ncfg_json_write_done(writer)) {
		const char *why = ncfg_json_write_failure(writer);

		out->failed = 1;
		ncfg_error_set(err, err_size, "the %s response could not be written: %s", what,
		    why ? why : "it was left unfinished");
		return 0;
	}
	return 1;
}

/* Whether every argument this module cannot work without is there. */
static int where_is_usable(const ncfg_wifi_where_t *where, char *err, size_t err_size)
{
	if (where && where->ctrl_dir && where->ctrl_dir[0] && where->class_net &&
	    where->class_net[0] && where->run_dir && where->run_dir[0]) {
		return 1;
	}
	/*
	 * No default, and the reason is `tests/testdir.h`'s: the real netcfgd runs
	 * on the machine this is built on and its wifi is real. A module that
	 * filled these in for itself would be one mistake away from a test
	 * scanning the developer's radio.
	 */
	ncfg_error_set(err, err_size,
	    "the wifi half was given no control directory, sysfs root or run directory, and "
	    "none of the three has a default here");
	return 0;
}

/* The link the observation holds by this name, or NULL. */
static const ncfg_observed_link_t *link_named(const ncfg_observed_t *observed,
    const char *interface)
{
	size_t at;

	if (!observed || !interface) {
		return NULL;
	}
	for (at = 0; at < observed->link_count; at++) {
		const char *name = observed->links[at].name;

		if (name && strcmp(name, interface) == 0) {
			return &observed->links[at];
		}
	}
	return NULL;
}

/*
 * The switch on this interface, when the radio is off.
 *
 * The one the observation already holds rather than a second read of `/sys`:
 * two paths answering the same question are two paths that can disagree, and
 * this one is the reconciled view.
 */
static const ncfg_observed_rfkill_t *blocked_switch(const ncfg_observed_t *observed,
    const char *interface)
{
	const ncfg_observed_link_t *link = link_named(observed, interface);

	if (!link || !link->rfkill || !ncfg_rfkill_blocked(link->rfkill)) {
		return NULL;
	}
	return link->rfkill;
}

/* The device block for this interface, or NULL. */
static const ncfg_device_t *device_named(const ncfg_document_t *document, const char *interface)
{
	size_t at;

	if (!document || !interface) {
		return NULL;
	}
	for (at = 0; at < document->device_count; at++) {
		const char *name = document->devices[at].name;

		if (name && strcmp(name, interface) == 0) {
			return &document->devices[at];
		}
	}
	return NULL;
}

/*
 * Whether these octets are text.
 *
 * **Absent rather than mangled**, so a client can tell "this name is not
 * UTF-8" from "this name is empty". A lossy conversion would put a replacement
 * character in a list the operator is trying to recognise their own network
 * in. The JSON writer refuses a string that is not UTF-8 (0263), so asking
 * here is also what keeps a scan from failing over one misbehaving access
 * point.
 */
static int is_text(const unsigned char *bytes, size_t length)
{
	size_t at = 0;

	while (at < length) {
		unsigned char lead = bytes[at];
		size_t        follow;
		unsigned      point;

		if (lead < 0x80u) {
			at++;
			continue;
		}
		if ((lead & 0xe0u) == 0xc0u) {
			follow = 1u;
			point = lead & 0x1fu;
		} else if ((lead & 0xf0u) == 0xe0u) {
			follow = 2u;
			point = lead & 0x0fu;
		} else if ((lead & 0xf8u) == 0xf0u) {
			follow = 3u;
			point = lead & 0x07u;
		} else {
			return 0;
		}
		if (at + follow >= length) {
			return 0;
		}
		{
			size_t step;

			for (step = 1u; step <= follow; step++) {
				unsigned char next = bytes[at + step];

				if ((next & 0xc0u) != 0x80u) {
					return 0;
				}
				point = (point << 6) | (next & 0x3fu);
			}
		}
		/* Overlong forms, surrogates and anything past U+10FFFF are refused
		 * for the reason the writer refuses them: each is a value nobody
		 * typed, arriving as text. */
		if ((follow == 1u && point < 0x80u) || (follow == 2u && point < 0x800u) ||
		    (follow == 3u && point < 0x10000u) || (point >= 0xd800u && point <= 0xdfffu) ||
		    point > 0x10ffffu) {
			return 0;
		}
		at += follow + 1u;
	}
	return 1;
}

/* An SSID as lowercase hex, which is its canonical encoding. `out` is
 * `NCFG_SUPPLICANT_SSID_HEX_SIZE` bytes. */
static void ssid_hex(const ncfg_ssid_t *ssid, char *out, size_t out_size)
{
	static const char digits[] = "0123456789abcdef";
	size_t            at;

	out[0] = '\0';
	if (!ssid || ssid->length * 2u + 1u > out_size) {
		return;
	}
	for (at = 0; at < ssid->length; at++) {
		out[at * 2u] = digits[ssid->bytes[at] >> 4];
		out[at * 2u + 1u] = digits[ssid->bytes[at] & 0x0fu];
	}
	out[ssid->length * 2u] = '\0';
}

/* The `ssid` and `name` members of a scan row, a status or a disabled network,
 * written together because the pair is one fact and two spellings of it. */
static void write_ssid_pair(ncfg_json_writer_t *writer, const ncfg_ssid_t *ssid)
{
	char hex[NCFG_SUPPLICANT_SSID_HEX_SIZE];

	ssid_hex(ssid, hex, sizeof(hex));
	ncfg_json_write_member_string(writer, "ssid", hex);
	if (is_text(ssid->bytes, ssid->length)) {
		ncfg_json_write_key(writer, "name");
		ncfg_json_write_string_bytes(writer, (const char *)ssid->bytes, ssid->length);
	}
}

/* Two SSIDs are the same SSID. */
static int ssid_equal(const ncfg_ssid_t *left, const ncfg_ssid_t *right)
{
	return left->length == right->length &&
	    memcmp(left->bytes, right->bytes, left->length) == 0;
}

/* Case-insensitive, because a BSSID from a config file and one from a scan are
 * written by different hands. */
static int same_address(const char *left, const char *right)
{
	size_t at = 0;

	if (!left || !right) {
		return 0;
	}
	for (;; at++) {
		char one = left[at];
		char two = right[at];

		if (one >= 'A' && one <= 'Z') {
			one = (char)(one - 'A' + 'a');
		}
		if (two >= 'A' && two <= 'Z') {
			two = (char)(two - 'A' + 'a');
		}
		if (one != two) {
			return 0;
		}
		if (one == '\0') {
			return 1;
		}
	}
}

/*
 * Open a control socket, or explain why not in terms of what to do.
 *
 * The sentence is the Rust's, and the caller decides whether the document has
 * a better one -- which only `scan` currently asks for, and which is the
 * defect this port reports rather than fixes.
 */
static ncfg_supplicant_client_t *open_control(const ncfg_wifi_where_t *where,
    const char *interface, char *err, size_t err_size)
{
	char                      why[NCFG_ERROR_MAX];
	ncfg_supplicant_client_t *client = ncfg_supplicant_connect(where->ctrl_dir, interface, why,
	    sizeof(why));

	if (!client) {
		ncfg_error_set(err, err_size,
		    "cannot reach the supplicant for `%s`: %s. netcfgd starts wpa_supplicant for "
		    "a managed wireless device; if this device is not managed, or the last apply "
		    "failed, there is nothing listening", interface, why);
	}
	return client;
}

/* ---------------------------------------------------------- the questions */

int ncfg_wifi_check_backend(const ncfg_document_t *document, const char *interface, char *err,
    size_t err_size)
{
	const ncfg_device_t *device = device_named(document, interface);

	if (!device || !device->wifi || device->wifi->backend != NCFG_WIFI_BACKEND_IWD) {
		return 1;
	}
	ncfg_error_set(err, err_size,
	    "`%s` asks for the iwd backend, which this build does not have. iwd keeps its own "
	    "network database and writes to it, which conflicts with netcfgd's configuration "
	    "being the only authority, so supporting it needs iwd to grow a stateless mode "
	    "(doc/decision/0014). Use `backend = \"wpa_supplicant\"`.", interface);
	return 0;
}

const ncfg_wifi_network_t *ncfg_wifi_network_for(const ncfg_wifi_network_t *networks,
    size_t count, const ncfg_ssid_t *ssid, const char *bssid)
{
	size_t at;
	size_t which;

	if (!networks || !ssid) {
		return NULL;
	}
	/* **The address first** (0239): it is the more specific statement, and it
	 * is the only thing that separates two blocks sharing an SSID and pinned
	 * to different access points. */
	for (at = 0; at < count; at++) {
		const ncfg_wifi_network_t *network = &networks[at];

		if (network->ssid.has && !ssid_equal(&network->ssid, ssid)) {
			continue;
		}
		for (which = 0; which < network->bssid_count; which++) {
			if (same_address(network->bssid[which], bssid)) {
				return network;
			}
		}
	}
	for (at = 0; at < count; at++) {
		if (networks[at].ssid.has && ssid_equal(&networks[at].ssid, ssid)) {
			return &networks[at];
		}
	}
	return NULL;
}

int ncfg_wifi_why_no_supplicant(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const char *interface, char *out, size_t out_size)
{
	const ncfg_device_t *device;
	char                 socket_path[512];
	char                 pidfile[512];
	struct stat          about;

	if (out && out_size) {
		out[0] = '\0';
	}
	if (!where || !out || !out_size || !interface) {
		return 0;
	}
	/*
	 * **The shared predicate, not a fourth copy of the path.** The Rust had
	 * its own `/sys/class/net` here -- written before `netcfgd_sys::radio`
	 * collected the other three -- so it asked the real machine while
	 * everything around it asked wherever the override pointed. On a test
	 * radio it therefore answered "not a radio at all" and declined to explain
	 * anything.
	 *
	 * Not a radio at all: the socket's own message is the right one, because
	 * the answer is not about configuration.
	 */
	if (!ncfg_radio_is_wireless(where->class_net, interface)) {
		return 0;
	}
	device = device_named(document, interface);
	if (device && !device->managed) {
		ncfg_error_set(out, out_size,
		    "`%s` is a radio, and its `device` block says `managed = false` -- so netcfgd "
		    "does not touch it and has started no supplicant. That is the documented way "
		    "to hand an interface to another daemon; remove the line to take it back.",
		    interface);
		return 1;
	}
	if (device && device->wifi) {
		/*
		 * **Configured correctly, and still no supplicant.** This arm said
		 * nothing at all for the case an operator is most likely to be in:
		 * radio managed, `wifi` policy present, network written down, and
		 * another daemon holding the control socket.
		 */
		if ((size_t)snprintf(socket_path, sizeof(socket_path), "%s/%s", where->ctrl_dir,
		        interface) >= sizeof(socket_path)) {
			return 0;
		}
		if (lstat(socket_path, &about) != 0) {
			/* Nothing has bound it. That is the ordinary "netcfgd has not
			 * applied yet, or the apply failed" case, and the caller's own
			 * message already says so. */
			return 0;
		}
		if ((size_t)snprintf(pidfile, sizeof(pidfile), "%s/supplicant/%s.pid",
		        where->run_dir, interface) >= sizeof(pidfile)) {
			return 0;
		}
		if (ncfg_process_pid_of(pidfile, pidfile) > 0) {
			/* netcfgd's own, and not answering: that is the wedged case,
			 * which the planner reports with its own warning and 0141's
			 * refusal. */
			ncfg_error_set(out, out_size,
			    "`%s` has a supplicant netcfgd started, and it is not answering its "
			    "control socket at %s. netcfgd does not kill it by default, because a "
			    "busy machine misses the deadline the same way. "
			    "`ncfg apply --restart-wedged %s` restarts it.", interface, socket_path,
			    interface);
			return 1;
		}
		/*
		 * Bound by something netcfgd did not start.
		 *
		 * **The question is who bound the socket, not whether it answers.**
		 * NetworkManager's supplicant is driven over D-Bus and does not reply
		 * on the control interface, so the socket exists, stays mute, and a
		 * check that asked whether it answered said nothing in exactly the
		 * reported case.
		 */
		ncfg_error_set(out, out_size,
		    "`%s` is a radio netcfgd manages and is configured for, but another daemon is "
		    "already running a supplicant on it: the control socket at %s was bound by a "
		    "process netcfgd did not start, so netcfgd will not take the radio from it "
		    "(0125). **Nothing here is misconfigured** -- the radio is somebody else's "
		    "until they let go.\n\nHand it over with:\n\n    systemctl stop "
		    "NetworkManager\n    systemctl stop wpa_supplicant\n\nBoth, because "
		    "wpa_supplicant runs independently of NetworkManager and keeps this socket "
		    "bound on its own -- stopping NetworkManager alone leaves netcfgd declining "
		    "forever, which is what \"netcfgd stops working without NetworkManager\" "
		    "actually is. netcfgd picks the radio up on the next reconcile. To leave it "
		    "to them instead, set `managed = false` here.", interface, socket_path);
		return 1;
	}
	ncfg_error_set(out, out_size,
	    "`%s` is a radio, and netcfgd has no `wifi` policy for it -- so it does not manage "
	    "the radio and has started no supplicant, which is why there is nothing to scan "
	    "with. Add this and netcfgd will run one:\n\n    device %s {\n        wifi {\n      "
	    "      autoconnect = true\n        }\n    }\n\n`ncfg config put radio -` will take "
	    "it on standard input. Until then a scan can only work through somebody else's "
	    "supplicant, which is what NetworkManager was providing.", interface, interface);
	return 1;
}

/* --------------------------------------------------- what activation writes */

int ncfg_wifi_radio_drop_in(const char *interface, char *out, size_t out_size, char *err,
    size_t err_size)
{
	int written;

	if (!out || !out_size) {
		ncfg_error_set(err, err_size, "nowhere to put the drop-in's name");
		return 0;
	}
	out[0] = '\0';
	if (!interface || !interface[0]) {
		ncfg_error_set(err, err_size, "a radio drop-in is named after an interface");
		return 0;
	}
	written = snprintf(out, out_size, "radio-%s", interface);
	if (written < 0 || (size_t)written >= out_size) {
		out[0] = '\0';
		ncfg_error_set(err, err_size,
		    "`%s` is too long a name for a drop-in to be filed under", interface);
		return 0;
	}
	return 1;
}

int ncfg_wifi_radio_blocks(const char *interface, ncfg_buf_t *out, char *err, size_t err_size)
{
	/*
	 * Built line by line rather than as one string with continuations. The
	 * first version used `\n\` continuations and the source's own indentation
	 * ended up *inside* the file: every line came out with a tab and a space
	 * in front of it. It compiled -- leading whitespace means nothing to the
	 * config language -- so nothing failed, and the only cost was a file
	 * netcfgd wrote for a person to read that looked like a mistake.
	 */
	static const char *const preamble[] = {
		"# Written by `ncfg wifi activate`. Ordinary configuration: read it,",
		"# edit it, or delete it -- deleting it hands the radio back.",
		"#",
		"# Two blocks, and both are needed. `device` is policy about the",
		"# hardware; `interface` is what makes this link netcfgd's to",
		"# configure, and without it nothing is planned for the radio at all.",
		"#",
		"# `dhcp` is the assumption. Change it here for a static address.",
		"#",
		"# **The empty `dns { }` is load-bearing and was missing.** A lease's",
		"# nameservers are offered to the interface and taken only where one",
		"# asks for them, so without this line the radio came up addressed,",
		"# routed and unable to resolve anything -- on a machine whose global",
		"# `dns` block said `write_resolv_conf`, which reads as though it had",
		"# been asked for. netcfgd said so in a `ncfg plan` warning naming this",
		"# exact remedy, and the file it was describing is one netcfgd wrote.",
		"# Reported from a machine that had just been switched to netcfgd: \"I",
		"# had to write to resolv.conf\"."
	};
	size_t at;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the radio's configuration");
		return 0;
	}
	if (!interface || !interface[0]) {
		ncfg_error_set(err, err_size, "a radio block is written for an interface");
		return 0;
	}
	for (at = 0; at < sizeof(preamble) / sizeof(preamble[0]); at++) {
		ncfg_buf_add_text(out, preamble[at]);
		ncfg_buf_add_char(out, '\n');
	}
	ncfg_buf_addf(out, "\ndevice %s {\n\twifi {\n\t\tautoconnect = true\n\t}\n}\n",
	    interface);
	ncfg_buf_addf(out,
	    "\ninterface %s {\n\tconfig = \"dhcp\"\n"
	    "\t# Use the nameservers the lease hands out. Delete it to keep the\n"
	    "\t# resolver this machine already had.\n\tdns { }\n}\n", interface);
	if (ncfg_buf_failed(out)) {
		ncfg_error_set(err, err_size,
		    "the configuration for `%s` could not be built", interface);
		return 0;
	}
	return 1;
}

/* -------------------------------------------------------------- the radios */

int ncfg_wifi_radios(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const ncfg_observed_t *observed, ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             at;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the radio list");
		return 0;
	}
	if (!where_is_usable(where, err, err_size)) {
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "radios");
	ncfg_json_write_key(&writer, "radios");
	ncfg_json_write_array_begin(&writer);
	for (at = 0; observed && at < observed->link_count; at++) {
		const ncfg_observed_link_t *link = &observed->links[at];
		const ncfg_device_t        *device;
		int                         activated;

		/* **The kernel's list, not the document's.** A list built out of
		 * `device` blocks would show only the radios already taken on, and
		 * this list exists so that somebody can take one on. */
		if (!link->wireless || !link->name) {
			continue;
		}
		device = device_named(document, link->name);
		activated = device && device->managed && device->wifi;
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "interface", link->name);
		ncfg_json_write_member_bool(&writer, "activated", activated);
		/* Asked separately, because the gap between the two is what a person
		 * needs to see: activated with nothing answering is a fault, and the
		 * other way round is another manager holding this radio. */
		ncfg_json_write_member_bool(&writer, "supplicant",
		    ncfg_supplicant_answers(where->ctrl_dir, link->name));
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, out, "radios", err, err_size);
}

int ncfg_wifi_set_radio(ncfg_daemon_state_t *state, const char *interface, int activate,
    ncfg_wifi_apply_fn apply, void *apply_context, ncfg_buf_t *out, char *err, size_t err_size)
{
	const ncfg_observed_link_t *link;
	char                        name[NCFG_WIFI_DROP_IN_MAX];
	char                        why[NCFG_ERROR_MAX];
	int                         done;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the answer");
		return 0;
	}
	if (!state) {
		ncfg_error_set(err, err_size, "there is no state to change a radio in");
		return 0;
	}
	link = link_named(state->observed, interface);
	if (!link || !link->wireless) {
		/* Named rather than silent: activating `eth0` is a mistake worth a
		 * sentence, and the alternative is a `device` block that quietly does
		 * nothing. */
		ncfg_error_set(err, err_size,
		    "`%s` is not a radio on this machine. `ncfg wifi radios` lists the ones there "
		    "are", interface ? interface : "");
		return 0;
	}
	if (activate && !apply) {
		/*
		 * **Written is not running.** A caller with no way to apply would
		 * write a correct plan that nothing runs, and the operator would get
		 * "cannot reach the supplicant" from the very next scan -- which is
		 * the defect this synchronous step exists to close. Refused rather
		 * than skipped, because skipping it silently is what that looked like.
		 */
		ncfg_error_set(err, err_size,
		    "`%s` cannot be activated here: this caller was given no way to start the "
		    "radio's supplicant, and writing the configuration without starting it is "
		    "the fault that made activation report success and change nothing",
		    interface);
		return 0;
	}
	if (!ncfg_wifi_radio_drop_in(interface, name, sizeof(name), err, err_size)) {
		return 0;
	}
	if (activate) {
		ncfg_buf_t blocks;

		ncfg_buf_init(&blocks, 0);
		if (!ncfg_wifi_radio_blocks(interface, &blocks, err, err_size)) {
			ncfg_buf_free(&blocks);
			return 0;
		}
		/* Replacing is right here and is not the general case: this is a
		 * switch, so turning on something already on is the state being asked
		 * for rather than a collision. */
		done = ncfg_config_install_drop_in(state->paths.config, state->paths.factory, name,
		    ncfg_buf_text(&blocks), 1, NULL, NULL, err, err_size);
		ncfg_buf_free(&blocks);
	} else {
		done = ncfg_config_remove_drop_in(state->paths.config, state->paths.factory, name,
		    NULL, NULL, err, err_size);
	}
	if (!done) {
		return 0;
	}
	/*
	 * The reload's own answer is not this call's answer, which is the Rust's
	 * shape: the install has already proved the whole configuration compiles,
	 * so a failure here is a race with something else writing the directory,
	 * and the daemon keeps the document it had. What the caller asked about is
	 * the radio.
	 */
	(void)ncfg_daemon_state_reload(state, why, sizeof(why));
	if (activate && !apply(apply_context, interface, err, err_size)) {
		return 0;
	}
	return ncfg_daemon_ok_encode(out, err, err_size);
}

/* --------------------------------------------------------------- the scan */

/*
 * Turn `SCAN_RESULTS` into a report.
 *
 * Split out so the switched-off path can answer with the same shape: the
 * cached results, and the reason they are not fresh. A second copy of this
 * would be a second place for the ordering, the naming and the
 * mobility-domain lookup to drift.
 *
 * `stale` is NULL on the ordinary answer, which is fresh.
 */
static int scan_report(const ncfg_document_t *document, ncfg_supplicant_client_t *client,
    const char *interface, const char *body, const char *stale, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_json_writer_t      writer;
	ncfg_supplicant_scan_t *scans = NULL;
	size_t                  count = 0;
	size_t                  at;
	size_t                  step;

	if (!ncfg_supplicant_parse_scan_results(body, &scans, &count, err, err_size)) {
		return 0;
	}
	/*
	 * Strongest first, because that is the order the question is asked in. An
	 * insertion sort, which is stable, so two access points at the same level
	 * keep the supplicant's ordering rather than swapping between scans.
	 */
	for (at = 1; at < count; at++) {
		ncfg_supplicant_scan_t hold = scans[at];

		step = at;
		while (step > 0 && scans[step - 1u].signal < hold.signal) {
			scans[step] = scans[step - 1u];
			step--;
		}
		scans[step] = hold;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "wifi_scan");
	ncfg_json_write_member_string(&writer, "interface", interface);
	ncfg_json_write_key(&writer, "access_points");
	ncfg_json_write_array_begin(&writer);
	for (at = 0; at < count; at++) {
		const ncfg_supplicant_scan_t *scan = &scans[at];
		const ncfg_wifi_network_t    *configured = NULL;

		if (document) {
			configured = ncfg_wifi_network_for(document->networks, document->network_count,
			    &scan->ssid, scan->bssid);
		}
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "bssid", scan->bssid ? scan->bssid : "");
		ncfg_json_write_member_int(&writer, "frequency", scan->frequency);
		ncfg_json_write_member_int(&writer, "signal", scan->signal);
		ncfg_json_write_member_bool(&writer, "secured",
		    ncfg_supplicant_scan_is_secured(scan));
		ncfg_json_write_member_bool(&writer, "owe", ncfg_supplicant_scan_is_owe(scan));
		ncfg_json_write_member_bool(&writer, "enterprise",
		    ncfg_supplicant_scan_is_enterprise(scan));
		write_ssid_pair(&writer, &scan->ssid);
		/*
		 * **Asked only where the flags say fast transition.** The domain
		 * lives in `BSS <bssid>` rather than in `SCAN_RESULTS`, so it costs
		 * one round trip per access point -- and with fifty networks in range,
		 * asking every one would make a scan noticeably slower to serve
		 * something almost none of them have.
		 */
		if (ncfg_supplicant_scan_does_fast_transition(scan) && scan->bssid) {
			char command[64];
			char reply[NCFG_SUPPLICANT_REPLY_MAX];
			char domain[64];
			char ignored[NCFG_ERROR_MAX];

			if ((size_t)snprintf(command, sizeof(command), "BSS %s", scan->bssid) <
			        sizeof(command) &&
			    ncfg_supplicant_ask(client, command, reply, sizeof(reply), ignored,
			        sizeof(ignored)) &&
			    ncfg_supplicant_parse_mobility_domain(reply, domain, sizeof(domain))) {
				ncfg_json_write_member_string(&writer, "mobility_domain", domain);
			}
		}
		if (configured && configured->id) {
			ncfg_json_write_member_string(&writer, "configured", configured->id);
		}
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	if (stale) {
		ncfg_json_write_member_string(&writer, "stale", stale);
	}
	ncfg_json_write_object_end(&writer);
	ncfg_supplicant_scans_free(scans, count);
	return finish(&writer, out, "wifi_scan", err, err_size);
}

int ncfg_wifi_scan(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const ncfg_observed_t *observed, const char *interface, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_supplicant_client_t     *client;
	const ncfg_observed_rfkill_t *switched_off;
	char                          body[NCFG_SUPPLICANT_REPLY_MAX];
	char                          stale[NCFG_ERROR_MAX];
	char                          why[NCFG_ERROR_MAX];
	const char                   *reason = NULL;
	int                           listening;
	int                           done;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the scan");
		return 0;
	}
	if (!where_is_usable(where, err, err_size) ||
	    !ncfg_wifi_check_backend(document, interface, err, err_size)) {
		return 0;
	}
	client = open_control(where, interface, err, err_size);
	if (!client) {
		/* The document's answer first where it has one: it says what to change
		 * rather than what is missing. */
		if (ncfg_wifi_why_no_supplicant(where, document, interface, why, sizeof(why))) {
			ncfg_error_set(err, err_size, "%s", why);
		}
		return 0;
	}
	switched_off = blocked_switch(observed, interface);
	if (switched_off) {
		/*
		 * **A switched-off radio cannot scan, so do not ask it to.** Without
		 * this the scan is sent, the supplicant answers with a failure or
		 * nothing at all, and the report says the results are stale "because
		 * the supplicant could not scan (ret=-100)" -- a translation of
		 * ENETDOWN rather than the fact that somebody pressed the button. It
		 * also spends the full patience waiting for an event that is not
		 * coming.
		 *
		 * The cached results are still returned: they are what the radio last
		 * saw and are worth more than nothing, so long as the reason they are
		 * old is one a person can act on.
		 */
		if (!ncfg_rfkill_remedy(switched_off, stale, sizeof(stale))) {
			ncfg_error_set(stale, sizeof(stale), "the radio is switched off");
		}
		if (!ncfg_supplicant_ask(client, "SCAN_RESULTS", body, sizeof(body), why,
		        sizeof(why))) {
			body[0] = '\0';
		}
		done = scan_report(document, client, interface, body, stale, out, err, err_size);
		ncfg_supplicant_client_free(client);
		return done;
	}
	/*
	 * **Attached before `SCAN` is sent, and that order is the whole of it**
	 * (0194). The completion event only reaches connections that asked for
	 * events, and asking afterwards would race the scan finishing on a radio
	 * with little to look at.
	 *
	 * A failure to attach is not a failure to scan. What is lost is the wait
	 * below, so the old behaviour returns: results one scan out of date, said
	 * in `stale` rather than swallowed.
	 */
	listening = ncfg_supplicant_attach(client, why, sizeof(why));
	if (!listening) {
		/* `ncfg_error_set` rather than `snprintf`, because the sentence plus
		 * a full `err` is longer than one `err` and the truncation here is
		 * the deliberate kind `base.h` describes. */
		ncfg_error_set(stale, sizeof(stale),
		    "netcfgd could not listen for the scan to finish (%s), so these are the "
		    "results of the scan before it", why);
		reason = stale;
	}
	/* A scan already in progress answers FAIL. Not a failure worth reporting
	 * and not a reason to skip the wait either: a scan *is* running, and its
	 * completion event is the one being waited for. */
	(void)ncfg_supplicant_command(client, "SCAN", why, sizeof(why));
	if (listening &&
	    !ncfg_supplicant_wait_for_scan(client, NCFG_SUPPLICANT_SCAN_PATIENCE_MS, stale,
	        sizeof(stale))) {
		reason = stale;
	}
	/* **Not logged here.** The reason travels to whoever asked, in `stale`,
	 * and a scan that failed already reaches the journal through the event
	 * watcher (0192) -- which sees the same `CTRL-EVENT-SCAN-FAILED` this
	 * waited on. Logging it in both places put two nearly identical lines in
	 * the journal for one event, from two subsystems. */
	if (!ncfg_supplicant_ask(client, "SCAN_RESULTS", body, sizeof(body), why, sizeof(why))) {
		ncfg_supplicant_client_free(client);
		ncfg_error_set(err, err_size, "scan failed on `%s`: %s", interface, why);
		return 0;
	}
	done = scan_report(document, client, interface, body, reason, out, err, err_size);
	ncfg_supplicant_client_free(client);
	return done;
}

/* ------------------------------------------------------------- the status */

/*
 * The networks the supplicant has and is not trying.
 *
 * **`STATUS` cannot answer this and never could.** It describes the one
 * association the interface has, so an interface with none reads `SCANNING`
 * whether the supplicant is scanning hopefully or has given up on every
 * network it was given. `LIST_NETWORKS` is where the difference lives, in
 * flags this tree has parsed since the beginning and never read past
 * `[CURRENT]`.
 *
 * The flags are passed through rather than translated, since the caller needs
 * to tell "somebody turned this off" from "the supplicant gave up on this" --
 * and `[TEMP-DISABLED]` contains `DISABLED`, which is why one test covers
 * both.
 *
 * A failure here is not a failure of the status: the interface's state is the
 * answer to the question that was asked and this is context on top of it.
 */
static void write_not_trying(ncfg_json_writer_t *writer, ncfg_supplicant_client_t *client)
{
	ncfg_supplicant_entry_t *entries = NULL;
	size_t                   count = 0;
	size_t                   at;
	size_t                   listed = 0;
	char                     body[NCFG_SUPPLICANT_REPLY_MAX];
	char                     why[NCFG_ERROR_MAX];

	if (!ncfg_supplicant_ask(client, "LIST_NETWORKS", body, sizeof(body), why, sizeof(why))) {
		return;
	}
	if (!ncfg_supplicant_parse_network_list(body, &entries, &count, why, sizeof(why))) {
		return;
	}
	for (at = 0; at < count; at++) {
		if (!entries[at].flags || !strstr(entries[at].flags, "DISABLED")) {
			continue;
		}
		if (listed == 0) {
			/* Written only once anything is in it, which is the Rust's
			 * `skip_serializing_if`: the ordinary answer to "what is this
			 * interface doing" should not carry a list of nothing. */
			ncfg_json_write_key(writer, "not_trying");
			ncfg_json_write_array_begin(writer);
		}
		listed++;
		ncfg_json_write_object_begin(writer);
		write_ssid_pair(writer, &entries[at].ssid);
		ncfg_json_write_member_string(writer, "flags", entries[at].flags);
		ncfg_json_write_object_end(writer);
	}
	if (listed) {
		ncfg_json_write_array_end(writer);
	}
	ncfg_supplicant_entries_free(entries, count);
}

int ncfg_wifi_status(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const ncfg_observed_t *observed, const char *interface, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_json_writer_t             writer;
	ncfg_supplicant_client_t      *client;
	ncfg_supplicant_status_pair_t *pairs = NULL;
	size_t                         count = 0;
	const ncfg_observed_rfkill_t  *switched_off;
	const char                    *state;
	const char                    *bssid;
	ncfg_ssid_t                    ssid;
	int                            named = 0;
	char                           body[NCFG_SUPPLICANT_REPLY_MAX];
	char                           why[NCFG_ERROR_MAX];

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the status");
		return 0;
	}
	if (!where_is_usable(where, err, err_size)) {
		return 0;
	}
	client = open_control(where, interface, err, err_size);
	if (!client) {
		return 0;
	}
	if (!ncfg_supplicant_ask(client, "STATUS", body, sizeof(body), why, sizeof(why))) {
		ncfg_supplicant_client_free(client);
		ncfg_error_set(err, err_size, "cannot read `%s`: %s", interface, why);
		return 0;
	}
	if (!ncfg_supplicant_parse_status(body, &pairs, &count, err, err_size)) {
		ncfg_supplicant_client_free(client);
		return 0;
	}
	memset(&ssid, 0, sizeof(ssid));
	/* The supplicant reports the SSID here already decoded from its own hex,
	 * but escaped the same way as everywhere else. */
	{
		const char *raw = ncfg_supplicant_status_field(pairs, count, "ssid");

		if (raw) {
			size_t length = ncfg_supplicant_printf_decode(raw, ssid.bytes,
			    sizeof(ssid.bytes));

			if (length <= sizeof(ssid.bytes)) {
				ssid.length = length;
				ssid.has = 1;
				named = 1;
			}
		}
	}
	state = ncfg_supplicant_status_field(pairs, count, "wpa_state");
	bssid = ncfg_supplicant_status_field(pairs, count, "bssid");
	switched_off = blocked_switch(observed, interface);

	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "wifi_status");
	ncfg_json_write_member_string(&writer, "interface", interface);
	ncfg_json_write_member_string(&writer, "state", state ? state : "UNKNOWN");
	if (named) {
		write_ssid_pair(&writer, &ssid);
	}
	if (bssid) {
		ncfg_json_write_member_string(&writer, "bssid", bssid);
	}
	if (named && document) {
		/* The associated BSSID is the second half: a network identified by
		 * address rather than by name is exactly the one whose SSID cannot
		 * answer "which of my networks is this?". */
		const ncfg_wifi_network_t *network = ncfg_wifi_network_for(document->networks,
		    document->network_count, &ssid, bssid ? bssid : "");

		if (network && network->id) {
			ncfg_json_write_member_string(&writer, "network", network->id);
		}
	}
	if (switched_off) {
		/* **Asked here because this is the command somebody runs when wifi is
		 * not working**, and a kill switch is one keystroke away on any
		 * laptop. The planner has warned about this since 0062 and a plan is
		 * not what a person reaches for when the network is simply absent. */
		char remedy[NCFG_ERROR_MAX];

		if (ncfg_rfkill_remedy(switched_off, remedy, sizeof(remedy))) {
			ncfg_json_write_member_string(&writer, "blocked", remedy);
		}
	}
	write_not_trying(&writer, client);
	ncfg_json_write_object_end(&writer);
	ncfg_supplicant_status_free(pairs, count);
	ncfg_supplicant_client_free(client);
	return finish(&writer, out, "wifi_status", err, err_size);
}

/* ---------------------------------------------------------- joining, leaving */

int ncfg_wifi_connect(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const char *secrets_dir, const char *certs_dir, const char *interface, const char *wanted,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	const ncfg_wifi_network_t *network = NULL;
	const ncfg_device_t       *device;
	ncfg_supplicant_client_t  *client;
	ncfg_supplicant_entry_t   *entries = NULL;
	ncfg_secret_resolver_t     resolver;
	size_t                     count = 0;
	size_t                     at;
	uint32_t                   id = 0;
	int                        have_id = 0;
	int                        listening;
	int                        mac_policy = NCFG_MAC_POLICY_PERMANENT;
	char                       body[NCFG_SUPPLICANT_REPLY_MAX];
	char                       command[64];
	char                       why[NCFG_ERROR_MAX];

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the answer");
		return 0;
	}
	if (!where_is_usable(where, err, err_size) ||
	    !ncfg_wifi_check_backend(document, interface, err, err_size)) {
		return 0;
	}
	if (!secrets_dir || !secrets_dir[0] || !certs_dir || !certs_dir[0]) {
		ncfg_error_set(err, err_size,
		    "joining a network needs somewhere to read credentials from and somewhere to "
		    "materialise a certificate, and neither has a default here");
		return 0;
	}
	/*
	 * The lookup is what makes this mean "join one of these" rather than "join
	 * anything", and the refusal has to say so plainly or it reads as the
	 * network being missing rather than the name being unknown. Since 0124 the
	 * same caller may add a network as well, so this is no longer a permission
	 * boundary between two tiers.
	 */
	if (!document) {
		ncfg_error_set(err, err_size,
		    "no configuration is loaded, so there is nothing to join");
		return 0;
	}
	for (at = 0; at < document->network_count; at++) {
		if (document->networks[at].id && wanted &&
		    strcmp(document->networks[at].id, wanted) == 0) {
			network = &document->networks[at];
			break;
		}
	}
	if (!network) {
		ncfg_buf_t known;

		ncfg_buf_init(&known, 0);
		for (at = 0; at < document->network_count; at++) {
			if (at) {
				ncfg_buf_add_text(&known, ", ");
			}
			ncfg_buf_add_text(&known,
			    document->networks[at].id ? document->networks[at].id : "");
		}
		ncfg_error_set(err, err_size,
		    "no `network` block called `%s`. This joins networks the configuration "
		    "already describes; `ncfg wifi add` writes a new one. Configured: %s",
		    wanted ? wanted : "", document->network_count ? ncfg_buf_text(&known) : "none");
		ncfg_buf_free(&known);
		return 0;
	}
	client = open_control(where, interface, err, err_size);
	if (!client) {
		return 0;
	}
	/*
	 * Already present? The supplicant was populated at apply time, so the
	 * usual case is selecting something that is already there. Adding a second
	 * copy would leave two entries for one network and make `LIST_NETWORKS`
	 * unreadable.
	 */
	if (!ncfg_supplicant_ask(client, "LIST_NETWORKS", body, sizeof(body), why, sizeof(why))) {
		ncfg_supplicant_client_free(client);
		ncfg_error_set(err, err_size, "cannot list networks: %s", why);
		return 0;
	}
	if (!ncfg_supplicant_parse_network_list(body, &entries, &count, err, err_size)) {
		ncfg_supplicant_client_free(client);
		return 0;
	}
	/* Matched by name, and only where the document states one. A network whose
	 * name is learned from a scan has nothing to compare here, so it is always
	 * added afresh rather than matched against something with a different
	 * name. */
	if (network->ssid.has) {
		for (at = 0; at < count; at++) {
			if (entries[at].ssid.has && ssid_equal(&entries[at].ssid, &network->ssid)) {
				id = entries[at].id;
				have_id = 1;
				break;
			}
		}
	}
	ncfg_supplicant_entries_free(entries, count);
	if (!have_id) {
		/*
		 * The device's policy, or permanent. Without this a network joined
		 * from the command line would go in with a different address policy
		 * from the same network added at apply time -- quietly leaking the
		 * hardware address an apply would have hidden.
		 */
		device = device_named(document, interface);
		if (device && device->wifi) {
			mac_policy = device->wifi->mac_policy;
		}
		/*
		 * Materialising too, for the reason `netcfgd-apply` does: a network
		 * with a stored certificate has to produce a path here as well, and a
		 * resolver that could read secrets but not write a certificate would
		 * join the same network from the command line and refuse it from a
		 * connect.
		 */
		resolver.secrets_dir = secrets_dir;
		resolver.materialise_dir = certs_dir;
		if (!ncfg_supplicant_add_network(client, network, mac_policy, &resolver, &id, why,
		        sizeof(why))) {
			ncfg_supplicant_client_free(client);
			/* `why` is the supplicant module's, which quotes the redacted
			 * form of a refused command -- the one most likely to be refused
			 * is the one carrying the passphrase. */
			ncfg_error_set(err, err_size, "cannot configure `%s`: %s", wanted, why);
			return 0;
		}
	}
	/*
	 * **Attached before the join is asked for**, so the outcome cannot happen
	 * between the command and the listening. Same order and same reason as the
	 * scan (0194). A connection that could not attach still joins; what is
	 * lost is knowing whether it worked, which is said rather than swallowed.
	 */
	listening = ncfg_supplicant_attach(client, why, sizeof(why));
	/*
	 * `SELECT_NETWORK` rather than `ENABLE_NETWORK`: it disables the others,
	 * which is what "join this one" means. `ENABLE` would leave the supplicant
	 * free to pick a different network it also knows about, and the operator
	 * would have asked for one thing and got another.
	 */
	(void)snprintf(command, sizeof(command), "SELECT_NETWORK %lu", (unsigned long)id);
	if (!ncfg_supplicant_command(client, command, why, sizeof(why))) {
		ncfg_supplicant_client_free(client);
		ncfg_error_set(err, err_size, "cannot join `%s`: %s", wanted, why);
		return 0;
	}
	/*
	 * **OK to that command means the supplicant took it, not that anything
	 * joined.** Association, the key exchange and any EAP handshake all happen
	 * after it, and every way they fail arrives as an event. Returning here is
	 * what made `ncfg wifi connect` print "joining; `ncfg wifi status` says
	 * whether it worked" -- the program admitting it did not know the answer
	 * to what it had just been asked. Decision 0197.
	 */
	if (!listening) {
		ncfg_supplicant_client_free(client);
		ncfg_error_set(err, err_size,
		    "`%s` was selected on `%s`, but netcfgd could not listen for the result, so "
		    "it cannot say whether the join worked. `ncfg wifi status %s` reports what "
		    "the supplicant is doing now", wanted, interface, interface);
		return 0;
	}
	if (!ncfg_supplicant_wait_for_connect(client, NCFG_SUPPLICANT_CONNECT_PATIENCE_MS, why,
	        sizeof(why))) {
		ncfg_supplicant_client_free(client);
		ncfg_error_set(err, err_size, "`%s` did not join on `%s`: %s", wanted, interface,
		    why);
		return 0;
	}
	ncfg_supplicant_client_free(client);
	return ncfg_daemon_ok_encode(out, err, err_size);
}

int ncfg_wifi_disconnect(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const char *interface, ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_supplicant_client_t *client;
	char                      why[NCFG_ERROR_MAX];

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the answer");
		return 0;
	}
	if (!where_is_usable(where, err, err_size) ||
	    !ncfg_wifi_check_backend(document, interface, err, err_size)) {
		return 0;
	}
	client = open_control(where, interface, err, err_size);
	if (!client) {
		return 0;
	}
	/* `DISCONNECT`, not `REMOVE_NETWORK`: the network stays configured and
	 * stays in the supplicant, so reconnecting does not need the credential
	 * resolved again. It also means the next reconcile does not see a network
	 * missing and put it back, which would undo the disconnect a second
	 * later. */
	if (!ncfg_supplicant_command(client, "DISCONNECT", why, sizeof(why))) {
		ncfg_supplicant_client_free(client);
		ncfg_error_set(err, err_size, "cannot disconnect `%s`: %s", interface, why);
		return 0;
	}
	ncfg_supplicant_client_free(client);
	return ncfg_daemon_ok_encode(out, err, err_size);
}

/* ----------------------------------------------------------- the stations */

/*
 * hostapd's own `aid` space, which is the bound on the station walk.
 *
 * Bounded rather than a loop: hostapd walks its own list and terminates, but
 * this is a network daemon reading another process's answers, and a reply that
 * echoed an address back unchanged would spin for ever.
 */
#define STATION_WALK_MAX 2007

/* Whether the document's access control names this address. Answered from the
 * document rather than from hostapd, deliberately: the document is the
 * authority, and the difference between the two is the thing worth seeing. */
static int acl_lists(const ncfg_access_point_t *access_point, const char *address)
{
	size_t at;

	if (!access_point->access_control) {
		return 0;
	}
	for (at = 0; at < access_point->access_control->station_count; at++) {
		const char *listed = access_point->access_control->stations[at];

		if (listed && strcmp(listed, address) == 0) {
			return 1;
		}
	}
	return 0;
}

static void write_optional_int(ncfg_json_writer_t *writer, const char *name, ncfg_optint_t value)
{
	if (value.has) {
		ncfg_json_write_member_int(writer, name, value.value);
	}
}

int ncfg_wifi_ap_stations(const ncfg_wifi_where_t *where, const ncfg_document_t *document,
    const char *interface, ncfg_buf_t *out, char *err, size_t err_size)
{
	const ncfg_access_point_t *access_point = NULL;
	ncfg_json_writer_t         writer;
	ncfg_supplicant_client_t  *client;
	size_t                     at;
	char                       ctrl_dir[512];
	char                       command[64];
	char                       body[NCFG_SUPPLICANT_REPLY_MAX];
	char                       why[NCFG_ERROR_MAX];

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the station list");
		return 0;
	}
	if (!where_is_usable(where, err, err_size)) {
		return 0;
	}
	for (at = 0; document && at < document->access_point_count; at++) {
		const char *device = document->access_points[at].device;

		if (device && interface && strcmp(device, interface) == 0) {
			access_point = &document->access_points[at];
			break;
		}
	}
	if (!access_point) {
		/* The block's absence is the answer rather than an error about a
		 * socket: an interface with no access point on it has no stations,
		 * and saying "no control socket" would send an operator looking for a
		 * broken hostapd that was never meant to exist. */
		ncfg_error_set(err, err_size,
		    "`%s` runs no access point, so nothing is associated with it. An "
		    "`access_point` block naming `device = \"%s\"` is what would put one there",
		    interface ? interface : "", interface ? interface : "");
		return 0;
	}
	if (!ncfg_hostapd_ctrl_dir(where->run_dir, ctrl_dir, sizeof(ctrl_dir), err, err_size)) {
		return 0;
	}
	client = ncfg_supplicant_connect(ctrl_dir, interface, why, sizeof(why));
	if (!client) {
		ncfg_error_set(err, err_size, "could not list the stations on %s: %s", interface,
		    why);
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "ap_stations");
	ncfg_json_write_member_string(&writer, "interface", interface);
	ncfg_json_write_member_string(&writer, "access_point",
	    access_point->id ? access_point->id : "");
	if (access_point->access_control) {
		/* Which way the list reads, because `listed` means opposite things
		 * under the two policies and a client would otherwise have to
		 * guess. */
		ncfg_json_write_member_string(&writer, "access_control",
		    access_point->access_control->policy == NCFG_ACL_POLICY_ALLOW ? "allow"
		                                                                 : "deny");
	}
	ncfg_json_write_key(&writer, "stations");
	ncfg_json_write_array_begin(&writer);
	(void)snprintf(command, sizeof(command), "%s", "STA-FIRST");
	for (at = 0; at < STATION_WALK_MAX; at++) {
		ncfg_hostapd_station_t station;

		if (!ncfg_supplicant_ask(client, command, body, sizeof(body), why, sizeof(why))) {
			/* The walk ends on an empty reply and on `FAIL`, which is what
			 * hostapd answers for an address it does not know -- both mean
			 * "no more", and neither is an error worth showing somebody. */
			break;
		}
		if (!ncfg_hostapd_parse_station(body, &station)) {
			break;
		}
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "address", station.address);
		ncfg_json_write_member_bool(&writer, "authorized", station.authorized);
		ncfg_json_write_member_bool(&writer, "listed",
		    acl_lists(access_point, station.address));
		write_optional_int(&writer, "signal", station.signal_dbm);
		write_optional_int(&writer, "connected_seconds", station.connected_seconds);
		write_optional_int(&writer, "inactive_msec", station.inactive_msec);
		write_optional_int(&writer, "rx_bytes", station.rx_bytes);
		write_optional_int(&writer, "tx_bytes", station.tx_bytes);
		ncfg_json_write_object_end(&writer);
		if ((size_t)snprintf(command, sizeof(command), "STA-NEXT %s", station.address) >=
		    sizeof(command)) {
			break;
		}
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_object_end(&writer);
	ncfg_supplicant_client_free(client);
	return finish(&writer, out, "ap_stations", err, err_size);
}

/* ---------------------------------------------------- adding a network (0117) */

/*
 * A counted protocol string as a NUL-terminated one, refused rather than cut.
 *
 * Every string in a decoded request points into the parsed line and is not
 * terminated, and a value that did not fit would otherwise be a *different*
 * value written into somebody's configuration. NULL where the member is
 * absent, which is what the caller then reports on.
 */
static int text_of(ncfg_proto_str_t value, const char *what, char *out, size_t out_size,
    const char **result, char *err, size_t err_size)
{
	*result = NULL;
	if (!value.bytes) {
		return 1;
	}
	if (memchr(value.bytes, '\0', value.length)) {
		/*
		 * **A counted string with a NUL in it cannot become a C string
		 * without becoming a different string**, and everything below this
		 * line writes one into a configuration file. The Rust's `&str` can
		 * carry it and `usable_id` refuses it a layer down, as a control
		 * character; here it has to be refused before the value exists,
		 * because the alternative is a silent truncation nobody asked for.
		 */
		ncfg_error_set(err, err_size,
		    "the `%s` in this request has a NUL in the middle of it, which is not "
		    "something netcfgd will write into a configuration file", what);
		return 0;
	}
	if (value.length >= out_size) {
		ncfg_error_set(err, err_size,
		    "the `%s` in this request is %zu bytes, which is longer than netcfgd will "
		    "write into a configuration file", what, value.length);
		return 0;
	}
	memcpy(out, value.bytes, value.length);
	out[value.length] = '\0';
	*result = out;
	return 1;
}

/*
 * The `@secret:` reference a stored certificate name becomes.
 *
 * **The one place the socket's names turn into configuration**, and the only
 * form they can take. A request carries a *name*; the configuration written
 * from it says `@secret:<name>`, which the compiler lowers to a stored source
 * and never to a path. A caller cannot reach the path form from here because
 * there is nothing to write it in -- 0117's construction, applied to the field
 * 0117 refused to accept for exactly this reason.
 */
static int stored_reference(ncfg_proto_str_t name, const char *what, char *out, size_t out_size,
    const char **result, char *err, size_t err_size)
{
	const char *plain = NULL;
	char        scratch[192];

	*result = NULL;
	if (!name.bytes) {
		return 1;
	}
	if (!text_of(name, what, scratch, sizeof(scratch), &plain, err, err_size)) {
		return 0;
	}
	if ((size_t)snprintf(out, out_size, "@secret:%s", plain) >= out_size) {
		ncfg_error_set(err, err_size, "the `%s` in this request is too long a name", what);
		return 0;
	}
	*result = out;
	return 1;
}

/* Lowercase hex of 0 to 32 octets, which is what an SSID is on this socket. */
static int ssid_from_hex(const char *text, ncfg_ssid_t *out)
{
	size_t length = strlen(text);
	size_t at;

	memset(out, 0, sizeof(*out));
	if (length % 2u != 0u || length / 2u > NCFG_SSID_MAX_LEN) {
		return 0;
	}
	for (at = 0; at < length; at += 2u) {
		unsigned value = 0;
		size_t   half;

		for (half = 0; half < 2u; half++) {
			char     digit = text[at + half];
			unsigned nibble;

			/* **Lowercase only**: two spellings of one SSID would break the
			 * byte-identical guarantee the whole document rests on. */
			if (digit >= '0' && digit <= '9') {
				nibble = (unsigned)(digit - '0');
			} else if (digit >= 'a' && digit <= 'f') {
				nibble = (unsigned)(digit - 'a') + 10u;
			} else {
				return 0;
			}
			value = (value << 4) | nibble;
		}
		out->bytes[at / 2u] = (unsigned char)value;
	}
	out->length = length / 2u;
	out->has = 1;
	return 1;
}

int ncfg_wifi_configure_network(const ncfg_document_t *document,
    const ncfg_proto_wifi_add_t *wanted, ncfg_wifi_install_fn install, void *install_context,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_wifi_profile_t profile;
	char                ssid_text[NCFG_SUPPLICANT_SSID_HEX_SIZE];
	char                id_text[129];
	char                proto_text[32];
	char                method_text[32];
	char                identity_text[256];
	char                anonymous_text[256];
	char                phase2_text[64];
	char                ca_text[208];
	char                client_text[208];
	const char         *ssid_hex_text = NULL;
	const char         *given_id = NULL;
	size_t              at;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the answer");
		return 0;
	}
	if (!wanted) {
		ncfg_error_set(err, err_size, "there is no network to add");
		return 0;
	}
	if (!install) {
		/* **Named rather than stubbed.** `netcfgd_host::wifi_profile` writes
		 * the block, stores the credential and compiles the result back, and
		 * this port does not carry it yet; a caller with no installer must be
		 * told so rather than answered `ok` for a file nobody wrote. */
		ncfg_error_set(err, err_size,
		    "this caller was given no way to write a `network` block, so the network "
		    "cannot be added");
		return 0;
	}
	memset(&profile, 0, sizeof(profile));
	if (!text_of(wanted->ssid, "ssid", ssid_text, sizeof(ssid_text), &ssid_hex_text, err,
	        err_size) ||
	    !text_of(wanted->id, "id", id_text, sizeof(id_text), &given_id, err, err_size) ||
	    !text_of(wanted->proto, "proto", proto_text, sizeof(proto_text), &profile.proto, err,
	        err_size)) {
		return 0;
	}
	if (!ssid_hex_text || !ssid_from_hex(ssid_hex_text, &profile.ssid)) {
		ncfg_error_set(err, err_size,
		    "`%s` is not a usable ssid: it has to be lowercase hex of 0 to 32 octets, "
		    "because an ssid is not guaranteed to be text", ssid_hex_text ? ssid_hex_text
		                                                                 : "");
		return 0;
	}
	/*
	 * The label defaults to the ssid read as text, which is what an operator
	 * means by "the network's name" whenever the two coincide. Where they do
	 * not -- an ssid that is not UTF-8 -- the caller has to say, because a
	 * label is a filename and this will not invent one.
	 */
	if (given_id) {
		profile.id = given_id;
	} else if (is_text(profile.ssid.bytes, profile.ssid.length) &&
	    !memchr(profile.ssid.bytes, '\0', profile.ssid.length)) {
		/* Text **and** free of NULs, because the label becomes a C string and
		 * a filename. The Rust refuses a NUL one layer down, in `usable_id`,
		 * as a control character; taking it here means no name is ever
		 * derived that is shorter than the ssid it came from. */
		memcpy(id_text, profile.ssid.bytes, profile.ssid.length);
		id_text[profile.ssid.length] = '\0';
		profile.id = id_text;
	} else {
		ncfg_error_set(err, err_size,
		    "this ssid is not text, so it cannot be used as a name. Send an `id` as well: "
		    "the ssid itself is kept exactly, as hex");
		return 0;
	}
	/* Refused before anything is written. A second block with the same label
	 * is a compile error, which would break every interface on the machine to
	 * add one network. */
	for (at = 0; document && at < document->network_count; at++) {
		if (document->networks[at].id &&
		    strcmp(document->networks[at].id, profile.id) == 0) {
			/* `wifi_profile.h` owns the sentence, because the CLI's own
			 * path refuses the same thing and the two used to say it
			 * separately. */
			return ncfg_wifi_profile_label_taken(document->networks[at].id, err,
			    err_size);
		}
	}
	/*
	 * An enterprise network is its own shape and takes the branch before the
	 * personal one: `proto` pins a WPA generation for a passphrase and means
	 * nothing here, and saying so beats writing a network that will not join.
	 */
	if (wanted->eap.present) {
		if (profile.proto) {
			ncfg_error_set(err, err_size,
			    "a `proto` was given with an `eap` block. `proto` pins the generation "
			    "protecting a passphrase, and an enterprise network negotiates its own");
			return 0;
		}
		profile.security = NCFG_WIFI_SECURITY_EAP;
		if (!text_of(wanted->eap.method, "eap.method", method_text, sizeof(method_text),
		        &profile.method, err, err_size) ||
		    !text_of(wanted->eap.identity, "eap.identity", identity_text,
		        sizeof(identity_text), &profile.identity, err, err_size) ||
		    !text_of(wanted->eap.anonymous_identity, "eap.anonymous_identity",
		        anonymous_text, sizeof(anonymous_text), &profile.anonymous_identity, err,
		        err_size) ||
		    !text_of(wanted->eap.phase2, "eap.phase2", phase2_text, sizeof(phase2_text),
		        &profile.phase2, err, err_size) ||
		    !stored_reference(wanted->eap.ca_cert, "eap.ca_cert", ca_text, sizeof(ca_text),
		        &profile.ca_cert, err, err_size) ||
		    !stored_reference(wanted->eap.client_cert, "eap.client_cert", client_text,
		        sizeof(client_text), &profile.client_cert, err, err_size)) {
			return 0;
		}
		/* A method netcfgd does not implement, named rather than silently
		 * accepted: the supplicant would refuse the network later and say so
		 * only in its log. */
		if (!profile.method || (strcmp(profile.method, "peap") != 0 &&
		    strcmp(profile.method, "ttls") != 0 && strcmp(profile.method, "tls") != 0 &&
		    strcmp(profile.method, "pwd") != 0)) {
			ncfg_error_set(err, err_size,
			    "`%s` is not an EAP method netcfgd implements; it is peap, ttls, tls or "
			    "pwd", profile.method ? profile.method : "");
			return 0;
		}
		{
			const char *walk = profile.identity;

			while (walk && (*walk == ' ' || *walk == '\t' || *walk == '\n' ||
			    *walk == '\r' || *walk == '\f' || *walk == '\v')) {
				walk++;
			}
			if (!walk || !*walk) {
				ncfg_error_set(err, err_size,
				    "an enterprise network needs an `identity`, which is who you are "
				    "to the authentication server -- often a username, often with a "
				    "realm");
				return 0;
			}
		}
	} else if (wanted->passphrase.bytes) {
		profile.security = NCFG_WIFI_SECURITY_PSK;
	} else if (profile.proto) {
		/* An open network with a passphrase is refused rather than quietly
		 * dropping one of the two; so is a generation with nothing to pin. */
		ncfg_error_set(err, err_size,
		    "a `proto` was given with no passphrase. An open network has no generation "
		    "to pin");
		return 0;
	} else {
		profile.security = NCFG_WIFI_SECURITY_OPEN;
	}
	if (profile.proto && strcmp(profile.proto, "wpa2") != 0 &&
	    strcmp(profile.proto, "wpa3") != 0) {
		ncfg_error_set(err, err_size,
		    "`%s` is not a generation this understands; it is `wpa2` or `wpa3`, and "
		    "leaving it out negotiates both", profile.proto);
		return 0;
	}
	profile.hidden = wanted->hidden ? 1 : 0;
	if (wanted->metric.present) {
		/*
		 * **Refused here rather than at the decode**, which is where the Rust
		 * refuses it: its request type says `Option<u32>` and serde will not
		 * build one out of range, while `ncfg_proto_int_t` carries whatever
		 * integer arrived on the wire.
		 */
		if (wanted->metric.value < 0 || wanted->metric.value > 4294967295LL) {
			ncfg_error_set(err, err_size,
			    "a `metric` is a route metric, so it is 0 to 4294967295 and `%lld` is "
			    "not", (long long)wanted->metric.value);
			return 0;
		}
		profile.metric.has = 1;
		profile.metric.value = wanted->metric.value;
	}
	/* The credential is handed over by count and is never copied here: it
	 * exists in exactly one place, the decoded line, for exactly as long as
	 * that line does. */
	if (!install(install_context, &profile, wanted->passphrase.bytes,
	        wanted->passphrase.length, err, err_size)) {
		return 0;
	}
	return ncfg_daemon_ok_encode(out, err, err_size);
}
