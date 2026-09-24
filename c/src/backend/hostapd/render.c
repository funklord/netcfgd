/*
 * render.c -- an access point from the document, as a hostapd configuration.
 *
 * Pure, and deliberately so. hostapd has no way to be handed a network over its
 * control socket the way `wpa_supplicant` takes one (0015) -- the configuration
 * is a file it reads once at startup -- so **the file is the interface**, and
 * getting a key name or a value spelling wrong is the whole failure mode.
 * Keeping the rendering here means every variant can be checked on a machine
 * with no radio, and `tests/live/ap.sh` then feeds the same output to a real
 * hostapd, which parses it and says which line it dislikes.
 */
#include "ncfg/hostapd.h"

#include "../backend_internal.h"
#include "ncfg/base.h"
#include "ncfg/buf.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A generated configuration. Small by any measure -- hostapd's expressible
 * surface is a couple of dozen keys (0046) -- and bounded all the same. */
#define HOSTAPD_FILE_MAX (64u * 1024u)

/*
 * The prefix of the line that records which policy hostapd was started with.
 *
 * At column zero with no leading whitespace, because
 * `hostapd_config_read_maclist` treats a line as a comment only when its *first
 * byte* is `#`. Short because the same function reads with `fgets` into a
 * 128-byte buffer.
 */
static const char POLICY_MARKER[] = "# netcfgd policy: ";

/* The 2.4 GHz band, as hostapd spells the mode and the document spells the
 * band; and the 5 GHz one likewise. */
static const char BAND_24[] = "2.4";
static const char BAND_5[] = "5";

/* `hostapd.h`'s, now that the currency pass reads the line back and has to
 * agree with what this writes. Kept as names here so the checks below read as
 * they did. */
#define PASSPHRASE_MIN NCFG_HOSTAPD_PASSPHRASE_MIN
#define PASSPHRASE_MAX NCFG_HOSTAPD_PASSPHRASE_MAX

void ncfg_hostapd_lines_free(ncfg_hostapd_lines_t *lines)
{
	size_t at;

	if (!lines) {
		return;
	}
	for (at = 0u; at < lines->count; at++) {
		free(lines->at[at].key);
		/* The value may be a passphrase. Wiped before it is released, because
		 * a freed allocation is a freed allocation and this one was the whole
		 * reason the file is 0600. */
		if (lines->at[at].value && lines->at[at].sensitive) {
			memset(lines->at[at].value, 0, strlen(lines->at[at].value));
		}
		free(lines->at[at].value);
	}
	free(lines->at);
	memset(lines, 0, sizeof(*lines));
}

const char *ncfg_hostapd_value_of(const ncfg_hostapd_lines_t *lines, const char *key)
{
	size_t at;

	if (!lines || !key) {
		return NULL;
	}
	for (at = 0u; at < lines->count; at++) {
		if (strcmp(lines->at[at].key, key) == 0) {
			return lines->at[at].value;
		}
	}
	return NULL;
}

static int add_line(ncfg_hostapd_lines_t *lines, const char *key, const char *value, int sensitive)
{
	ncfg_hostapd_line_t *one;

	if (lines->count == lines->capacity) {
		size_t               wanted = lines->capacity ? lines->capacity * 2u : 16u;
		ncfg_hostapd_line_t *grown = realloc(lines->at, wanted * sizeof(*grown));

		if (!grown) {
			return 0;
		}
		lines->at = grown;
		lines->capacity = wanted;
	}
	one = &lines->at[lines->count];
	one->key = ncfg_backend_strdup(key);
	one->value = ncfg_backend_strdup(value);
	one->sensitive = sensitive;
	if (!one->key || !one->value) {
		free(one->key);
		free(one->value);
		return 0;
	}
	lines->count++;
	return 1;
}

static int refuse(ncfg_hostapd_unsupported_t code, ncfg_hostapd_unsupported_t *why, char *err,
    size_t err_size, const char *text)
{
	if (why) {
		*why = code;
	}
	ncfg_error_set(err, err_size, "%s", text);
	return 0;
}

const char *ncfg_hostapd_band_of_hw_mode(const char *hw_mode)
{
	if (!hw_mode) {
		return NULL;
	}
	if (strcmp(hw_mode, "g") == 0) {
		return BAND_24;
	}
	if (strcmp(hw_mode, "a") == 0) {
		return BAND_5;
	}
	return NULL;
}

/* The `hw_mode` for a band, which is hostapd's word for the same thing. */
static const char *hw_mode_of(const char *band)
{
	return strcmp(band, BAND_24) == 0 ? "g" : "a";
}

/*
 * Which band and hardware mode to operate in.
 *
 * The channel number alone is ambiguous in one direction only: 1..=14 is 2.4
 * GHz and nothing else, while the numbers above it belong to 5 GHz -- but
 * channel 6 exists in both 6 GHz and 2.4 GHz, which is exactly why the model
 * carries `band` at all. So `band` decides when it is present, the channel
 * decides when it is not, and **a channel that belongs to neither band is
 * refused either way** rather than passed to hostapd to fail on later:
 * inferring a band and skipping the check is how channel 20 would have become
 * `hw_mode=a`, a 5 GHz mode on a channel that only exists in 2.4 GHz.
 */
static int band_of(const ncfg_access_point_t *access_point, const char **band_out,
    ncfg_hostapd_unsupported_t *why, char *err, size_t err_size)
{
	const char *declared = NULL;
	const char *band;

	if (access_point->band) {
		if (strcmp(access_point->band, "6") == 0) {
			return refuse(NCFG_HOSTAPD_SIX_GIGAHERTZ, why, err, err_size,
			    "the 6 GHz band needs an operating class and HE parameters, which the "
			    "document has no fields for and which this build has never run against a "
			    "radio. Use \"2.4\" or \"5\"");
		}
		declared = ncfg_access_point_effective_band(access_point->band, NULL);
		if (!declared) {
			if (why) {
				*why = NCFG_HOSTAPD_UNKNOWN_BAND;
			}
			ncfg_error_set(err, err_size,
			    "`%s` is not a band this build knows. Use \"2.4\" or \"5\", or leave "
			    "`band` out and let the channel number say which",
			    access_point->band);
			return 0;
		}
	}
	if (!access_point->channel.has) {
		/* No channel: the band as declared, or 2.4 GHz, which every radio has
		 * and which the automatic channel selection can then choose within. */
		*band_out = declared ? declared : BAND_24;
		return 1;
	}
	band = declared ? declared : ncfg_access_point_effective_band(NULL, &access_point->channel);
	if (!ncfg_channel_in_band(band, access_point->channel.value)) {
		if (why) {
			*why = NCFG_HOSTAPD_CHANNEL_NOT_IN_BAND;
		}
		ncfg_error_set(err, err_size, "channel %lld is not in the %s GHz band",
		    (long long)access_point->channel.value, band);
		return 0;
	}
	*band_out = band;
	return 1;
}

/*
 * Whether a passphrase can go in the file at all.
 *
 * **Only two bytes are a problem, and neither is one hostapd rejects** -- they
 * end the line, so hostapd would read a *different* passphrase, or a stray key,
 * without either end noticing. `#`, spaces and quotes are all fine: hostapd
 * splits on the first `=` and takes the rest of the line verbatim, which was
 * checked against hostapd 2.10 rather than assumed.
 */
static int is_writable(const char *passphrase)
{
	size_t at;

	for (at = 0u; passphrase[at] != '\0'; at++) {
		if (passphrase[at] == '\n') {
			return 0;
		}
	}
	/* A NUL cannot be inside a C string, so the `\0` half of the rule is
	 * structural here rather than checked -- and `ncfg_secret_expose` hands
	 * back a NUL-terminated value, so a credential carrying one is already
	 * truncated before it arrives. Said out loud because the Rust checks both
	 * and a reader comparing the two would otherwise find one missing. */
	return 1;
}

/* The `wpa_*` lines for a pre-shared key network. */
static int psk_lines(ncfg_hostapd_lines_t *lines, int proto, const char *passphrase,
    ncfg_hostapd_unsupported_t *why, char *err, size_t err_size)
{
	size_t length = strlen(passphrase);

	if (!is_writable(passphrase)) {
		return refuse(NCFG_HOSTAPD_PASSPHRASE_NOT_WRITABLE, why, err, err_size,
		    "the passphrase contains a newline or NUL, which cannot go in a hostapd "
		    "configuration file -- the file is one key per line");
	}
	/*
	 * **Only the two arms that write `wpa_passphrase` are length-checked**
	 * (0205). Asked of hostapd 2.10 with 70 characters: `wpa_passphrase` gives
	 * "invalid WPA passphrase length 70 (expected 8..63)" and `sae_password` is
	 * parsed without complaint. So netcfgd was refusing a WPA3 access point
	 * hostapd would have run, and telling the operator it was WPA's rule.
	 *
	 * Transition mode keeps the limit, and that is the whole subtlety: it emits
	 * `wpa_passphrase` as well.
	 *
	 * Checked here at all so the operator hears it from netcfgd naming their
	 * `access_point` block rather than from a daemon naming a line number in a
	 * file under the run directory that netcfgd wrote.
	 */
	if (proto != NCFG_PSK_PROTO_WPA3 && (length < PASSPHRASE_MIN || length > PASSPHRASE_MAX)) {
		if (why) {
			*why = NCFG_HOSTAPD_PASSPHRASE_LENGTH;
		}
		/* The length and never the value: this sentence reaches a log. */
		ncfg_error_set(err, err_size,
		    "a `wpa_passphrase` is %u to %u octets and this one is %zu -- a character "
		    "outside ASCII counts as more than one, which is how hostapd counts it. That "
		    "limit is the field's rather than WPA's: an access point on `proto = \"wpa3\"` "
		    "alone writes `sae_password`, which hostapd does not length-check, so it would "
		    "take this one",
		    (unsigned int)PASSPHRASE_MIN, (unsigned int)PASSPHRASE_MAX, length);
		return 0;
	}

	/* `wpa=2` for all three: it selects RSN, which is what WPA2 and WPA3 both
	 * are. **WPA3 is not `wpa=3`** -- there is no such value, and the generation
	 * is carried by the key management and the management frame protection. */
	if (!add_line(lines, "wpa", "2", 0)) {
		return refuse(NCFG_HOSTAPD_OK, why, err, err_size, "out of memory rendering wpa lines");
	}
	switch (proto) {
	case NCFG_PSK_PROTO_WPA2:
		if (!add_line(lines, "wpa_key_mgmt", ncfg_psk_proto_key_mgmt(proto), 0) ||
		    !add_line(lines, "rsn_pairwise", "CCMP", 0) ||
		    !add_line(lines, "wpa_passphrase", passphrase, 1)) {
			return refuse(NCFG_HOSTAPD_OK, why, err, err_size, "out of memory rendering wpa "
			                         "lines");
		}
		break;
	case NCFG_PSK_PROTO_WPA3:
		if (!add_line(lines, "wpa_key_mgmt", ncfg_psk_proto_key_mgmt(proto), 0) ||
		    !add_line(lines, "rsn_pairwise", "CCMP", 0) ||
		    /* Management frame protection is required for WPA3, not optional. */
		    !add_line(lines, "ieee80211w", "2", 0) ||
		    !add_line(lines, "sae_password", passphrase, 1)) {
			return refuse(NCFG_HOSTAPD_OK, why, err, err_size, "out of memory rendering wpa "
			                         "lines");
		}
		break;
	case NCFG_PSK_PROTO_WPA2_WPA3:
	default:
		if (!add_line(lines, "wpa_key_mgmt", ncfg_psk_proto_key_mgmt(proto), 0) ||
		    !add_line(lines, "rsn_pairwise", "CCMP", 0) ||
		    /* Optional, because a WPA2 client cannot do it and the point of
		     * transition mode is that such a client can still associate. */
		    !add_line(lines, "ieee80211w", "1", 0) ||
		    /* But a client that negotiates SAE must use it, which is what stops
		     * transition mode being a downgrade to WPA2 for everybody. */
		    !add_line(lines, "sae_require_mfp", "1", 0) ||
		    !add_line(lines, "wpa_passphrase", passphrase, 1) ||
		    !add_line(lines, "sae_password", passphrase, 1)) {
			return refuse(NCFG_HOSTAPD_OK, why, err, err_size, "out of memory rendering wpa "
			                         "lines");
		}
		break;
	}
	return 1;
}

int ncfg_hostapd_config(const ncfg_access_point_t *access_point, const char *ctrl_dir,
    const char *passphrase, ncfg_hostapd_lines_t *out, ncfg_hostapd_unsupported_t *why, char *err,
    size_t err_size)
{
	static const char hex[] = "0123456789abcdef";
	const char       *band = BAND_24;
	char              ssid[NCFG_SSID_MAX_LEN * 2u + 1u];
	char              channel[24];
	char              acl_file[NCFG_HOSTAPD_PATH_MAX];
	size_t            at;

	if (why) {
		*why = NCFG_HOSTAPD_OK;
	}
	if (!out || !access_point || !ctrl_dir) {
		ncfg_error_set(err, err_size, "an access point was rendered with nothing to render it "
		                  "from");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!band_of(access_point, &band, why, err, err_size)) {
		return 0;
	}

	/* `ssid2` rather than `ssid`, because an SSID is 0..32 arbitrary octets
	 * (section 2.1) and `ssid=` is text. `ssid2=` takes bare hex, which is
	 * exactly what the model already holds -- verified against hostapd 2.10,
	 * which decodes the hex and then rejects 33 octets as an invalid SSID. */
	for (at = 0u; at < access_point->ssid.length && at < NCFG_SSID_MAX_LEN; at++) {
		ssid[at * 2u] = hex[access_point->ssid.bytes[at] >> 4];
		ssid[at * 2u + 1u] = hex[access_point->ssid.bytes[at] & 0x0fu];
	}
	ssid[at * 2u] = '\0';

	/* **Channel 0 is not a channel**; it asks hostapd to survey the band and
	 * pick one. That is what "absent means the implementation chooses" means
	 * here, and it beats naming a default that would put every netcfgd access
	 * point in the country on the same channel. */
	if (access_point->channel.has) {
		(void)snprintf(channel, sizeof(channel), "%lld",
		    (long long)access_point->channel.value);
	} else {
		(void)snprintf(channel, sizeof(channel), "0");
	}

	if (!add_line(out, "interface", access_point->device ? access_point->device : "", 0) ||
	    !add_line(out, "driver", "nl80211", 0) || !add_line(out, "ctrl_interface", ctrl_dir, 0) ||
	    !add_line(out, "ssid2", ssid, 0) || !add_line(out, "hw_mode", hw_mode_of(band), 0) ||
	    !add_line(out, "channel", channel, 0)) {
		ncfg_hostapd_lines_free(out);
		ncfg_error_set(err, err_size, "out of memory rendering `%s`",
		    access_point->id ? access_point->id : "");
		return 0;
	}

	if (access_point->regdom) {
		char upper[8];

		if (strlen(access_point->regdom) != 2u ||
		    !isalpha((unsigned char)access_point->regdom[0]) ||
		    !isalpha((unsigned char)access_point->regdom[1])) {
			if (why) {
				*why = NCFG_HOSTAPD_MALFORMED_REGDOM;
			}
			ncfg_error_set(err, err_size,
			    "`%s` is not a regulatory domain; it is an ISO 3166-1 alpha-2 country "
			    "code, such as \"SE\"",
			    access_point->regdom);
			ncfg_hostapd_lines_free(out);
			return 0;
		}
		upper[0] = (char)toupper((unsigned char)access_point->regdom[0]);
		upper[1] = (char)toupper((unsigned char)access_point->regdom[1]);
		upper[2] = '\0';
		/* Without `ieee80211d` the country code is recorded and not advertised,
		 * so clients never learn which regulatory domain they are in; hostapd
		 * accepts the one without the other and it is not useful.
		 *
		 * **And radar detection, without which half of 5 GHz cannot be used**
		 * (0232). hostapd documents DFS support as "required on outdoor 5 GHz
		 * channels in most countries of the world" and defaults it off; the
		 * radio on the reporting machine marks fifteen of its channels as
		 * needing it. Written in this branch and not unconditionally, because
		 * hostapd says `ieee80211h` "can be used only with ieee80211d=1" -- so
		 * the pair travels together or not at all. */
		if (!add_line(out, "country_code", upper, 0) ||
		    !add_line(out, "ieee80211d", "1", 0) || !add_line(out, "ieee80211h", "1", 0)) {
			ncfg_hostapd_lines_free(out);
			ncfg_error_set(err, err_size, "out of memory rendering the regulatory domain");
			return 0;
		}
	}

	if (access_point->hidden) {
		/* 1 rather than 2: the beacon carries an empty SSID field. Mode 2 sends
		 * a beacon whose SSID is the right length and all zeroes, which some
		 * clients handle worse and which hides nothing extra. */
		if (!add_line(out, "ignore_broadcast_ssid", "1", 0)) {
			ncfg_hostapd_lines_free(out);
			ncfg_error_set(err, err_size, "out of memory rendering a hidden network");
			return 0;
		}
	}

	if (access_point->access_control) {
		/* The list goes in its own file rather than inline, because hostapd has
		 * no inline form -- `macaddr_acl` selects which file to read. The two
		 * files are alternatives, so naming both would leave one of them
		 * silently unread. */
		int         allow = access_point->access_control->policy == NCFG_ACL_POLICY_ALLOW;
		const char *key = allow ? "accept_mac_file" : "deny_mac_file";

		(void)snprintf(acl_file, sizeof(acl_file), "%s/%s.acl", ctrl_dir,
		    access_point->device ? access_point->device : "");
		if (!add_line(out, "macaddr_acl", allow ? "1" : "0", 0) ||
		    !add_line(out, key, acl_file, 0)) {
			ncfg_hostapd_lines_free(out);
			ncfg_error_set(err, err_size, "out of memory rendering the access control list");
			return 0;
		}
	}

	switch (access_point->security.kind) {
	case NCFG_SECURITY_OPEN:
		break;
	case NCFG_SECURITY_PSK:
		if (!passphrase) {
			ncfg_hostapd_lines_free(out);
			return refuse(NCFG_HOSTAPD_MISSING_PASSPHRASE, why, err, err_size,
			    "this access point needs a passphrase and none was resolved");
		}
		if (!psk_lines(out, access_point->security.psk.proto, passphrase, why, err,
		    err_size)) {
			ncfg_hostapd_lines_free(out);
			return 0;
		}
		break;
	case NCFG_SECURITY_OWE:
		if (!add_line(out, "wpa", "2", 0) || !add_line(out, "wpa_key_mgmt",
		    ncfg_security_key_mgmt(&access_point->security), 0) ||
		    !add_line(out, "rsn_pairwise", "CCMP", 0) || !add_line(out, "ieee80211w", "2", 0)) {
			ncfg_hostapd_lines_free(out);
			ncfg_error_set(err, err_size, "out of memory rendering an OWE network");
			return 0;
		}
		break;
	case NCFG_SECURITY_EAP:
	default:
		ncfg_hostapd_lines_free(out);
		return refuse(NCFG_HOSTAPD_ENTERPRISE_NEEDS_RADIUS, why, err, err_size,
		    "an access point using EAP authenticates against a RADIUS server, and the "
		    "document has no field for one -- an `eap` block on an `access_point` describes "
		    "a client's credentials, which is the wrong end of the exchange. Use `psk` or "
		    "`owe` here");
	}
	return 1;
}

static char *render(const char *id, const ncfg_hostapd_lines_t *lines, int redact, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	size_t     at;
	char      *out;

	ncfg_buf_init(&buf, HOSTAPD_FILE_MAX);
	ncfg_buf_addf(&buf,
	    "# hostapd configuration for the `%s` access point.\n"
	    "# Written by netcfgd from /etc/netcfgd. Regenerated on every apply, so\n"
	    "# editing it changes nothing that survives.\n",
	    id ? id : "");
	for (at = 0u; lines && at < lines->count; at++) {
		ncfg_buf_addf(&buf, "%s=%s\n", lines->at[at].key,
		    (redact && lines->at[at].sensitive) ? ncfg_secret_redacted()
		                    : lines->at[at].value);
	}
	if (ncfg_buf_failed(&buf)) {
		ncfg_error_set(err, err_size,
		    "the hostapd configuration for `%s` is larger than this build will render",
		    id ? id : "");
		ncfg_buf_free(&buf);
		return NULL;
	}
	out = ncfg_buf_take(&buf, NULL);
	if (!out) {
		ncfg_error_set(err, err_size, "out of memory rendering the hostapd configuration");
	}
	ncfg_buf_free(&buf);
	return out;
}

char *ncfg_hostapd_to_file(const char *id, const ncfg_hostapd_lines_t *lines, char *err,
    size_t err_size)
{
	return render(id, lines, 0, err, err_size);
}

char *ncfg_hostapd_to_redacted(const char *id, const ncfg_hostapd_lines_t *lines, char *err,
    size_t err_size)
{
	return render(id, lines, 1, err, err_size);
}

char *ncfg_hostapd_acl_contents(const ncfg_access_control_t *access_control, char *err,
    size_t err_size)
{
	ncfg_buf_t buf;
	size_t     at;
	char      *out;

	if (!access_control) {
		ncfg_error_set(err, err_size, "a station list was rendered with no access control "
		                  "block");
		return NULL;
	}
	ncfg_buf_init(&buf, HOSTAPD_FILE_MAX);
	ncfg_buf_addf(&buf, "%s%s\n", POLICY_MARKER,
	    access_control->policy == NCFG_ACL_POLICY_ALLOW ? "allow" : "deny");
	for (at = 0u; at < access_control->station_count; at++) {
		ncfg_buf_addf(&buf, "%s\n", access_control->stations[at]);
	}
	if (ncfg_buf_failed(&buf)) {
		ncfg_error_set(err, err_size, "the station list is larger than this build will render");
		ncfg_buf_free(&buf);
		return NULL;
	}
	out = ncfg_buf_take(&buf, NULL);
	if (!out) {
		ncfg_error_set(err, err_size, "out of memory rendering the station list");
	}
	ncfg_buf_free(&buf);
	return out;
}

int ncfg_hostapd_policy_in(const char *contents, int *policy_out)
{
	size_t marker = sizeof(POLICY_MARKER) - 1u;

	while (contents != NULL && *contents != '\0') {
		const char *end = strchr(contents, '\n');
		size_t      length = end ? (size_t)(end - contents) : strlen(contents);

		/* The marker must start at byte zero of the line: an indented one is
		 * not a comment to hostapd either, since it checks byte zero, so a file
		 * like that is not one netcfgd wrote. */
		if (length > marker && strncmp(contents, POLICY_MARKER, marker) == 0) {
			const char *value = contents + marker;
			size_t      value_length = length - marker;

			while (value_length > 0u && isspace((unsigned char)value[value_length - 1u])) {
				value_length--;
			}
			while (value_length > 0u && isspace((unsigned char)value[0])) {
				value++;
				value_length--;
			}
			if (value_length == 4u && strncmp(value, "deny", 4u) == 0) {
				if (policy_out) {
					*policy_out = NCFG_ACL_POLICY_DENY;
				}
				return 1;
			}
			if (value_length == 5u && strncmp(value, "allow", 5u) == 0) {
				if (policy_out) {
					*policy_out = NCFG_ACL_POLICY_ALLOW;
				}
				return 1;
			}
			/* A marker with something else after it claims no policy. Guessing
			 * here would be guessing which list a running hostapd reads, and
			 * getting that wrong opens a network. */
			return 0;
		}
		contents = end ? end + 1u : NULL;
	}
	return 0;
}
