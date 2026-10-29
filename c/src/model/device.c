/*
 * device.c -- the radio rules three modules need and two may not ask the third.
 *
 * WHY THESE ARE IN THE MODEL AND NOT IN THE BACKEND THAT USES THEM MOST
 *   Decision 0222. Three places need to know which band an access point will
 *   come up in: the hostapd renderer, to pick a `hw_mode`; the planner, to
 *   decide whether a running access point is still in the band the document
 *   asks for; and the compiler, to refuse a channel that is in no band before
 *   the interface is up rather than after. The planner and the compiler are
 *   not allowed to ask the backend -- 0263's module order puts `model` third
 *   and the backends last, and a planner that included a backend header would
 *   invert it -- so a rule kept in the backend is a rule the other two have to
 *   get from somewhere else.
 *
 *   What that costs is not abstract. An access point whose document and whose
 *   running configuration disagree about the band is **restarted**, so two
 *   copies of this rule that drift apart is an access point stopped and
 *   started on every reconcile for a document nobody has edited. The same
 *   holds one step harder for the key management: hostapd does not report it
 *   back, so netcfgd's record of what it started with is the only account
 *   there is, and a second spelling of "WPA2" is the same restart loop.
 *
 * WHAT THIS FILE IS THE FIX FOR
 *   The port put all four rules in `hostapd.h`, public, with a note saying
 *   they would move here when the model grew them and that **a second copy
 *   appearing in the model is the failure that note exists to prevent**. The
 *   model never grew them, and the second copy appeared anyway -- as two
 *   private statics in `compile/lower_network.c`, because the compiler needed
 *   the rule and could not reach a backend to ask. So the guard was watching
 *   the one direction the copy did not come from.
 *
 *   The two copies agreed on every input either could be given, which is the
 *   part worth knowing: they were written from the same Rust within a few
 *   waves of each other, and nothing had yet asked them the one question they
 *   answer differently -- an absent channel with no band, which the hostapd
 *   copy answers `2.4` and the compiler's copy was guarded from ever being
 *   asked. A drift that has not happened yet is still two things to keep in
 *   step, and the restart loop is what it costs when they stop being.
 *
 * WHAT THE RUST SPLITS AND THIS DOES NOT
 *   `netcfgd-model` keeps the band rules in `device.rs` and the key
 *   management in `security.rs`. They are one file here because they are one
 *   decision: every word of the argument above applies to both, and the C
 *   model is a directory of files rather than a crate of modules, so a
 *   `security.c` holding one function would be a second place to look for the
 *   same reasoning.
 *
 * WHAT STAYS IN THE BACKEND
 *   `ncfg_hostapd_band_of_hw_mode`, which is hostapd's spelling of a band
 *   rather than the document's, and is what the observer reads out of a file
 *   hostapd wrote. The Rust keeps its in `netcfgd-hostapd` for the same
 *   reason. The test is whose vocabulary the function is in, not which
 *   subject it is about.
 */
#include "ncfg/document.h"
#include "ncfg/sha256.h"

#include <ctype.h>
#include <string.h>

/* The document's two spellings, named once so a comparison cannot be typed
 * wrong in one arm of a switch and right in the other. */
#define BAND_24 "2.4"
#define BAND_5  "5"

const char *ncfg_access_point_effective_band(const char *band, const ncfg_optint_t *channel)
{
	if (band) {
		if (strcmp(band, BAND_24) == 0) {
			return BAND_24;
		}
		if (strcmp(band, BAND_5) == 0) {
			return BAND_5;
		}
		/*
		 * `6` reaches here, and so does anything that got past the compiler.
		 * NULL rather than a guess, and the caller tells the two apart: "a
		 * band this build cannot render" has to stay a different answer from
		 * "not a band", because the compiler accepts `6` on purpose so that
		 * the renderer can refuse it in its own words.
		 */
		return NULL;
	}
	if (!channel || !channel->has) {
		/* Every radio has 2.4 GHz, and automatic channel selection can then
		 * choose within it. */
		return BAND_24;
	}
	return channel->value <= 14 ? BAND_24 : BAND_5;
}

/* The 40 MHz secondary on 5 GHz, or 0: the pairs inside one block of the
 * band, so that no domain allows one channel of a pair and not the other --
 * measured, hostapd refuses to start on a secondary the domain forbids
 * rather than falling back to 20 MHz. 140/144 is left out, since several
 * domains have no 144, and so is 165 and above. */
static int pair_on_5(int64_t channel)
{
	int64_t base = channel >= 149 ? channel - 1 : channel;

	if (base % 4 != 0 || !((channel >= 36 && channel <= 64) ||
	        (channel >= 100 && channel <= 136) || (channel >= 149 && channel <= 161))) {
		return 0;
	}
	return (base / 4) % 2 == 1 ? 1 : -1;
}

/* The centre of the 80 MHz block a 5 GHz channel is in, or 0. The blocks
 * every domain that has the band allows whole; 132-144 is left out with
 * 144 (10.598). */
static int block_of_80(int64_t channel)
{
	static const struct {
		int first;
		int centre;
	} blocks[] = { { 36, 42 }, { 52, 58 }, { 100, 106 }, { 116, 122 }, { 149, 155 } };
	size_t at;

	if (!pair_on_5(channel)) {
		return 0;
	}
	for (at = 0; at < sizeof(blocks) / sizeof(blocks[0]); at++) {
		if (channel >= blocks[at].first && channel <= blocks[at].first + 12) {
			return blocks[at].centre;
		}
	}
	return 0;
}

/* The centre of the 160 MHz block, or 0: 36-64 on 50 and 100-128 on 114,
 * the two the band has (10.599). */
static int block_of_160(int64_t channel)
{
	if (!pair_on_5(channel)) {
		return 0;
	}
	if (channel >= 36 && channel <= 64) {
		return 50;
	}
	if (channel >= 100 && channel <= 128) {
		return 114;
	}
	return 0;
}

/* `why` set only where nothing earlier set it, so the first reason a wider
 * width was not given is the one said. */
static void reason(const char **why, const char *sentence)
{
	if (why && !*why) {
		*why = sentence;
	}
}

void ncfg_access_point_channel_plan(const ncfg_access_point_t *access_point,
    const ncfg_radio_widths_t *radio, ncfg_channel_plan_t *out, const char **why)
{
	const char *band = ncfg_access_point_effective_band(access_point->band,
	    &access_point->channel);
	int64_t     channel = access_point->channel.has ? access_point->channel.value : 0;
	int         five;
	int64_t     width;

	memset(out, 0, sizeof(*out));
	out->width = 20;
	if (why) {
		*why = NULL;
	}
	/* A band this build cannot render, or a channel outside its band, is
	 * refused by the renderer in its own words; 20 MHz is all this says. */
	if (!radio || !band || (access_point->channel.has && access_point->channel.value != 0 &&
	        !ncfg_channel_in_band(band, access_point->channel.value))) {
		return;
	}
	five = strcmp(band, BAND_24) != 0;
	out->vht = five && radio->vht_5;
	out->he = five ? (out->vht && radio->he_5) : radio->he_24;
	width = access_point->width.has ? access_point->width.value
	                                : (five ? (out->vht ? 80 : 40) : 20);
	/*
	 * 160 MHz only when asked (10.599): both of the band's 160 MHz blocks
	 * take in radar channels, so an access point listens for a minute
	 * before it beacons -- measured, even on 36 -- and radar can move it.
	 * With no channel it is 80, since automatic selection at 160 was not
	 * measured.
	 */
	if (width == 160) {
		if (!five) {
			reason(why, "160 MHz is a 5 GHz width");
			return;
		}
		if (!out->vht || !radio->vht160_5) {
			reason(why, "the radio cannot do 160 MHz");
		} else if (channel == 0) {
			reason(why, "160 MHz needs a `channel`, in 36 to 64 or 100 to 128");
		} else if (block_of_160(channel)) {
			out->width = 160;
			out->secondary = pair_on_5(channel);
			out->centre = block_of_160(channel);
			return;
		} else {
			reason(why, "this channel is in neither 160 MHz block, 36 to 64 or 100 to 128");
		}
		width = 80;
	}
	if (width == 80) {
		if (!five) {
			reason(why, "80 MHz is a 5 GHz width");
			return;
		}
		if (!out->vht) {
			reason(why, "the radio has no 802.11ac, which 80 MHz needs");
			width = 40;
		} else if (channel == 0) {
			/* Measured: automatic selection with an 80 MHz width and no
			 * centre chooses a block, and fills the centre in. */
			out->width = 80;
			out->secondary = 1;
			return;
		} else if (block_of_80(channel)) {
			out->width = 80;
			out->secondary = pair_on_5(channel);
			out->centre = block_of_80(channel);
			return;
		} else {
			reason(why, "this channel is in no 80 MHz block every regulatory domain allows");
			width = 40;
		}
	}
	if (width != 40) {
		return;
	}
	if (!(five ? radio->forty_mhz_5 : radio->forty_mhz_24)) {
		if (why && !*why) {
			*why = "the radio cannot do 40 MHz in this band";
		}
		return;
	}
	if (!five) {
		/* Measured: [HT40+] on 1 and [HT40-] on 11 both run. Five to seven
		 * could go either way, and up is taken. With no channel the
		 * direction cannot be known before hostapd chooses one. */
		if (channel >= 1 && channel <= 7) {
			out->width = 40;
			out->secondary = 1;
		} else if (channel >= 8 && channel <= 13) {
			out->width = 40;
			out->secondary = -1;
		} else if (why) {
			*why = channel ? "channel 14 has no second channel to pair with"
			               : "40 MHz on 2.4 GHz needs a `channel`, since the second "
			                 "channel is above it or below it";
		}
		return;
	}
	/* Measured: automatic selection with [HT40+] chooses a pair. */
	if (channel == 0 || pair_on_5(channel)) {
		out->width = 40;
		out->secondary = channel ? pair_on_5(channel) : 1;
		return;
	}
	if (why && !*why) {
		*why = "this channel has no partner every regulatory domain allows";
	}
}

int ncfg_channel_in_band(const char *band, int64_t channel)
{
	if (band && strcmp(band, BAND_24) == 0) {
		return channel >= 1 && channel <= 14;
	}
	return channel >= 36 && channel <= 177;
}

int ncfg_channel_needs_radar_detection(int64_t channel)
{
	return (channel >= 52 && channel <= 64) || (channel >= 100 && channel <= 144);
}

const char *ncfg_psk_proto_key_mgmt(int proto)
{
	switch (proto) {
	case NCFG_PSK_PROTO_WPA2:
		return "WPA-PSK";
	case NCFG_PSK_PROTO_WPA3:
		return "SAE";
	case NCFG_PSK_PROTO_WPA2_WPA3:
	default:
		return "WPA-PSK SAE";
	}
}

const char *ncfg_access_point_key_mgmt(const ncfg_access_point_t *point)
{
	if (!point) {
		return NULL;
	}
	if (point->fast_roaming && point->security.kind == NCFG_SECURITY_PSK) {
		/* FT-SAE only with a key to carry SAE's keys between access points;
		 * without one an SAE client associates as it always did. */
		switch (point->security.psk.proto) {
		case NCFG_PSK_PROTO_WPA2:
			return "WPA-PSK FT-PSK";
		case NCFG_PSK_PROTO_WPA2_WPA3:
			return point->roaming_key ? "WPA-PSK FT-PSK SAE FT-SAE" : "WPA-PSK FT-PSK SAE";
		case NCFG_PSK_PROTO_WPA3:
			if (point->roaming_key) {
				return "SAE FT-SAE";
			}
			break;
		default:
			break;
		}
	}
	return ncfg_security_key_mgmt(&point->security);
}

void ncfg_access_point_mobility_domain(const ncfg_access_point_t *point,
    char out[NCFG_MOBILITY_DOMAIN_TEXT_MAX])
{
	char   digest[65];
	size_t at;

	out[0] = '\0';
	if (!point) {
		return;
	}
	if (point->mobility_domain && strlen(point->mobility_domain) == 4u) {
		for (at = 0u; at < 4u; at++) {
			out[at] = (char)tolower((unsigned char)point->mobility_domain[at]);
		}
		out[4] = '\0';
		return;
	}
	ncfg_sha256_hex(point->ssid.bytes, point->ssid.length, digest);
	(void)memcpy(out, digest, 4u);
	out[4] = '\0';
}

const char *ncfg_security_key_mgmt(const ncfg_security_t *security)
{
	if (!security) {
		return NULL;
	}
	switch (security->kind) {
	case NCFG_SECURITY_PSK:
		return ncfg_psk_proto_key_mgmt(security->psk.proto);
	case NCFG_SECURITY_OWE:
		return "OWE";
	/* An open network has no key management, and an access point using EAP is
	 * refused before anything is rendered -- the document has no RADIUS server
	 * to point it at. Neither has a spelling to compare. */
	case NCFG_SECURITY_OPEN:
	case NCFG_SECURITY_EAP:
	default:
		return NULL;
	}
}
