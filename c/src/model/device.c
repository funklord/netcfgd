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
