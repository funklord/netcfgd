/*
 * value_test.c -- the spellings, and the two canonical forms.
 *
 * WHY THIS EXISTS
 *   Every word below is asserted as a literal, on purpose and not as a
 *   tautology: the enum is C's and the word is the configuration language's,
 *   and nothing but a test holds the two together. A variant renamed to read
 *   better, or a word remembered instead of read, compiles a block that means
 *   something else -- which this project has done twice, writing `wire_guard`
 *   for `wireguard` and `open_vpn` for `openvpn`. Neither failed to build.
 *
 *   The other half is the canonicalisation. `2001:0DB8::/32` in a rule's
 *   `from` was torn down and reinstalled on every apply, for ever, because the
 *   comparison against what the kernel reports is a string comparison and the
 *   kernel spells it `2001:db8::/32`. That case is here by name.
 */
#include "ncfg/base.h"
#include "ncfg/value.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-58s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

static int canonical_is(const char *text, const char *want)
{
	char out[NCFG_ADDRESS_MAX];

	if (!ncfg_address_canonical(text, out, sizeof(out), NULL, 0)) {
		return 0;
	}
	return strcmp(out, want) == 0;
}

/*
 * Refused, *and* with something said.
 *
 * A failure carrying no sentence is the one base.h's convention exists to
 * prevent, and it is invisible to a test that only checks the return value.
 */
static int canonical_fails(const char *text)
{
	char out[NCFG_ADDRESS_MAX];
	char message[NCFG_ERROR_MAX];

	message[0] = '\0';
	if (ncfg_address_canonical(text, out, sizeof(out), message, sizeof(message))) {
		return 0;
	}
	return message[0] != '\0';
}

typedef int (*hardware_parse)(const char *, char *, size_t, char *, size_t);

static int hardware_is(hardware_parse parse, const char *text, const char *want)
{
	char out[NCFG_HARDWARE_ADDRESS_MAX];

	if (!parse(text, out, sizeof(out), NULL, 0)) {
		return 0;
	}
	return strcmp(out, want) == 0;
}

static int hardware_fails(hardware_parse parse, const char *text)
{
	char out[NCFG_HARDWARE_ADDRESS_MAX];
	char message[NCFG_ERROR_MAX];

	message[0] = '\0';
	if (parse(text, out, sizeof(out), message, sizeof(message))) {
		return 0;
	}
	return message[0] != '\0';
}

int main(void)
{
	/* Hook phases: `crates/netcfgd-model/src/hook.rs`, `HookPhase::name`. */
	{
		static const struct {
			ncfg_hook_phase_t value;
			const char       *word;
		} phases[] = {
			{ NCFG_HOOK_PHASE_PRE_UP,    "pre_up"    },
			{ NCFG_HOOK_PHASE_UP,        "up"        },
			{ NCFG_HOOK_PHASE_POST_UP,   "post_up"   },
			{ NCFG_HOOK_PHASE_PRE_DOWN,  "pre_down"  },
			{ NCFG_HOOK_PHASE_DOWN,      "down"      },
			{ NCFG_HOOK_PHASE_POST_DOWN, "post_down" },
			{ NCFG_HOOK_PHASE_CARRIER,   "carrier"   },
			{ NCFG_HOOK_PHASE_LEASE,     "lease"     },
			{ NCFG_HOOK_PHASE_ROAM,      "roam"      },
			{ NCFG_HOOK_PHASE_PORTAL,    "portal"    },
			{ NCFG_HOOK_PHASE_DRIFT,     "drift"     }
		};
		char message[NCFG_ERROR_MAX];
		ncfg_hook_phase_t back = NCFG_HOOK_PHASE_DRIFT;
		size_t i;
		int round_trip = 1;

		for (i = 0; i < sizeof(phases) / sizeof(phases[0]); i++) {
			const char *word = ncfg_hook_phase_name(phases[i].value);
			ncfg_hook_phase_t got = NCFG_HOOK_PHASE_DRIFT;

			if (!word || strcmp(word, phases[i].word) != 0) {
				round_trip = 0;
				continue;
			}
			if (!ncfg_hook_phase_from_name(phases[i].word, &got, NULL, 0) ||
			    got != phases[i].value) {
				round_trip = 0;
			}
		}
		check(round_trip, "every hook phase round-trips through its word");
		/* With the eleven above, this is the whole set: nothing has been
		 * added without a word and no word has been added without a test. */
		check(ncfg_hook_phase_name((ncfg_hook_phase_t)11) == NULL,
		    "and the phases stop at eleven");
		message[0] = '\0';
		check(!ncfg_hook_phase_from_name("preup", &back, message, sizeof(message)) &&
		    back == NCFG_HOOK_PHASE_DRIFT && message[0] != '\0',
		    "an unknown phase fails, saying so, and sets nothing");
		/* `on carrier` in the config; the word inside it is still `carrier`. */
		check(strcmp(ncfg_hook_phase_name(NCFG_HOOK_PHASE_CARRIER), "carrier") == 0,
		    "an `on` phase is spelled without the `on`");
	}

	/* Rule actions and families: `crates/netcfgd-model/src/rule.rs`. */
	{
		static const struct {
			ncfg_rule_action_t value;
			const char        *word;
		} actions[] = {
			{ NCFG_RULE_ACTION_LOOKUP,      "lookup"      },
			{ NCFG_RULE_ACTION_BLACKHOLE,   "blackhole"   },
			{ NCFG_RULE_ACTION_UNREACHABLE, "unreachable" },
			{ NCFG_RULE_ACTION_PROHIBIT,    "prohibit"    }
		};
		char message[NCFG_ERROR_MAX];
		ncfg_rule_action_t back = NCFG_RULE_ACTION_PROHIBIT;
		size_t i;
		int round_trip = 1;

		for (i = 0; i < sizeof(actions) / sizeof(actions[0]); i++) {
			const char *word = ncfg_rule_action_name(actions[i].value);
			ncfg_rule_action_t got = NCFG_RULE_ACTION_PROHIBIT;

			if (!word || strcmp(word, actions[i].word) != 0) {
				round_trip = 0;
				continue;
			}
			if (!ncfg_rule_action_from_name(actions[i].word, &got, NULL, 0) ||
			    got != actions[i].value) {
				round_trip = 0;
			}
		}
		check(round_trip, "every rule action round-trips through its word");
		check(ncfg_rule_action_name((ncfg_rule_action_t)4) == NULL,
		    "and the actions stop at four");
		message[0] = '\0';
		/* `lookup` is the zero value, so a word that quietly became it would
		 * install the rule in the main table and say nothing. */
		check(!ncfg_rule_action_from_name("drop", &back, message, sizeof(message)) &&
		    back == NCFG_RULE_ACTION_PROHIBIT && message[0] != '\0',
		    "an unknown action does not quietly become `lookup`");
	}

	{
		static const struct {
			ncfg_rule_family_t value;
			const char        *word;
		} families[] = {
			{ NCFG_RULE_FAMILY_INET,  "inet"  },
			{ NCFG_RULE_FAMILY_INET6, "inet6" }
		};
		char message[NCFG_ERROR_MAX];
		ncfg_rule_family_t back = NCFG_RULE_FAMILY_INET6;
		size_t i;
		int round_trip = 1;

		for (i = 0; i < sizeof(families) / sizeof(families[0]); i++) {
			const char *word = ncfg_rule_family_name(families[i].value);
			ncfg_rule_family_t got = NCFG_RULE_FAMILY_INET6;

			if (!word || strcmp(word, families[i].word) != 0) {
				round_trip = 0;
				continue;
			}
			if (!ncfg_rule_family_from_name(families[i].word, &got, NULL, 0) ||
			    got != families[i].value) {
				round_trip = 0;
			}
		}
		check(round_trip, "both rule families round-trip through their word");
		check(ncfg_rule_family_name((ncfg_rule_family_t)2) == NULL,
		    "and the families stop at two");
		message[0] = '\0';
		/* `ipv6` and `v6` are what a person writes; neither is the word. */
		check(!ncfg_rule_family_from_name("ipv6", &back, message, sizeof(message)) &&
		    back == NCFG_RULE_FAMILY_INET6 && message[0] != '\0',
		    "`ipv6` is not the spelling and is refused");
	}

	/* Bluetooth profiles: `crates/netcfgd-model/src/bluetooth.rs`. */
	{
		static const struct {
			ncfg_bluetooth_profile_t value;
			const char              *word;
		} profiles[] = {
			{ NCFG_BLUETOOTH_PROFILE_A2DP_SINK,   "a2dp-sink"   },
			{ NCFG_BLUETOOTH_PROFILE_A2DP_SOURCE, "a2dp-source" },
			{ NCFG_BLUETOOTH_PROFILE_HFP,         "hfp"         },
			{ NCFG_BLUETOOTH_PROFILE_PAN,         "pan"         },
			{ NCFG_BLUETOOTH_PROFILE_NAP,         "nap"         }
		};
		char message[NCFG_ERROR_MAX];
		ncfg_bluetooth_profile_t back = NCFG_BLUETOOTH_PROFILE_NAP;
		size_t i;
		int round_trip = 1;

		for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++) {
			const char *word = ncfg_bluetooth_profile_name(profiles[i].value);
			ncfg_bluetooth_profile_t got = NCFG_BLUETOOTH_PROFILE_NAP;

			if (!word || strcmp(word, profiles[i].word) != 0) {
				round_trip = 0;
				continue;
			}
			if (!ncfg_bluetooth_profile_from_name(profiles[i].word, &got, NULL, 0) ||
			    got != profiles[i].value) {
				round_trip = 0;
			}
		}
		check(round_trip, "every bluetooth profile round-trips through its word");
		check(ncfg_bluetooth_profile_name((ncfg_bluetooth_profile_t)5) == NULL,
		    "and the profiles stop at five");
		message[0] = '\0';
		/* The one kebab-cased set in the language, so the underscored
		 * spelling is the mistake that will actually be made. */
		check(!ncfg_bluetooth_profile_from_name("a2dp_sink", &back, message,
		    sizeof(message)) && back == NCFG_BLUETOOTH_PROFILE_NAP && message[0] != '\0',
		    "`a2dp_sink` is not the spelling: these are kebab-cased");
	}

	/* Drift policy: `DriftPolicy` in `crates/netcfgd-model/src/lib.rs`. */
	{
		static const struct {
			ncfg_drift_policy_t value;
			const char         *word;
		} policies[] = {
			{ NCFG_DRIFT_POLICY_REPORT,    "report"    },
			{ NCFG_DRIFT_POLICY_RECONCILE, "reconcile" },
			{ NCFG_DRIFT_POLICY_IGNORE,    "ignore"    }
		};
		char message[NCFG_ERROR_MAX];
		ncfg_drift_policy_t back = NCFG_DRIFT_POLICY_IGNORE;
		size_t i;
		int round_trip = 1;

		for (i = 0; i < sizeof(policies) / sizeof(policies[0]); i++) {
			const char *word = ncfg_drift_policy_name(policies[i].value);
			ncfg_drift_policy_t got = NCFG_DRIFT_POLICY_IGNORE;

			if (!word || strcmp(word, policies[i].word) != 0) {
				round_trip = 0;
				continue;
			}
			if (!ncfg_drift_policy_from_name(policies[i].word, &got, NULL, 0) ||
			    got != policies[i].value) {
				round_trip = 0;
			}
		}
		check(round_trip, "every drift policy round-trips through its word");
		check(ncfg_drift_policy_name((ncfg_drift_policy_t)3) == NULL,
		    "and the policies stop at three");
		message[0] = '\0';
		check(!ncfg_drift_policy_from_name("repair", &back, message, sizeof(message)) &&
		    back == NCFG_DRIFT_POLICY_IGNORE && message[0] != '\0',
		    "an unknown drift policy fails and sets nothing");
	}

	/* DNS modes: `crates/netcfgd-model/src/dns.rs`, `DnsMode::name`. */
	{
		static const struct {
			ncfg_dns_mode_t value;
			const char     *word;
		} modes[] = {
			{ NCFG_DNS_MODE_NONE,              "none"              },
			{ NCFG_DNS_MODE_WRITE_RESOLV_CONF, "write_resolv_conf" },
			{ NCFG_DNS_MODE_RESOLVCONF,        "resolvconf"        },
			{ NCFG_DNS_MODE_OPENRESOLV,        "openresolv"        },
			{ NCFG_DNS_MODE_RESOLVED,          "resolved"          },
			{ NCFG_DNS_MODE_DNSMASQ,           "dnsmasq"           },
			{ NCFG_DNS_MODE_UNBOUND,           "unbound"           },
			{ NCFG_DNS_MODE_EXEC,              "exec"              }
		};
		char message[NCFG_ERROR_MAX];
		ncfg_dns_mode_t back = NCFG_DNS_MODE_EXEC;
		size_t i;
		int round_trip = 1;

		for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
			const char *word = ncfg_dns_mode_name(modes[i].value);
			ncfg_dns_mode_t got = NCFG_DNS_MODE_EXEC;

			if (!word || strcmp(word, modes[i].word) != 0) {
				round_trip = 0;
				continue;
			}
			if (!ncfg_dns_mode_from_name(modes[i].word, &got, NULL, 0) ||
			    got != modes[i].value) {
				round_trip = 0;
			}
		}
		check(round_trip, "every dns mode round-trips through its word");
		check(ncfg_dns_mode_name((ncfg_dns_mode_t)8) == NULL, "and the modes stop at eight");
		/* `resolvconf` and `resolved` are different tools and adjacent
		 * words, which is the pair worth pinning rather than asserting in
		 * general that a table is a table. */
		check(strcmp(ncfg_dns_mode_name(NCFG_DNS_MODE_RESOLVCONF), "resolvconf") == 0 &&
		    strcmp(ncfg_dns_mode_name(NCFG_DNS_MODE_RESOLVED), "resolved") == 0,
		    "`resolvconf` and `resolved` are two modes, not one");
		back = NCFG_DNS_MODE_EXEC;
		check(ncfg_dns_mode_from_name("resolv.conf", &back, NULL, 0) &&
		    back == NCFG_DNS_MODE_WRITE_RESOLV_CONF,
		    "the file's own name is the alias `lower.rs` takes");
		back = NCFG_DNS_MODE_EXEC;
		message[0] = '\0';
		check(!ncfg_dns_mode_from_name("systemd-resolved", &back, message,
		    sizeof(message)) && back == NCFG_DNS_MODE_EXEC && message[0] != '\0',
		    "an unknown dns mode does not quietly become `none`");
	}

	/*
	 * **The case this module was split out for.** A rule's `from` written in
	 * the operator's spelling was compared against the kernel's as a string,
	 * matched nothing, and was deleted and reinstalled on every apply.
	 */
	{
		check(canonical_is("2001:0DB8::/32", "2001:db8::/32"),
		    "`2001:0DB8::/32` is the kernel's `2001:db8::/32`");
		check(canonical_is("2001:0db8::1/64", "2001:db8::1/64"),
		    "a leading zero in an address goes the same way");
		check(canonical_is("2001:db8::/32", "2001:db8::/32"),
		    "and the canonical form is already a fixed point");
		check(canonical_is("192.0.2.10/24", "192.0.2.10/24"), "IPv4 passes through as written");
		/* A bare address is not a `/32`: a rule's `from` takes either, and the
		 * kernel prints a bare one back unchanged. */
		check(canonical_is("2001:0DB8::1", "2001:db8::1") &&
		    canonical_is("192.0.2.10", "192.0.2.10"),
		    "a bare address stays bare rather than gaining a prefix");
		check(canonical_is("192.0.2.10/024", "192.0.2.10/24"),
		    "a leading zero in a prefix length reads as the number");
	}

	{
		check(canonical_fails("192.0.2.10/33"), "a /33 is not an IPv4 prefix length");
		check(canonical_fails("2001:db8::/129"), "nor a /129 an IPv6 one");
		check(canonical_fails("192.0.2.10 and more"), "rubbish after an address is refused");
		check(canonical_fails("192.0.2.10/24junk"), "and rubbish after a prefix length");
		check(canonical_fails(""), "an empty string is not an address");
		check(canonical_fails("192.0.2.10/"), "nor an address with a slash and nothing after");
		check(canonical_fails("192.0.2.300"), "nor four numbers that are not octets");
	}

	/*
	 * The two hardware-address readers. The strict one is the configuration
	 * language's and the forgiving one is the editor's, and the difference
	 * between them is deliberate rather than an oversight in either.
	 */
	{
		check(hardware_is(ncfg_hardware_address_strict, "aa:bb:cc:dd:ee:ff",
		    "AA:BB:CC:DD:EE:FF"),
		    "the language takes colons, and uppercases");
		check(hardware_is(ncfg_hardware_address_typed, "AA:BB:CC:DD:EE:FF",
		    "AA:BB:CC:DD:EE:FF") &&
		    hardware_is(ncfg_hardware_address_typed, "aa-bb-cc-dd-ee-ff",
		    "AA:BB:CC:DD:EE:FF") &&
		    hardware_is(ncfg_hardware_address_typed, "aabbccddeeff",
		    "AA:BB:CC:DD:EE:FF"),
		    "the editor takes colons, dashes or neither");
		check(hardware_is(ncfg_hardware_address_typed, "  AA:BB:CC:DD:EE:FF  ",
		    "AA:BB:CC:DD:EE:FF"),
		    "and what a paste left around it");
		/* The whole of the difference: what an editor forgives, the
		 * language does not, so a document never grows a spelling nobody
		 * decided on. */
		check(hardware_fails(ncfg_hardware_address_strict, "aa-bb-cc-dd-ee-ff") &&
		    hardware_fails(ncfg_hardware_address_strict, "aabbccddeeff"),
		    "while the language refuses both of those");
	}

	{
		hardware_parse both[] = { ncfg_hardware_address_strict,
			ncfg_hardware_address_typed };
		size_t i;
		int refused = 1;

		for (i = 0; i < sizeof(both) / sizeof(both[0]); i++) {
			if (!hardware_fails(both[i], "AA:BB:CC:DD:EE") ||
			    !hardware_fails(both[i], "AA:BB:CC:DD:EE:FF:00") ||
			    !hardware_fails(both[i], "AA:BB:CC:DD:EE:GG") ||
			    !hardware_fails(both[i], "")) {
				refused = 0;
			}
		}
		check(refused, "five octets, seven, a non-hex digit and none: all refused");
	}

	if (failures == 0) {
		printf("value_test: all checks passed\n");
	} else {
		printf("value_test: %d check(s) failed\n", failures);
	}
	return failures == 0 ? 0 : 1;
}
