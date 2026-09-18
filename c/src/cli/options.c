/*
 * options.c -- the command line, walked once, and the usage it is checked
 * against.
 *
 * WHY ONE WALK
 *   There used to be three: this parser, a `positional` helper with its own
 *   list of which flags take a value, and `explain`'s own scan for the first
 *   `--`. The lists had already drifted -- `--factory-dir` and
 *   `--strand-credentials` were missing from the helper's -- so
 *   `ncfg wifi --factory-dir /some/dir scan` read the directory as a
 *   subcommand and `ncfg explain --json interface eth0` found no subject at
 *   all. One walk cannot disagree with itself.
 *
 * WHY AN UNKNOWN OPTION IS AN ERROR AND AN UNKNOWN WORD IS NOT
 *   Positional arguments belong to the subcommand: `explain` takes three,
 *   `wifi add` takes one. An unknown *option* is still refused, because a typo
 *   in a flag that is silently ignored is how somebody thinks they passed
 *   `--confirm-within` and did not.
 */
#include "ncfg/cli.h"

#include "ncfg/base.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/*
 * The usage, exactly as it is printed.
 *
 * Kept as one string rather than assembled, because it is the list every
 * command in this program is checked against: the test walks it for lines
 * beginning `ncfg ` and asserts each names a command the dispatcher knows.
 * `reload` drifted the other way for a whole milestone -- the request was in
 * the protocol, in the schema and in the authorisation table, and no shipped
 * client could send it -- because nothing compared the two lists.
 */
static const char usage_text[] =
    "ncfg -- netcfgd command line\n"
    "\n"
    "usage:\n"
    "  ncfg --version           the version, and who holds the copyright\n"
    "  ncfg plan [options]      show what would change, and change nothing\n"
    "  ncfg apply [options]     make the observed state match the config\n"
    "  ncfg status [options]    show what is currently observed\n"
    "  ncfg show [options]      print the compiled desired-state document\n"
    "  ncfg explain SUBJECT      why is it like this? SUBJECT is one of:\n"
    "                             interface NAME\n"
    "                             address   IFACE CIDR\n"
    "                             route     IFACE DEST\n"
    "  ncfg wifi SUBCOMMAND      wireless, via netcfgd. SUBCOMMAND is one of:\n"
    "                             scan       [IFACE]  list access points in range\n"
    "                             status     [IFACE]  what the radio is doing\n"
    "                             clients    [IFACE]  who is on the access point\n"
    "                             add SSID            remember a network: writes\n"
    "                                                 conf.d/wifi-ID.conf and asks\n"
    "                                                 for the credential, or reads\n"
    "                                                 it from standard input. See\n"
    "                                                 the flags below, including\n"
    "                                                 --eap for a campus or\n"
    "                                                 corporate network\n"
    "                             forget ID           take a network away, and its\n"
    "                                                 credential with it unless\n"
    "                                                 something else refers to it\n"
    "                             connect ID [IFACE]  join a configured network\n"
    "                             disconnect [IFACE]  leave it, keeping the config\n"
    "                           IFACE may be omitted when the config describes one\n"
    "                           wireless device.\n"
    "  ncfg control SUBCOMMAND  who may ask netcfgd for what. SUBCOMMAND is one of:\n"
    "                             show                what the policy is now\n"
    "                             set --observe P     change a tier; P is one of\n"
    "                                 --wifi P        root, any, user:NAME or\n"
    "                                 --admin P       group:NAME. Repeatable, and\n"
    "                                                 what is not named is left\n"
    "                                                 alone. Needs root: this is\n"
    "                                                 what grants a desktop client\n"
    "                                                 access in the first place\n"
    "  ncfg config SUBCOMMAND   configuration netcfgd stores for you. SUBCOMMAND is:\n"
    "                             put NAME [FILE]     send a drop-in; FILE or `-`\n"
    "                                                 or nothing reads standard\n"
    "                                                 input. The name is what\n"
    "                                                 netcfgd files it under, never\n"
    "                                                 a path. --replace to overwrite\n"
    "                             rm NAME             take one away\n"
    "                           netcfgd compiles the result before keeping it, so a\n"
    "                           drop-in that would break the configuration is\n"
    "                           refused with the diagnostics\n"
    "  ncfg profile SUBCOMMAND  which set of drop-ins this machine runs on top of\n"
    "                           its own configuration. SUBCOMMAND is:\n"
    "                             get                 the profile in effect, or that\n"
    "                                                 none is chosen\n"
    "                             list                the profiles this machine has,\n"
    "                                                 the chosen one marked `*`\n"
    "                             set NAME            choose one. Never automatic:\n"
    "                                                 nothing netcfgd writes for\n"
    "                                                 itself may change it\n"
    "                             save NAME           write what this machine is\n"
    "                                                 running into a profile, and\n"
    "                                                 select it. The only thing\n"
    "                                                 that writes into a profile\n"
    "                                                 directory; --replace to\n"
    "                                                 overwrite one it wrote before\n"
    "                             unset               go back to no profile chosen,\n"
    "                                                 which is the default and is\n"
    "                                                 not a profile called `none`\n"
    "  ncfg modem [status]      which SIM source each modem is on, and whether it\n"
    "                           is still waiting for its link to be cycled. Reports\n"
    "                           only: the order is the config's and the choice is\n"
    "                           netcfgd's\n"
    "  ncfg secret SUBCOMMAND   credentials the config refers to. SUBCOMMAND is:\n"
    "                             set NAME            store the value of\n"
    "                                                 `@secret:NAME`, asked for at\n"
    "                                                 the prompt with echo off, or\n"
    "                                                 read from standard input.\n"
    "                                                 Written 0600; --replace to\n"
    "                                                 overwrite an existing one.\n"
    "                                                 Removing one is `rm`\n"
    "  ncfg tui [options]       full-screen client: devices, wifi, plan, events\n"
    "  ncfg monitor [options]   stream events until interrupted (needs netcfgd)\n"
    "  ncfg confirm [options]   keep a change made under a confirm window\n"
    "  ncfg revert [options]    undo it now rather than at expiry\n"
    "  ncfg wait-online [SECONDS]\n"
    "                           block until the machine has an address and a\n"
    "                             default route, or fail after SECONDS (30 by\n"
    "                             default). What netcfgd-wait-online.service runs,\n"
    "                             so that `network-online.target` means something\n"
    "  ncfg reload [options]    re-read the config directory now, and say here\n"
    "                           whether it compiled. netcfgd notices an edit by\n"
    "                           itself; this is for when the answer belongs in your\n"
    "                           terminal rather than in the log\n"
    "  ncfg reset [--yes]       discard the writable config, leaving the factory\n"
    "                           defaults. Prints what it would remove unless --yes\n"
    "\n"
    "options:\n"
    "  --config-dir PATH        default /etc/netcfgd, or $NCFG_CONFIG_DIR\n"
    "  --factory-dir PATH       default /usr/share/netcfgd, or $NCFG_FACTORY_DIR.\n"
    "                           Read before --config-dir, which overrides it\n"
    "  --yes                    for `reset`: actually remove the files\n"
    "  --replace                for `secret set` and `profile save`: overwrite one\n"
    "                           that already exists\n"
    "  --run-dir PATH           default /run/netcfgd, or $NCFG_RUN_DIR\n"
    "  --oneshot                apply once and exit; the default, there being no\n"
    "                           daemon yet\n"
    "  --json                   machine-readable output\n"
    "  --confirm-within SECS    apply, then revert automatically unless confirmed\n"
    "                           within SECS. Needs netcfgd running, since the\n"
    "                           window has to outlive this command. A machine whose\n"
    "                           config says `global { confirm = N }` arms one\n"
    "                           without this; `--confirm-within 0` is how to say no\n"
    "                           window on such a machine\n"
    "  --restart-wedged IFACE   kill and restart a backend that is running and\n"
    "                           answering nothing on this interface (0141)\n"
    "  --allow-disruption IFACE consent to disrupting one guarded interface;\n"
    "                           repeatable, and deliberately not a blanket --force\n"
    "  --strand-credentials DEV consent to unmanaging one device while leaving a\n"
    "                           key on it that cannot be revoked; repeatable.\n"
    "                           `on_unmanage = \"clear\"` is the durable answer\n"
    "  -h, --help               this text\n"
    "\n"
    "options for `wifi add`:\n"
    "  --id LABEL               name the block this, for an SSID that is not usable\n"
    "                           as a name. The SSID itself is kept exactly, as hex\n"
    "  --open                   no security at all, and no passphrase asked for\n"
    "  --wpa2, --wpa3           pin one generation; the default negotiates both\n"
    "  --hidden                 the SSID is not broadcast, so probe for it\n"
    "  --metric N               lower wins; ranks this network against every link\n"
    "\n"
    "options for `wifi add` on an enterprise network (802.1X):\n"
    "  --eap METHOD             peap, ttls, tls or pwd. What is asked for at the\n"
    "                           prompt follows from it: a password for the first\n"
    "                           three, the private key for tls\n"
    "  --identity NAME          who you are to the authentication server, often\n"
    "                           with a realm: you@example.ac.uk\n"
    "  --anonymous-identity N   who you are outside the tunnel, which is all the\n"
    "                           radio sees. eduroam suggests anonymous@realm\n"
    "  --ca-cert PATH           the certificate the server is checked against.\n"
    "                           Without it the machine will trust any server that\n"
    "                           answers, and the compiler says so\n"
    "  --client-cert PATH       the certificate presented, for --eap tls\n"
    "  --phase2 NAME            the inner method, such as mschapv2\n"
    "\n"
    "exit codes:\n"
    "  0  the desired state was reached, or already held\n"
    "  1  an action failed, or the config did not compile\n"
    "  3  a guard refused a disruptive action; nothing else failed\n"
    "  4  the config walks away from a credential nobody can revoke, and has not\n"
    "     said whether that is meant. Nothing else failed\n";

const char *ncfg_cli_usage(void)
{
	return usage_text;
}

/*
 * The value that follows an option, or a refusal naming the option.
 *
 * `index` is advanced past the value, so the caller's loop sees the argument
 * after it. Returning NULL is the whole of the failure: every caller stops.
 */
static const char *take_value(const char *name, int count, char *const *arguments, int *index,
    char *err, size_t err_size)
{
	if (*index + 1 >= count) {
		ncfg_error_set(err, err_size, "%s needs a value", name);
		return NULL;
	}
	*index += 1;
	return arguments[*index];
}

/*
 * A count of seconds or a metric, refusing anything that is not one.
 *
 * `strtoul` on its own accepts a leading `-` and wraps it, so
 * `--metric -1` would arrive as a very strong metric rather than as a
 * refusal. The Rust parses into a `u32` and refuses the sign; this refuses it
 * by hand, and also refuses trailing text so that `--confirm-within 30s` says
 * what is wrong rather than quietly meaning 30.
 */
static int whole_number(const char *text, int64_t *out)
{
	char *end = NULL;
	unsigned long value;

	if (!text || (text[0] < '0' || text[0] > '9')) {
		return 0;
	}
	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno != 0 || !end || *end != '\0' || value > 0xffffffffUL) {
		return 0;
	}
	*out = (int64_t)value;
	return 1;
}

/* One value onto a repeatable option, or a refusal naming the flag. */
static int push(ncfg_cli_list_t *list, const char *name, const char *value, char *err,
    size_t err_size)
{
	if (list->count >= NCFG_CLI_LIST_MAX) {
		ncfg_error_set(err, err_size, "%s may be given at most %d times", name,
		    NCFG_CLI_LIST_MAX);
		return 0;
	}
	list->items[list->count++] = value;
	return 1;
}

/*
 * The EAP method, by name.
 *
 * Named here as well as in the compiler, because this is the one an operator
 * sees first and "unknown wifi key" an hour later -- after the network has
 * been written -- is not the same sentence.
 */
static const char *eap_method(const char *value)
{
	static const char *const methods[] = { "peap", "ttls", "tls", "pwd" };
	size_t at;

	for (at = 0; at < sizeof(methods) / sizeof(methods[0]); at++) {
		if (strcmp(value, methods[at]) == 0) {
			return methods[at];
		}
	}
	return NULL;
}

int ncfg_cli_parse(int count, char *const *arguments, ncfg_cli_options_t *options,
    const char **positional, size_t *positional_count, char *err, size_t err_size)
{
	int index;

	if (!options || !positional_count) {
		ncfg_error_set(err, err_size, "no options to fill in");
		return 0;
	}
	memset(options, 0, sizeof(*options));
	*positional_count = 0;
	if (count > 0 && (!arguments || !positional)) {
		ncfg_error_set(err, err_size, "no arguments to walk");
		return 0;
	}

	for (index = 0; index < count; index++) {
		const char *argument = arguments[index];
		const char *value;

		if (strcmp(argument, "--config-dir") == 0) {
			if (!(value = take_value("--config-dir", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->config_dir = value;
		} else if (strcmp(argument, "--factory-dir") == 0) {
			if (!(value = take_value("--factory-dir", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->factory_dir = value;
		} else if (strcmp(argument, "--run-dir") == 0) {
			if (!(value = take_value("--run-dir", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->run_dir = value;
		} else if (strcmp(argument, "--confirm-within") == 0) {
			int64_t seconds = 0;

			if (!(value = take_value("--confirm-within", count, arguments, &index,
			    err, err_size))) {
				return 0;
			}
			if (!whole_number(value, &seconds)) {
				ncfg_error_set(err, err_size,
				    "--confirm-within wants a number of seconds, not `%s`", value);
				return 0;
			}
			options->confirm.has = 1;
			options->confirm.value = seconds;
		} else if (strcmp(argument, "--restart-wedged") == 0) {
			if (!(value = take_value("--restart-wedged", count, arguments, &index,
			    err, err_size))) {
				return 0;
			}
			if (!push(&options->restart_wedged, "--restart-wedged", value, err,
			    err_size)) {
				return 0;
			}
		} else if (strcmp(argument, "--allow-disruption") == 0) {
			if (!(value = take_value("--allow-disruption", count, arguments, &index,
			    err, err_size))) {
				return 0;
			}
			if (!push(&options->allow_disruption, "--allow-disruption", value, err,
			    err_size)) {
				return 0;
			}
		} else if (strcmp(argument, "--strand-credentials") == 0) {
			if (!(value = take_value("--strand-credentials", count, arguments, &index,
			    err, err_size))) {
				return 0;
			}
			if (!push(&options->strand_credentials, "--strand-credentials", value, err,
			    err_size)) {
				return 0;
			}
		} else if (strcmp(argument, "--json") == 0) {
			options->json = 1;
		} else if (strcmp(argument, "--yes") == 0) {
			options->yes = 1;
		} else if (strcmp(argument, "--replace") == 0) {
			options->replace = 1;
		} else if (strcmp(argument, "--observe") == 0) {
			/*
			 * The control tiers. Named here rather than parsed inside the
			 * subcommand because this parser refuses a flag it does not know,
			 * which is what stops a mistyped one being ignored.
			 */
			if (!(value = take_value("--observe", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->control.observe = value;
		} else if (strcmp(argument, "--wifi") == 0) {
			if (!(value = take_value("--wifi", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->control.wifi = value;
		} else if (strcmp(argument, "--admin") == 0) {
			if (!(value = take_value("--admin", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->control.admin = value;
		} else if (strcmp(argument, "--id") == 0) {
			if (!(value = take_value("--id", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->wifi.id = value;
		} else if (strcmp(argument, "--metric") == 0) {
			int64_t metric = 0;

			if (!(value = take_value("--metric", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			if (!whole_number(value, &metric)) {
				ncfg_error_set(err, err_size,
				    "--metric wants a number, and lower wins, not `%s`", value);
				return 0;
			}
			options->wifi.metric.has = 1;
			options->wifi.metric.value = metric;
		} else if (strcmp(argument, "--priority") == 0) {
			/*
			 * Named rather than left to "unknown flag". Somebody's script has
			 * this in it, and the replacement runs the OTHER WAY UP -- so the
			 * one thing they must not do is pass the same number through.
			 */
			ncfg_error_set(err, err_size,
			    "--priority has been replaced by --metric, which ranks the other "
			    "way up: lower wins, and it now sets both which network to join "
			    "and how its routes rank against every other link");
			return 0;
		} else if (strcmp(argument, "--open") == 0) {
			options->wifi.open = 1;
		} else if (strcmp(argument, "--wpa2") == 0) {
			options->wifi.proto = "wpa2";
		} else if (strcmp(argument, "--wpa3") == 0) {
			options->wifi.proto = "wpa3";
		} else if (strcmp(argument, "--hidden") == 0) {
			options->wifi.hidden = 1;
		} else if (strcmp(argument, "--eap") == 0) {
			const char *method;

			if (!(value = take_value("--eap", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			if (!(method = eap_method(value))) {
				ncfg_error_set(err, err_size,
				    "`%s` is not an EAP method: one of peap, ttls, tls, pwd",
				    value);
				return 0;
			}
			options->wifi.eap = method;
		} else if (strcmp(argument, "--interface") == 0) {
			if (!(value = take_value("--interface", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->wifi.interface = value;
		} else if (strcmp(argument, "--sys-class-net") == 0) {
			if (!(value = take_value("--sys-class-net", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->sys_class_net = value;
		} else if (strcmp(argument, "--identity") == 0) {
			if (!(value = take_value("--identity", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->wifi.identity = value;
		} else if (strcmp(argument, "--anonymous-identity") == 0) {
			if (!(value = take_value("--anonymous-identity", count, arguments, &index,
			    err, err_size))) {
				return 0;
			}
			options->wifi.anonymous_identity = value;
		} else if (strcmp(argument, "--ca-cert") == 0) {
			if (!(value = take_value("--ca-cert", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->wifi.ca_cert = value;
		} else if (strcmp(argument, "--client-cert") == 0) {
			if (!(value = take_value("--client-cert", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->wifi.client_cert = value;
		} else if (strcmp(argument, "--phase2") == 0) {
			if (!(value = take_value("--phase2", count, arguments, &index, err,
			    err_size))) {
				return 0;
			}
			options->wifi.phase2 = value;
		} else if (strcmp(argument, "--oneshot") == 0) {
			/*
			 * There is no daemon yet in the port, so oneshot is the only mode
			 * there is. Accepting the flag means the command line does not change
			 * when the daemon lands.
			 */
			continue;
		} else if (strcmp(argument, "-") == 0) {
			/*
			 * **A bare `-` is a positional argument, not an option.** It is the
			 * conventional spelling of "standard input", `ncfg config put`
			 * implements it, and the help documents it. The arm below caught it
			 * first and answered `unknown option -`, so the one form the help
			 * spells out by name was the one that could not be used.
			 */
			positional[(*positional_count)++] = argument;
		} else if (argument[0] == '-') {
			ncfg_error_set(err, err_size, "unknown option `%s`", argument);
			return 0;
		} else {
			positional[(*positional_count)++] = argument;
		}
	}
	return 1;
}
