/*
 * rescue_main.c -- `netrescue`: climb until a gateway answers, and say so.
 *
 * WHAT IT DOES
 *   0326 is the design. Every two seconds this takes the machine's Ethernet
 *   ports again, renders the document for the rung it is on, writes it where
 *   its own netcfgd reads (only when it changed, since the daemon re-applies
 *   on every write), and asks the default gateways for an echo. A rung that
 *   has had its wait with no answer gives way to the next; after the last the
 *   ladder starts again from the first, because what was missing may have
 *   been a cable somebody has plugged in since.
 *
 *   An answer holds the rung where it is. A lost answer starts the wait
 *   again at the same rung rather than at the bottom: the rung that worked is
 *   the best guess at the rung that will work again.
 *
 * THE DAEMON IS A CHILD, AND ITS DIRECTORIES ARE NETRESCUE'S
 *   `netcfgd` from this same image, on `DIR/etc`, `DIR/run`, an empty
 *   factory directory and no fuzznet store: nothing it does traces to
 *   anything but the file this writes (0326, on constraint 1). Restarted if
 *   it dies, five seconds apart, because a rescue that gave up when its one
 *   helper crashed would be the wrong program to be running unattended.
 *
 * WHAT STOPS IT
 *   A signal (TERM, INT, HUP), or `--for SECONDS` running out -- the bound a
 *   test gives it, kept in the program so that a test run by hand is bounded
 *   too. Either way the daemon is sent TERM, given ten seconds, then KILL,
 *   and waited for: netrescue does not leave a netcfgd behind.
 */
/* `struct in6_pktinfo`, which glibc and musl declare only under it. */
#define _GNU_SOURCE

#include "main_internal.h"

#include "ncfg/base.h"
#include "ncfg/log.h"
#include "ncfg/rescue.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RESCUE_TICK_SECONDS     2
#define RESCUE_RESTART_SECONDS  5
#define RESCUE_STOP_SECONDS     10
#define RESCUE_DOCUMENT_MAX     16384

typedef struct {
	const char *dir;
	const char *fallback;
	const char *sysfs;
	const char *routes;
	const char *log;
	const char *name;
	int         wait;
	int         listen;
	int         run_for;
	int         console;
} rescue_options_t;

static volatile sig_atomic_t stop_asked;

static void on_stop(int signal_number)
{
	(void)signal_number;
	stop_asked = 1;
}

static FILE *log_file;
static int   to_console;

/* One line of the report, to every place it goes: standard output, the log,
 * and the console when asked -- the person this is for may only have a
 * screen, or a BMC's serial-over-LAN. */
static void say(const char *format, ...) __attribute__((format(printf, 1, 2)));

static void say(const char *format, ...)
{
	char      line[1024];
	char      stamp[32];
	time_t    now = time(NULL);
	struct tm when;
	va_list   args;

	va_start(args, format);
	(void)vsnprintf(line, sizeof(line), format, args);
	va_end(args);
	if (!localtime_r(&now, &when) || strftime(stamp, sizeof(stamp), "%H:%M:%S", &when) == 0) {
		stamp[0] = '\0';
	}
	ncfg_out_writef("netrescue %s: %s\n", stamp, line);
	if (log_file) {
		(void)fprintf(log_file, "%s %s\n", stamp, line);
		(void)fflush(log_file);
	}
	if (to_console) {
		int fd = open("/dev/console", O_WRONLY | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);

		if (fd >= 0) {
			char whole[1100];
			int  length = snprintf(whole, sizeof(whole), "netrescue: %s\r\n", line);

			if (length > 0) {
				(void)!write(fd, whole, (size_t)length < sizeof(whole) ? (size_t)length : sizeof(whole) - 1u);
			}
			(void)close(fd);
		}
	}
}

static const char *usage(void)
{
	return "netrescue -- get this machine onto a network nobody configured\n"
	       "\n"
	       "usage:\n"
	       "  netrescue [options]\n"
	       "\n"
	       "options:\n"
	       "  --dir PATH         its own directory, default /run/netrescue\n"
	       "  --fallback CIDR    the fixed address beside DHCP, default " NCFG_RESCUE_FALLBACK_DEFAULT ";\n"
	       "                     `none` for none\n"
	       "  --wait SECONDS     how long a rung has before the next, default 30\n"
	       "  --listen SECONDS   how long the listening rung listens per port, default 15\n"
	       "  --for SECONDS      stop after this long; default never\n"
	       "  --console          say each line on /dev/console as well\n"
	       "  --log PATH         default DIR/netrescue.log\n"
	       "  --name NAME        answered to as NAME.local over mDNS, default "
	       NCFG_RESCUE_NAME_DEFAULT "\n"
	       "  --sysfs PATH       where the ports are read, default /sys/class/net\n"
	       "  --routes PATH      the route table read, default /proc/net/route\n"
	       "  -h, --help         this text\n"
	       "\n"
	       "It runs netcfgd on DIR/etc, which it writes; decision 0326 is the design.\n";
}

/* One DNS label of letters, digits and hyphens: what `NAME.local` may be. */
static int plain_label(const char *text)
{
	size_t at;

	if (!text || text[0] == '\0' || strlen(text) > 63u) {
		return 0;
	}
	for (at = 0; text[at] != '\0'; at++) {
		char c = text[at];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		    c == '-')) {
			return 0;
		}
	}
	return 1;
}

static int number(const char *text, int *out)
{
	char *end;
	long  value;

	errno = 0;
	value = strtol(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' || value <= 0 || value > 86400L * 365L) {
		return 0;
	}
	*out = (int)value;
	return 1;
}

/* 1 to run, 0 to exit with `*status`. */
static int parse(int argc, char **argv, rescue_options_t *options, int *status)
{
	int at;

	options->dir = "/run/netrescue";
	options->fallback = NCFG_RESCUE_FALLBACK_DEFAULT;
	options->sysfs = "/sys/class/net";
	options->routes = "/proc/net/route";
	options->log = NULL;
	options->name = NCFG_RESCUE_NAME_DEFAULT;
	options->wait = 30;
	options->listen = 15;
	options->run_for = 0;
	options->console = 0;
	for (at = 1; at < argc; at++) {
		const char *arg = argv[at];
		const char *value = at + 1 < argc ? argv[at + 1] : NULL;

		if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
			ncfg_out_write(usage());
			*status = NCFG_MAIN_EXIT_OK;
			return 0;
		}
		if (strcmp(arg, "--console") == 0) {
			options->console = 1;
			continue;
		}
		if (!value) {
			ncfg_out_writef("netrescue: `%s` is not an option it takes, or needs a value\n%s", arg,
			    usage());
			*status = NCFG_MAIN_EXIT_MISCALLED;
			return 0;
		}
		if (strcmp(arg, "--dir") == 0) {
			options->dir = value;
		} else if (strcmp(arg, "--fallback") == 0) {
			options->fallback = strcmp(value, "none") == 0 ? NULL : value;
		} else if (strcmp(arg, "--sysfs") == 0) {
			options->sysfs = value;
		} else if (strcmp(arg, "--routes") == 0) {
			options->routes = value;
		} else if (strcmp(arg, "--log") == 0) {
			options->log = value;
		} else if (strcmp(arg, "--name") == 0 && plain_label(value)) {
			options->name = value;
		} else if (strcmp(arg, "--listen") == 0 && number(value, &options->listen)) {
			/* taken */
		} else if (strcmp(arg, "--wait") == 0 && number(value, &options->wait)) {
			/* taken */
		} else if (strcmp(arg, "--for") == 0 && number(value, &options->run_for)) {
			/* taken */
		} else {
			ncfg_out_writef("netrescue: `%s %s` is not something it takes\n%s", arg, value, usage());
			*status = NCFG_MAIN_EXIT_MISCALLED;
			return 0;
		}
		at++;
	}
	return 1;
}

static int make_dir(const char *path)
{
	return mkdir(path, 0700) == 0 || errno == EEXIST;
}

static pid_t start_daemon(const rescue_options_t *options)
{
	char  etc[512], run[512], factory[512], socket_path[512], daemon_log[512];
	pid_t child;

	(void)snprintf(etc, sizeof(etc), "%s/etc", options->dir);
	(void)snprintf(run, sizeof(run), "%s/run", options->dir);
	(void)snprintf(factory, sizeof(factory), "%s/factory", options->dir);
	(void)snprintf(socket_path, sizeof(socket_path), "%s/run/netcfgd.sock", options->dir);
	(void)snprintf(daemon_log, sizeof(daemon_log), "%s/netcfgd.log", options->dir);
	child = fork();
	if (child == 0) {
		char *const argv[] = { (char *)"netcfgd", (char *)"--config-dir", etc, (char *)"--run-dir", run,
			(char *)"--factory-dir", factory, (char *)"--socket", socket_path,
			(char *)"--fuzznet-dir", (char *)"", NULL };
		int fd = open(daemon_log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);

		if (fd >= 0) {
			(void)dup2(fd, 1);
			(void)dup2(fd, 2);
		}
		(void)signal(SIGTERM, SIG_DFL);
		(void)signal(SIGINT, SIG_DFL);
		(void)signal(SIGHUP, SIG_DFL);
		(void)execv("/proc/self/exe", argv);
		_exit(127);
	}
	return child;
}

static void stop_daemon(pid_t child)
{
	int waited;
	int status;

	if (child <= 0) {
		return;
	}
	(void)kill(child, SIGTERM);
	for (waited = 0; waited < RESCUE_STOP_SECONDS * 10; waited++) {
		if (waitpid(child, &status, WNOHANG) == child) {
			return;
		}
		(void)usleep(100000);
	}
	(void)kill(child, SIGKILL);
	(void)waitpid(child, &status, 0);
}

/* Write `text` as `DIR/etc/netcfgd.conf`, whole or not at all: the daemon's
 * watcher may read at any moment, and half a document is a compile error in
 * its log rather than a rung. */
static int write_document(const rescue_options_t *options, const char *text)
{
	char    path[512], temporary[512];
	int     fd;
	size_t  length = strlen(text);
	ssize_t wrote;

	(void)snprintf(path, sizeof(path), "%s/etc/netcfgd.conf", options->dir);
	(void)snprintf(temporary, sizeof(temporary), "%s/etc/.netcfgd.conf.new", options->dir);
	fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0) {
		return 0;
	}
	wrote = write(fd, text, length);
	if (close(fd) != 0 || wrote < 0 || (size_t)wrote != length || rename(temporary, path) != 0) {
		(void)unlink(temporary);
		return 0;
	}
	return 1;
}

static char *read_text(const char *path)
{
	FILE  *file = fopen(path, "re");
	char  *text;
	size_t used;

	if (!file) {
		return NULL;
	}
	text = malloc(65536);
	if (!text) {
		(void)fclose(file);
		return NULL;
	}
	used = fread(text, 1, 65535, file);
	text[used] = '\0';
	(void)fclose(file);
	return text;
}

/* Which gateway answered, as text into `said`; 0 when none did. */
static int reachable(const rescue_options_t *options, char *said, size_t said_size, char *why,
    size_t why_size)
{
	uint32_t gateways[8];
	size_t   count, at;
	char    *routes = read_text(options->routes);

	why[0] = '\0';
	if (!routes) {
		(void)snprintf(why, why_size, "cannot read %s", options->routes);
		return 0;
	}
	count = ncfg_rescue_default_gateways(routes, gateways, 8);
	free(routes);
	if (count == 0u) {
		(void)snprintf(why, why_size, "no default route");
		return 0;
	}
	for (at = 0; at < count; at++) {
		struct in_addr address;
		char           err[NCFG_ERROR_MAX];

		address.s_addr = gateways[at];
		(void)inet_ntop(AF_INET, &address, said, (socklen_t)said_size);
		if (ncfg_rescue_gateway_answers(gateways[at], 1000, err, sizeof(err))) {
			return 1;
		}
		(void)snprintf(why, why_size, "%s %.180s", said, err[0] ? err : "does not answer");
	}
	return 0;
}

static void describe_ports(const ncfg_rescue_ports_t *ports, char *out, size_t size)
{
	size_t at, used = 0;

	out[0] = '\0';
	for (at = 0; at < ports->count && used < size; at++) {
		const ncfg_rescue_port_t *port = &ports->ports[at];
		int wrote = snprintf(out + used, size - used, "%s%s (%s)", at ? ", " : "", port->name,
		    port->carrier == 1 ? "carrier" : port->carrier == 0 ? "no carrier" : "down");

		if (wrote < 0) {
			break;
		}
		used += (size_t)wrote;
	}
	if (ports->count == 0u) {
		(void)snprintf(out, size, "none");
	}
}

/*
 * What listening learned, by port name, kept across ticks: the port list is
 * read again every two seconds and would otherwise forget it. A port that
 * loses its carrier loses what was learned on it -- it may be on another
 * network when it comes back.
 */
typedef struct {
	char name[NCFG_RESCUE_NAME_MAX];
	char learned[24];
	char gateway[16];
} learned_t;

static learned_t learned_ports[NCFG_RESCUE_PORT_MAX];
static size_t    learned_count;

static void apply_learned(ncfg_rescue_ports_t *ports)
{
	size_t at, kept = 0, port;

	for (at = 0; at < learned_count; at++) {
		int still = 0;

		for (port = 0; port < ports->count; port++) {
			if (strcmp(ports->ports[port].name, learned_ports[at].name) == 0 &&
			    ports->ports[port].carrier != 0) {
				memcpy(ports->ports[port].learned, learned_ports[at].learned,
				    sizeof(learned_ports[at].learned));
				memcpy(ports->ports[port].gateway, learned_ports[at].gateway,
				    sizeof(learned_ports[at].gateway));
				still = 1;
			}
		}
		if (still) {
			learned_ports[kept++] = learned_ports[at];
		} else {
			say("forgetting what was learned on %s: it is gone or lost its carrier",
			    learned_ports[at].name);
		}
	}
	learned_count = kept;
}

/* Listen on every port with a carrier and nothing learned, and keep what
 * each says. Blocking, `--listen` seconds a port: the daemon is its own
 * process and goes on meanwhile. */
static void listen_all(const rescue_options_t *options, const ncfg_rescue_ports_t *ports)
{
	static ncfg_rescue_heard_t heard[4096];
	size_t                     at;

	for (at = 0; at < ports->count && !stop_asked; at++) {
		const ncfg_rescue_port_t *port = &ports->ports[at];
		ncfg_rescue_learned_t     learned;
		uint32_t                  taken[5];
		size_t                    taken_count = 0;
		size_t                    count = 0;
		char                      err[NCFG_ERROR_MAX];
		char                      address[INET_ADDRSTRLEN], gateway[INET_ADDRSTRLEN];
		struct in_addr            value;

		if (port->carrier != 1 || port->learned[0] != '\0' ||
		    learned_count == NCFG_RESCUE_PORT_MAX) {
			continue;
		}
		say("listening on %s for %d s", port->name, options->listen);
		if (!ncfg_rescue_listen(port->name, options->listen, heard,
		        sizeof(heard) / sizeof(heard[0]), &count, err, sizeof(err))) {
			say("cannot listen on %s: %s", port->name, err);
			continue;
		}
		for (;;) {
			if (!ncfg_rescue_learn(heard, count, 3, taken, taken_count, &learned) ||
			    learned.address == 0u) {
				say("heard %zu ARP frame(s) on %s, not enough to say what network it is",
				    count, port->name);
				break;
			}
			value.s_addr = learned.address;
			(void)inet_ntop(AF_INET, &value, address, sizeof(address));
			value.s_addr = learned.gateway;
			(void)inet_ntop(AF_INET, &value, gateway, sizeof(gateway));
			if (ncfg_rescue_address_free(port->name, learned.address, 1000, err, sizeof(err))) {
				learned_t *keep = &learned_ports[learned_count++];

				(void)snprintf(keep->name, sizeof(keep->name), "%s", port->name);
				(void)snprintf(keep->learned, sizeof(keep->learned), "%s/24", address);
				(void)snprintf(keep->gateway, sizeof(keep->gateway), "%s", gateway);
				say("learned on %s: %zu frame(s) in its /24, gateway %s by traffic; "
				    "taking %s/24, which nothing answered for", port->name, learned.heard,
				    gateway, address);
				break;
			}
			if (err[0] != '\0' || taken_count == 5u) {
				say("cannot take an address on %s: %s", port->name,
				    err[0] ? err : "five in a row were in use");
				break;
			}
			say("%s is in use on %s; trying another", address, port->name);
			taken[taken_count++] = learned.address;
		}
	}
}

/*
 * Rebind the driver of every port without a carrier, then report what the
 * kernel said about those devices in the next three seconds: a firmware that
 * would not load, a reset that timed out. The log is read from where it stood
 * before the first rebind, so nothing older is blamed on it.
 */
static void rebind_all(const rescue_options_t *options, const ncfg_rescue_ports_t *ports)
{
	char   drivers[NCFG_RESCUE_PORT_MAX][64];
	char   devices[NCFG_RESCUE_PORT_MAX][64];
	size_t rebound = 0, at, said = 0;
	int    kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	int    waited;

	if (kmsg >= 0) {
		(void)lseek(kmsg, 0, SEEK_END);
	}
	for (at = 0; at < ports->count && !stop_asked; at++) {
		char err[NCFG_ERROR_MAX];

		if (ports->ports[at].carrier == 1) {
			continue;
		}
		if (!ncfg_rescue_rebind(options->sysfs, ports->ports[at].name, drivers[rebound],
		        sizeof(drivers[0]), devices[rebound], sizeof(devices[0]), err, sizeof(err))) {
			say("cannot rebind %s: %s", ports->ports[at].name, err);
			continue;
		}
		say("rebound %s: device %s unbound from %s and bound again", ports->ports[at].name,
		    devices[rebound], drivers[rebound]);
		rebound++;
	}
	if (rebound == 0u) {
		if (kmsg >= 0) {
			(void)close(kmsg);
		}
		return;
	}
	if (kmsg < 0) {
		say("the kernel log cannot be read (%s), so what the drivers said is not reported",
		    strerror(errno));
		return;
	}
	for (waited = 0; waited < 30 && !stop_asked; waited++) {
		char    record[2048];
		ssize_t got;

		while ((got = read(kmsg, record, sizeof(record) - 1u)) > 0) {
			char complaint[512];

			record[got] = '\0';
			for (at = 0; at < rebound; at++) {
				if (said < 10u && ncfg_rescue_kmsg_complaint(record, drivers[at], devices[at],
				        complaint, sizeof(complaint))) {
					say("kernel, after rebinding: %s", complaint);
					said++;
					break;
				}
			}
		}
		(void)usleep(100000);
	}
	(void)close(kmsg);
	if (said == 0u) {
		say("the kernel said nothing troubled about the rebound devices");
	}
}

/*
 * The mDNS responder: NAME.local on every port, so a laptop on a direct
 * cable finds the box without knowing which address any rung gave it.
 *
 * **IPv6 as well as IPv4, and IPv6 is the one that always works there**: a
 * link-local address is on every port from the moment it is up, where an
 * IPv4 one is only on the port the fallback is on. A query is answered on the
 * port it arrived on, with that port's own addresses -- another port's would
 * be unreachable from where the asker is. One that came from a port other
 * than 5353 is a "legacy" resolver's and is answered to it directly, with its
 * ID (RFC 6762 6.7); everything else goes to the group.
 */
typedef struct {
	int fd4;
	int fd6;
	int joined[NCFG_RESCUE_PORT_MAX];
	size_t joined_count;
} mdns_t;

static mdns_t mdns = { -1, -1, { 0 }, 0 };

static void mdns_open(void)
{
	struct sockaddr_in  any4;
	struct sockaddr_in6 any6;
	int                 on = 1, off = 0, hops = 255;

	mdns.fd4 = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	memset(&any4, 0, sizeof(any4));
	any4.sin_family = AF_INET;
	any4.sin_port = htons(NCFG_RESCUE_MDNS_PORT);
	if (mdns.fd4 >= 0 && (setsockopt(mdns.fd4, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0 ||
	    setsockopt(mdns.fd4, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) != 0 ||
	    setsockopt(mdns.fd4, IPPROTO_IP, IP_MULTICAST_TTL, &hops, sizeof(hops)) != 0 ||
	    setsockopt(mdns.fd4, IPPROTO_IP, IP_MULTICAST_LOOP, &off, sizeof(off)) != 0 ||
	    bind(mdns.fd4, (const struct sockaddr *)&any4, sizeof(any4)) != 0)) {
		say("mDNS over IPv4 is off: %s", strerror(errno));
		(void)close(mdns.fd4);
		mdns.fd4 = -1;
	}
	mdns.fd6 = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	memset(&any6, 0, sizeof(any6));
	any6.sin6_family = AF_INET6;
	any6.sin6_port = htons(NCFG_RESCUE_MDNS_PORT);
	if (mdns.fd6 >= 0 && (setsockopt(mdns.fd6, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) != 0 ||
	    setsockopt(mdns.fd6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0 ||
	    setsockopt(mdns.fd6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) != 0 ||
	    setsockopt(mdns.fd6, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) != 0 ||
	    setsockopt(mdns.fd6, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &off, sizeof(off)) != 0 ||
	    bind(mdns.fd6, (const struct sockaddr *)&any6, sizeof(any6)) != 0)) {
		say("mDNS over IPv6 is off: %s", strerror(errno));
		(void)close(mdns.fd6);
		mdns.fd6 = -1;
	}
}

static int mdns_port_index(const ncfg_rescue_ports_t *ports, int index)
{
	size_t at;

	for (at = 0; at < ports->count; at++) {
		if ((int)if_nametoindex(ports->ports[at].name) == index) {
			return 1;
		}
	}
	return 0;
}

/* Join both groups on every port not yet joined. A port that has gone and
 * come back has a new index and is joined again; a failure is tried again
 * next tick, since a link that is down cannot join. */
static void mdns_join(const ncfg_rescue_ports_t *ports)
{
	size_t at, seen;

	for (at = 0; at < ports->count; at++) {
		int index = (int)if_nametoindex(ports->ports[at].name);
		int ok = 0;

		if (index == 0 || mdns.joined_count == NCFG_RESCUE_PORT_MAX) {
			continue;
		}
		for (seen = 0; seen < mdns.joined_count && mdns.joined[seen] != index; seen++) {
		}
		if (seen < mdns.joined_count) {
			continue;
		}
		if (mdns.fd4 >= 0) {
			struct ip_mreqn group;

			memset(&group, 0, sizeof(group));
			(void)inet_pton(AF_INET, "224.0.0.251", &group.imr_multiaddr);
			group.imr_ifindex = index;
			ok |= setsockopt(mdns.fd4, IPPROTO_IP, IP_ADD_MEMBERSHIP, &group, sizeof(group)) == 0;
		}
		if (mdns.fd6 >= 0) {
			struct ipv6_mreq group;

			memset(&group, 0, sizeof(group));
			(void)inet_pton(AF_INET6, "ff02::fb", &group.ipv6mr_multiaddr);
			group.ipv6mr_interface = (unsigned)index;
			ok |= setsockopt(mdns.fd6, IPPROTO_IPV6, IPV6_JOIN_GROUP, &group, sizeof(group)) == 0;
		}
		if (ok) {
			mdns.joined[mdns.joined_count++] = index;
		}
	}
}

/* One port's own addresses, for the answer. */
static void addresses_of(int index, uint32_t *ipv4, size_t *ipv4_count, uint8_t (*ipv6)[16],
    size_t *ipv6_count)
{
	struct ifaddrs *all, *at;
	char            name[IF_NAMESIZE];

	*ipv4_count = 0;
	*ipv6_count = 0;
	if (!if_indextoname((unsigned)index, name) || getifaddrs(&all) != 0) {
		return;
	}
	for (at = all; at; at = at->ifa_next) {
		if (!at->ifa_addr || strcmp(at->ifa_name, name) != 0) {
			continue;
		}
		if (at->ifa_addr->sa_family == AF_INET && *ipv4_count < 8u) {
			ipv4[(*ipv4_count)++] = ((const struct sockaddr_in *)(const void *)at->ifa_addr)->sin_addr.s_addr;
		} else if (at->ifa_addr->sa_family == AF_INET6 && *ipv6_count < 8u) {
			memcpy(ipv6[(*ipv6_count)++],
			    &((const struct sockaddr_in6 *)(const void *)at->ifa_addr)->sin6_addr, 16);
		}
	}
	freeifaddrs(all);
}

static void mdns_answer_one(int fd, int family, const rescue_options_t *options,
    const ncfg_rescue_ports_t *ports)
{
	uint8_t                 query[1500], answer[1500];
	union {
		struct sockaddr_in  v4;
		struct sockaddr_in6 v6;
	} from;
	char                    control[256];
	struct iovec            io = { query, sizeof(query) };
	struct msghdr           message;
	struct cmsghdr         *header;
	uint32_t                ipv4[8];
	uint8_t                 ipv6[8][16];
	size_t                  ipv4_count, ipv6_count, length;
	ssize_t                 got;
	int                     index = 0;
	uint16_t                source_port;

	memset(&message, 0, sizeof(message));
	message.msg_name = &from;
	message.msg_namelen = sizeof(from);
	message.msg_iov = &io;
	message.msg_iovlen = 1;
	message.msg_control = control;
	message.msg_controllen = sizeof(control);
	got = recvmsg(fd, &message, 0);
	if (got <= 0) {
		return;
	}
	for (header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
		if (header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo info;

			memcpy(&info, CMSG_DATA(header), sizeof(info));
			index = info.ipi_ifindex;
		} else if (header->cmsg_level == IPPROTO_IPV6 && header->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo info;

			memcpy(&info, CMSG_DATA(header), sizeof(info));
			index = (int)info.ipi6_ifindex;
		}
	}
	if (index == 0 || !mdns_port_index(ports, index)) {
		return;
	}
	addresses_of(index, ipv4, &ipv4_count, ipv6, &ipv6_count);
	length = ncfg_rescue_mdns_answer(query, (size_t)got, options->name, ipv4, ipv4_count,
	    (const uint8_t (*)[16])ipv6, ipv6_count, answer, sizeof(answer));
	if (length == 0u) {
		return;
	}
	source_port = family == AF_INET ? ntohs(from.v4.sin_port) : ntohs(from.v6.sin6_port);
	if (source_port != NCFG_RESCUE_MDNS_PORT) {
		/* A legacy resolver's question, answered to it with its own ID. */
		answer[0] = query[0];
		answer[1] = query[1];
		(void)sendto(fd, answer, length, 0, (const struct sockaddr *)&from, message.msg_namelen);
		return;
	}
	if (family == AF_INET) {
		struct ip_mreqn     out;
		struct sockaddr_in  group;

		memset(&out, 0, sizeof(out));
		out.imr_ifindex = index;
		(void)setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &out, sizeof(out));
		memset(&group, 0, sizeof(group));
		group.sin_family = AF_INET;
		group.sin_port = htons(NCFG_RESCUE_MDNS_PORT);
		(void)inet_pton(AF_INET, "224.0.0.251", &group.sin_addr);
		(void)sendto(fd, answer, length, 0, (const struct sockaddr *)&group, sizeof(group));
	} else {
		struct sockaddr_in6 group;
		unsigned            out = (unsigned)index;

		(void)setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &out, sizeof(out));
		memset(&group, 0, sizeof(group));
		group.sin6_family = AF_INET6;
		group.sin6_port = htons(NCFG_RESCUE_MDNS_PORT);
		group.sin6_scope_id = (uint32_t)index;
		(void)inet_pton(AF_INET6, "ff02::fb", &group.sin6_addr);
		(void)sendto(fd, answer, length, 0, (const struct sockaddr *)&group, sizeof(group));
	}
}

/* Answer what arrives for `seconds`, which is the loop's tick: the wait
 * between two looks at the machine is spent listening rather than asleep. */
static void mdns_serve(const rescue_options_t *options, const ncfg_rescue_ports_t *ports,
    int seconds)
{
	struct pollfd wait[2];
	struct timespec start, now;
	long long       left;

	(void)clock_gettime(CLOCK_MONOTONIC, &start);
	wait[0].fd = mdns.fd4;
	wait[0].events = POLLIN;
	wait[1].fd = mdns.fd6;
	wait[1].events = POLLIN;
	for (;;) {
		(void)clock_gettime(CLOCK_MONOTONIC, &now);
		left = (long long)seconds * 1000LL - ((long long)(now.tv_sec - start.tv_sec) * 1000LL +
		    (now.tv_nsec - start.tv_nsec) / 1000000L);
		if (left <= 0 || stop_asked) {
			return;
		}
		wait[0].revents = 0;
		wait[1].revents = 0;
		if (poll(wait, 2, (int)left) <= 0) {
			continue;
		}
		if (wait[0].revents & POLLIN) {
			mdns_answer_one(mdns.fd4, AF_INET, options, ports);
		}
		if (wait[1].revents & POLLIN) {
			mdns_answer_one(mdns.fd6, AF_INET6, options, ports);
		}
	}
}

static long long now_seconds(void)
{
	struct timespec now;

	(void)clock_gettime(CLOCK_MONOTONIC, &now);
	return (long long)now.tv_sec;
}

int ncfg_main_rescue(int argc, char **argv)
{
	rescue_options_t   options;
	ncfg_rescue_ports_t ports;
	ncfg_rescue_rung_t rung = NCFG_RESCUE_RUNG_ADDRESS;
	struct sigaction   action;
	char               path[512];
	char              *document = NULL;
	char              *written = NULL;
	char               fallback_port[NCFG_RESCUE_NAME_MAX] = "";
	char               last_ports[1024] = "";
	long long          started, rung_since, restart_at = 0;
	pid_t              daemon = -1;
	int                status = NCFG_MAIN_EXIT_OK;
	int                answered = 0;
	int                wrapped = 0;
	int                listened = 0;
	int                rebound = 0;
	char               last_why[256] = "";

	if (!parse(argc, argv, &options, &status)) {
		return status;
	}
	to_console = options.console;
	(void)snprintf(path, sizeof(path), "%s/etc", options.dir);
	if (!make_dir(options.dir) || !make_dir(path)) {
		ncfg_out_writef("netrescue: cannot make `%s`: %s\n", path, strerror(errno));
		return NCFG_MAIN_EXIT_FAILED;
	}
	(void)snprintf(path, sizeof(path), "%s/run", options.dir);
	(void)make_dir(path);
	(void)snprintf(path, sizeof(path), "%s/factory", options.dir);
	(void)make_dir(path);
	if (options.log) {
		(void)snprintf(path, sizeof(path), "%s", options.log);
	} else {
		(void)snprintf(path, sizeof(path), "%s/netrescue.log", options.dir);
	}
	log_file = fopen(path, "ae");
	document = malloc(RESCUE_DOCUMENT_MAX);
	written = calloc(1, RESCUE_DOCUMENT_MAX);
	if (!document || !written) {
		ncfg_out_line("netrescue: out of memory");
		free(document);
		free(written);
		return NCFG_MAIN_EXIT_FAILED;
	}

	memset(&action, 0, sizeof(action));
	action.sa_handler = on_stop;
	(void)sigaction(SIGTERM, &action, NULL);
	(void)sigaction(SIGINT, &action, NULL);
	(void)sigaction(SIGHUP, &action, NULL);

	started = rung_since = now_seconds();
	say("started: rungs of %d s, fallback %s, directory %s, answering to %s.local",
	    options.wait, options.fallback ? options.fallback : "none", options.dir, options.name);
	mdns_open();

	while (!stop_asked) {
		char err[NCFG_ERROR_MAX];
		char gateway[64] = "";
		char why[256];
		char described[1024];
		int  fallback_at;
		int  child_status;

		if (options.run_for > 0 && now_seconds() - started >= options.run_for) {
			say("stopping: --for %d s has run out", options.run_for);
			break;
		}
		if (!ncfg_rescue_ports(options.sysfs, &ports, err, sizeof(err))) {
			say("cannot read the ports: %s", err);
			ports.count = 0;
			ports.skipped = 0;
		}
		apply_learned(&ports);
		if (rung == NCFG_RESCUE_RUNG_LISTEN && !listened) {
			listen_all(&options, &ports);
			listened = 1;
			/* The rung's wait starts once there is something to wait for:
			 * time spent listening is not time the daemon had to apply
			 * what was heard, and counting it climbed past the rung
			 * that worked. */
			rung_since = now_seconds();
			apply_learned(&ports);
		}
		describe_ports(&ports, described, sizeof(described));
		if (strcmp(described, last_ports) != 0) {
			say("ports: %s%s", described, ports.skipped ? "; and some it cannot name" : "");
			(void)snprintf(last_ports, sizeof(last_ports), "%s", described);
		}
		fallback_at = options.fallback ? ncfg_rescue_fallback_port(&ports, fallback_port) : -1;
		if (fallback_at >= 0) {
			(void)snprintf(fallback_port, sizeof(fallback_port), "%s", ports.ports[fallback_at].name);
		}
		if (!ncfg_rescue_render(&ports, rung, options.fallback, fallback_at, wrapped, document,
		        RESCUE_DOCUMENT_MAX, err, sizeof(err))) {
			say("cannot write rung %d: %s", (int)rung, err);
			status = NCFG_MAIN_EXIT_FAILED;
			break;
		}
		if (strcmp(document, written) != 0) {
			if (!write_document(&options, document)) {
				say("cannot write %s/etc/netcfgd.conf: %s", options.dir, strerror(errno));
			} else {
				memcpy(written, document, strlen(document) + 1u);
				say("rung %d: %s%s%s", (int)rung, ncfg_rescue_rung_says(rung),
				    fallback_at >= 0 ? "; fallback on " : "", fallback_at >= 0 ? fallback_port : "");
			}
		}

		/* After the rung's document is written, so the report says which
		 * rung it is before what the rung did. */
		if (rung == NCFG_RESCUE_RUNG_REBIND && !rebound) {
			rebind_all(&options, &ports);
			rebound = 1;
			rung_since = now_seconds();
		}

		if (daemon > 0 && waitpid(daemon, &child_status, WNOHANG) == daemon) {
			say("netcfgd stopped (%s %d); see %s/netcfgd.log",
			    WIFEXITED(child_status) ? "exit" : "signal",
			    WIFEXITED(child_status) ? WEXITSTATUS(child_status) : WTERMSIG(child_status),
			    options.dir);
			daemon = -1;
			restart_at = now_seconds() + RESCUE_RESTART_SECONDS;
		}
		if (daemon <= 0 && now_seconds() >= restart_at) {
			daemon = start_daemon(&options);
			if (daemon < 0) {
				say("cannot start netcfgd: %s", strerror(errno));
				restart_at = now_seconds() + RESCUE_RESTART_SECONDS;
			}
		}

		if (reachable(&options, gateway, sizeof(gateway), why, sizeof(why))) {
			if (!answered) {
				say("reachable: gateway %s answers, at rung %d", gateway, (int)rung);
			}
			answered = 1;
			rung_since = now_seconds();
		} else {
			if (answered) {
				say("lost: %s; waiting at rung %d", why, (int)rung);
			} else if (strcmp(why, last_why) != 0) {
				say("not yet: %s", why);
			}
			(void)snprintf(last_why, sizeof(last_why), "%s", why);
			answered = 0;
			if (now_seconds() - rung_since >= options.wait) {
				if (rung == NCFG_RESCUE_RUNG_LAST) {
					say("no gateway after every rung; starting again from the first");
					rung = NCFG_RESCUE_RUNG_ADDRESS;
					wrapped = 1;
					listened = 0;
					rebound = 0;
				} else {
					rung = (ncfg_rescue_rung_t)((int)rung + 1);
				}
				rung_since = now_seconds();
			}
		}
		mdns_join(&ports);
		mdns_serve(&options, &ports, RESCUE_TICK_SECONDS);
	}
	if (stop_asked) {
		say("stopping: asked to");
	}
	stop_daemon(daemon);
	if (mdns.fd4 >= 0) {
		(void)close(mdns.fd4);
	}
	if (mdns.fd6 >= 0) {
		(void)close(mdns.fd6);
	}
	free(document);
	free(written);
	if (log_file) {
		(void)fclose(log_file);
		log_file = NULL;
	}
	return status;
}
