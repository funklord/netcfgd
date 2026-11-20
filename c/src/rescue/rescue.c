/*
 * rescue.c -- netrescue's ports, documents and gateways. `rescue.h` says what
 * each part is for; 0326 says why a rung is a document.
 */
#include "ncfg/rescue.h"

#include "ncfg/base.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

const char *ncfg_rescue_rung_says(ncfg_rescue_rung_t rung)
{
	switch (rung) {
	case NCFG_RESCUE_RUNG_ADDRESS:
		return "DHCP on every Ethernet port, and the fixed fallback address on one";
	case NCFG_RESCUE_RUNG_LISTEN:
		return "the same, and an address learned by listening on ports with a carrier and no lease";
	case NCFG_RESCUE_RUNG_FORCE_1000:
		return "the same, with ports that have no carrier forced to 1000/full";
	case NCFG_RESCUE_RUNG_FORCE_100:
		return "the same, with ports that have no carrier forced to 100/full";
	case NCFG_RESCUE_RUNG_REBIND:
		return "the same, and the driver of each port still without a carrier bound again";
	}
	return "an unknown rung";
}

/* ---------------------------------------------------------------- ports */

/* The first line of a small sysfs file, without its newline. 0 when it cannot
 * be read, which for `carrier` is the normal answer on a link that is down. */
static int read_small(const char *dir, const char *name, const char *leaf, char *out, size_t size)
{
	char    path[512];
	int     fd;
	ssize_t got;

	if (snprintf(path, sizeof(path), "%s/%s/%s", dir, name, leaf) >= (int)sizeof(path)) {
		return 0;
	}
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) {
		return 0;
	}
	got = read(fd, out, size - 1u);
	(void)close(fd);
	if (got <= 0) {
		return 0;
	}
	out[got] = '\0';
	out[strcspn(out, "\n")] = '\0';
	return 1;
}

static int has_entry(const char *dir, const char *name, const char *leaf)
{
	char        path[512];
	struct stat st;

	if (snprintf(path, sizeof(path), "%s/%s/%s", dir, name, leaf) >= (int)sizeof(path)) {
		return 0;
	}
	/* `lstat`: `device` is a link in sysfs, and its being there is the
	 * answer -- where it points is a bus this does not need to know. */
	return lstat(path, &st) == 0;
}

/* A radio by its `uevent`: cfg80211 says `DEVTYPE=wlan`, and a modem's
 * network function -- cdc_mbim, qmi_wwan -- says `DEVTYPE=wwan`. */
static int is_radio(const char *dir, const char *name)
{
	char        path[512];
	char        line[256];
	FILE       *uevent;
	int         radio = 0;

	if (has_entry(dir, name, "wireless") || has_entry(dir, name, "phy80211")) {
		return 1;
	}
	if (snprintf(path, sizeof(path), "%s/%s/uevent", dir, name) >= (int)sizeof(path)) {
		return 0;
	}
	uevent = fopen(path, "re");
	if (!uevent) {
		return 0;
	}
	while (fgets(line, sizeof(line), uevent)) {
		if (strcmp(line, "DEVTYPE=wlan\n") == 0 || strcmp(line, "DEVTYPE=wwan\n") == 0) {
			radio = 1;
		}
	}
	(void)fclose(uevent);
	return radio;
}

/* Whether the language can carry `name` as a quoted label with no escape.
 * The kernel refuses `/`, `:` and whitespace in a link name and nothing else,
 * so a quote or a backslash is possible, and such a port is skipped and
 * counted rather than written into a document it could break. */
static int name_is_plain(const char *name)
{
	const unsigned char *at;

	if (name[0] == '\0') {
		return 0;
	}
	for (at = (const unsigned char *)name; *at != '\0'; at++) {
		if (*at <= 0x20u || *at >= 0x7fu || *at == '"' || *at == '\\') {
			return 0;
		}
	}
	return 1;
}

static int by_name(const void *left, const void *right)
{
	return strcmp(((const ncfg_rescue_port_t *)left)->name, ((const ncfg_rescue_port_t *)right)->name);
}

int ncfg_rescue_ports(const char *sysfs_net, ncfg_rescue_ports_t *out, char *err, size_t err_size)
{
	DIR           *dir;
	struct dirent *entry;
	char           value[64];

	if (!sysfs_net || !out) {
		ncfg_error_set(err, err_size, "no directory to read ports from");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	dir = opendir(sysfs_net);
	if (!dir) {
		ncfg_error_set(err, err_size, "cannot read `%s`: %s", sysfs_net, strerror(errno));
		return 0;
	}
	while ((entry = readdir(dir)) != NULL) {
		ncfg_rescue_port_t *port;

		if (entry->d_name[0] == '.') {
			continue;
		}
		if (!read_small(sysfs_net, entry->d_name, "type", value, sizeof(value)) ||
		    strcmp(value, "1") != 0) {
			continue;
		}
		if (!has_entry(sysfs_net, entry->d_name, "device") || is_radio(sysfs_net, entry->d_name)) {
			continue;
		}
		if (strlen(entry->d_name) >= NCFG_RESCUE_NAME_MAX || !name_is_plain(entry->d_name) ||
		    out->count == NCFG_RESCUE_PORT_MAX) {
			out->skipped++;
			continue;
		}
		port = &out->ports[out->count++];
		memcpy(port->name, entry->d_name, strlen(entry->d_name) + 1u);
		port->carrier = -1;
		if (read_small(sysfs_net, entry->d_name, "carrier", value, sizeof(value))) {
			port->carrier = strcmp(value, "1") == 0 ? 1 : 0;
		}
	}
	(void)closedir(dir);
	qsort(out->ports, out->count, sizeof(out->ports[0]), by_name);
	return 1;
}

int ncfg_rescue_fallback_port(const ncfg_rescue_ports_t *ports, const char *keep)
{
	size_t at;

	if (!ports || ports->count == 0u) {
		return -1;
	}
	if (keep && keep[0] != '\0') {
		for (at = 0; at < ports->count; at++) {
			if (strcmp(ports->ports[at].name, keep) == 0 && ports->ports[at].carrier != 0) {
				return (int)at;
			}
		}
	}
	for (at = 0; at < ports->count; at++) {
		if (ports->ports[at].carrier == 1) {
			return (int)at;
		}
	}
	return 0;
}

/* ------------------------------------------------------------- document */

typedef struct {
	char  *out;
	size_t size;
	size_t used;
	int    overflow;
} text_t;

static void add(text_t *text, const char *format, ...) __attribute__((format(printf, 2, 3)));

static void add(text_t *text, const char *format, ...)
{
	va_list args;
	int     wrote;

	if (text->overflow) {
		return;
	}
	va_start(args, format);
	wrote = vsnprintf(text->out + text->used, text->size - text->used, format, args);
	va_end(args);
	if (wrote < 0 || (size_t)wrote >= text->size - text->used) {
		text->overflow = 1;
		return;
	}
	text->used += (size_t)wrote;
}

int ncfg_rescue_render(const ncfg_rescue_ports_t *ports, ncfg_rescue_rung_t rung,
    const char *fallback, int fallback_at, int renegotiate, char *out, size_t out_size, char *err,
    size_t err_size)
{
	text_t text = { out, out_size, 0, 0 };
	size_t at;
	int    speed = 0;

	if (!ports || !out || out_size == 0u) {
		ncfg_error_set(err, err_size, "nothing to render into");
		return 0;
	}
	out[0] = '\0';
	if (rung < NCFG_RESCUE_RUNG_ADDRESS || rung > NCFG_RESCUE_RUNG_LAST) {
		ncfg_error_set(err, err_size, "rung %d is not one netrescue has", (int)rung);
		return 0;
	}
	if (fallback && fallback_at >= 0 && !name_is_plain(fallback)) {
		ncfg_error_set(err, err_size, "the fallback address `%s` is not one the document can carry",
		    fallback);
		return 0;
	}
	if (rung == NCFG_RESCUE_RUNG_FORCE_1000) {
		speed = 1000;
	} else if (rung == NCFG_RESCUE_RUNG_FORCE_100 || rung == NCFG_RESCUE_RUNG_REBIND) {
		speed = 100;
	}
	add(&text, "# Written by netrescue, rung %d: %s.\n", (int)rung, ncfg_rescue_rung_says(rung));
	add(&text, "# Rewritten at every rung; an edit here is lost at the next one.\n");
	for (at = 0; at < ports->count; at++) {
		const ncfg_rescue_port_t *port = &ports->ports[at];

		add(&text, "\n");
		/*
		 * **Forced only where there is no carrier.** A port that negotiated
		 * a link has nothing to gain from losing it, and forcing one side
		 * of a link that negotiates is the duplex mismatch this rung exists
		 * to get around. A carrier of -1 is a link that is down, and is
		 * forced like one without a carrier: bringing it up is the daemon's
		 * first act, and that is when the setting matters.
		 */
		if (speed != 0 && port->carrier != 1) {
			add(&text, "device \"%s\" {\n\tethtool {\n\t\tautoneg = \"off\"\n"
			    "\t\tspeed   = %d\n\t\tduplex  = \"full\"\n\t}\n}\n", port->name, speed);
		} else if (speed == 0 && renegotiate && port->carrier != 1) {
			add(&text, "device \"%s\" {\n\tethtool {\n\t\tautoneg = \"on\"\n\t}\n}\n", port->name);
		}
		/*
		 * **What was learned is written at every rung once it has been**,
		 * whichever rung it is: a rung that dropped it would take away the
		 * one way in listening found. Checked for characters here as the
		 * fallback is; the caller wrote both from numbers.
		 */
		add(&text, "interface \"%s\" {\n\tconfig = [\"dhcp\"", port->name);
		if (fallback && (int)at == fallback_at) {
			add(&text, ", \"%s\"", fallback);
		}
		if (port->learned[0] != '\0' && name_is_plain(port->learned)) {
			add(&text, ", \"%s\"", port->learned);
		}
		add(&text, "]\n");
		if (port->learned[0] != '\0' && port->gateway[0] != '\0' && name_is_plain(port->gateway)) {
			add(&text, "\troutes = \"default via %s\"\n", port->gateway);
		}
		add(&text, "}\n");
	}
	if (text.overflow) {
		ncfg_error_set(err, err_size, "the document for %zu ports does not fit in %zu bytes",
		    ports->count, out_size);
		out[0] = '\0';
		return 0;
	}
	return 1;
}

/* ------------------------------------------------------------- gateways */

size_t ncfg_rescue_default_gateways(const char *route_text, uint32_t *out, size_t max)
{
	const char *line = route_text;
	size_t      found = 0;

	if (!route_text || !out) {
		return 0;
	}
	while (line && *line != '\0' && found < max) {
		char          iface[32];
		unsigned long destination, gateway, flags;
		const char   *next = strchr(line, '\n');

		/* Iface Destination Gateway Flags ..., hexadecimal in host order of
		 * the bytes as they sit in memory -- which is network order read as
		 * a native integer, so the value is stored back unchanged. The
		 * header line fails the scan and is passed over. */
		if (sscanf(line, "%31s %lx %lx %lx", iface, &destination, &gateway, &flags) == 4 &&
		    destination == 0u && (flags & 0x1u) && (flags & 0x2u) && gateway != 0u) {
			out[found++] = (uint32_t)gateway;
		}
		line = next ? next + 1 : NULL;
	}
	return found;
}

static uint16_t checksum(const void *data, size_t length)
{
	const uint8_t *bytes = data;
	uint32_t       sum = 0;
	size_t         at;

	for (at = 0; at + 1u < length; at += 2u) {
		sum += (uint32_t)((bytes[at] << 8) | bytes[at + 1u]);
	}
	if (length & 1u) {
		sum += (uint32_t)(bytes[length - 1u] << 8);
	}
	while (sum >> 16) {
		sum = (sum & 0xffffu) + (sum >> 16);
	}
	return htons((uint16_t)~sum);
}

static long long now_ms(void)
{
	struct timespec now;

	(void)clock_gettime(CLOCK_MONOTONIC, &now);
	return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

int ncfg_rescue_gateway_answers(uint32_t gateway, int timeout_ms, char *err, size_t err_size)
{
	struct sockaddr_in to;
	struct icmphdr     echo;
	uint16_t           ident = (uint16_t)(getpid() & 0xffff);
	long long          deadline;
	int                fd;

	if (err && err_size) {
		err[0] = '\0';
	}
	fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_ICMP);
	if (fd < 0) {
		ncfg_error_set(err, err_size, "cannot open a raw ICMP socket: %s", strerror(errno));
		return 0;
	}
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = gateway;
	memset(&echo, 0, sizeof(echo));
	echo.type = ICMP_ECHO;
	echo.un.echo.id = htons(ident);
	echo.un.echo.sequence = htons(1);
	echo.checksum = checksum(&echo, sizeof(echo));
	if (sendto(fd, &echo, sizeof(echo), 0, (const struct sockaddr *)&to, sizeof(to)) < 0) {
		/* No route, no neighbour: the network said no, which is silence
		 * as far as reachability goes, so `err` stays empty. */
		(void)close(fd);
		return 0;
	}
	deadline = now_ms() + timeout_ms;
	for (;;) {
		struct pollfd      wait = { fd, POLLIN, 0 };
		uint8_t            packet[256];
		struct sockaddr_in from;
		socklen_t          from_size = sizeof(from);
		long long          left = deadline - now_ms();
		ssize_t            got;
		size_t             header;
		const struct icmphdr *reply;

		if (left <= 0) {
			break;
		}
		if (poll(&wait, 1, (int)left) <= 0) {
			continue;
		}
		got = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&from, &from_size);
		if (got < (ssize_t)sizeof(struct iphdr)) {
			continue;
		}
		/* A raw socket hands back the IP header; its length is in it. */
		header = (size_t)(packet[0] & 0x0fu) * 4u;
		if (header < sizeof(struct iphdr) || (size_t)got < header + sizeof(struct icmphdr)) {
			continue;
		}
		reply = (const struct icmphdr *)(const void *)(packet + header);
		if (from.sin_addr.s_addr == gateway && reply->type == ICMP_ECHOREPLY &&
		    reply->un.echo.id == htons(ident)) {
			(void)close(fd);
			return 1;
		}
	}
	(void)close(fd);
	return 0;
}

/* ------------------------------------------------------------- listening */

/* Addresses no host on a LAN uses as its own. */
static int unusable(uint32_t address)
{
	uint32_t host = ntohl(address);

	return host == 0u || (host >> 24) == 127u || (host >> 24) == 0u || (host >> 28) == 0xeu ||
	    (host >> 28) == 0xfu || (host >> 16) == 0xa9feu;
}

typedef struct {
	uint32_t address;
	size_t   count;
} tally_t;

static void tally(tally_t *tallies, size_t *count, size_t max, uint32_t address)
{
	size_t at;

	for (at = 0; at < *count; at++) {
		if (tallies[at].address == address) {
			tallies[at].count++;
			return;
		}
	}
	if (*count < max) {
		tallies[*count].address = address;
		tallies[*count].count = 1;
		(*count)++;
	}
}

#define LEARN_TALLY_MAX 512u

int ncfg_rescue_learn(const ncfg_rescue_heard_t *heard, size_t count, size_t minimum,
    const uint32_t *taken, size_t taken_count, ncfg_rescue_learned_t *out)
{
	tally_t  networks[LEARN_TALLY_MAX];
	tally_t  hosts[LEARN_TALLY_MAX];
	size_t   network_count = 0, host_count = 0, at, best = 0;
	uint32_t network, host;

	if (!out) {
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!heard) {
		return 0;
	}
	for (at = 0; at < count; at++) {
		if (!unusable(heard[at].sender)) {
			tally(networks, &network_count, LEARN_TALLY_MAX, heard[at].sender & htonl(0xffffff00u));
		}
		if (!unusable(heard[at].target)) {
			tally(networks, &network_count, LEARN_TALLY_MAX, heard[at].target & htonl(0xffffff00u));
		}
	}
	if (network_count == 0u) {
		return 0;
	}
	for (at = 1; at < network_count; at++) {
		if (networks[at].count > networks[best].count) {
			best = at;
		}
	}
	network = networks[best].address;
	for (at = 0; at < count; at++) {
		if ((heard[at].sender & htonl(0xffffff00u)) == network && !unusable(heard[at].sender)) {
			tally(hosts, &host_count, LEARN_TALLY_MAX, heard[at].sender);
			out->heard++;
		}
		if ((heard[at].target & htonl(0xffffff00u)) == network && !unusable(heard[at].target)) {
			tally(hosts, &host_count, LEARN_TALLY_MAX, heard[at].target);
		}
	}
	if (out->heard < minimum || host_count == 0u) {
		memset(out, 0, sizeof(*out));
		return 0;
	}
	best = 0;
	for (at = 1; at < host_count; at++) {
		if (hosts[at].count > hosts[best].count) {
			best = at;
		}
	}
	out->network = network;
	out->gateway = hosts[best].address;
	for (host = 250; host >= 200; host--) {
		uint32_t candidate = network | htonl(host);
		int      used = 0;

		for (at = 0; at < host_count && !used; at++) {
			used = hosts[at].address == candidate;
		}
		for (at = 0; taken && at < taken_count && !used; at++) {
			used = taken[at] == candidate;
		}
		if (!used) {
			out->address = candidate;
			break;
		}
	}
	return 1;
}

/* An ARP payload as a packet socket of type SOCK_DGRAM hands it over: no
 * Ethernet header, and the hardware addresses six bytes wide. */
typedef struct __attribute__((packed)) {
	uint16_t hardware;
	uint16_t protocol;
	uint8_t  hardware_size;
	uint8_t  protocol_size;
	uint16_t opcode;
	uint8_t  sender_mac[6];
	uint8_t  sender_ip[4];
	uint8_t  target_mac[6];
	uint8_t  target_ip[4];
} arp_t;

static int open_arp(const char *port, struct sockaddr_ll *where, char *err, size_t err_size)
{
	int fd;

	memset(where, 0, sizeof(*where));
	where->sll_family = AF_PACKET;
	where->sll_protocol = htons(ETH_P_ARP);
	where->sll_ifindex = (int)if_nametoindex(port);
	if (where->sll_ifindex == 0) {
		ncfg_error_set(err, err_size, "there is no port called `%s`", port);
		return -1;
	}
	fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_ARP));
	if (fd < 0) {
		ncfg_error_set(err, err_size, "cannot open a packet socket: %s", strerror(errno));
		return -1;
	}
	if (bind(fd, (const struct sockaddr *)where, sizeof(*where)) != 0) {
		ncfg_error_set(err, err_size, "cannot listen on `%s`: %s", port, strerror(errno));
		(void)close(fd);
		return -1;
	}
	return fd;
}

/* One ARP frame for IPv4 over Ethernet, or 0. */
static int read_arp(int fd, arp_t *arp)
{
	ssize_t got = recv(fd, arp, sizeof(*arp), 0);

	return got >= (ssize_t)sizeof(*arp) && ntohs(arp->hardware) == ARPHRD_ETHER &&
	    ntohs(arp->protocol) == ETH_P_IP && arp->hardware_size == 6u && arp->protocol_size == 4u;
}

int ncfg_rescue_listen(const char *port, int seconds, ncfg_rescue_heard_t *heard, size_t max,
    size_t *count, char *err, size_t err_size)
{
	struct sockaddr_ll where;
	long long          deadline;
	int                fd;

	if (!port || !heard || !count) {
		ncfg_error_set(err, err_size, "nothing to listen with");
		return 0;
	}
	*count = 0;
	fd = open_arp(port, &where, err, err_size);
	if (fd < 0) {
		return 0;
	}
	deadline = now_ms() + (long long)seconds * 1000LL;
	while (*count < max) {
		struct pollfd wait = { fd, POLLIN, 0 };
		long long     left = deadline - now_ms();
		arp_t         arp;

		if (left <= 0) {
			break;
		}
		if (poll(&wait, 1, (int)left) <= 0) {
			continue;
		}
		while (*count < max && read_arp(fd, &arp)) {
			memcpy(&heard[*count].sender, arp.sender_ip, 4);
			memcpy(&heard[*count].target, arp.target_ip, 4);
			(*count)++;
		}
	}
	(void)close(fd);
	return 1;
}

int ncfg_rescue_address_free(const char *port, uint32_t address, int timeout_ms, char *err,
    size_t err_size)
{
	struct sockaddr_ll where;
	struct ifreq       request;
	arp_t              probe;
	long long          deadline;
	int                fd;

	if (err && err_size) {
		err[0] = '\0';
	}
	if (!port || strlen(port) >= sizeof(request.ifr_name)) {
		ncfg_error_set(err, err_size, "no port to probe on");
		return 0;
	}
	fd = open_arp(port, &where, err, err_size);
	if (fd < 0) {
		return 0;
	}
	memset(&request, 0, sizeof(request));
	memcpy(request.ifr_name, port, strlen(port) + 1u);
	if (ioctl(fd, SIOCGIFHWADDR, &request) != 0) {
		ncfg_error_set(err, err_size, "cannot read `%s`'s hardware address: %s", port, strerror(errno));
		(void)close(fd);
		return 0;
	}
	memset(&probe, 0, sizeof(probe));
	probe.hardware = htons(ARPHRD_ETHER);
	probe.protocol = htons(ETH_P_IP);
	probe.hardware_size = 6;
	probe.protocol_size = 4;
	probe.opcode = htons(ARPOP_REQUEST);
	memcpy(probe.sender_mac, request.ifr_hwaddr.sa_data, 6);
	/* RFC 5227: the sender address is zero, so nobody's cache learns an
	 * address that is not yet ours. */
	memcpy(probe.target_ip, &address, 4);
	where.sll_halen = 6;
	memset(where.sll_addr, 0xff, 6);
	if (sendto(fd, &probe, sizeof(probe), 0, (const struct sockaddr *)&where, sizeof(where)) < 0) {
		ncfg_error_set(err, err_size, "cannot send a probe on `%s`: %s", port, strerror(errno));
		(void)close(fd);
		return 0;
	}
	deadline = now_ms() + timeout_ms;
	for (;;) {
		struct pollfd wait = { fd, POLLIN, 0 };
		long long     left = deadline - now_ms();
		arp_t         arp;

		if (left <= 0) {
			break;
		}
		if (poll(&wait, 1, (int)left) <= 0) {
			continue;
		}
		while (read_arp(fd, &arp)) {
			uint32_t sender, target;

			memcpy(&sender, arp.sender_ip, 4);
			memcpy(&target, arp.target_ip, 4);
			/* Somebody has it, or somebody else is probing for it --
			 * our own probe comes back as an outgoing frame on some
			 * drivers, and is told apart by its hardware address. */
			if (sender == address || (sender == 0u && target == address &&
			    memcmp(arp.sender_mac, request.ifr_hwaddr.sa_data, 6) != 0)) {
				(void)close(fd);
				return 0;
			}
		}
	}
	(void)close(fd);
	return 1;
}

/* ------------------------------------------------------------- rebinding */

/* The last component of the path a link resolves to. */
static int link_name(const char *path, char *out, size_t out_size)
{
	char        target[PATH_MAX];
	const char *slash;

	if (!realpath(path, target)) {
		return 0;
	}
	slash = strrchr(target, '/');
	slash = slash ? slash + 1 : target;
	if (strlen(slash) >= out_size || slash[0] == '\0') {
		return 0;
	}
	memcpy(out, slash, strlen(slash) + 1u);
	return 1;
}

static int write_word(const char *path, const char *word, char *err, size_t err_size)
{
	int     fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t wrote;

	if (fd < 0) {
		ncfg_error_set(err, err_size, "cannot open `%s`: %s", path, strerror(errno));
		return 0;
	}
	wrote = write(fd, word, strlen(word));
	if (wrote < 0 || (size_t)wrote != strlen(word)) {
		ncfg_error_set(err, err_size, "writing `%s` to `%s` failed: %s", word, path,
		    wrote < 0 ? strerror(errno) : "short write");
		(void)close(fd);
		return 0;
	}
	if (close(fd) != 0) {
		ncfg_error_set(err, err_size, "writing `%s` to `%s` failed: %s", word, path,
		    strerror(errno));
		return 0;
	}
	return 1;
}

int ncfg_rescue_rebind(const char *sysfs_net, const char *port, char *driver, size_t driver_size,
    char *device, size_t device_size, char *err, size_t err_size)
{
	char path[PATH_MAX];
	char driver_dir[PATH_MAX];
	char control[PATH_MAX + 16];

	if (!sysfs_net || !port || !name_is_plain(port) || strchr(port, '/') || !driver || !device) {
		ncfg_error_set(err, err_size, "no port to rebind");
		return 0;
	}
	(void)snprintf(path, sizeof(path), "%s/%s/device", sysfs_net, port);
	if (!link_name(path, device, device_size)) {
		ncfg_error_set(err, err_size, "%s has no device to rebind", port);
		return 0;
	}
	(void)snprintf(path, sizeof(path), "%s/%s/device/driver", sysfs_net, port);
	if (!realpath(path, driver_dir) || !link_name(path, driver, driver_size)) {
		ncfg_error_set(err, err_size, "%s's device %s has no driver bound", port, device);
		return 0;
	}
	(void)snprintf(control, sizeof(control), "%s/unbind", driver_dir);
	if (!write_word(control, device, err, err_size)) {
		return 0;
	}
	/*
	 * **Bound again even where this fails**, by the caller seeing the
	 * sentence: a device left unbound is a port gone until reboot. There is
	 * nothing between the two writes for that reason -- no wait, no check.
	 */
	(void)snprintf(control, sizeof(control), "%s/bind", driver_dir);
	return write_word(control, device, err, err_size);
}

/* Whether `haystack` contains `needle`, ignoring case. */
static int mentions(const char *haystack, const char *needle)
{
	size_t length = strlen(needle);

	if (length == 0u) {
		return 0;
	}
	for (; *haystack != '\0'; haystack++) {
		size_t at;

		for (at = 0; at < length && haystack[at] != '\0'; at++) {
			if (tolower((unsigned char)haystack[at]) != tolower((unsigned char)needle[at])) {
				break;
			}
		}
		if (at == length) {
			return 1;
		}
	}
	return 0;
}

int ncfg_rescue_kmsg_complaint(const char *record, const char *driver, const char *device,
    char *out, size_t out_size)
{
	static const char *const trouble[] = { "firmware", "fail", "error", "timeout", "timed out",
		"reset", "hang", "unable", "cannot", "can't" };
	const char *text;
	size_t      at;
	int         troubled = 0;

	if (!record || !out || out_size == 0u) {
		return 0;
	}
	/* `/dev/kmsg`: `prio,seq,usec,flags;text`, continuation lines after. */
	text = strchr(record, ';');
	text = text ? text + 1 : record;
	if (!((driver && mentions(text, driver)) || (device && mentions(text, device)))) {
		return 0;
	}
	for (at = 0; at < sizeof(trouble) / sizeof(trouble[0]) && !troubled; at++) {
		troubled = mentions(text, trouble[at]);
	}
	if (!troubled) {
		return 0;
	}
	(void)snprintf(out, out_size, "%.*s", (int)strcspn(text, "\n"), text);
	return 1;
}
