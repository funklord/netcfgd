/*
 * pair.c -- `ncfg pair PREKEY`: admit a device to this host's estate, and draw
 * the code it takes (project.md 10.722).
 *
 * The terminal displays and the phone scans. The card says where this host is,
 * so the host's own address is set first; a card that says nowhere would leave
 * a phone with nothing to reach.
 *
 * Asked of the daemon's fuzznet socket, whose verbs are its own user's, so this
 * is root's on a machine, as the node's trust is not grantable (fuzznet's
 * `node/permit.h`).
 */
#include "cli_internal.h"
#include "ncfg/base.h"
#include "ncfg/node.h"
#include "ncfg_fuzznet.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* The quiet zone the standard asks for, in modules. */
#define PAIR_QUIET 4u

/* Whether module (x, y), quiet zone included, is dark. */
static int dark(const uint8_t *modules, size_t size, size_t x, size_t y)
{
	if (x < PAIR_QUIET || y < PAIR_QUIET || x >= size + PAIR_QUIET || y >= size + PAIR_QUIET) {
		return 0;
	}
	return modules[(y - PAIR_QUIET) * size + (x - PAIR_QUIET)] != 0;
}

/*
 * Two rows of modules to a line of half blocks, or a card's code is taller than
 * a terminal. **The colours are said, black on white**: on a dark terminal these
 * characters would otherwise be light on dark, an inverted code, which quirc does
 * not read.
 */
void ncfg_cli_pair_draw(FILE *out, const uint8_t *modules, size_t size)
{
	const size_t side = size + 2u * PAIR_QUIET;

	for (size_t y = 0; y < side; y += 2u) {
		fputs("\033[30;47m", out);
		for (size_t x = 0; x < side; x++) {
			int top = dark(modules, size, x, y);
			int bottom = y + 1u < side && dark(modules, size, x, y + 1u);

			fputs(top ? (bottom ? "\xe2\x96\x88" : "\xe2\x96\x80")
			          : (bottom ? "\xe2\x96\x84" : " "),
			    out);
		}
		fputs("\033[0m\n", out);
	}
}

/* The address this machine reaches the world from: connecting a datagram socket
 * sends nothing, and the kernel's route lookup picks the source. */
static int outward_address(char *out, size_t size)
{
	struct sockaddr_in to;
	struct sockaddr_in from;
	socklen_t          length = sizeof(from);
	int                fd = socket(AF_INET, SOCK_DGRAM, 0);
	int                ok;

	if (fd < 0) {
		return 0;
	}
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_port = htons(9);
	to.sin_addr.s_addr = htonl(0xc0000201u); /* 192.0.2.1, documentation's */
	ok = connect(fd, (struct sockaddr *)&to, sizeof(to)) == 0 &&
	    getsockname(fd, (struct sockaddr *)&from, &length) == 0 &&
	    inet_ntop(AF_INET, &from.sin_addr, out, (socklen_t)size) != NULL;
	close(fd);
	return ok;
}

/* Whether something holds netcfgd's port: binding it is the question that needs
 * no privilege and no second opinion on what the config said at the start. A
 * dual-stack socket, so it meets a holder of either family. */
static int port_is_served(void)
{
	struct sockaddr_in6 here;
	int                 fd = socket(AF_INET6, SOCK_DGRAM, 0);
	int                 held;

	if (fd < 0) {
		return 1; /* no way to look, so the node's own answer decides */
	}
	memset(&here, 0, sizeof(here));
	here.sin6_family = AF_INET6;
	here.sin6_port = htons(NCFG_FUZZNET_PORT);
	held = bind(fd, (struct sockaddr *)&here, sizeof(here)) != 0 && errno == EADDRINUSE;
	close(fd);
	return held;
}

static int ask_node(const char *socket_path, const char *line, char *reply, size_t size,
    char *err, size_t err_size)
{
	char why[NCFG_ERROR_MAX];
	int  silent = 0;

	if (!ncfg_fuzznet_ask(socket_path, line, reply, size, 5000, &silent, why, sizeof(why))) {
		ncfg_error_set(err, err_size, "netcfgd's node did not answer: %s", why);
		return 0;
	}
	return 1;
}

int ncfg_cli_pair(const ncfg_cli_options_t *options, const char **positional, size_t count,
    char *err, size_t err_size)
{
	static uint8_t modules[32768];
	char           run_dir[NCFG_CLI_TEXT_MAX];
	char           socket_path[1100];
	char           address[64];
	char           line[NCFG_FUZZNET_REQUEST_MAX];
	char           reply[2048];
	size_t         size = 0;

	if (count != 1u) {
		ncfg_error_set(err, err_size, "`ncfg pair` takes the device's prekey");
		return 0;
	}
	(void)ncfg_state_resolve_dir(options->run_dir, run_dir, sizeof(run_dir));
	if (!ncfg_fuzznet_daemon_socket(run_dir, socket_path, sizeof(socket_path))) {
		ncfg_error_set(err, err_size, "the daemon's fuzznet socket path does not fit");
		return 0;
	}
	if (!port_is_served()) {
		ncfg_error_set(err, err_size,
		    "nothing here listens for a device: open `remote` in the `global` block, "
		    "`remote { observe = true; admin = true }` for a phone that configures this "
		    "machine, and restart netcfgd");
		return 0;
	}
	if (!outward_address(address, sizeof(address))) {
		ncfg_error_set(err, err_size,
		    "this machine has no route out, so a card could say nowhere to reach it");
		return 0;
	}
	(void)snprintf(line, sizeof(line), "set setting host net/address %s %u", address,
	    NCFG_FUZZNET_PORT);
	if (!ask_node(socket_path, line, reply, sizeof(reply), err, err_size)) {
		return 0;
	}
	if (strncmp(reply, "ok", 2) != 0) {
		ncfg_error_set(err, err_size, "netcfgd's node refused its address: %s", reply);
		return 0;
	}
	if (snprintf(line, sizeof(line), "add peer %s delegable", positional[0]) >=
	    (int)sizeof(line)) {
		ncfg_error_set(err, err_size, "that is too long to be a prekey");
		return 0;
	}
	if (!ask_node(socket_path, line, reply, sizeof(reply), err, err_size)) {
		return 0;
	}
	if (strncmp(reply, "ok ", 3) != 0) {
		ncfg_error_set(err, err_size, "netcfgd's node refused the device: %s", reply);
		return 0;
	}
	if (!ncfg_node_qr(reply + 3, modules, sizeof(modules), &size)) {
		ncfg_error_set(err, err_size, "the card would not fit a code");
		return 0;
	}
	ncfg_cli_pair_draw(stdout, modules, size);
	printf("\nScan this with the device. It reaches this machine at %s, port %u.\n\n%s\n",
	    address, NCFG_FUZZNET_PORT, reply + 3);
	return 1;
}
