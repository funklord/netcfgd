/*
 * rescue_test.c -- netrescue's ports, documents and gateways (0326).
 *
 * WHAT THESE CASES ARE FOR
 *   * **Which links are ports**, against a sysfs directory built here with
 *     every kind a machine shows beside its Ethernet: loopback, a bridge and
 *     a veth with no `device`, a radio by its `wireless` directory and by its
 *     `DEVTYPE`, a modem's network function, and a name the language could
 *     not carry. Only the Ethernet ports with hardware behind them are taken.
 *   * **Every rung's document compiles**, with the compiler the daemon runs:
 *     a document netrescue writes and netcfgd refuses is a rescue that sits
 *     at its first rung saying nothing, so this is the check that matters
 *     most, and it asks the real thing rather than comparing text.
 *   * **The fallback stays put** while its port keeps a carrier, and moves
 *     when it loses one.
 *   * **Gateways are read from `/proc/net/route`'s text**, which is
 *     hexadecimal in memory order.
 *
 *   Nothing here sends a packet; `tests/live/rescue.sh` does.
 */
#include "ncfg/ast.h"
#include "ncfg/base.h"
#include "ncfg/document.h"
#include "ncfg/hooks.h"
#include "ncfg/lower.h"
#include "ncfg/parse.h"
#include "ncfg/rescue.h"

#include "testdir.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* One link under the fake sysfs: its `type`, whether it has a `device`, and
 * an optional extra entry -- a directory such as `wireless`, or a `uevent`
 * body. `carrier` NULL leaves the file absent, as a down link reads. */
static void link_entry(const char *root, const char *name, const char *type, int device,
    const char *subdir, const char *uevent, const char *carrier)
{
	char path[1024];

	(void)snprintf(path, sizeof(path), "%s/%s", root, name);
	testdir_mkdirp(path);
	(void)snprintf(path, sizeof(path), "%s/%s/type", root, name);
	(void)testdir_write(path, type, strlen(type));
	if (device) {
		char target[1024];

		(void)snprintf(target, sizeof(target), "%s/%s/device", root, name);
		(void)symlink("../../devices/pci0000:00", target);
	}
	if (subdir) {
		(void)snprintf(path, sizeof(path), "%s/%s/%s", root, name, subdir);
		testdir_mkdirp(path);
	}
	if (uevent) {
		(void)snprintf(path, sizeof(path), "%s/%s/uevent", root, name);
		(void)testdir_write(path, uevent, strlen(uevent));
	}
	if (carrier) {
		(void)snprintf(path, sizeof(path), "%s/%s/carrier", root, name);
		(void)testdir_write(path, carrier, strlen(carrier));
	}
}

/* Compile `text` as the daemon would; 1 when it does. The document is handed
 * back for a look when `out` is not NULL. */
static int compiles(const char *text, ncfg_document_t **out)
{
	ncfg_ast_file_t *file = NULL;
	ncfg_source_t    source;
	ncfg_document_t *document;
	char             err[NCFG_ERROR_MAX];

	if (!ncfg_parse(text, strlen(text), &file, NULL, err, sizeof(err))) {
		printf("did not parse: %s\n%s", err, text);
		return 0;
	}
	source.name = "netcfgd.conf";
	source.file = file;
	document = ncfg_compile(&source, 1u, ncfg_hook_sink_unwritten(), NULL, err, sizeof(err));
	ncfg_ast_file_free(file);
	if (!document) {
		printf("did not compile: %s\n%s", err, text);
		return 0;
	}
	if (out) {
		*out = document;
	} else {
		ncfg_document_free(document);
	}
	return 1;
}

static const ncfg_device_t *device_named(const ncfg_document_t *document, const char *name)
{
	size_t at;

	for (at = 0; at < document->device_count; at++) {
		if (strcmp(document->devices[at].name, name) == 0) {
			return &document->devices[at];
		}
	}
	return NULL;
}

static void test_ports(const char *root)
{
	ncfg_rescue_ports_t ports;
	char                err[NCFG_ERROR_MAX];

	link_entry(root, "lo", "772\n", 0, NULL, NULL, "1\n");
	link_entry(root, "eno2", "1\n", 1, NULL, "INTERFACE=eno2\n", "0\n");
	link_entry(root, "eno1", "1\n", 1, NULL, "INTERFACE=eno1\n", "1\n");
	link_entry(root, "enp3s0", "1\n", 1, NULL, NULL, NULL);
	link_entry(root, "br0", "1\n", 0, "bridge", NULL, "1\n");
	link_entry(root, "veth0", "1\n", 0, NULL, NULL, "1\n");
	link_entry(root, "wlan0", "1\n", 1, "wireless", NULL, "1\n");
	link_entry(root, "wlp2s0", "1\n", 1, NULL, "DEVTYPE=wlan\nINTERFACE=wlp2s0\n", "1\n");
	link_entry(root, "wwan0", "1\n", 1, NULL, "DEVTYPE=wwan\n", "1\n");
	link_entry(root, "usb0", "1\n", 1, NULL, "DEVTYPE=gadget\n", "1\n");
	link_entry(root, "q\"x", "1\n", 1, NULL, NULL, "1\n");

	check(ncfg_rescue_ports(root, &ports, err, sizeof(err)), "the fake sysfs is read");
	check(ports.count == 4u, "four Ethernet ports with hardware behind them");
	check(ports.count == 4u && strcmp(ports.ports[0].name, "eno1") == 0 &&
	    strcmp(ports.ports[1].name, "eno2") == 0 && strcmp(ports.ports[2].name, "enp3s0") == 0 &&
	    strcmp(ports.ports[3].name, "usb0") == 0, "sorted by name, a USB link among them");
	check(ports.count == 4u && ports.ports[0].carrier == 1 && ports.ports[1].carrier == 0 &&
	    ports.ports[2].carrier == -1, "carrier read as up, down, and not said");
	check(ports.skipped == 1u, "the name the language cannot carry is counted, not taken");
	check(!ncfg_rescue_ports("/nonexistent/netrescue", &ports, err, sizeof(err)) && err[0] != '\0',
	    "an unreadable directory is a failure with a sentence");
}

static void test_fallback(void)
{
	ncfg_rescue_ports_t ports;

	memset(&ports, 0, sizeof(ports));
	check(ncfg_rescue_fallback_port(&ports, NULL) == -1, "no ports, no fallback port");
	ports.count = 3;
	(void)snprintf(ports.ports[0].name, NCFG_RESCUE_NAME_MAX, "eth0");
	(void)snprintf(ports.ports[1].name, NCFG_RESCUE_NAME_MAX, "eth1");
	(void)snprintf(ports.ports[2].name, NCFG_RESCUE_NAME_MAX, "eth2");
	ports.ports[0].carrier = 0;
	ports.ports[1].carrier = -1;
	ports.ports[2].carrier = 0;
	check(ncfg_rescue_fallback_port(&ports, NULL) == 0, "no carrier anywhere: the first port");
	ports.ports[2].carrier = 1;
	check(ncfg_rescue_fallback_port(&ports, NULL) == 2, "otherwise the first with a carrier");
	ports.ports[0].carrier = 1;
	check(ncfg_rescue_fallback_port(&ports, "eth2") == 2, "and it stays while it keeps its carrier");
	ports.ports[2].carrier = 0;
	check(ncfg_rescue_fallback_port(&ports, "eth2") == 0, "and moves when it loses it");
	check(ncfg_rescue_fallback_port(&ports, "eth9") == 0, "a port that went away is not kept");
}

static void test_render(void)
{
	ncfg_rescue_ports_t   ports;
	ncfg_document_t      *document = NULL;
	const ncfg_device_t  *device;
	char                  text[8192];
	char                  err[NCFG_ERROR_MAX];

	memset(&ports, 0, sizeof(ports));
	ports.count = 2;
	(void)snprintf(ports.ports[0].name, NCFG_RESCUE_NAME_MAX, "eno1");
	(void)snprintf(ports.ports[1].name, NCFG_RESCUE_NAME_MAX, "eno2");
	ports.ports[0].carrier = 1;
	ports.ports[1].carrier = 0;

	check(ncfg_rescue_render(&ports, NCFG_RESCUE_RUNG_ADDRESS, "10.0.0.250/16", 0, 0, text, sizeof(text),
	          err, sizeof(err)), "rung 1 renders");
	check(compiles(text, &document), "and compiles as the daemon would compile it");
	if (document) {
		check(document->interface_count == 2u, "an interface for each port");
		check(document->interface_count == 2u && document->interfaces[0].addressing_count == 2u &&
		    document->interfaces[1].addressing_count == 1u, "DHCP on both, the fallback beside it on one");
		check((!device_named(document, "eno1") || !device_named(document, "eno1")->link_settings) &&
		    (!device_named(document, "eno2") || !device_named(document, "eno2")->link_settings),
		    "and no link settings at the first rung");
		ncfg_document_free(document);
		document = NULL;
	}

	check(ncfg_rescue_render(&ports, NCFG_RESCUE_RUNG_FORCE_1000, "10.0.0.250/16", 0, 0, text,
	          sizeof(text), err, sizeof(err)), "rung 2 renders");
	check(compiles(text, &document), "and compiles");
	if (document) {
		device = device_named(document, "eno2");
		check(!device_named(document, "eno1") || !device_named(document, "eno1")->link_settings,
		    "the port with a carrier is left negotiating");
		check(device && device->link_settings && device->link_settings->speed.has &&
		    device->link_settings->speed.value == 1000 && device->link_settings->duplex &&
		    strcmp(device->link_settings->duplex, "full") == 0, "the one without is forced to 1000/full");
		ncfg_document_free(document);
		document = NULL;
	}

	check(ncfg_rescue_render(&ports, NCFG_RESCUE_RUNG_FORCE_100, NULL, -1, 0, text, sizeof(text), err,
	          sizeof(err)), "rung 3 renders with no fallback");
	check(compiles(text, &document), "and compiles");
	if (document) {
		device = device_named(document, "eno2");
		check(device && device->link_settings && device->link_settings->speed.value == 100,
		    "at 100/full");
		check(document->interfaces[0].addressing_count == 1u, "and no fallback when asked for none");
		ncfg_document_free(document);
		document = NULL;
	}

	check(ncfg_rescue_render(&ports, NCFG_RESCUE_RUNG_ADDRESS, "10.0.0.250/16", 0, 1, text, sizeof(text),
	          err, sizeof(err)), "rung 1 again, after the ladder went round");
	check(compiles(text, &document), "and compiles");
	if (document) {
		device = device_named(document, "eno2");
		check(device && device->link_settings && !device->link_settings->speed.has &&
		    device->link_settings->autoneg != 0, "the forced port is asked to negotiate again");
		ncfg_document_free(document);
		document = NULL;
	}

	check(!ncfg_rescue_render(&ports, NCFG_RESCUE_RUNG_ADDRESS, "10.0.0.250/16\"", 0, 0, text,
	          sizeof(text), err, sizeof(err)), "a fallback with a quote in it is refused");
	check(!ncfg_rescue_render(&ports, NCFG_RESCUE_RUNG_ADDRESS, NULL, -1, 0, text, 64, err, sizeof(err)) &&
	    text[0] == '\0', "a document that does not fit is refused, not cut");
	memset(&ports, 0, sizeof(ports));
	check(ncfg_rescue_render(&ports, NCFG_RESCUE_RUNG_ADDRESS, "10.0.0.250/16", -1, 0, text,
	          sizeof(text), err, sizeof(err)) && compiles(text, NULL), "no ports is an empty document");
}

static uint32_t ip(const char *text)
{
	struct in_addr address;

	(void)inet_pton(AF_INET, text, &address);
	return address.s_addr;
}

static void test_learn(void)
{
	ncfg_rescue_heard_t   heard[16];
	ncfg_rescue_learned_t learned;
	uint32_t              taken[1];
	size_t                count = 0;

#define HEARD(s, t) (heard[count].sender = ip(s), heard[count].target = ip(t), count++)
	HEARD("192.168.5.10", "192.168.5.1");
	HEARD("192.168.5.11", "192.168.5.1");
	HEARD("192.168.5.1", "192.168.5.12");
	HEARD("192.168.5.12", "192.168.5.1");
	HEARD("192.168.5.250", "192.168.5.1");
	HEARD("169.254.3.4", "169.254.3.5");
	HEARD("169.254.3.4", "169.254.3.6");
	HEARD("0.0.0.0", "192.168.5.249");
#undef HEARD
	check(ncfg_rescue_learn(heard, count, 3, NULL, 0, &learned), "a LAN's ARP is learned from");
	check(learned.network == ip("192.168.5.0"), "its /24, link-local passed over");
	check(learned.gateway == ip("192.168.5.1"), "the busiest address taken for the gateway");
	check(learned.address == ip("192.168.5.248"),
	    "and an address nobody was heard using or probing for: .250 and .249 are");
	taken[0] = ip("192.168.5.248");
	check(ncfg_rescue_learn(heard, count, 3, taken, 1, &learned) &&
	    learned.address == ip("192.168.5.247"), "one a probe found in use is passed over");
	check(!ncfg_rescue_learn(heard, count, 9, NULL, 0, &learned) && learned.network == 0u,
	    "too little traffic says nothing");
	check(!ncfg_rescue_learn(heard + 5, 2, 1, NULL, 0, &learned), "link-local alone says nothing");
}

static void test_render_learned(void)
{
	ncfg_rescue_ports_t ports;
	ncfg_document_t    *document = NULL;
	char                text[8192];
	char                err[NCFG_ERROR_MAX];

	memset(&ports, 0, sizeof(ports));
	ports.count = 1;
	(void)snprintf(ports.ports[0].name, NCFG_RESCUE_NAME_MAX, "eno1");
	ports.ports[0].carrier = 1;
	(void)snprintf(ports.ports[0].learned, sizeof(ports.ports[0].learned), "192.168.5.248/24");
	(void)snprintf(ports.ports[0].gateway, sizeof(ports.ports[0].gateway), "192.168.5.1");
	check(ncfg_rescue_render(&ports, NCFG_RESCUE_RUNG_FORCE_100, "10.0.0.250/16", 0, 0, text,
	          sizeof(text), err, sizeof(err)) && compiles(text, &document),
	    "a learned address renders and compiles, at a later rung too");
	if (document) {
		check(document->interface_count == 1u && document->interfaces[0].addressing_count == 3u,
		    "beside DHCP and the fallback");
		check(document->interface_count == 1u && document->interfaces[0].route_count == 1u,
		    "with a default route through what was learned");
		ncfg_document_free(document);
	}
}

static void test_gateways(void)
{
	static const char table[] =
	    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	    "eno1\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	    "eno1\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	    "eno2\t00000000\t0100000A\t0001\t0\t0\t200\t00000000\t0\t0\t0\n"
	    "eno2\t00000000\t0100000A\t0003\t0\t0\t200\t00000000\t0\t0\t0\n";
	uint32_t       found[4];
	struct in_addr address;
	char           text[32];

	check(ncfg_rescue_default_gateways(table, found, 4) == 2u,
	    "two default routes with a gateway, the down one passed over");
	address.s_addr = found[0];
	check(strcmp(inet_ntop(AF_INET, &address, text, sizeof(text)), "192.168.2.1") == 0,
	    "the gateway in network order");
	check(ncfg_rescue_default_gateways("", found, 4) == 0u, "an empty table has none");
}

int main(void)
{
	const char *root = testdir_make("rescue");

	if (!root) {
		return 1;
	}
	test_ports(root);
	test_fallback();
	test_render();
	test_gateways();
	test_learn();
	test_render_learned();
	testdir_remove(root);
	check(!testdir_exists(root), "the test's directory is gone");
	printf("%s\n", failures ? "rescue_test: FAILED" : "rescue_test: all passed");
	return failures ? 1 : 0;
}
