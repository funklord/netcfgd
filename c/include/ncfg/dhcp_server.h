/*
 * dhcp_server.h -- a DHCPv4 server, which netcfgd configures and does not
 * run itself (decision 0297).
 *
 * WHAT THIS IS
 *   netcfgd decides what an interface hands out and gives that to dnsmasq,
 *   one instance per interface with its DNS side off -- the split ra.h makes
 *   for radvd, and for its reason: a program that answers other machines'
 *   requests has a parser and a timer loop facing the network.
 *
 * WHAT WAS MEASURED, dnsmasq 2.91
 *   With `port=0` it offers no DNS server unless `dhcp-option=6` names one,
 *   and offers its own address as the router. Two instances on two
 *   interfaces both serve, with `bind-interfaces`. `dhcp-authoritative`
 *   refuses at once a client asking for an address from another network.
 *
 * WHERE THE FILES GO
 *   `<run>/dhcp-server/<iface>.conf`, `.pid`, `.log` and `.leases`, for
 *   hostapd's reason. The lease file is the record of who has which address,
 *   and is kept across a restart, so a changed range does not cost every
 *   client its lease.
 */
#ifndef NCFG_DHCP_SERVER_H
#define NCFG_DHCP_SERVER_H

#include <stddef.h>
#include <sys/types.h>

#include "ncfg/document.h"

#define NCFG_DHCP_SERVER_PATH_MAX 512
#define NCFG_DHCP_SERVER_SUMMARY_MAX 512

int ncfg_dhcp_server_config_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);
int ncfg_dhcp_server_pid_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);
int ncfg_dhcp_server_leases_path(const char *run, const char *iface, char *out, size_t out_size,
    char *err, size_t err_size);

/*
 * One line saying what an interface serves -- its range, lease and DNS
 * servers, as `192.168.1.100-192.168.1.249, 43200 s, dns 9.9.9.9`. The
 * generated file carries it as its second line and the planner computes it
 * from the document, so a changed policy is a difference an operator can
 * read in the plan. 0 where the interface serves nothing it can work out.
 */
int ncfg_dhcp_server_summary(const ncfg_interface_t *interface, char *out, size_t out_size);

/* The summary a running server's file carries, into `out`; 0 for none. */
int ncfg_dhcp_server_recorded(const char *run, const char *iface, char *out, size_t out_size);

/*
 * dnsmasq's configuration for one interface. Pure, so what is served can be
 * checked without serving it. Allocated; free with `free`. NULL with a
 * sentence where the interface's policy cannot be worked out.
 */
char *ncfg_dhcp_server_render(const ncfg_interface_t *interface, const char *leases_path,
    char *err, size_t err_size);

/*
 * Start serving on one interface. `program` is the dnsmasq to run, or NULL
 * to find one. 0 with a sentence naming what failed, quoting dnsmasq.
 */
int ncfg_dhcp_server_start(const char *run, const ncfg_interface_t *interface,
    const char *program, char *err, size_t err_size);

/*
 * Stop serving on one interface: by the pid file dnsmasq wrote, checked
 * against `/proc/<pid>/cmdline` naming the configuration netcfgd generated,
 * so an operator's own dnsmasq cannot match. Nothing running is success.
 */
int ncfg_dhcp_server_stop(const char *run, const char *iface, char *err, size_t err_size);

/* The pid of netcfgd's dnsmasq on this interface, or 0. */
pid_t ncfg_dhcp_server_running_pid(const char *run, const char *iface);

/*
 * The name and address netcfgd's DHCP servers have given the host with this
 * MAC (project.md 10.602): read out of every lease file under
 * `<run>/dhcp-server/`, which dnsmasq keeps as `<expiry> <mac> <address>
 * <name> <client id>`, so it answers for a station on a radio that is itself the served interface
 * and on one bridged into it alike -- a MAC is one host, whichever interface
 * leased to it.
 *
 * A lease that has expired by `now` is not one; an expiry of 0 never does.
 * **The name is the client's, and is untrusted**: it is given only where it
 * is a plain host name -- letters, digits, hyphens and dots, starting with a
 * letter or digit, at most 63 characters -- and otherwise `hostname` is left
 * empty while `address` is still given. 1 where a lease was found, with
 * either buffer possibly empty; 0 where none was.
 */
#define NCFG_DHCP_SERVER_HOSTNAME_MAX 64
int ncfg_dhcp_server_lease_of(const char *run, const char *mac, long long now, char *hostname,
    size_t hostname_size, char *address, size_t address_size);

#endif /* NCFG_DHCP_SERVER_H */
