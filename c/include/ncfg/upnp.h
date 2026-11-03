/*
 * upnp.h -- miniupnpd, for UPnP IGD and NAT-PMP/PCP on a router (0310).
 *
 * WHAT NETCFGD DOES AND WHAT MINIUPNPD DOES
 *   netcfgd writes a configuration under `<run>/upnp/`, makes the nftables
 *   table miniupnpd adds its mappings to, starts the daemon, and stops it
 *   and deletes the table. miniupnpd answers the clients and writes the
 *   mappings. Three facts measured in a vm decide that split, and 0310 has
 *   them: miniupnpd makes no table of its own, a rule it adds cannot pass
 *   netcfgd's own forward chain unless that chain accepts translated
 *   connections, and it leaves its mappings behind when it stops.
 *
 * THE TABLE IS NAMED HERE AND MADE BY THE EXECUTOR
 *   `inet netcfgd_upnp`, with three hooked chains that accept by policy and
 *   hold nothing until miniupnpd fills them. It is not netcfgd's own table,
 *   which is replaced on every apply -- that would drop every mapping on
 *   every apply -- and the nftables builder admits it by name (`nft.h`).
 *
 * A RUNNING DAEMON IS NETCFGD'S BY ITS CONFIGURATION PATH
 *   As dnsmasq is (`dhcp_server.h`): `-f <path>` in its own argv, a path
 *   netcfgd chose, and a pid file beside it.
 */
#ifndef NCFG_UPNP_H
#define NCFG_UPNP_H

#include "ncfg/document.h"
#include "ncfg/nft.h"

#include <stddef.h>
#include <sys/types.h>

#define NCFG_UPNP_PATH_MAX    512
#define NCFG_UPNP_SUMMARY_MAX 512

/* The table and its three chains, as miniupnpd is told them. */
#define NCFG_UPNP_TABLE            NCFG_NFT_UPNP_TABLE
#define NCFG_UPNP_CHAIN_FORWARD    NCFG_NFT_UPNP_CHAIN_FORWARD
#define NCFG_UPNP_CHAIN_PREROUTING NCFG_NFT_UPNP_CHAIN_PREROUTING
#define NCFG_UPNP_CHAIN_POSTROUTING NCFG_NFT_UPNP_CHAIN_POSTROUTING

int ncfg_upnp_config_path(const char *run, char *out, size_t out_size, char *err,
    size_t err_size);
int ncfg_upnp_pid_path(const char *run, char *out, size_t out_size, char *err, size_t err_size);
int ncfg_upnp_leases_path(const char *run, char *out, size_t out_size, char *err,
    size_t err_size);

/*
 * What a running miniupnpd was started to do, as one line: the uplink and the
 * LAN interfaces, in order. The first line of the configuration carries it, so
 * the planner can compare what is running against what is wanted without
 * reading miniupnpd's own keys back.
 */
int ncfg_upnp_summary(const ncfg_upnp_t *upnp, char *out, size_t out_size);
/* The summary a running daemon's configuration records, or 0. */
int ncfg_upnp_recorded(const char *run, char *out, size_t out_size);

/*
 * miniupnpd's configuration, allocated, or NULL with a sentence. `uuid` is
 * the device's identity in a UPnP client's list, and is the caller's so that
 * it stays one device across restarts.
 */
char *ncfg_upnp_render(const ncfg_upnp_t *upnp, const char *leases, const char *uuid, char *err,
    size_t err_size);

/* Write the configuration and start miniupnpd, which daemonizes. The table
 * must exist first: a mapping asked for before it does fails with UPnP error
 * 501. `program` NULL finds `miniupnpd`. */
int ncfg_upnp_start(const char *run, const ncfg_upnp_t *upnp, const char *program, char *err,
    size_t err_size);
/* SIGTERM, waited for. The leases stay: a start that follows restores the
 * mappings clients asked for. */
int ncfg_upnp_stop(const char *run, char *err, size_t err_size);
pid_t ncfg_upnp_running_pid(const char *run);

#endif /* NCFG_UPNP_H */
