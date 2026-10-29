/*
 * devlink.h -- a network card's ports as devlink describes them, read only.
 *
 * WHY DEVLINK, AND WHAT IT IS FOR HERE
 *   A VPI card -- the ConnectX family -- runs each port as InfiniBand or as
 *   Ethernet, and which one it is decides whether there is an Ethernet
 *   interface at all. Nothing in rtnetlink says so: a port in InfiniBand mode
 *   simply has no `eth` netdev, and the configuration naming one meets an
 *   interface that is not there. devlink is the kernel's own, vendor-neutral
 *   description of a device's ports, and its `PORT_GET` dump says each port's
 *   type and what it became -- which is what `ncfg status` reports.
 *
 * READ ONLY
 *   Setting the type is `DEVLINK_CMD_PORT_SET`, implemented in mainline by
 *   mlx4 alone, and it destroys the netdev it replaces. That is not built;
 *   project.md 10.586 says what would have to be decided first.
 *
 * THE NUMBERS ARE THE KERNEL'S
 *   From <linux/devlink.h>, for `genl.h`'s reason.
 */
#ifndef NCFG_DEVLINK_H
#define NCFG_DEVLINK_H

#include <stddef.h>
#include <stdint.h>

#include "ncfg/base.h"
#include "ncfg/buf.h"
#include "ncfg/genl.h"

/* `pci/0000:05:00.0`: a bus name, a slash and a device name, each of which the
 * kernel bounds well inside this. */
#define NCFG_DEVLINK_DEVICE_MAX 64
/* An interface name and its NUL. */
#define NCFG_DEVLINK_NETDEV_MAX 16
/* An RDMA device name -- `mlx4_0`, `rocep5s0` -- and its NUL. */
#define NCFG_DEVLINK_IBDEV_MAX 64

/* What a port is running as: the kernel's four answers. */
typedef enum {
	NCFG_DEVLINK_PORT_NOTSET = 0,
	NCFG_DEVLINK_PORT_AUTO,
	NCFG_DEVLINK_PORT_ETH,
	NCFG_DEVLINK_PORT_IB
} ncfg_devlink_port_type_t;

/* One port. Empty strings where the kernel did not say. */
typedef struct {
	char                     device[NCFG_DEVLINK_DEVICE_MAX];
	uint32_t                 index;
	ncfg_devlink_port_type_t type;
	/* Whether it is a physical port. The others -- a CPU port, a switch's
	 * internal ports, a virtual function's representor -- are not something a
	 * cable plugs into, and are not what `ncfg status` is asked about. */
	int                      physical;
	/* The Ethernet interface it became, where it is one. */
	char                     netdev[NCFG_DEVLINK_NETDEV_MAX];
	/* The RDMA device it became, where it is InfiniBand. */
	char                     ibdev[NCFG_DEVLINK_IBDEV_MAX];
} ncfg_devlink_port_t;

/* The word for a type, as the observation carries it. Never NULL. */
const char *ncfg_devlink_port_type_name(ncfg_devlink_port_type_t type);

/* A `PORT_GET` dump of every port of every device, to a family resolved. */
int ncfg_devlink_ports_request(ncfg_buf_t *out, const ncfg_genl_family_t *family, uint32_t seq,
    char *err, size_t err_size);

/*
 * One port out of one reply payload, the generic netlink header first.
 *
 * Refused where the device or the index is missing, since a port nobody can
 * name is not one an operator can act on, and where the type is one this
 * build has no word for -- printing a guessed mode is the thing this exists
 * to stop. A type that is absent is `NOTSET`, the kernel's own word for it.
 */
int ncfg_devlink_port_parse(const void *payload, size_t length, ncfg_devlink_port_t *out,
    char *err, size_t err_size);

#endif /* NCFG_DEVLINK_H */
