/*
 * tun.h -- persistent tun and tap devices, which netlink cannot create.
 *
 * THE ONE LINK KIND THAT IS NOT AN `RTM_NEWLINK`
 *   Every other virtual link netcfgd makes -- a bridge, a bond, a VLAN, a
 *   VXLAN, a tunnel, a veth pair -- is a netlink message with a kind name in
 *   it, and lives in ops.h. A tun or tap device is not: it comes from a
 *   `TUNSETIFF` ioctl on `/dev/net/tun`, and it exists only as long as
 *   something holds that descriptor unless `TUNSETPERSIST` is set on it. That
 *   is why the kind sat in the schema for years with "in the schema and not
 *   implemented" written on it, and decision 0254 is the record of closing it.
 *
 * THE ORDER IS THE MODULE
 *   What `ip tuntap add` does, in the same order: open the clone device, ask
 *   for a name and a mode, hand it an owner and a group where the configuration
 *   names them, then make it persist and close. Two orderings in that are
 *   load-bearing and both are silent when wrong:
 *
 *     * **Owner and group before persistence.** A device that cannot be given
 *       the owner the document asked for is not left behind for somebody to
 *       find: closing the descriptor before persisting removes it. Measured --
 *       asking for a uid that is not mapped in the namespace fails with
 *       `EINVAL`, and no link remains.
 *     * **Persistence last, and it is the reason the device survives the
 *       call.** Without it the close deletes what was just made, and the call
 *       reports success over a machine with no such link. Sabotaged in the
 *       Rust and it failed exactly as predicted: the apply reported
 *       `link.create` as done and the next action failed with no such device.
 *
 *   **So the order is a value here rather than only a sequence of statements.**
 *   `ncfg_tun_plan` returns the ioctls in the order they must be made, and
 *   `ncfg_tun_create` does nothing but perform them. That is a divergence from
 *   the Rust, which writes the sequence out inline, and the reason is that the
 *   ordering is the one property of this module that cannot otherwise be
 *   checked without `CAP_NET_ADMIN` and a real device -- the C port's suite has
 *   neither, and an ordering nobody can assert on is an ordering that comes
 *   back wrong.
 *
 * `IFF_NO_PI` ALWAYS
 *   Which is what `ip tuntap add` does without saying so. Without it every
 *   packet carries a four-byte protocol header that nothing else on the machine
 *   expects, and the device looks subtly broken to whatever attaches to it
 *   rather than failing to appear.
 *
 * BOTH MODES, ONE KIND NAME
 *   The kernel registers one `rtnl_link_ops` for tun and tap alike, so
 *   `IFLA_INFO_KIND` says `tun` whichever was asked for and the mode is visible
 *   only in the link's own nest. A planner comparing kinds therefore catches a
 *   `tun` block whose name is held by something else and does **not** catch a
 *   block changed from `tun` to `tap`; 0254 records that rather than working
 *   around it, because telling them apart needs `IFLA_TUN_TYPE`, which the
 *   observation does not read.
 *
 * THE NUMBERS ARE THE KERNEL'S
 *   `TUNSETIFF` and its three neighbours come from <linux/if_tun.h>, which is
 *   where `_IOW('T', n, int)` is spelled once. The Rust writes them out because
 *   `libc` does not export them; a C port that copied the numbers across would
 *   be inventing a second place for them to be wrong. `tun_test.c` asserts the
 *   four against the values 0254 measured against `ip tuntap`, which is the
 *   check that keeps the header and the record honest about each other.
 */
#ifndef NCFG_TUN_H
#define NCFG_TUN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "ncfg/base.h"

/* The clone device every tun and tap comes from. */
#define NCFG_TUN_CLONE_DEVICE "/dev/net/tun"

/* `IFNAMSIZ`, written out rather than included, for the reason wire.h gives:
 * `linux/if.h` and `net/if.h` redefine each other's `struct ifreq`, and a
 * caller of this header is very likely to want the second. Checked against the
 * libc's own in tun.c. */
#define NCFG_TUN_NAME_MAX 16u

/* `struct ifreq` as `TUNSETIFF` reads it: a name, the flags, and a tail the
 * kernel ignores. Checked against the libc's `sizeof` in tun.c. */
#define NCFG_TUN_REQUEST_LEN 40u

/* Whether the device carries IP packets or ethernet frames. */
typedef enum {
	/* Layer 3: IP packets, no ethernet header. */
	NCFG_TUN_MODE_TUN = 0,
	/* Layer 2: full ethernet frames. */
	NCFG_TUN_MODE_TAP = 1
} ncfg_tun_mode_t;

/* The mode as the configuration language spells it -- which is the block's own
 * name, since `tun` and `tap` are two kinds to whoever writes one. NULL for a
 * mode this build does not know. */
const char *ncfg_tun_mode_name(ncfg_tun_mode_t mode);

/* The mode a block name asks for. 0 where the name is neither, which is a
 * caller's refusal to write rather than a default to pick: a `tap` block opened
 * as a `tun` is a device silently replaced by the other sort. */
int ncfg_tun_mode_from_name(const char *text, ncfg_tun_mode_t *out);

/*
 * `struct ifreq`, as `TUNSETIFF` reads it.
 *
 * Declared here rather than taken from the libc, whose union arm depends on the
 * version and would make the one field this needs -- the flags -- reachable
 * only through a cast. The kernel reads the name and the flags from this call
 * and nothing else, and the tail is padding it ignores.
 */
typedef struct {
	char    name[NCFG_TUN_NAME_MAX];
	int16_t flags;
	uint8_t padding[22];
} ncfg_tun_request_t;

/* What to make. `owner` and `group` are the ids permitted to attach to it,
 * where the configuration names them; a device with neither may be attached to
 * by root alone, which is the kernel's default and not something this
 * invents. */
typedef struct {
	const char     *name;
	ncfg_tun_mode_t mode;
	int             has_owner;
	uid_t           owner;
	int             has_group;
	gid_t           group;
} ncfg_tun_spec_t;

/*
 * The flags `TUNSETIFF` wants for this mode, with `IFF_NO_PI` beside them.
 *
 * Zero is not a valid answer, so a caller that gets one has asked for a mode
 * this build does not know.
 */
int16_t ncfg_tun_flags(ncfg_tun_mode_t mode);

/*
 * Fill in the `TUNSETIFF` request for a device.
 *
 * Refuses a name the kernel would not take -- empty, or too long to leave room
 * for its terminator -- before anything is opened. The name is copied into a
 * zeroed array, so it is NUL-terminated by construction.
 */
int ncfg_tun_request(const ncfg_tun_spec_t *spec, ncfg_tun_request_t *out,
    char *err, size_t err_size);

/* One ioctl, named. */
typedef struct {
	/* What it is called, for the sentence a failure becomes: an operator
	 * reading "TUNSETOWNER for tun0 failed" can look that up. */
	const char   *what;
	/* The request number. */
	unsigned long request;
	/* The integer argument, for the three that take one by value. */
	unsigned long value;
	/* Whether the argument is the `ifreq` rather than `value`. `TUNSETIFF`
	 * alone takes a pointer; the others take an integer, which is what the
	 * `_IOW('T', n, int)` encoding says. */
	int           is_request_struct;
} ncfg_tun_step_t;

/* Four at most: the mode, the owner, the group, and persistence. */
#define NCFG_TUN_STEPS_MAX 4u

/*
 * The ioctls to make, in the order they must be made.
 *
 * `out` holds at least `NCFG_TUN_STEPS_MAX`; `*count` is how many were filled
 * in. See the header comment for why this is a value: the order is the module,
 * and it is otherwise only observable on a machine with the privilege to make
 * a device.
 */
int ncfg_tun_plan(const ncfg_tun_spec_t *spec, ncfg_tun_step_t *out, size_t max,
    size_t *count, char *err, size_t err_size);

/*
 * Make a persistent tun or tap device.
 *
 * `clone_device` is `NCFG_TUN_CLONE_DEVICE` for every caller that is not a
 * test; it is a parameter for the reason radio.h's root is one, and a test
 * that hands it an ordinary file exercises the failure path without a
 * privilege or a device.
 *
 * The refusal names the step that failed, because the three that happen are
 * three different things to do about it: `EBUSY` from `TUNSETIFF` means a
 * device by that name already exists and is not a tun, `EPERM` means no
 * `CAP_NET_ADMIN`, and `ENOENT` on the open means the `tun` module is not
 * loaded. Flattening them into one message would leave an operator with no
 * next step.
 */
int ncfg_tun_create(const char *clone_device, const ncfg_tun_spec_t *spec,
    char *err, size_t err_size);

#endif /* NCFG_TUN_H */
