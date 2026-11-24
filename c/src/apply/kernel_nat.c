/*
 * kernel_nat.c -- replacing the one nftables table netcfgd owns.
 *
 * THE WHOLE LICENCE THIS OP HAS
 *   Decision 0022: netcfgd may own exactly one nftables table, named
 *   `netcfgd`, containing NAT and nothing else. It replaces that table
 *   wholesale on every apply and never writes to or deletes any other.
 *   `nft.h` is what enforces that -- no call it publishes takes a table or
 *   chain name, every read refuses a payload from another table, and the
 *   assembled transaction is audited as bytes before it is handed back -- so
 *   this file chooses nothing and only carries the op across.
 *
 * WHY THIS OPENS A SOCKET OF ITS OWN
 *   `NETLINK_NETFILTER` is a third protocol, and the executor's socket is
 *   rtnetlink. `kernel_genl.c` has the same arrangement for the same reason
 *   and the reason it gives applies here twice over: a machine that does no
 *   NAT never opens this at all, and nothing outlives the op.
 *
 * WHY THE TABLE IS DUMPED FIRST
 *   `ncfg_nft_build_replace_nat` needs to know whether `inet netcfgd` is there
 *   now, because the delete at the top of the transaction is conditional on
 *   it: deleting a table that is not there is `ENOENT`, one failure aborts the
 *   whole transaction, and the error an operator would then read is not "no
 *   table" but "no NAT".
 *
 *   The dump reads **every** table, in every family, which is deliberate and
 *   is not a leak: 0022 requires netcfgd to detect a second table doing source
 *   NAT at the same hook and report it, and detecting that means looking. What
 *   this file does with the rest is nothing at all -- `ncfg_nft_table_is_ours`
 *   compares the family and the name together, because `ip netcfgd` would be
 *   somebody else's table with the same name.
 *
 * IDEMPOTENCE IS FREE HERE AND IT IS WORTH SAYING WHY
 *   The transaction replaces the table whole, and `table_exists` is read again
 *   on every run. So the second apply of one plan builds a *different*
 *   transaction from the first -- one with the delete in it -- and leaves the
 *   kernel in the same state. That is the shape `plan.h` asks for, reached by
 *   asking the machine rather than by forgiving an errno.
 */
#include "kernel_internal.h"

#include "ncfg/apply.h"
#include "ncfg/base.h"
#include "ncfg/dhcp_server.h"
#include "ncfg/log.h"
#include "ncfg/state.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <linux/neighbour.h>
#include <linux/netfilter.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* The same deadline `kernel.c` and `kernel_genl.c` give a request. */
#define REQUEST_SECONDS 5

int ncfg_kernel_nat_table_seen(const ncfg_netlink_reply_t *reply)
{
	size_t i;

	if (!reply) {
		return 0;
	}
	for (i = 0; i < reply->count; i++) {
		ncfg_nft_table_t table;

		/*
		 * A payload this cannot read is skipped rather than failing the op.
		 * The dump covers every table on the machine, including ones written
		 * by container runtimes with attributes this port has never seen, and
		 * refusing the apply over somebody else's table would be netcfgd
		 * declining to configure NAT because Docker is running.
		 */
		if (!ncfg_nft_table_read(reply->items[i].bytes, reply->items[i].length, &table,
		    NULL, 0)) {
			continue;
		}
		if (ncfg_nft_table_is_ours(&table)) {
			return 1;
		}
	}
	return 0;
}

const char *ncfg_slot_dir(void)
{
	const char *dir = getenv("NCFG_SLOT_DIR");

	return dir && dir[0] ? dir : NCFG_SLOT_DIR;
}

/*
 * One slot's members as the kernel holds them, both families, appended. A set
 * that is not there has none, and says nothing; any other failure is said on
 * the log and is 0.
 */
static int slot_dump_one(ncfg_netlink_t *socket, const char *slot,
    ncfg_nft_slot_member_t **members, size_t *count)
{
	int ipv6;
	int ok = 1;

	for (ipv6 = 0; ipv6 < 2; ipv6++) {
		ncfg_netlink_reply_t reply;
		ncfg_buf_t           message;
		char                 detail[NCFG_ERROR_MAX];
		uint32_t             seq = ncfg_netlink_take_seq(socket);
		size_t               at;

		detail[0] = '\0';
		memset(&reply, 0, sizeof(reply));
		ncfg_buf_init(&message, 0);
		if (ncfg_nft_build_slot_dump(&message, seq, slot, ipv6, detail, sizeof(detail)) &&
		    ncfg_netlink_send_batch(socket, message.data, message.length, seq, &reply,
		        detail, sizeof(detail))) {
			for (at = 0; at < reply.count; at++) {
				if (!ncfg_nft_slot_members_read(reply.items[at].bytes,
				        reply.items[at].length, members, count, detail, sizeof(detail))) {
					ncfg_log_emitf("apply", NCFG_LOG_WARNING,
					    "slot `%s`: a member was not read: %s", slot, detail);
					ok = 0;
				}
			}
		} else if (strstr(detail, "ENOENT") == NULL &&
		    strstr(detail, "No such file") == NULL) {
			ncfg_log_emitf("apply", NCFG_LOG_WARNING,
			    "slot `%s`: its members could not be read: %s", slot, detail);
			ok = 0;
		}
		ncfg_netlink_reply_free(&reply);
		ncfg_buf_free(&message);
	}
	return ok;
}

/* Calls `visit` for every slot `firewall` declares. */
static void each_slot(const ncfg_firewall_t *firewall, void (*visit)(const char *, void *),
    void *context)
{
	const ncfg_firewall_chain_t *chains[3];
	size_t                       c, s;

	if (!firewall) {
		return;
	}
	chains[0] = &firewall->input;
	chains[1] = &firewall->forward;
	chains[2] = &firewall->output;
	for (c = 0; c < 3u; c++) {
		for (s = 0; s < chains[c]->slot_count; s++) {
			visit(chains[c]->slots[s].name, context);
		}
	}
}

typedef struct {
	ncfg_netlink_t          *socket;
	ncfg_nft_slot_member_t **members;
	size_t                  *count;
} slot_gather_t;

static void gather_from_kernel(const char *slot, void *context)
{
	slot_gather_t *gather = context;

	(void)slot_dump_one(gather->socket, slot, gather->members, gather->count);
}

/*
 * Whether the record at `path` already says what `text` says: the same
 * addresses in the same order, each expiry within two seconds -- an expiry is
 * worked out again from what is left, so it moves by a rounding between two
 * readings of one member. On a router the record is on flash (procd's
 * `NCFG_SLOT_DIR`, 10.915), and every apply rewriting every record would
 * wear it for nothing.
 */
/* Members in one order whatever order the kernel listed them in: a hash set
 * lists the same members differently from one dump to the next, and a record
 * written in that order would differ from itself. */
static int member_order(const void *left, const void *right)
{
	const ncfg_nft_slot_member_t *one = left;
	const ncfg_nft_slot_member_t *other = right;

	if (one->ipv6 != other->ipv6) {
		return one->ipv6 - other->ipv6;
	}
	return memcmp(one->address, other->address, sizeof(one->address));
}

static int record_unchanged(const char *path, const char *text)
{
	char        old[16384];
	FILE       *file = fopen(path, "re");
	size_t      length;
	const char *a;
	const char *b;

	if (!file) {
		return 0;
	}
	length = fread(old, 1u, sizeof(old) - 1u, file);
	(void)fclose(file);
	if (length == sizeof(old) - 1u) {
		return 0; /* too long to compare here: written again */
	}
	old[length] = '\0';
	a = old;
	b = text;
	while (*a && *b) {
		char      address_a[64], address_b[64];
		long long expires_a = 0, expires_b = 0;

		if (sscanf(a, "%63s %lld", address_a, &expires_a) != 2 ||
		    sscanf(b, "%63s %lld", address_b, &expires_b) != 2 ||
		    strcmp(address_a, address_b) != 0 || (expires_a == 0) != (expires_b == 0) ||
		    expires_a - expires_b > 2 || expires_b - expires_a > 2) {
			return 0;
		}
		a = strchr(a, '\n');
		b = strchr(b, '\n');
		if (!a || !b) {
			return !a && !b;
		}
		a++;
		b++;
	}
	return !*a && !*b;
}

/*
 * One slot's record, rewritten from what the kernel holds now (0340): after a
 * live write and after every replacement, so the file is the membership as of
 * the last change netcfgd made. A slot with no members has no file. A record
 * that cannot be written is said on the log and changes nothing else: the
 * kernel holds the membership, and only a reboot would show the difference.
 */
static void slot_record(ncfg_netlink_t *socket, const char *slot)
{
	ncfg_nft_slot_member_t *members = NULL;
	size_t                  count = 0;
	size_t                  at;
	char                    path[PATH_MAX];
	char                    why[NCFG_ERROR_MAX];
	ncfg_buf_t              text;
	const long long         now = (long long)time(NULL);
	const char             *dir = ncfg_slot_dir();

	if (!slot_dump_one(socket, slot, &members, &count)) {
		free(members);
		return; /* what the kernel holds is unknown, so the record stands */
	}
	if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir, slot) >= sizeof(path)) {
		free(members);
		return;
	}
	if (count == 0u) {
		if (unlink(path) != 0 && errno != ENOENT) {
			ncfg_log_emitf("apply", NCFG_LOG_WARNING,
			    "slot `%s`: its old record %s could not be removed: %s", slot, path,
			    strerror(errno));
		}
		free(members);
		return;
	}
	if (count > 1u) {
		qsort(members, count, sizeof(*members), member_order);
	}
	ncfg_buf_init(&text, 0);
	for (at = 0; at < count; at++) {
		char address[64];

		ncfg_nft_slot_member_text(&members[at], address, sizeof(address));
		ncfg_buf_addf(&text, "%s %lld\n", address, members[at].remaining_ms
		    ? now + (long long)((members[at].remaining_ms + 999u) / 1000u) : 0LL);
	}
	free(members);
	why[0] = '\0';
	if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
		ncfg_error_set(why, sizeof(why), "%s: %s", dir, strerror(errno));
	} else if (ncfg_buf_failed(&text)) {
		ncfg_error_set(why, sizeof(why), "out of memory");
	} else if (record_unchanged(path, ncfg_buf_text(&text))) {
		/* Already says so: nothing written. */
	} else if (!ncfg_write_atomically(path, text.data, text.length, 0600, why, sizeof(why)) &&
	    why[0] == '\0') {
		ncfg_error_set(why, sizeof(why), "the write failed");
	}
	if (why[0] != '\0') {
		ncfg_log_emitf("apply", NCFG_LOG_WARNING,
		    "slot `%s`: its members are in the kernel but not recorded, so a reboot would "
		    "empty it: %s", slot, why);
	}
	ncfg_buf_free(&text);
}

static void record_one(const char *slot, void *context)
{
	slot_record(context, slot);
}

/* The records of slots the firewall no longer declares, removed by the name
 * the directory gives, and only where that name is one a slot can have. */
static void slot_forget(const ncfg_firewall_t *firewall)
{
	DIR           *dir = opendir(ncfg_slot_dir());
	struct dirent *entry;

	if (!dir) {
		return;
	}
	while ((entry = readdir(dir)) != NULL) {
		const ncfg_firewall_chain_t *chains[3];
		size_t                       c, s;
		int                          declared = 0;
		char                         path[PATH_MAX];

		if (!ncfg_firewall_slot_name_valid(entry->d_name)) {
			continue;
		}
		if (firewall) {
			chains[0] = &firewall->input;
			chains[1] = &firewall->forward;
			chains[2] = &firewall->output;
			for (c = 0; c < 3u; c++) {
				for (s = 0; s < chains[c]->slot_count; s++) {
					declared = declared ||
					    strcmp(chains[c]->slots[s].name, entry->d_name) == 0;
				}
			}
		}
		if (!declared && (size_t)snprintf(path, sizeof(path), "%s/%s", ncfg_slot_dir(),
		        entry->d_name) < sizeof(path)) {
			(void)unlink(path);
		}
	}
	closedir(dir);
}

typedef struct {
	ncfg_nft_slot_member_t **members;
	size_t                  *count;
	long long                now;
} slot_restore_t;

/* One slot's record read back, its lapsed members left out. */
static void restore_one(const char *slot, void *context)
{
	slot_restore_t *restore = context;
	char            path[PATH_MAX];
	char            line[128];
	FILE           *file;

	if ((size_t)snprintf(path, sizeof(path), "%s/%s", ncfg_slot_dir(), slot) >= sizeof(path)) {
		return;
	}
	file = fopen(path, "re");
	if (!file) {
		return;
	}
	while (fgets(line, sizeof(line), file)) {
		char                    address[64];
		long long               expires = -1;
		ncfg_nft_slot_member_t  one;
		ncfg_nft_slot_member_t *grown;

		if (sscanf(line, "%63s %lld", address, &expires) != 2 || expires < 0 ||
		    (expires != 0 && expires <= restore->now) ||
		    !ncfg_nft_slot_member_parse(slot, address, &one)) {
			continue;
		}
		one.remaining_ms = expires ? (uint64_t)(expires - restore->now) * 1000u : 0u;
		grown = realloc(*restore->members, (*restore->count + 1u) * sizeof(*grown));
		if (!grown) {
			break;
		}
		*restore->members = grown;
		grown[(*restore->count)++] = one;
	}
	fclose(file);
}

/*
 * The members every declared slot is to start the new table with (0340):
 * where the table is there, what its sets hold; where it is not -- the first
 * apply after a boot -- what was recorded, less what has lapsed since.
 */
static void slot_members(ncfg_netlink_t *socket, int table_exists,
    const ncfg_firewall_t *firewall, ncfg_nft_slot_member_t **members, size_t *count)
{
	*members = NULL;
	*count = 0;
	if (table_exists) {
		slot_gather_t gather = { socket, members, count };

		each_slot(firewall, gather_from_kernel, &gather);
	} else {
		slot_restore_t restore = { members, count, (long long)time(NULL) };

		each_slot(firewall, restore_one, &restore);
	}
}

int ncfg_kernel_build_nat(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const ncfg_op_t *op, ncfg_nft_batch_t *batch, char *err, size_t err_size)
{
	return ncfg_kernel_build_nat_carrying(out, first_seq, table_exists, op, NULL, 0, batch,
	    err, err_size);
}

int ncfg_kernel_build_nat_carrying(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const ncfg_op_t *op, const ncfg_nft_slot_member_t *members, size_t member_count,
    ncfg_nft_batch_t *batch, char *err, size_t err_size)
{
	if (!op || !batch) {
		ncfg_error_set(err, err_size, "there is no nftables action to carry out");
		return 0;
	}
	/*
	 * A count with no list behind it is refused by
	 * `ncfg_nft_build_replace_nat` and **not a second time here**: that
	 * module already says it, and a duplicate check is a second rule about
	 * one field in the file least likely to be read when the first changes.
	 * Measured: with the check removed the refusal is unchanged.
	 */
	/*
	 * An empty set removes the table and puts nothing back, which is how a
	 * document that stops asking for NAT is honoured -- and it is a legitimate
	 * instruction rather than a caller that forgot to fill the list, because
	 * the planner emits the op only where the document and the machine
	 * disagree.
	 */
	/* The firewall rides in the same transaction (10.592): the table is
	 * replaced whole, so a NAT change that left it out would delete it. */
	if (op->u.nftables.offload.has) {
		ncfg_nft_offload_t offload;

		offload.hardware = op->u.nftables.offload.value == NCFG_FLOW_OFFLOAD_HARDWARE;
		offload.devices = op->u.nftables.offload_devices;
		offload.device_count = op->u.nftables.offload_device_count;
		return ncfg_nft_build_replace_carrying(out, first_seq, table_exists,
		    op->u.nftables.uplinks, op->u.nftables.uplink_count, op->u.nftables.firewall,
		    op->u.nftables.forwards, op->u.nftables.forward_count, &offload,
		    op->u.nftables.clamp, op->u.nftables.clamp_count, members, member_count, batch,
		    err, err_size);
	}
	return ncfg_nft_build_replace_carrying(out, first_seq, table_exists, op->u.nftables.uplinks,
	    op->u.nftables.uplink_count, op->u.nftables.firewall, op->u.nftables.forwards,
	    op->u.nftables.forward_count, NULL, op->u.nftables.clamp, op->u.nftables.clamp_count,
	    members, member_count, batch, err, err_size);
}

/*
 * The table dump, sent through the socket call that hands the payloads back.
 *
 * `ncfg_kernel_send` and its reporting twin free the reply, which is right for
 * every other op here -- a `RTM_NEWLINK` answers with an acknowledgement and
 * nothing to read. This one needs what came back, so the send is written out.
 */
static int tables_seen(ncfg_netlink_t *socket, int *exists, char *err, size_t err_size)
{
	ncfg_netlink_reply_t reply;
	ncfg_buf_t           message;
	char                 detail[NCFG_ERROR_MAX];
	uint32_t             seq = ncfg_netlink_take_seq(socket);
	int                  ok;

	*exists = 0;
	detail[0] = '\0';
	memset(&reply, 0, sizeof(reply));
	ncfg_buf_init(&message, 0);
	ok = ncfg_nft_build_table_dump(&message, seq, err, err_size);
	if (ok && ncfg_buf_failed(&message)) {
		ncfg_error_set(err, err_size, "could not build the nftables table dump");
		ok = 0;
	}
	if (ok) {
		ok = ncfg_netlink_send_batch(socket, message.data, message.length, seq, &reply,
		    detail, sizeof(detail));
		if (!ok) {
			ncfg_error_set(err, err_size, "could not read the nftables tables: %s",
			    detail);
		}
	}
	if (ok) {
		*exists = ncfg_kernel_nat_table_seen(&reply);
	}
	ncfg_netlink_reply_free(&reply);
	ncfg_buf_free(&message);
	return ok;
}

/* Whether the dump holds the UPnP table. */
static int upnp_table_seen(ncfg_netlink_t *socket, int *exists, char *err, size_t err_size)
{
	ncfg_netlink_reply_t reply;
	ncfg_buf_t           message;
	char                 detail[NCFG_ERROR_MAX];
	uint32_t             seq = ncfg_netlink_take_seq(socket);
	size_t               i;
	int                  ok;

	*exists = 0;
	detail[0] = '\0';
	memset(&reply, 0, sizeof(reply));
	ncfg_buf_init(&message, 0);
	ok = ncfg_nft_build_table_dump(&message, seq, err, err_size);
	if (ok) {
		ok = ncfg_netlink_send_batch(socket, message.data, message.length, seq, &reply,
		    detail, sizeof(detail));
		if (!ok) {
			ncfg_error_set(err, err_size, "could not read the nftables tables: %s",
			    detail);
		}
	}
	for (i = 0; ok && i < reply.count; i++) {
		ncfg_nft_table_t table;

		if (ncfg_nft_table_read(reply.items[i].bytes, reply.items[i].length, &table, NULL,
		        0) && table.family == NFPROTO_INET &&
		    strcmp(table.name, NCFG_NFT_UPNP_TABLE) == 0) {
			*exists = 1;
		}
	}
	ncfg_netlink_reply_free(&reply);
	ncfg_buf_free(&message);
	return ok;
}

int ncfg_kernel_upnp_table(int wanted, char *err, size_t err_size)
{
	ncfg_netlink_t   socket;
	ncfg_nft_batch_t batch;
	ncfg_buf_t       message;
	int              exists = 0;
	int              ok;

	ncfg_netlink_init(&socket);
	if (!ncfg_netlink_open_protocol(&socket, NCFG_NFT_NETLINK_PROTOCOL, 0, err, err_size)) {
		char detail[NCFG_ERROR_MAX];

		(void)snprintf(detail, sizeof(detail), "%s", err);
		ncfg_error_set(err, err_size,
		    "cannot reach nftables for UPnP's table: %s. It needs `nf_tables` in this "
		    "kernel and CAP_NET_ADMIN in this namespace", detail);
		return 0;
	}
	if (!ncfg_netlink_set_timeout(&socket, REQUEST_SECONDS, err, err_size) ||
	    !upnp_table_seen(&socket, &exists, err, err_size)) {
		ncfg_netlink_close(&socket);
		return 0;
	}
	ncfg_buf_init(&message, 0);
	ok = ncfg_nft_build_upnp_table(&message, ncfg_netlink_take_seq(&socket), exists, wanted,
	    &batch, err, err_size);
	if (ok && !batch.empty) {
		ok = ncfg_kernel_send(&socket, &message, batch.last_acked, NCFG_OP_BACKEND_START,
		    wanted ? "make the `" NCFG_NFT_UPNP_TABLE "` table"
		           : "delete the `" NCFG_NFT_UPNP_TABLE "` table", err, err_size);
	}
	ncfg_buf_free(&message);
	ncfg_netlink_close(&socket);
	return ok;
}

int ncfg_kernel_nat_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size)
{
	ncfg_netlink_t   socket;
	ncfg_nft_batch_t        batch;
	ncfg_buf_t              message;
	uint32_t                seq;
	int                     exists = 0;
	int                     ok;
	ncfg_nft_slot_member_t *members = NULL;
	size_t                  member_count = 0;

	(void)world;
	ncfg_netlink_init(&socket);
	if (!ncfg_netlink_open_protocol(&socket, NCFG_NFT_NETLINK_PROTOCOL, 0, err, err_size)) {
		char detail[NCFG_ERROR_MAX];

		(void)snprintf(detail, sizeof(detail), "%s", err);
		ncfg_error_set(err, err_size,
		    "cannot reach nftables: %s. NAT needs `nf_tables` in this kernel and "
		    "CAP_NET_ADMIN in this namespace", detail);
		return 0;
	}
	/* The same five seconds every other request here waits, and for the same
	 * reason: a wedged transaction is worse than a reported failure. */
	if (!ncfg_netlink_set_timeout(&socket, REQUEST_SECONDS, err, err_size)) {
		ncfg_netlink_close(&socket);
		return 0;
	}
	if (!tables_seen(&socket, &exists, err, err_size)) {
		ncfg_netlink_close(&socket);
		return 0;
	}

	/* What each slot holds now, or held before a reboot, to be written into
	 * its new sets (0340). */
	slot_members(&socket, exists, op->u.nftables.firewall, &members, &member_count);
	memset(&batch, 0, sizeof(batch));
	seq = ncfg_netlink_take_seq(&socket);
	ncfg_buf_init(&message, 0);
	ok = ncfg_kernel_build_nat_carrying(&message, seq, exists, op, members, member_count,
	    &batch, err, err_size);
	free(members);
	if (ok && batch.empty) {
		/*
		 * **Nothing was built and nothing must be sent.** There was no table
		 * to remove and none to create, so the transaction would be a begin
		 * and an end with no contents -- which asks for no acknowledgement,
		 * receives no reply, and leaves the reply loop waiting out the
		 * deadline for a message the kernel was never going to send.
		 */
		ncfg_buf_free(&message);
		ncfg_netlink_close(&socket);
		return 1;
	}
	if (ok) {
		/*
		 * `batch.last_acked` and deliberately not the batch-end marker: the
		 * kernel acknowledges the messages *inside* a transaction and says
		 * nothing about its end, so waiting for the end waits for the
		 * timeout.
		 */
		ok = ncfg_kernel_send(&socket, &message, batch.last_acked, op->kind,
		    "replace the `" NCFG_NFT_TABLE "` table", err, err_size);
		/* The records follow the table: each declared slot's rewritten from
		 * what it now holds, and any other slot's removed. */
		if (ok) {
			each_slot(op->u.nftables.firewall, record_one, &socket);
			slot_forget(op->u.nftables.firewall);
		}
		/*
		 * **A hardware flowtable a driver cannot carry, named** (0319). The
		 * kernel answers `EOPNOTSUPP` for the whole transaction, and the
		 * generic sentence for that is about modules and link kinds, which
		 * sends an operator looking for the wrong thing. The flag is the one
		 * thing in this table only a driver can refuse.
		 */
		if (!ok && err && op->u.nftables.offload.has &&
		    op->u.nftables.offload.value == NCFG_FLOW_OFFLOAD_HARDWARE &&
		    strstr(err, "EOPNOTSUPP") != NULL) {
			ncfg_error_set(err, err_size,
			    "hardware flow offload was refused (EOPNOTSUPP): a driver of the devices "
			    "the flowtable names has no flow offload, and the table is one transaction, "
			    "so NAT and the firewall were not replaced either. `flow_offload = "
			    "\"software\"` works on every device (0319)");
		}
	}
	ncfg_buf_free(&message);
	ncfg_netlink_close(&socket);
	return ok;
}

/* The slot `name` declares, or NULL. */
static const ncfg_firewall_slot_t *declared_slot(const ncfg_document_t *desired,
    const char *name)
{
	const ncfg_firewall_chain_t *chains[3];
	size_t                       c, s;

	if (!desired || !desired->firewall || !name) {
		return NULL;
	}
	chains[0] = &desired->firewall->input;
	chains[1] = &desired->firewall->forward;
	chains[2] = &desired->firewall->output;
	for (c = 0; c < 3u; c++) {
		for (s = 0; s < chains[c]->slot_count; s++) {
			if (strcmp(chains[c]->slots[s].name, name) == 0) {
				return &chains[c]->slots[s];
			}
		}
	}
	return NULL;
}

int ncfg_firewall_slot_write(const ncfg_document_t *desired, const char *slot, int add,
    const char *address, const char *lifetime, char *err, size_t err_size)
{
	ncfg_netlink_t   socket;
	ncfg_nft_batch_t batch;
	ncfg_buf_t       message;
	int64_t          seconds = 0;
	int              code = 0;
	int              ok;

	if (!declared_slot(desired, slot)) {
		ncfg_error_set(err, err_size,
		    "`%s` is not a slot this configuration opens, so it is a static value and "
		    "is not written live (0339); a chain opens one with `slot \"%s\" { ... }`",
		    slot ? slot : "", slot ? slot : "");
		return 0;
	}
	if (lifetime && lifetime[0] && !ncfg_firewall_duration(lifetime, &seconds)) {
		ncfg_error_set(err, err_size,
		    "`%s` is not a lifetime: a count and s, m, h or d, such as \"30m\", a week at most",
		    lifetime);
		return 0;
	}
	if (!add && lifetime && lifetime[0]) {
		ncfg_error_set(err, err_size, "a lifetime is for a member being added");
		return 0;
	}
	ncfg_buf_init(&message, 0);
	ncfg_netlink_init(&socket);
	if (!ncfg_nft_build_slot_write(&message, 1u, slot, add, address, (uint64_t)seconds, &batch,
	        err, err_size)) {
		ncfg_buf_free(&message);
		return 0;
	}
	if (!ncfg_netlink_open_protocol(&socket, NCFG_NFT_NETLINK_PROTOCOL, 0, err, err_size) ||
	    !ncfg_netlink_set_timeout(&socket, REQUEST_SECONDS, err, err_size)) {
		ncfg_buf_free(&message);
		ncfg_netlink_close(&socket);
		return 0;
	}
	/* The sequence numbers the socket hands out, rather than the 1 the
	 * transaction was checked with: rebuilt once the socket exists. */
	ncfg_buf_free(&message);
	ncfg_buf_init(&message, 0);
	ok = ncfg_nft_build_slot_write(&message, ncfg_netlink_take_seq(&socket), slot, add,
	    address, (uint64_t)seconds, &batch, err, err_size);
	if (ok) {
		ok = ncfg_kernel_send_reporting(&socket, &message, batch.last_acked, &code,
		    add ? "add a member to a slot" : "remove a member from a slot", err, err_size);
	}
	if (!ok && (code == ENOENT || code == -ENOENT)) {
		if (!add) {
			ok = 1; /* not a member: what removing it asks for */
		} else {
			ncfg_error_set(err, err_size,
			    "slot `%s` is declared but not in the kernel yet: `ncfg apply` puts it there",
			    slot);
		}
	}
	if (ok) {
		slot_record(&socket, slot);
	}
	ncfg_buf_free(&message);
	ncfg_netlink_close(&socket);
	return ok;
}

static void free_texts(char **list, size_t count)
{
	size_t at;

	for (at = 0; list && at < count; at++) {
		free(list[at]);
	}
	free(list);
}

/*
 * The addresses the kernel's neighbour table holds for `clients` (10.934),
 * both families, appended to `*out` where not there already: a client with
 * a static address, or the IPv6 addresses no DHCPv4 lease names. A dump
 * that cannot be had adds nothing, says so on the log and sets `*partial`:
 * what was not read is not a client gone, so the caller takes nothing out
 * on such a pass. 0 only for a failed allocation.
 */
static int neighbour_clients(char *const *clients, size_t client_count, char ***out,
    size_t *count, int *partial)
{
	ncfg_netlink_t       socket;
	ncfg_netlink_reply_t reply;
	ncfg_buf_t           body;
	struct ndmsg         head;
	char                 detail[NCFG_ERROR_MAX];
	size_t               at;
	int                  ok = 1;

	memset(&reply, 0, sizeof(reply));
	memset(&head, 0, sizeof(head));
	head.ndm_family = AF_UNSPEC;
	ncfg_buf_init(&body, 0);
	ncfg_buf_add(&body, &head, sizeof(head));
	ncfg_netlink_init(&socket);
	if (!ncfg_netlink_open_protocol(&socket, NETLINK_ROUTE, 0, detail, sizeof(detail)) ||
	    !ncfg_netlink_set_timeout(&socket, REQUEST_SECONDS, detail, sizeof(detail)) ||
	    !ncfg_netlink_request(&socket, RTM_GETNEIGH, ncfg_dump_flags(), &body, NULL, &reply,
	        detail, sizeof(detail))) {
		ncfg_log_emitf("apply", NCFG_LOG_WARNING,
		    "the neighbour table could not be read for zones' clients: %s", detail);
		*partial = 1;
		ncfg_netlink_reply_free(&reply);
		ncfg_netlink_close(&socket);
		ncfg_buf_free(&body);
		return 1;
	}
	ncfg_netlink_close(&socket);
	ncfg_buf_free(&body);
	for (at = 0; ok && at < reply.count; at++) {
		char   address[64];
		char   mac[18];
		size_t one;
		int    ours = 0;
		int    again = 0;

		if (!ncfg_dump_neighbour(reply.items[at].bytes, reply.items[at].length, address,
		        sizeof(address), mac, sizeof(mac))) {
			continue;
		}
		for (one = 0; one < client_count; one++) {
			ours = ours || strcasecmp(mac, clients[one]) == 0;
		}
		for (one = 0; ours && one < *count; one++) {
			again = again || strcmp((*out)[one], address) == 0;
		}
		if (ours && !again) {
			char **grown = realloc(*out, (*count + 1u) * sizeof(**out));

			if (!grown || !(grown[*count] = strdup(address))) {
				if (grown) {
					*out = grown;
				}
				ok = 0;
				continue;
			}
			*out = grown;
			(*count)++;
		}
	}
	ncfg_netlink_reply_free(&reply);
	return ok;
}

/* Whether any access point here has a key naming `zone` (10.935). */
static int zone_has_keys(const ncfg_document_t *desired, const char *zone)
{
	size_t point;
	size_t key;

	for (point = 0; point < desired->access_point_count; point++) {
		for (key = 0; key < desired->access_points[point].key_count; key++) {
			const char *named = desired->access_points[point].keys[key].zone;

			if (named && strcmp(named, zone) == 0) {
				return 1;
			}
		}
	}
	return 0;
}

/*
 * The stations that joined one of this host's access points with a key that
 * names `zone` (10.935), as hardware addresses appended to `*out`: from what
 * the observation read of each, `ADDRESS KEYID`. 0 only for a failed
 * allocation.
 */
static int keyed_clients(const ncfg_document_t *desired, const ncfg_observed_t *observed,
    const char *zone, char ***out, size_t *count)
{
	size_t point;
	size_t at;

	for (point = 0; observed && point < desired->access_point_count; point++) {
		const ncfg_access_point_t *ap = &desired->access_points[point];

		for (at = 0; ap->device && at < observed->backend_count; at++) {
			const ncfg_observed_backend_t *backend = &observed->backends[at];
			size_t                         one;

			if (!backend->access_control || !backend->interface ||
			    strcmp(backend->interface, ap->device) != 0) {
				continue;
			}
			for (one = 0; one < backend->access_control->keyed_count; one++) {
				const char *pair = backend->access_control->keyed[one];
				const char *space = strchr(pair, ' ');
				size_t      key;
				int         ours = 0;

				for (key = 0; space && key < ap->key_count; key++) {
					ours = ours || (ap->keys[key].zone &&
					    strcmp(ap->keys[key].zone, zone) == 0 &&
					    strcmp(ap->keys[key].name, space + 1) == 0);
				}
				if (ours) {
					char **grown = realloc(*out, (*count + 1u) * sizeof(**out));

					if (!grown) {
						return 0;
					}
					*out = grown;
					(*out)[*count] = strndup(pair, (size_t)(space - pair));
					if (!(*out)[*count]) {
						return 0;
					}
					(*count)++;
				}
			}
		}
	}
	return 1;
}

int ncfg_firewall_zone_clients_sync(const ncfg_document_t *desired,
    const ncfg_observed_t *observed, const char *run, char *err, size_t err_size)
{
	size_t z;
	int    ok = 1;

	for (z = 0; desired && desired->firewall && z < desired->zone_count; z++) {
		const ncfg_zone_t      *zone = &desired->zones[z];
		ncfg_nft_slot_member_t *members = NULL;
		size_t                  member_count = 0;
		char                  **wanted = NULL;
		size_t                  wanted_count = 0;
		ncfg_netlink_t          socket;
		size_t                  at;
		size_t                  other;
		int                     partial = 0;
		char                  **clients = NULL;
		size_t                  client_count = 0;
		int                     gathered;

		if (!declared_slot(desired, zone->name)) {
			continue;
		}
		/* The zone's clients: those it names, and those a key of this host's
		 * access points put in it (10.935). */
		gathered = keyed_clients(desired, observed, zone->name, &clients, &client_count);
		for (at = 0; gathered && at < zone->client_count; at++) {
			char **grown = realloc(clients, (client_count + 1u) * sizeof(*clients));

			gathered = grown != NULL;
			if (grown) {
				clients = grown;
				clients[client_count] = strdup(zone->clients[at]);
				gathered = clients[client_count] != NULL;
				client_count += (size_t)gathered;
			}
		}
		if (!client_count && gathered) {
			/* A zone with no clients and no keyed station: nothing to keep
			 * unless something is in its slot -- a station that left. Read
			 * on, so it is taken out. */
			if (!zone->client_count && !zone_has_keys(desired, zone->name)) {
				free(clients);
				continue;
			}
		}
		if (!gathered ||
		    !ncfg_dhcp_server_zone_clients(run, desired, clients, client_count,
		        &wanted, &wanted_count, &partial) ||
		    !neighbour_clients(clients, client_count, &wanted, &wanted_count,
		        &partial)) {
			free_texts(clients, client_count);
			free_texts(wanted, wanted_count);
			ncfg_error_set(err, err_size, "out of memory reading zone `%s`'s leases",
			    zone->name);
			return 0;
		}
		ncfg_netlink_init(&socket);
		if (!ncfg_netlink_open_protocol(&socket, NCFG_NFT_NETLINK_PROTOCOL, 0, err,
		        err_size) ||
		    !ncfg_netlink_set_timeout(&socket, REQUEST_SECONDS, err, err_size) ||
		    !slot_dump_one(&socket, zone->name, &members, &member_count)) {
			ncfg_netlink_close(&socket);
			free(members);
			free_texts(wanted, wanted_count);
			free_texts(clients, client_count);
			ok = 0;
			continue;
		}
		ncfg_netlink_close(&socket);
		/* In: a client's address the slot does not hold yet. */
		for (at = 0; at < wanted_count; at++) {
			int held = 0;

			for (other = 0; other < member_count; other++) {
				char shown[64];

				ncfg_nft_slot_member_text(&members[other], shown, sizeof(shown));
				held = held || strcmp(shown, wanted[at]) == 0;
			}
			if (!held) {
				char why[NCFG_ERROR_MAX];

				if (ncfg_firewall_slot_write(desired, zone->name, 1, wanted[at], NULL, why,
				        sizeof(why))) {
					ncfg_log_emitf("apply", NCFG_LOG_INFO,
					    "zone `%s`: %s, a client's lease, is in", zone->name, wanted[at]);
				} else if (!strstr(why, "not in the kernel yet")) {
					/* Before the first apply the slot is not there to fill;
					 * the next pass after it does. */
					ncfg_log_emitf("apply", NCFG_LOG_WARNING,
					    "zone `%s`: %s could not be put in: %s", zone->name, wanted[at], why);
					ok = 0;
				}
			}
		}
		/* Out: anything else the slot holds -- a lease that ended, or an
		 * address now leased to a device that is not a client. The zone's
		 * slot is the zone's: a member written by hand goes too. **Never on
		 * a pass that could not read where clients are**: a table that timed
		 * out under load once emptied the slot and freed a capped client. */
		for (other = 0; !partial && other < member_count; other++) {
			char shown[64];
			int  kept = 0;

			ncfg_nft_slot_member_text(&members[other], shown, sizeof(shown));
			for (at = 0; at < wanted_count; at++) {
				kept = kept || strcmp(shown, wanted[at]) == 0;
			}
			if (!kept) {
				char why[NCFG_ERROR_MAX];

				if (ncfg_firewall_slot_write(desired, zone->name, 0, shown, NULL, why,
				        sizeof(why))) {
					ncfg_log_emitf("apply", NCFG_LOG_INFO,
					    "zone `%s`: %s holds no client's lease, and is out", zone->name,
					    shown);
				} else {
					ncfg_log_emitf("apply", NCFG_LOG_WARNING,
					    "zone `%s`: %s could not be taken out: %s", zone->name, shown, why);
					ok = 0;
				}
			}
		}
		free(members);
		free_texts(wanted, wanted_count);
		free_texts(clients, client_count);
	}
	if (!ok) {
		ncfg_error_set(err, err_size, "a zone's clients were not all brought up to date");
	}
	return ok;
}
