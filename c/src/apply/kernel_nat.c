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

#include "ncfg/base.h"

#include <stdio.h>
#include <string.h>

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

int ncfg_kernel_build_nat(ncfg_buf_t *out, uint32_t first_seq, int table_exists,
    const ncfg_op_t *op, ncfg_nft_batch_t *batch, char *err, size_t err_size)
{
	if (!op || !batch) {
		ncfg_error_set(err, err_size, "there is no NAT action to carry out");
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
	return ncfg_nft_build_replace_nat(out, first_seq, table_exists, op->u.nat.uplinks,
	    op->u.nat.uplink_count, batch, err, err_size);
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

int ncfg_kernel_nat_op(const ncfg_kernel_world_t *world, const ncfg_op_t *op, char *err,
    size_t err_size)
{
	ncfg_netlink_t   socket;
	ncfg_nft_batch_t batch;
	ncfg_buf_t       message;
	uint32_t         seq;
	int              exists = 0;
	int              ok;

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

	memset(&batch, 0, sizeof(batch));
	seq = ncfg_netlink_take_seq(&socket);
	ncfg_buf_init(&message, 0);
	ok = ncfg_kernel_build_nat(&message, seq, exists, op, &batch, err, err_size);
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
	}
	ncfg_buf_free(&message);
	ncfg_netlink_close(&socket);
	return ok;
}
