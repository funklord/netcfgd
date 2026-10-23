/*
 * subject_test.c -- the key that names what an action acts on.
 *
 * WHAT IS WORTH CHECKING
 *   Not that the function returns a string. What separates a key that three
 *   records can build on from one that only looks like it:
 *
 *     * **every op kind is classified or deliberately excluded.** A kind
 *       nobody gave a class to has no subject, which means nothing can lock
 *       or guard it -- and the switch's silence is the only way to find that
 *       out, so a test walks every kind rather than the ones somebody
 *       remembered. This is the check that fires when a new op arrives.
 *     * **two actions against one object share a subject**, because that is
 *       the whole point: a standing (0287) must survive `link.up` becoming
 *       `link.down`, and a lock (0290) must cover both directions of a
 *       change rather than one.
 *     * **a value that can be owned separately has a class of its own.** An
 *       MTU is not the link, so `mtu:eth0` and `link:eth0` differ -- without
 *       that, locking an MTU would stop the link coming up.
 *     * **distinct objects of one class differ**, or a list of addresses
 *       would show one row and a lock on one address would cover them all.
 *     * **truncation is refused rather than silently shortened**, because a
 *       key cut short can collide with another object's and then names the
 *       wrong thing.
 */
#include "ncfg/plan.h"

#include "ncfg/base.h"
#include "ncfg/document.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(int condition, const char *what)
{
	printf("%-70s %s\n", what, condition ? "ok" : "FAILED");
	if (!condition) {
		failures++;
	}
}

/* The subject of a zeroed op of this kind, or "" where there is none. */
static void subject_of_kind(int kind, char *out, size_t out_size)
{
	ncfg_op_t op;

	memset(&op, 0, sizeof(op));
	op.kind = kind;
	if (!ncfg_op_subject(&op, out, out_size)) {
		out[0] = '\0';
	}
}

int main(void)
{
	char      subject[NCFG_OP_SUBJECT_MAX];
	char      other[NCFG_OP_SUBJECT_MAX];
	ncfg_op_t op;
	int       kind;
	int       classified = 0;
	int       excluded = 0;
	int       unclassified = 0;

	/*
	 * **Every kind, walked rather than listed.** The commit family is the
	 * deliberate exclusion -- arming and confirming a window are how a change
	 * is made safely rather than configuration, and a lock over them would
	 * cover the mechanism that rescues a locked-out machine.
	 */
	/* **Bounded by the enum's last member, not by the last one I remembered.**
	 * This read `<= NCFG_OP_COMMIT_CONFIRM` first and counted 45 classified
	 * and 2 excluded of 47, which is the loop stopping one short of
	 * `NCFG_OP_COMMIT_REVERT` -- found by the excluded count rather than by
	 * the completeness check, which is the argument for asserting both. */
	for (kind = 0; kind <= NCFG_OP_COMMIT_REVERT; kind++) {
		subject_of_kind(kind, subject, sizeof(subject));
		if (subject[0] != '\0') {
			classified++;
			continue;
		}
		if (kind == NCFG_OP_COMMIT_ARM || kind == NCFG_OP_COMMIT_CONFIRM ||
		    kind == NCFG_OP_COMMIT_REVERT) {
			excluded++;
			continue;
		}
		unclassified++;
		printf("  no subject for op kind %d\n", kind);
	}
	check(unclassified == 0,
	    "every op kind has a subject or is one of the three deliberately without");
	printf("  %d classified, %d excluded\n", classified, excluded);
	check(excluded == 3, "  and the three are the commit family, which is not configuration");

	/* Two actions against one object share a subject. */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_UP;
	op.u.named.name = "eth0";
	check(ncfg_op_subject(&op, subject, sizeof(subject)) && strcmp(subject, "link:eth0") == 0,
	    "a link's subject is its class and its name");
	op.kind = NCFG_OP_LINK_DOWN;
	check(ncfg_op_subject(&op, other, sizeof(other)) && strcmp(other, subject) == 0,
	    "  and bringing it down names the same object as bringing it up");

	/* A value owned separately from the link it sits on. */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_LINK_SET_MTU;
	op.u.set_mtu.name = "eth0";
	op.u.set_mtu.mtu = 9000;
	check(ncfg_op_subject(&op, other, sizeof(other)) && strcmp(other, "mtu:eth0") == 0 &&
	    strcmp(other, subject) != 0,
	    "an MTU is its own subject, so locking it does not stop the link coming up");

	/* Distinct objects of one class differ, and the two sides of one object
	 * do not. */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_ADDR_ADD;
	op.u.addr_add.iface = "eth0";
	op.u.addr_add.addr = "192.0.2.10/24";
	check(ncfg_op_subject(&op, subject, sizeof(subject)) &&
	    strcmp(subject, "addr:eth0/192.0.2.10/24") == 0,
	    "an address is named by its interface and the address itself");
	op.u.addr_add.addr = "192.0.2.11/24";
	check(ncfg_op_subject(&op, other, sizeof(other)) && strcmp(other, subject) != 0,
	    "  so two addresses on one interface are two subjects");
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_ADDR_DEL;
	op.u.addr_del.iface = "eth0";
	op.u.addr_del.addr = "192.0.2.10/24";
	check(ncfg_op_subject(&op, other, sizeof(other)) && strcmp(other, subject) == 0,
	    "  and removing one names what adding it named");

	/* Host-wide objects say `host` rather than leaving the scope empty, so a
	 * reader needs no list of which classes are host-wide to parse a key. */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_NAT_REPLACE;
	check(ncfg_op_subject(&op, other, sizeof(other)) && strcmp(other, "nat:host") == 0,
	    "a host-wide object is scoped to `host` rather than to nothing");

	/* Truncation is a refusal. */
	memset(&op, 0, sizeof(op));
	op.kind = NCFG_OP_ADDR_ADD;
	op.u.addr_add.iface = "eth0";
	op.u.addr_add.addr = "192.0.2.10/24";
	check(!ncfg_op_subject(&op, other, 8u) && other[0] == '\0',
	    "a buffer too small is refused and left empty, never truncated into a collision");

	if (failures > 0) {
		printf("subject: %d check(s) failed\n", failures);
		return 1;
	}
	printf("subject: every check passed\n");
	return 0;
}
