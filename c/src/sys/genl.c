/*
 * genl.c -- the family lookup described in genl.h.
 *
 * Nothing here opens, reads or writes a descriptor. What arrives is bytes a
 * caller already has, and they are treated as hostile for the reason wire.c
 * gives: a reply that came from the kernel came through a socket, and on a
 * socket subscribed to the controller's `notify` group it also carries
 * announcements about families nobody asked about.
 */
#include "ncfg/genl.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/*
 * The header length genl.h publishes is the kernel's, and here is the proof.
 *
 * `GENL_HDRLEN` is `NLMSG_ALIGN(sizeof(struct genlmsghdr))`, so this pins both
 * the struct and the alignment the attributes start after. A port that wrote
 * `4` because the Rust wrote `4` would carry a number nobody had checked
 * against the machine it runs on.
 */
_Static_assert(sizeof(struct genlmsghdr) == 4u, "genlmsghdr is four bytes");
_Static_assert(GENL_HDRLEN == NCFG_GENL_HDR_LEN, "the attributes start after four bytes");
_Static_assert(NCFG_GENL_NAME_MAX == GENL_NAMSIZ, "a family name is GENL_NAMSIZ bytes");

/*
 * The controller's interface version.
 *
 * One, and it has never been anything else. Written here rather than taken
 * from a caller because a version the controller does not implement is
 * answered with `EOPNOTSUPP` naming nothing.
 */
#define CTRL_VERSION 1u

/* How many groups a family is expected to publish before the array grows.
 * `nlctrl` publishes one and `nl80211` six; the growth below handles a family
 * that publishes forty, and this keeps the ordinary case to one allocation. */
#define GROUPS_FIRST 8u

void ncfg_genl_header_encode(const ncfg_genl_header_t *header, ncfg_buf_t *out)
{
	unsigned char bytes[NCFG_GENL_HDR_LEN];

	if (!out || out->failed) {
		return;
	}
	if (!header) {
		out->failed = 1;
		return;
	}
	bytes[0] = header->cmd;
	bytes[1] = header->version;
	/* `reserved`: two bytes the kernel neither reads nor sets. Written as
	 * zeroes rather than left alone, because "left alone" in C is whatever
	 * the buffer held, and a request that carries uninitialised memory is a
	 * request that carries whatever was freed before it. */
	bytes[2] = 0;
	bytes[3] = 0;
	ncfg_buf_add(out, bytes, sizeof(bytes));
}

int ncfg_genl_header_decode(const void *bytes, size_t length, ncfg_genl_header_t *out,
    char *err, size_t err_size)
{
	const unsigned char *raw = bytes;

	if (!raw || !out || length < NCFG_GENL_HDR_LEN) {
		ncfg_error_set(err, err_size,
		    "a generic netlink header is %u bytes and this payload has %zu",
		    (unsigned)NCFG_GENL_HDR_LEN, raw ? length : (size_t)0);
		return 0;
	}
	out->cmd = raw[0];
	out->version = raw[1];
	return 1;
}

int ncfg_genl_payload_attrs(const void *payload, size_t length, ncfg_wire_attrs_t *out,
    char *err, size_t err_size)
{
	const unsigned char *raw = payload;

	if (!out) {
		ncfg_error_set(err, err_size, "an attribute area needs somewhere to go");
		return 0;
	}
	ncfg_wire_attrs_start(out, NULL, 0);
	if (!raw || length < NCFG_GENL_HDR_LEN) {
		ncfg_error_set(err, err_size,
		    "a generic netlink payload of %zu bytes has no attributes behind its "
		    "%u-byte header", raw ? length : (size_t)0, (unsigned)NCFG_GENL_HDR_LEN);
		return 0;
	}
	ncfg_wire_attrs_start(out, raw + NCFG_GENL_HDR_LEN, length - NCFG_GENL_HDR_LEN);
	return 1;
}

/* A name that could name a family at all. See `NCFG_GENL_NAME_MAX`. */
static int name_fits(const char *name, char *err, size_t err_size)
{
	size_t length;

	if (!name) {
		ncfg_error_set(err, err_size, "a family lookup needs a name");
		return 0;
	}
	length = strlen(name);
	if (length == 0) {
		ncfg_error_set(err, err_size, "the empty string does not name a family");
		return 0;
	}
	if (length >= NCFG_GENL_NAME_MAX) {
		ncfg_error_set(err, err_size,
		    "`%s` is %zu characters; a generic netlink family name is at most %u",
		    name, length, (unsigned)(NCFG_GENL_NAME_MAX - 1u));
		return 0;
	}
	return 1;
}

int ncfg_genl_getfamily_request(ncfg_buf_t *out, const char *name, uint32_t seq,
    char *err, size_t err_size)
{
	ncfg_genl_header_t header;
	ncfg_buf_t body;
	ncfg_buf_t attrs;
	int ok;

	if (!out) {
		ncfg_error_set(err, err_size, "a request needs somewhere to be built");
		return 0;
	}
	if (!name_fits(name, err, err_size)) {
		return 0;
	}
	header.cmd = CTRL_CMD_GETFAMILY;
	header.version = CTRL_VERSION;
	ncfg_buf_init(&body, 0);
	ncfg_buf_init(&attrs, 0);
	ncfg_genl_header_encode(&header, &body);
	/* NUL-terminated, which `ncfg_wire_attr_put_str` is: the controller
	 * compares the value with `nla_strcmp`, and a name sent without its
	 * terminator matches nothing at all. */
	ncfg_wire_attr_put_str(&attrs, CTRL_ATTR_FAMILY_NAME, name);
	ok = ncfg_wire_build_request(out, GENL_ID_CTRL, NLM_F_REQUEST, seq, &body, &attrs,
	    err, err_size);
	ncfg_buf_free(&body);
	ncfg_buf_free(&attrs);
	return ok;
}

int ncfg_genl_build_request(ncfg_buf_t *out, uint16_t family_id,
    const ncfg_genl_header_t *header, uint16_t flags, uint32_t seq,
    const ncfg_buf_t *attrs, char *err, size_t err_size)
{
	ncfg_buf_t body;
	int ok;

	if (!out || !header) {
		ncfg_error_set(err, err_size, "a request needs somewhere to be built");
		return 0;
	}
	if (family_id < GENL_MIN_ID) {
		/* Zero is the commonest way to get here: a family whose lookup
		 * failed and whose id was used anyway. Sent as it is, the kernel
		 * reads it as `NLMSG_NOOP` and answers nothing, so the failure
		 * arrives as a five-second timeout with no sentence in it. */
		ncfg_error_set(err, err_size,
		    "%u is not a generic netlink family id; the family was never resolved",
		    (unsigned)family_id);
		return 0;
	}
	ncfg_buf_init(&body, 0);
	ncfg_genl_header_encode(header, &body);
	ok = ncfg_wire_build_request(out, family_id, (uint16_t)(NLM_F_REQUEST | flags), seq,
	    &body, attrs, err, err_size);
	ncfg_buf_free(&body);
	return ok;
}

/* One entry of the groups array: a nest holding a name and an id. */
static int group_parse(const ncfg_wire_attr_t *entry, ncfg_genl_group_t *out,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t inside;
	ncfg_wire_attr_t attr;

	ncfg_wire_attrs_start(&inside, entry->value, entry->length);
	if (ncfg_wire_attrs_find(&inside, CTRL_ATTR_MCAST_GRP_NAME, &attr, err, err_size)
	    != NCFG_WIRE_OK) {
		return 0;
	}
	if (!ncfg_wire_attr_string(&attr, out->name, sizeof(out->name), err, err_size)) {
		return 0;
	}
	if (ncfg_wire_attrs_find(&inside, CTRL_ATTR_MCAST_GRP_ID, &attr, err, err_size)
	    != NCFG_WIRE_OK) {
		return 0;
	}
	/* Four bytes, where the family id beside it is two. Netlink is not
	 * consistent about integer widths and the attribute header gives no
	 * hint, so reading one with the wrong accessor has to fail loudly or it
	 * returns a number that is merely wrong. */
	return ncfg_wire_attr_u32(&attr, &out->id, err, err_size);
}

/*
 * How many entries the array holds for a given count.
 *
 * A function of the count rather than a field, because the family is a public
 * type and a capacity in it would be one more thing a caller could get wrong
 * -- `family.groups` is allocated here and read everywhere, and the count is
 * the only number anybody else needs.
 */
static size_t groups_capacity(size_t count)
{
	size_t capacity = GROUPS_FIRST;

	while (capacity < count && capacity <= SIZE_MAX / 2u) {
		capacity *= 2u;
	}
	return capacity;
}

static int groups_append(ncfg_genl_family_t *family, const ncfg_genl_group_t *group,
    char *err, size_t err_size)
{
	if (!family->groups || family->group_count == groups_capacity(family->group_count)) {
		size_t want = groups_capacity(family->group_count + 1u);
		ncfg_genl_group_t *bigger;

		if (want <= family->group_count || want > SIZE_MAX / sizeof(*bigger)) {
			ncfg_error_set(err, err_size, "too many multicast groups to hold");
			return 0;
		}
		bigger = realloc(family->groups, want * sizeof(*bigger));
		if (!bigger) {
			ncfg_error_set(err, err_size, "out of memory for a family's groups");
			return 0;
		}
		family->groups = bigger;
	}
	family->groups[family->group_count] = *group;
	family->group_count++;
	return 1;
}

static int groups_parse(ncfg_genl_family_t *family, const ncfg_wire_attr_t *nest,
    char *err, size_t err_size)
{
	ncfg_wire_attrs_t walk;
	ncfg_wire_attr_t entry;
	ncfg_wire_step_t step;

	/*
	 * The groups nest is an array: each attribute's *type* is an index
	 * rather than a meaning, and its value is another nest holding the name
	 * and the id. A reader that treated the index as a kind would find
	 * nothing and report a family with no groups -- which reads as "this
	 * kernel publishes no notifications" rather than as a parser fault.
	 */
	ncfg_wire_attrs_start(&walk, nest->value, nest->length);
	for (;;) {
		ncfg_genl_group_t group;

		step = ncfg_wire_attrs_next(&walk, &entry, err, err_size);
		if (step == NCFG_WIRE_END) {
			return 1;
		}
		if (step == NCFG_WIRE_BAD) {
			return 0;
		}
		memset(&group, 0, sizeof(group));
		if (!group_parse(&entry, &group, NULL, 0)) {
			/* An entry missing either half is skipped rather than fatal:
			 * the controller may publish attributes this port does not
			 * read, and a family's other groups are still usable. A
			 * malformed *area* is the case above, and is fatal. */
			continue;
		}
		if (!groups_append(family, &group, err, err_size)) {
			return 0;
		}
	}
}

int ncfg_genl_family_parse(const char *name, const void *payload, size_t length,
    ncfg_genl_family_t *out, char *err, size_t err_size)
{
	ncfg_wire_attrs_t attrs;
	ncfg_wire_attr_t attr;
	ncfg_wire_step_t step;

	if (!out) {
		ncfg_error_set(err, err_size, "a family needs somewhere to be written");
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if (!name_fits(name, err, err_size)) {
		return 0;
	}
	if (!ncfg_genl_payload_attrs(payload, length, &attrs, err, err_size)) {
		return 0;
	}

	/* See genl.h: a controller reply that names a different family is an
	 * announcement about somebody else, arriving on a socket that subscribed
	 * to notifications. Taking its id would resolve `wireguard` to whatever
	 * module loaded last. */
	step = ncfg_wire_attrs_find(&attrs, CTRL_ATTR_FAMILY_NAME, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_OK) {
		char reported[NCFG_GENL_NAME_MAX];

		if (!ncfg_wire_attr_string(&attr, reported, sizeof(reported), err, err_size)) {
			return 0;
		}
		if (strcmp(reported, name) != 0) {
			ncfg_error_set(err, err_size,
			    "the controller answered about `%s` when `%s` was asked for",
			    reported, name);
			return 0;
		}
	}

	step = ncfg_wire_attrs_find(&attrs, CTRL_ATTR_FAMILY_ID, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		return 0;
	}
	if (step == NCFG_WIRE_END) {
		ncfg_error_set(err, err_size,
		    "the controller answered about `%s` without a family id", name);
		return 0;
	}
	/*
	 * Two bytes, not four. Nothing in the attribute header says which this
	 * is, and the multicast group id beside it is four -- reading this one as
	 * four bytes fails, which surfaced as "the controller answered without a
	 * family id": an honest error for the wrong reason.
	 */
	if (!ncfg_wire_attr_u16(&attr, &out->id, err, err_size)) {
		return 0;
	}
	/* `name_fits` has already bounded this. */
	memcpy(out->name, name, strlen(name) + 1u);

	step = ncfg_wire_attrs_find(&attrs, CTRL_ATTR_MCAST_GROUPS, &attr, err, err_size);
	if (step == NCFG_WIRE_BAD) {
		ncfg_genl_family_free(out);
		return 0;
	}
	if (step == NCFG_WIRE_OK && !groups_parse(out, &attr, err, err_size)) {
		ncfg_genl_family_free(out);
		return 0;
	}
	return 1;
}

void ncfg_genl_family_free(ncfg_genl_family_t *family)
{
	if (!family) {
		return;
	}
	free(family->groups);
	memset(family, 0, sizeof(*family));
}

int ncfg_genl_family_group(const ncfg_genl_family_t *family, const char *name, uint32_t *out,
    char *err, size_t err_size)
{
	size_t index;

	if (!family || !name || !out) {
		ncfg_error_set(err, err_size, "a group lookup needs a family and a name");
		return 0;
	}
	for (index = 0; index < family->group_count; index++) {
		if (strcmp(family->groups[index].name, name) == 0) {
			*out = family->groups[index].id;
			return 1;
		}
	}
	ncfg_error_set(err, err_size,
	    "the `%s` family publishes no multicast group called `%s`", family->name, name);
	return 0;
}

int ncfg_genl_lookup_failed(const char *name, int error_number, char *err, size_t err_size)
{
	if (error_number == ENOENT) {
		ncfg_error_set(err, err_size,
		    "the kernel has no generic netlink family called `%s`; the module "
		    "providing it is probably not loaded", name ? name : "");
		return 0;
	}
	ncfg_error_set(err, err_size, "asking the controller about `%s` failed: %s",
	    name ? name : "", strerror(error_number));
	return 0;
}
