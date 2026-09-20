/*
 * daemon_world.c -- the four seams a pass reaches the machine through.
 *
 * WHY THESE ARE HERE AND NOT IN THE DAEMON MODULE
 *   `reconcile_pass.c` owns no descriptor: that is what makes every ordering
 *   in it a list a test reads back. The other side of that sentence is that
 *   somebody opens the apply lock, the netlink socket and the connections an
 *   event is written to -- and 0263 says that somebody is a `main`, for the
 *   same reason the watchers are here.
 *
 * WHAT A MISSING ONE COSTS, WHICH IS THE POINT OF THE SEAM
 *   `daemon.h` says every member of `ncfg_reconcile_world_t` may be NULL and
 *   the pass says what a NULL one costs. A loop with none of these observes,
 *   reports drift, runs its hooks and changes nothing -- which is what this
 *   port has had until now, and is why the four below are the whole of this
 *   file's subject.
 *
 * THE ORDERING THAT IS THE WHOLE OF `release_contended`
 *   Ask who is contending **before** opening an executor. The Rust asks
 *   afterwards, so on every machine netcfgd manages a backend on -- which is
 *   every laptop with wifi -- it takes the global apply lock and a netlink
 *   socket every five seconds to discover there is nothing to give back,
 *   against the same lock `ncfg apply` waits on (0184, and project.md
 *   10.169). The same instinct is carried one step further here: asking
 *   `ncfg_apply_supported` costs nothing, so the lock is not taken to be
 *   refused either -- and it is asked of the kinds that are actually running.
 *   Asking it of a representative op is what made that guard unreachable for
 *   as long as it existed; see `any_stop_is_supported`.
 *
 * THE SWEEP, WHICH IS THE OTHER HALF OF "A WRITE THAT FAILED"
 *   A subscriber used to be found dead only by writing to it, and a converged
 *   machine writes nothing -- so sixteen streams nobody was reading could hold
 *   every place in the list until something happened, and refuse the
 *   seventeenth `monitor` in the meantime. `ncfg_main_subscribers_prune` asks
 *   `poll` about the list's own descriptors with no wait at all, once a round.
 *   The decision it asks with is `daemon_wake.c`'s, like every other reading of
 *   a `revents` in this program, and it is **not** the one a source gets: a
 *   source's data wins over its hang-up because somebody drains it, and nothing
 *   drains a subscriber.
 */
#include "loop_internal.h"

#include "ncfg/json_write.h"
#include "ncfg/log.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ------------------------------------------------------------------------ *
 * Who is listening
 * ------------------------------------------------------------------------ */

void ncfg_main_subscribers_init(ncfg_main_subscribers_t *subscribers)
{
	if (!subscribers) {
		return;
	}
	memset(subscribers, 0, sizeof(*subscribers));
}

int ncfg_main_subscribers_add(ncfg_main_subscribers_t *subscribers, int fd, char *err,
    size_t err_size)
{
	int flags;

	if (!subscribers || fd < 0) {
		ncfg_error_set(err, err_size, "there is no stream to subscribe");
		return 0;
	}
	if (subscribers->count >= (size_t)NCFG_MAIN_SUBSCRIBERS_MAX) {
		ncfg_error_set(err, err_size,
		    "this daemon is already streaming events to %d clients, which is all it "
		    "carries at once", NCFG_MAIN_SUBSCRIBERS_MAX);
		return 0;
	}
	/*
	 * Non-blocking before it is in the list, never after: the loop writes from
	 * the thread that reconciles, and one blocking write to a client that
	 * stopped reading would stop the daemon reconciling for as long as the
	 * client felt like it.
	 */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		ncfg_error_set(err, err_size,
		    "this stream could not be made non-blocking (%s), and a blocking one would "
		    "let a client that stopped reading stop the daemon", strerror(errno));
		return 0;
	}
	subscribers->at[subscribers->count] = fd;
	subscribers->count++;
	return 1;
}

size_t ncfg_main_subscribers_prune(ncfg_main_subscribers_t *subscribers)
{
	struct pollfd waiting[NCFG_MAIN_SUBSCRIBERS_MAX];
	size_t        at;
	size_t        kept = 0;
	size_t        gone = 0;
	int           answered;

	if (!subscribers || subscribers->count == 0u) {
		return 0;
	}
	for (at = 0; at < subscribers->count; at++) {
		waiting[at].fd = subscribers->at[at];
		/*
		 * `POLLIN` is asked for so that `POLLHUP` is reported beside it rather
		 * than instead of it -- and it is asked for on a descriptor nothing
		 * reads, which is why `ncfg_main_subscriber_ended` may not read data as
		 * a reason to keep one. `POLLERR` and `POLLHUP` arrive whatever is
		 * requested.
		 */
		waiting[at].events = POLLIN;
		waiting[at].revents = 0;
	}
	/*
	 * Zero, never a wait. This runs on the loop's thread between the round's
	 * own `poll` and the pass, and a sweep that could block would be the
	 * daemon stopping to ask whether anybody had hung up.
	 *
	 * `EINTR` is not retried here for the same reason the timeout is zero:
	 * what is lost is one sweep, and the next round is a tick away. Every
	 * other failure means `poll` refused the whole set, and dropping sixteen
	 * live streams because one call failed is the wrong direction -- a
	 * subscriber kept is told one event too many, a subscriber dropped is a
	 * client that silently stops hearing.
	 */
	answered = poll(waiting, (nfds_t)subscribers->count, 0);
	if (answered <= 0) {
		return 0;
	}
	for (at = 0; at < subscribers->count; at++) {
		if (!ncfg_main_subscriber_ended(waiting[at].revents)) {
			subscribers->at[kept] = subscribers->at[at];
			kept++;
			continue;
		}
		/* Ordinary, and not worth a line each on a machine where a tray
		 * reconnects: the count is what a caller says it with, once. */
		(void)close(subscribers->at[at]);
		subscribers->dropped++;
		gone++;
	}
	subscribers->count = kept;
	return gone;
}

void ncfg_main_subscribers_close(ncfg_main_subscribers_t *subscribers)
{
	size_t at;

	if (!subscribers) {
		return;
	}
	for (at = 0; at < subscribers->count; at++) {
		(void)close(subscribers->at[at]);
	}
	subscribers->count = 0;
}

/*
 * One counted string as a member, or nothing where it is absent.
 *
 * `ncfg_proto_str_t` carries bytes and a length rather than a NUL, so the
 * writer's counted call is the one that can take it -- a summary the kernel
 * put a NUL in the middle of would otherwise be written as the part before it.
 * `required` writes an empty string rather than omitting the member, because
 * the decoder refuses an event missing one of those and a client reading a
 * missing `summary` as absent could not tell it from an event of another kind.
 */
static void write_str(ncfg_json_writer_t *writer, const char *name, ncfg_proto_str_t text,
    int required)
{
	if (!ncfg_proto_str_present(text)) {
		if (!required) {
			return;
		}
		ncfg_json_write_member_string(writer, name, "");
		return;
	}
	ncfg_json_write_key(writer, name);
	ncfg_json_write_string_bytes(writer, text.bytes, text.length);
}

int ncfg_main_event_encode(const ncfg_proto_event_t *event, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;
	const char        *name;

	if (!event || !out) {
		ncfg_error_set(err, err_size, "there is no event to write");
		return 0;
	}
	name = ncfg_proto_event_name(event->kind);
	if (!name) {
		/* An event outside the enum is a bug here rather than a client's
		 * doing, and writing `"event":null` would put a line on every monitor
		 * stream that no client can decode. */
		ncfg_error_set(err, err_size, "there is no event spelled %d", (int)event->kind);
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "event");
	ncfg_json_write_member_string(&writer, "event", name);
	switch (event->kind) {
	case NCFG_PROTO_EVENT_OBSERVED:
		write_str(&writer, "summary", event->summary, 1);
		break;
	case NCFG_PROTO_EVENT_RELOADED:
		ncfg_json_write_member_bool(&writer, "ok", event->ok ? 1 : 0);
		/* Omitted where it compiled, which is what the decoder reads as
		 * absent -- an empty string there would say the compiler had
		 * something to report and nothing to say. */
		write_str(&writer, "diagnostics", event->diagnostics, 0);
		break;
	case NCFG_PROTO_EVENT_DRIFT:
		write_str(&writer, "interface", event->interface, 1);
		write_str(&writer, "summary", event->summary, 1);
		write_str(&writer, "action", event->action, 1);
		break;
	case NCFG_PROTO_EVENT_CONFIRM_ARMED:
		ncfg_json_write_member_int(&writer, "seconds", event->seconds);
		break;
	case NCFG_PROTO_EVENT_CONFIRM_RESOLVED:
	case NCFG_PROTO_EVENT_COUNT:
	default:
		ncfg_json_write_member_bool(&writer, "confirmed", event->confirmed ? 1 : 0);
		break;
	}
	ncfg_json_write_object_end(&writer);
	if (!ncfg_json_write_done(&writer)) {
		const char *why = ncfg_json_write_failure(&writer);

		/* Failed rather than merely reported on, which is `answer.c`'s rule:
		 * `ncfg_buf_text` hands out the empty string for a failed buffer, so
		 * a writer that trusted it would send nothing and say it had sent an
		 * event. */
		out->failed = 1;
		ncfg_error_set(err, err_size, "the %s event could not be written: %s", name,
		    why ? why : "it was left unfinished");
		return 0;
	}
	return 1;
}

/*
 * Put one built line on a subscriber, or say it has gone.
 *
 * A short write is a gone subscriber and not a retry: what is on the wire is
 * then half a line, the next event would be read as its tail, and there is no
 * state a reader could recover from. `MSG_NOSIGNAL` for `answer.c`'s reason --
 * a daemon holding `CAP_NET_ADMIN` must not be killable by a client that hung
 * up.
 */
static int put_line(int fd, const char *bytes, size_t length)
{
	ssize_t put;

	for (;;) {
		put = send(fd, bytes, length, MSG_NOSIGNAL);
		if (put >= 0) {
			break;
		}
		if (errno == EINTR) {
			continue;
		}
		return 0;
	}
	return (size_t)put == length;
}

void ncfg_main_subscribers_tell(ncfg_main_subscribers_t *subscribers,
    const ncfg_proto_event_t *event)
{
	ncfg_buf_t line;
	char       err[NCFG_ERROR_MAX];
	const char *bytes;
	size_t      length;
	size_t      at;
	size_t      kept = 0;

	if (!subscribers || subscribers->count == 0u || !event) {
		return;
	}
	/* Once, not per subscriber: the line is the same for everybody and
	 * building it inside the walk would make the cost of an event scale with
	 * how many people are watching. */
	ncfg_buf_init(&line, NCFG_PROTO_MAX_LINE);
	err[0] = '\0';
	if (!ncfg_main_event_encode(event, &line, err, sizeof(err)) ||
	    !ncfg_proto_line_finish(&line, err, sizeof(err)) || ncfg_buf_failed(&line)) {
		ncfg_log_emitf("control", NCFG_LOG_ERROR,
		    "an event could not be serialised, which is a bug: %s. Nobody watching was "
		    "told about it.", err[0] ? err : "the line was never fully built");
		ncfg_buf_free(&line);
		return;
	}
	bytes = ncfg_buf_text(&line);
	length = line.length;

	for (at = 0; at < subscribers->count; at++) {
		int fd = subscribers->at[at];

		if (put_line(fd, bytes, length)) {
			subscribers->at[kept] = fd;
			kept++;
			continue;
		}
		/* Ordinary: a client that closed its stream, or one that stopped
		 * reading until its buffer filled. Neither is worth a line of its own
		 * on a machine where a tray reconnects, and the count is kept so that
		 * a caller can say so once. */
		(void)close(fd);
		subscribers->dropped++;
	}
	subscribers->count = kept;
	ncfg_buf_free(&line);
}

/* ------------------------------------------------------------------------ *
 * The world
 * ------------------------------------------------------------------------ */

size_t ncfg_main_hooks_of(const ncfg_document_t *document, ncfg_hook_ref_t *out, size_t out_max,
    size_t *missed)
{
	size_t taken = 0;
	size_t lost = 0;
	size_t at;
	size_t which;

	if (missed) {
		*missed = 0;
	}
	if (!document || !out) {
		return 0;
	}
	for (at = 0; at < document->interface_count; at++) {
		const ncfg_interface_t *interface = &document->interfaces[at];

		for (which = 0; which < interface->hook_count; which++) {
			if (taken >= out_max) {
				lost++;
				continue;
			}
			out[taken] = interface->hooks[which];
			taken++;
		}
	}
	for (at = 0; at < document->network_count; at++) {
		const ncfg_wifi_network_t *network = &document->networks[at];

		for (which = 0; which < network->hook_count; which++) {
			if (taken >= out_max) {
				lost++;
				continue;
			}
			out[taken] = network->hooks[which];
			taken++;
		}
	}
	if (missed) {
		*missed = lost;
	}
	return taken;
}

int ncfg_main_world_open(ncfg_main_world_t *world, const ncfg_main_world_where_t *where,
    const ncfg_daemon_state_t *state, ncfg_main_subscribers_t *subscribers,
    ncfg_main_watchers_t *watchers, char *err, size_t err_size)
{
	if (!world || !where || !where->run_dir || !where->run_dir[0]) {
		ncfg_error_set(err, err_size,
		    "a world needs somewhere to be and a run directory to take the apply lock "
		    "in");
		return 0;
	}
	memset(world, 0, sizeof(*world));
	ncfg_lock_init(&world->lock);
	world->run_dir = where->run_dir;
	/*
	 * The other four exactly as they were given, including absent. A default
	 * spelled here would be `ncfg_service_t`'s bargain broken at the one layer
	 * that could break it quietly: every one of these is a place this daemon
	 * *writes*, and the machine it is built on has a live network.
	 */
	world->proc_root = where->proc_root;
	world->supplicant_dir = where->supplicant_dir;
	world->resolv_conf = where->resolv_conf;
	world->dnsmasq_conf = where->dnsmasq_conf;
	world->unbound_conf = where->unbound_conf;
	world->dhcp = where->dhcp;
	world->hostapd_program = where->hostapd_program;
	world->radvd_program = where->radvd_program;
	world->openvpn_program = where->openvpn_program;
	world->supplicant_program = where->supplicant_program;
	world->secrets.secrets_dir = where->secrets_dir;
	world->secrets.materialise_dir = where->certs_dir;
	world->state = state;
	world->subscribers = subscribers;
	world->watchers = watchers;
	world->patience_ms = NCFG_MAIN_APPLY_PATIENCE_MS;
	/* Once, here, rather than per tick: `/run` and `/proc` are written down in
	 * one place and this reads that place one time, which is
	 * `ncfg_observe_source_machine`'s rule applied to the other reader of the
	 * machine. */
	ncfg_contention_machine(&world->contention);
	return 1;
}

void ncfg_main_world_close(ncfg_main_world_t *world)
{
	if (!world) {
		return;
	}
	/* An executor left open is a failure path that did not reach its close,
	 * and leaving the apply lock held for the life of the process is the one
	 * way this file could stop `ncfg apply` for ever. */
	if (world->open) {
		ncfg_kernel_free(world->kernel);
		world->kernel = NULL;
		ncfg_lock_release(&world->lock);
		world->open = 0;
	}
	world->hook_count = 0;
	/* Unconditionally, and not inside the branch above: a world that opened no
	 * executor holds no scope list, and one whose open failed after the
	 * service was built holds one with nothing to say it. */
	ncfg_main_service_release(world);
}

void ncfg_main_world_seams(ncfg_main_world_t *world, ncfg_reconcile_world_t *out)
{
	if (!out) {
		return;
	}
	out->context = world;
	out->executor_open = ncfg_main_world_executor_open;
	out->executor_close = ncfg_main_world_executor_close;
	out->announce = ncfg_main_world_announce;
	out->expiry = ncfg_main_world_expiry;
	out->release_contended = ncfg_main_world_release_contended;
}

int ncfg_main_world_executor_open(void *context, ncfg_executor_t *out, char *err, size_t err_size)
{
	ncfg_main_world_t *world = context;
	char               path[512];
	size_t             missed = 0;
	int                held = 0;

	if (!world || !out) {
		ncfg_error_set(err, err_size, "there is nowhere to put an executor");
		return 0;
	}
	if (world->open) {
		/*
		 * Refused by name rather than attempted. `flock` is held by the open
		 * file description, so a second `open` in this very process conflicts
		 * with the first -- the call would wait out the whole patience and
		 * then report somebody else holding the lock, which is a sentence
		 * naming the wrong machine.
		 */
		ncfg_error_set(err, err_size,
		    "this daemon already has an executor open, and a second would wait out the "
		    "apply lock against itself");
		return 0;
	}
	(void)snprintf(path, sizeof(path), "%s/apply.lock", world->run_dir);
	if (!ncfg_lock_take_within(&world->lock, path, world->patience_ms, &held, err, err_size)) {
		return 0;
	}
	world->kernel = ncfg_kernel_new(err, err_size);
	if (!world->kernel) {
		ncfg_lock_release(&world->lock);
		return 0;
	}
	/*
	 * The hooks the document declares, so that `hook.run` has something to
	 * check a script against. Without them `ncfg_hook_run` refuses rather than
	 * running whatever is on disk now, which is the safe direction and is also
	 * every hook in the configuration silently not firing.
	 */
	if (world->state) {
		world->hook_count = ncfg_main_hooks_of(world->state->desired, world->hooks,
		    (size_t)NCFG_MAIN_HOOKS_MAX, &missed);
		ncfg_kernel_set_hooks(world->kernel, world->hooks, world->hook_count);
		if (missed > 0u) {
			ncfg_log_emitf("apply", NCFG_LOG_WARNING,
			    "%zu hook(s) of this configuration did not fit in the %d an executor "
			    "is given, so they will be refused rather than run", missed,
			    NCFG_MAIN_HOOKS_MAX);
		}
	}
	/*
	 * And the half that is not netlink. Built here rather than at
	 * `ncfg_main_world_open` because it borrows the document, and the document
	 * is replaced by a reload: a service resolved once at startup would hold a
	 * `dns_scopes` list and a metric table belonging to a configuration this
	 * daemon has stopped believing in. Open-to-close is inside one call of the
	 * pass, which is the window `service.h` says a borrow has to fit in.
	 *
	 * A failure to resolve it is not a failure to open: `ncfg_main_service_of`
	 * says what each unresolved member costs and every one of them is an op
	 * refused by name. An executor that could not be opened at all is a daemon
	 * that cannot bring a link up, which is worse than one that cannot deliver
	 * a resolver file and says so.
	 */
	if (!ncfg_main_service_of(world, err, err_size)) {
		ncfg_log_emitf("apply", NCFG_LOG_WARNING,
		    "this executor's service context is incomplete, so some ops will refuse "
		    "by name: %s", err);
	}
	ncfg_kernel_set_service(world->kernel, &world->service);
	/*
	 * **And the two setters beside it, which the service half was wired
	 * without.** They are the same shape one field along: six netlink ops
	 * carry a device's name and nothing else -- `link.set_bridge`,
	 * `link.set_bond`, `link.set_macvlan`, `link.set_tunnel`,
	 * `link.set_vxlan` and `wg.set_device` -- and what they change is the
	 * document's, so without one they refuse by name rather than configuring
	 * a device from an empty block.
	 *
	 * The resolver matters for a different reason: NULL means the machine's
	 * own secrets directory, so a daemon pointed at a scratch tree would load
	 * the machine's real key material to configure it. Handing over the one
	 * this world was given is what makes that seam mean anything.
	 */
	ncfg_kernel_set_document(world->kernel, world->state ? world->state->desired : NULL);
	ncfg_kernel_set_secrets(world->kernel,
	    world->secrets.secrets_dir || world->secrets.materialise_dir ? &world->secrets : NULL);
	ncfg_kernel_executor(world->kernel, out);
	world->open = 1;
	return 1;
}

void ncfg_main_world_executor_close(void *context, ncfg_executor_t *executor)
{
	ncfg_main_world_t *world = context;

	if (executor) {
		memset(executor, 0, sizeof(*executor));
	}
	if (!world || !world->open) {
		return;
	}
	ncfg_kernel_free(world->kernel);
	world->kernel = NULL;
	world->hook_count = 0;
	ncfg_main_service_release(world);
	/* The lock after the socket, which is the order the Rust's `Drop` gives
	 * and is the one that matters: the lock covers the acting, so releasing it
	 * while a socket is still open would let the next apply start against a
	 * machine this one has not finished with. */
	ncfg_lock_release(&world->lock);
	world->open = 0;
}

void ncfg_main_world_expiry(void *context, uint32_t seconds)
{
	ncfg_main_world_t *world = context;

	if (!world) {
		return;
	}
	/*
	 * **The reason this struct exists.** `ncfg_reconcile_world_t` has one
	 * `void *` for every seam, and the timer belongs to the watchers while the
	 * executor belongs here -- so without something holding both, arming a
	 * window and opening an executor could not be installed at the same time.
	 * `ncfg_main_watchers_expiry` is the implementation; this is the address
	 * of the watchers, carried past a seam that has nowhere else to put it.
	 */
	ncfg_main_watchers_expiry(world->watchers, seconds);
}

void ncfg_main_world_announce(void *context, const ncfg_proto_event_t *event)
{
	ncfg_main_world_t *world = context;

	if (!world) {
		return;
	}
	ncfg_main_subscribers_tell(world->subscribers, event);
}

/* ------------------------------------------------------------------------ *
 * Giving a contended radio back
 * ------------------------------------------------------------------------ */

/*
 * The interfaces netcfgd is actually running a backend on, as claims.
 *
 * Only those: a contended interface netcfgd is not touching is the ordinary
 * coexistence case, and saying anything about it here would repeat the warning
 * the plan already carries.
 *
 * An interface whose kernel index does not fit is skipped, which is 0263's
 * narrowing rule pointed at a claim -- truncating would match a contender
 * against an interface nobody named, and that is worse than not asking about
 * this one.
 */
size_t ncfg_main_claims_of(const ncfg_daemon_state_t *state, ncfg_interface_claim_t *out,
    size_t out_max)
{
	size_t taken = 0;
	size_t at;

	if (!state || !state->desired || !state->observed || !out) {
		return 0;
	}
	for (at = 0; at < state->desired->interface_count && taken < out_max; at++) {
		const char                 *name = state->desired->interfaces[at].name;
		const ncfg_observed_link_t *link;
		size_t                      kind;
		int                         running = 0;

		if (!name) {
			continue;
		}
		for (kind = 0; kind < state->observed->backend_count; kind++) {
			const ncfg_observed_backend_t *backend = &state->observed->backends[kind];

			if (backend->running && backend->interface &&
			    strcmp(backend->interface, name) == 0) {
				running = 1;
				break;
			}
		}
		if (!running) {
			continue;
		}
		link = ncfg_observed_link(state->observed, name);
		if (!link || link->index < 0 || link->index > (int64_t)UINT32_MAX) {
			continue;
		}
		out[taken].name = name;
		out[taken].index = (uint32_t)link->index;
		taken++;
	}
	return taken;
}

/*
 * Whether stopping what netcfgd runs on the contended interfaces is something
 * this executor would carry out, with the sentence for the first one it would
 * not. `*candidates` answers how many backends were asked about at all.
 *
 * Asked before the lock for the reason the contenders are: taking the apply
 * lock to be refused is the cost this whole ordering is about.
 *
 * **Of the kinds that are actually running, and that is the correction.** It
 * used to build one `backend.stop` carrying kind 0 and ask about that. Kind 0
 * is `NCFG_BACKEND_DHCP4`, which `ncfg_service_backend_supported` has always
 * answered yes for, so the guard said yes whatever the executor could really
 * do and the branch under it could not be reached -- a check whose answer does
 * not depend on the thing it checks, which is the shape this port has already
 * found twice. A WireGuard device or a `pppd` session is refused by name, and
 * an interface holding only those is now one the lock is not taken for.
 */
static int any_stop_is_supported(const ncfg_daemon_state_t *state,
    const ncfg_contenders_t *found, size_t *candidates, char *why, size_t why_size)
{
	size_t at;

	*candidates = 0;
	if (!state || !state->observed) {
		return 0;
	}
	for (at = 0; at < found->count; at++) {
		size_t which;

		for (which = 0; which < found->at[at].interface_count; which++) {
			const char *interface = found->at[at].interfaces[which];
			size_t      i;

			for (i = 0; interface && i < state->observed->backend_count; i++) {
				const ncfg_observed_backend_t *backend =
				    &state->observed->backends[i];
				ncfg_op_t                      op;

				if (!backend->running || !backend->interface ||
				    strcmp(backend->interface, interface) != 0) {
					continue;
				}
				(*candidates)++;
				memset(&op, 0, sizeof(op));
				op.kind = NCFG_OP_BACKEND_STOP;
				op.u.backend.kind = backend->kind;
				op.u.backend.iface = interface;
				/* The first one that can be stopped is enough to make the
				 * lock worth taking: `hand_back` asks again per backend
				 * and says why for each one it cannot. */
				if (ncfg_apply_supported(&op, why, why_size)) {
					return 1;
				}
			}
		}
	}
	return 0;
}

/* Stop every backend netcfgd runs on one interface, saying why each time. */
static void hand_back(const ncfg_daemon_state_t *state, const ncfg_contender_t *contender,
    const char *interface, ncfg_executor_t *executor, ncfg_buf_t *described)
{
	size_t at;

	for (at = 0; at < state->observed->backend_count; at++) {
		const ncfg_observed_backend_t *backend = &state->observed->backends[at];
		ncfg_op_t                      op;
		char                           message[NCFG_ERROR_MAX];

		if (!backend->running || !backend->interface ||
		    strcmp(backend->interface, interface) != 0) {
			continue;
		}
		ncfg_log_emitf("contention", NCFG_LOG_WARNING,
		    "%s claims %s, which netcfgd is running a %s on -- two managers on one "
		    "interface drop the association, so netcfgd is stopping its own and "
		    "leaving the interface to %s. %s", contender->name, interface,
		    ncfg_backend_kind_name(backend->kind), contender->name,
		    ncfg_buf_text(described));
		memset(&op, 0, sizeof(op));
		op.kind = NCFG_OP_BACKEND_STOP;
		op.u.backend.kind = backend->kind;
		op.u.backend.iface = interface;
		message[0] = '\0';
		if (executor->execute && !executor->execute(executor->state, &op, message,
		    sizeof(message))) {
			ncfg_log_emitf("contention", NCFG_LOG_ERROR,
			    "could not stop the %s on %s: %s",
			    ncfg_backend_kind_name(backend->kind), interface, message);
		}
	}
}

int ncfg_main_world_release_contended(void *context, ncfg_daemon_state_t *state, char *err,
    size_t err_size)
{
	ncfg_main_world_t     *world = context;
	ncfg_interface_claim_t claims[NCFG_MAIN_CLAIMS_MAX];
	ncfg_contenders_t      found;
	ncfg_executor_t        executor;
	char                   why[NCFG_ERROR_MAX];
	size_t                 claim_count;
	size_t                 candidates = 0;
	size_t                 at;
	int                    opened;

	if (!world) {
		ncfg_error_set(err, err_size, "there is no machine to give a radio back on");
		return 0;
	}
	claim_count = ncfg_main_claims_of(state, claims, sizeof(claims) / sizeof(claims[0]));
	if (claim_count == 0u) {
		/* netcfgd is running nothing, so it is holding nothing that could be
		 * contended. The ordinary answer on a machine that has just started. */
		return 1;
	}
	memset(&found, 0, sizeof(found));
	if (!ncfg_contenders_find(&world->contention, claims, claim_count, &found, err, err_size)) {
		return 0;
	}
	if (found.count == 0u) {
		/*
		 * **The whole reason this asks first.** This is the answer on every
		 * ordinary machine, and reaching it without having taken the apply
		 * lock or opened a netlink socket is the difference between this and
		 * the Rust, which does both every five seconds for the life of the
		 * daemon to arrive here (0184, project.md 10.169).
		 */
		ncfg_contenders_free(&found);
		return 1;
	}

	why[0] = '\0';
	if (!any_stop_is_supported(state, &found, &candidates, why, sizeof(why))) {
		if (candidates == 0u) {
			/*
			 * Nothing of netcfgd's is running on any contended interface, so
			 * there is nothing to give back and nothing to say. Reachable
			 * because the claims and this walk read the same observation at
			 * two moments and a backend can stop between them.
			 */
			ncfg_contenders_free(&found);
			return 1;
		}
		/*
		 * Said once per contender and then given up on, rather than taking a
		 * lock to be refused per backend. The operator still learns that
		 * something else claims the radio and what to do about it, which is
		 * the half of this that does not need an executor.
		 */
		for (at = 0; at < found.count; at++) {
			ncfg_buf_t described;
			char       message[NCFG_ERROR_MAX];

			ncfg_buf_init(&described, NCFG_ERROR_MAX);
			message[0] = '\0';
			(void)ncfg_contender_describe(&found.at[at], &described, message,
			    sizeof(message));
			ncfg_log_emitf("contention", NCFG_LOG_WARNING,
			    "%s claims an interface netcfgd is running a backend on, and this "
			    "build cannot give it back: %s. %s", found.at[at].name, why,
			    ncfg_buf_text(&described));
			ncfg_buf_free(&described);
		}
		ncfg_contenders_free(&found);
		return 1;
	}

	memset(&executor, 0, sizeof(executor));
	opened = ncfg_main_world_executor_open(world, &executor, err, err_size);
	if (!opened) {
		ncfg_contenders_free(&found);
		return 0;
	}
	for (at = 0; at < found.count; at++) {
		ncfg_buf_t described;
		char       message[NCFG_ERROR_MAX];
		size_t     which;

		ncfg_buf_init(&described, NCFG_ERROR_MAX);
		message[0] = '\0';
		(void)ncfg_contender_describe(&found.at[at], &described, message, sizeof(message));
		for (which = 0; which < found.at[at].interface_count; which++) {
			hand_back(state, &found.at[at], found.at[at].interfaces[which], &executor,
			    &described);
		}
		ncfg_buf_free(&described);
	}
	ncfg_main_world_executor_close(world, &executor);
	ncfg_contenders_free(&found);
	return 1;
}
