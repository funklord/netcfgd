/*
 * report.c -- the responses that are a model plus an envelope.
 *
 * WHY THESE ARE NOT IN `answer.c`
 *   That file holds the three the authorization path decides for itself --
 *   `error`, `ok` and `hello` -- and says why the rest are not there: "a
 *   `status` encoder without a status to encode would be a shape nobody had
 *   checked against anything". These three have one. They take the daemon's own
 *   state, which is this module's, and they are checked against the frozen
 *   witness in `doc/schema/socket.json` byte for byte.
 *
 * WHY THE MEMBERS ARE THE MODEL'S OWN WRITER AND NOT A LIST HERE
 *   `Response::Status(Box<Observed>)` is flattened on the wire, so the
 *   envelope's members *are* the observation's. Writing them here would be a
 *   second list of a model's members in a module that does not own it -- and a
 *   member added to the model and forgotten here is a client reading a field
 *   the daemon has stopped sending, with nothing failing to compile. So
 *   `ncfg_observed_write_members`, `ncfg_document_write_members` and
 *   `ncfg_plan_write_members` are published for this, and each response and
 *   the file of the same shape under `/run` cannot disagree.
 *
 * WHAT AN ABSENT ANSWER IS
 *   None of these invents an empty one. An observation with no links reads as
 *   a machine with nothing on it, a document with no interfaces as a machine
 *   nobody has configured, and a plan with no actions as a machine that is
 *   already right -- and a client cannot tell any of the three from a daemon
 *   that has not looked, has no configuration, or ran out of memory half way
 *   through. Each refuses instead, and a refusal is an answer: `answer.c`
 *   turns it into `{"response":"error","message":...}` with the sentence in
 *   it.
 */
#include "ncfg/daemon.h"

#include "ncfg/json_write.h"

/* `answer.c`'s, for its reason: a half-written message is the one that gets
 * sent by accident, so the buffer is failed rather than merely reported on. */
static int finish(ncfg_json_writer_t *writer, ncfg_buf_t *out, const char *what, char *err,
    size_t err_size)
{
	if (!ncfg_json_write_done(writer)) {
		const char *why = ncfg_json_write_failure(writer);

		out->failed = 1;
		ncfg_error_set(err, err_size, "the %s response could not be written: %s", what,
		    why ? why : "it was left unfinished");
		return 0;
	}
	return 1;
}

int ncfg_daemon_status_encode(const ncfg_observed_t *observed, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the status");
		return 0;
	}
	if (!observed) {
		ncfg_error_set(err, err_size,
		    "this daemon has not managed to observe the machine, so there is no status "
		    "to report -- which is not the same as a machine with nothing on it");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "status");
	ncfg_observed_write_members(&writer, observed);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, out, "status", err, err_size);
}

int ncfg_daemon_plan_encode(const ncfg_plan_t *plan, ncfg_buf_t *out, char *err,
    size_t err_size)
{
	ncfg_json_writer_t writer;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the plan");
		return 0;
	}
	if (!plan) {
		ncfg_error_set(err, err_size, "there is no plan to answer with");
		return 0;
	}
	if (plan->failed) {
		/* `ncfg_plan_write`'s refusal, in the same words for the same reason:
		 * this is the one message a client would act on. */
		ncfg_error_set(err, err_size, "the plan could not be built: out of memory");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "plan");
	ncfg_plan_write_members(&writer, plan);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, out, "plan", err, err_size);
}

int ncfg_daemon_document_encode(const ncfg_document_t *desired, const char *diagnostics,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_json_writer_t writer;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the document");
		return 0;
	}
	if (!desired) {
		/*
		 * The diagnostics are the answer where there are any: somebody asking
		 * to see the configuration when it does not compile wants the reason,
		 * not a second sentence saying there is nothing to see. The Rust
		 * answers the same way, and falls back to the same words.
		 */
		ncfg_error_set(err, err_size, "%s",
		    diagnostics && diagnostics[0] ? diagnostics : "no configuration");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "document");
	ncfg_document_write_members(&writer, desired);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, out, "document", err, err_size);
}

int ncfg_daemon_secrets_encode(const ncfg_secret_entry_t *entries, size_t count,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             at;
	size_t             which;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the credential list");
		return 0;
	}
	if (!entries && count != 0u) {
		ncfg_error_set(err, err_size, "a credential list was asked for with no entries");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "secrets");
	ncfg_json_write_key(&writer, "secrets");
	ncfg_json_write_array_begin(&writer);
	for (at = 0u; at < count; at++) {
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "name",
		    entries[at].name ? entries[at].name : "");
		ncfg_json_write_member_bool(&writer, "stored", entries[at].stored ? 1 : 0);
		/* Omitted rather than empty: `daemon.h` says why, and it is the
		 * difference between "nothing wants this" and "netcfgd could not tell
		 * what wants this". */
		if (entries[at].used_by_count > 0u) {
			ncfg_json_write_key(&writer, "used_by");
			ncfg_json_write_array_begin(&writer);
			for (which = 0u; which < entries[at].used_by_count; which++) {
				ncfg_json_write_string(&writer,
				    entries[at].used_by[which] ? entries[at].used_by[which] : "");
			}
			ncfg_json_write_array_end(&writer);
		}
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, out, "secrets", err, err_size);
}

int ncfg_daemon_profiles_encode(const ncfg_profile_entry_t *entries, size_t count,
    const char *chosen, ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             at;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the profile list");
		return 0;
	}
	if (!entries && count != 0u) {
		ncfg_error_set(err, err_size, "a profile list was asked for with no entries");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "profiles");
	ncfg_json_write_key(&writer, "profiles");
	ncfg_json_write_array_begin(&writer);
	for (at = 0u; at < count; at++) {
		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "name",
		    entries[at].name ? entries[at].name : "");
		ncfg_json_write_member_bool(&writer, "shipped", entries[at].shipped ? 1 : 0);
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	/* Absent where none is chosen, never null and never an empty name: the
	 * client reads the absence as "none", and `cli/profile.c` says the same
	 * of the text form it prints from this. */
	if (chosen && chosen[0]) {
		ncfg_json_write_member_string(&writer, "chosen", chosen);
	}
	ncfg_json_write_object_end(&writer);
	return finish(&writer, out, "profiles", err, err_size);
}

int ncfg_daemon_configs_encode(const ncfg_config_entry_t *entries, size_t count,
    ncfg_buf_t *out, char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             at;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the configuration list");
		return 0;
	}
	if (!entries && count != 0u) {
		ncfg_error_set(err, err_size, "a configuration list was asked for with no entries");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "configs");
	ncfg_json_write_key(&writer, "configs");
	ncfg_json_write_array_begin(&writer);
	for (at = 0u; at < count; at++) {
		ncfg_json_write_object_begin(&writer);
		/* Omitted for a file that is not a drop-in: `daemon.h` says why, and
		 * it is the member a client acts on rather than displays. */
		if (entries[at].name && entries[at].name[0]) {
			ncfg_json_write_member_string(&writer, "name", entries[at].name);
		}
		ncfg_json_write_member_string(&writer, "file",
		    entries[at].file ? entries[at].file : "");
		ncfg_json_write_member_bool(&writer, "removable", entries[at].removable ? 1 : 0);
		ncfg_json_write_member_string(&writer, "text",
		    entries[at].text ? entries[at].text : "");
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, out, "configs", err, err_size);
}

int ncfg_daemon_hooks_encode(const ncfg_hook_script_t *scripts, size_t count, ncfg_buf_t *out,
    char *err, size_t err_size)
{
	ncfg_json_writer_t writer;
	size_t             at;

	if (!out) {
		ncfg_error_set(err, err_size, "nowhere to put the hook list");
		return 0;
	}
	if (!scripts && count != 0u) {
		ncfg_error_set(err, err_size, "a hook list was asked for with no entries");
		return 0;
	}
	ncfg_json_write_init(&writer, out);
	ncfg_json_write_object_begin(&writer);
	ncfg_json_write_member_string(&writer, "response", "hooks");
	ncfg_json_write_key(&writer, "hooks");
	ncfg_json_write_array_begin(&writer);
	for (at = 0u; at < count; at++) {
		const char *phase = ncfg_hook_phase_name((ncfg_hook_phase_t)scripts[at].phase);

		ncfg_json_write_object_begin(&writer);
		ncfg_json_write_member_string(&writer, "interface",
		    scripts[at].interface ? scripts[at].interface : "");
		ncfg_json_write_member_string(&writer, "phase", phase ? phase : "");
		ncfg_json_write_member_string(&writer, "path",
		    scripts[at].path ? scripts[at].path : "");
		ncfg_json_write_member_string(&writer, "text",
		    scripts[at].text ? scripts[at].text : "");
		ncfg_json_write_member_bool(&writer, "readable", scripts[at].readable ? 1 : 0);
		ncfg_json_write_object_end(&writer);
	}
	ncfg_json_write_array_end(&writer);
	ncfg_json_write_object_end(&writer);
	return finish(&writer, out, "hooks", err, err_size);
}
