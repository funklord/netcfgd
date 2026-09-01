/*
 * ncfg_connection.cpp -- the conversion described in ncfg_connection.h.
 *
 * Everything here is the same three lines: ask the C layer, turn its structs
 * into Qt types, free them. There is no walking of JSON in this file and there
 * must not be one again -- the models are below the seam (gui/project.md sec 3)
 * and the reason they moved is that three more screens would have made the
 * walking the pattern.
 */
#include "ncfg_connection.h"

namespace {

/*
 * A C string from the model structs into a QString.
 *
 * UTF-8 because the reader below the seam has already unescaped into it,
 * surrogate pairs included -- so this is a decode of known-good bytes rather
 * than a place that has to be careful. NULL becomes empty rather than
 * asserting: a field the daemon did not send is a field a screen leaves blank,
 * and crashing a client over it would be the worse answer.
 */
QString from_c(const char *text)
{
	return text ? QString::fromUtf8(text) : QString();
}

/*
 * What a device is doing, in one word.
 *
 * netcfgd reports `up` and `carrier` separately, and the difference is the
 * whole of "no cable" versus "not configured" -- 0011 and the shim's device
 * states both turn on it, so flattening them into "up" here would throw away
 * the distinction an operator most needs at a glance.
 *
 * The flattening happens on this side of the seam and not below it because
 * "down" and "no cable" are words for a person to read. client/ keeps the two
 * booleans, which is the fact; this picks the word, which is presentation.
 */
QString state_of(const ncfg_link_t &link)
{
	if (!link.up) {
		return QStringLiteral("down");
	}
	if (!link.carrier) {
		return QStringLiteral("no cable");
	}
	return QStringLiteral("up");
}

ncfg_note_row note_of(const ncfg_note_t &note)
{
	ncfg_note_row row;

	row.message = from_c(note.message);
	row.interface = from_c(note.interface);
	row.detail = from_c(note.detail);
	row.remedy = from_c(note.remedy);
	row.consent = from_c(note.consent);
	row.field = from_c(note.field);
	row.desired = from_c(note.desired);
	row.observed = from_c(note.observed);
	return row;
}

void notes_into(const ncfg_note_t *items, size_t count, QList<ncfg_note_row> *out)
{
	for (size_t i = 0; i < count; i++) {
		out->append(note_of(items[i]));
	}
}

} /* namespace */

QString ncfg_wifi_status_row::summary() const
{
	QString line = QStringLiteral("%1: %2").arg(interface, state);
	if (!display.isEmpty()) {
		line += QStringLiteral(" on %1").arg(display);
	}
	if (!display.isEmpty() && network.isEmpty()) {
		line += QStringLiteral(" -- not from any network block");
	} else if (!network.isEmpty()) {
		line += QStringLiteral(" (%1)").arg(network);
	}
	return line;
}

ncfg_connection::ncfg_connection(QObject *parent) : QObject(parent) {}

ncfg_connection::~ncfg_connection()
{
	close();
}

bool ncfg_connection::open(const QString &socket_path, QString *error)
{
	close();

	const QByteArray requested = socket_path.toUtf8();
	char message[NCFG_ERROR_MAX];

	client = ncfg_client_open(requested.isEmpty() ? nullptr : requested.constData(), message,
	              sizeof(message));
	if (!client) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	path = QString::fromUtf8(ncfg_client_socket_path(client));
	return true;
}

void ncfg_connection::close()
{
	if (client) {
		ncfg_client_close(client);
		client = nullptr;
	}
	path.clear();
}

QString ncfg_connection::where() const
{
	return path;
}

bool ncfg_connection::links(QList<ncfg_link_row> *out, QString *error)
{
	if (!out) {
		return false;
	}
	out->clear();

	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_links_t links = {};
	char message[NCFG_ERROR_MAX];

	if (!ncfg_client_links(client, &links, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	for (size_t i = 0; i < links.count; i++) {
		const ncfg_link_t &link = links.items[i];
		ncfg_link_row row;

		row.name = from_c(link.name);
		/* An empty kind is what the kernel reports for a real NIC, and
		 * the shim already learned not to guess from the name -- `eth0`
		 * is a convention, not a fact. */
		row.kind = from_c(link.kind);
		if (row.kind.isEmpty()) {
			row.kind = QStringLiteral("device");
		}
		row.state = state_of(link);
		row.mac = from_c(link.mac);
		row.addresses = from_c(link.addresses);
		row.default_route = link.default_route != 0;
		row.mtu = link.mtu;
		row.wireless = link.wireless != 0;
		out->append(row);
	}

	ncfg_links_free(&links);
	return true;
}

bool ncfg_connection::plan(ncfg_plan_data *out, QString *error)
{
	if (!out) {
		return false;
	}
	*out = ncfg_plan_data();

	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_plan_t plan = {};
	char message[NCFG_ERROR_MAX];

	if (!ncfg_client_plan_of(client, &plan, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	for (size_t i = 0; i < plan.action_count; i++) {
		const ncfg_action_t &action = plan.actions[i];
		ncfg_action_row row;

		row.id = action.id;
		row.op = from_c(action.op);
		row.interface = from_c(action.interface);
		row.field = from_c(action.field);
		row.desired = from_c(action.desired);
		row.observed = from_c(action.observed);
		row.reversible = action.reversible != 0;
		out->actions.append(row);
	}

	notes_into(plan.warnings, plan.warning_count, &out->warnings);
	notes_into(plan.refusals, plan.refusal_count, &out->refusals);
	notes_into(plan.stranded, plan.stranded_count, &out->stranded);

	ncfg_plan_free(&plan);
	return true;
}

bool ncfg_connection::apply(unsigned confirm_seconds, const ncfg_consent_rows &consent,
                QList<ncfg_record_row> *out, QString *error)
{
	if (!out) {
		return false;
	}
	out->clear();

	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_journal_t journal = {};
	char message[NCFG_ERROR_MAX];

	/* The Qt strings have to outlive the call, so the byte arrays are held
	 * here and only pointers into them go into the C struct. Building the
	 * pointer array from temporaries would hand the C layer memory that had
	 * already gone -- and the failure would be an operator consenting to a
	 * name nobody typed. */
	QList<QByteArray> disrupt_bytes;
	QList<QByteArray> strand_bytes;
	QList<const char *> disrupt;
	QList<const char *> strand;
	for (const QString &name : consent.disrupt) {
		disrupt_bytes.append(name.toUtf8());
	}
	for (const QString &name : consent.strand) {
		strand_bytes.append(name.toUtf8());
	}
	for (const QByteArray &name : disrupt_bytes) {
		disrupt.append(name.constData());
	}
	for (const QByteArray &name : strand_bytes) {
		strand.append(name.constData());
	}

	const ncfg_consent_t given = {
		disrupt.isEmpty() ? nullptr : disrupt.constData(),
		static_cast<size_t>(disrupt.size()),
		strand.isEmpty() ? nullptr : strand.constData(),
		static_cast<size_t>(strand.size()),
	};

	if (!ncfg_client_apply(client, confirm_seconds, consent.isEmpty() ? nullptr : &given,
	               &journal, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	for (size_t i = 0; i < journal.count; i++) {
		const ncfg_record_t &record = journal.items[i];
		ncfg_record_row row;

		row.id = record.id;
		row.op = from_c(record.op);
		row.interface = from_c(record.interface);
		row.outcome = from_c(record.outcome);
		row.detail = from_c(record.detail);
		out->append(row);
	}

	ncfg_journal_free(&journal);
	return true;
}

ncfg_tiers_t ncfg_connection::tiers()
{
	ncfg_tiers_t held = {};
	char message[NCFG_ERROR_MAX];

	if (!client || !ncfg_client_tiers(client, &held, message, sizeof(message))) {
		// Nothing granted, which the caller reads as "could not tell" rather
		// than as "not allowed" -- see the header.
		return ncfg_tiers_t{};
	}
	return held;
}

unsigned ncfg_connection::confirm_default()
{
	unsigned seconds = 0;
	char message[NCFG_ERROR_MAX];

	if (!client || !ncfg_client_confirm_default(client, &seconds, message, sizeof(message))) {
		// Could not ask -- an older daemon, or one that refused `show`. Zero,
		// and the dialog keeps its own default, which is the same answer as a
		// machine that names none.
		return 0;
	}
	return seconds;
}

bool ncfg_connection::wifi_add(const QString &ssid, const QString &id,
                   const QString &passphrase, const QString &proto, bool hidden,
                   const eap_request *eap, QString *error)
{
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	char message[NCFG_ERROR_MAX];
	/* Held here so the pointers below outlive the call. Temporaries would be
	 * gone before the C layer read them, and one of them is a passphrase. */
	const QByteArray ssid_bytes = ssid.toUtf8();
	const QByteArray id_bytes = id.toUtf8();
	const QByteArray passphrase_bytes = passphrase.toUtf8();
	const QByteArray proto_bytes = proto.toUtf8();

	ncfg_network_t network = {};
	network.ssid = ssid_bytes.constData();
	/* Empty means "not given" rather than "given as empty": the daemon
	 * derives an id from the ssid, and applies its own defaults, and a client
	 * sending empty strings would be inventing answers on its behalf. */
	network.id = id.isEmpty() ? nullptr : id_bytes.constData();
	network.passphrase = passphrase.isEmpty() ? nullptr : passphrase_bytes.constData();
	network.proto = proto.isEmpty() ? nullptr : proto_bytes.constData();
	network.hidden = hidden ? 1 : 0;
	network.priority = -1;

	/* Held at this scope for the same reason as the members above: the C
	 * layer reads the pointers during the call, and a QByteArray built inside
	 * the `if` would be gone before it did. */
	QByteArray  method_bytes;
	QByteArray  identity_bytes;
	QByteArray  anonymous_bytes;
	QByteArray  phase2_bytes;
	QByteArray  ca_cert_bytes;
	QByteArray  client_cert_bytes;
	ncfg_eap_t  eap_fields = {};
	if (eap) {
		method_bytes = eap->method.toUtf8();
		identity_bytes = eap->identity.toUtf8();
		anonymous_bytes = eap->anonymous_identity.toUtf8();
		phase2_bytes = eap->phase2.toUtf8();
		ca_cert_bytes = eap->ca_cert.toUtf8();
		client_cert_bytes = eap->client_cert.toUtf8();

		eap_fields.method = method_bytes.constData();
		eap_fields.identity = identity_bytes.constData();
		/* Empty means "not given" rather than "given as empty", the same
		 * distinction the members above draw: an empty string sent as a
		 * value is this window answering on the operator's behalf. */
		eap_fields.anonymous_identity =
		    eap->anonymous_identity.isEmpty() ? nullptr : anonymous_bytes.constData();
		eap_fields.phase2 = eap->phase2.isEmpty() ? nullptr : phase2_bytes.constData();
		eap_fields.ca_cert = eap->ca_cert.isEmpty() ? nullptr : ca_cert_bytes.constData();
		eap_fields.client_cert =
		    eap->client_cert.isEmpty() ? nullptr : client_cert_bytes.constData();
		network.eap = &eap_fields;
	}

	if (!ncfg_client_wifi_add(client, &network, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	return true;
}

bool ncfg_connection::secret_put(const QString &name, const QString &value, bool replace,
                QString *error)
{
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	char message[NCFG_ERROR_MAX];
	/* Held so the pointers outlive the call, as wifi_add() does, and one of
	 * them is a credential. */
	const QByteArray name_bytes = name.toUtf8();
	const QByteArray value_bytes = value.toUtf8();

	if (!ncfg_client_secret_put(client, name_bytes.constData(), value_bytes.constData(),
	              replace ? 1 : 0, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	return true;
}

QString ncfg_dns_row::summary() const
{
	if (mode.isEmpty() || mode == QStringLiteral("none")) {
		return QStringLiteral(
		    "not managed by netcfgd -- whatever wrote /etc/resolv.conf still owns it");
	}
	if (!managing) {
		return QStringLiteral("%1, not in effect yet").arg(mode);
	}
	QString line = mode;
	if (!servers.isEmpty()) {
		line += QStringLiteral(" -- %1").arg(servers.join(QStringLiteral(", ")));
	}
	return line;
}

bool ncfg_connection::saved_networks(QList<ncfg_saved_network_row> *out, QString *error)
{
	if (!out) {
		return false;
	}
	out->clear();
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_saved_networks_t networks = {};
	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_saved_networks(client, &networks, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	for (size_t i = 0; i < networks.count; i++) {
		ncfg_saved_network_row row;
		row.id = QString::fromUtf8(networks.items[i].id ? networks.items[i].id : "");
		row.name = QString::fromUtf8(networks.items[i].name ? networks.items[i].name : "");
		row.ssid = QString::fromUtf8(networks.items[i].ssid ? networks.items[i].ssid : "");
		row.security =
		    QString::fromUtf8(networks.items[i].security ? networks.items[i].security : "");
		row.credential = QString::fromUtf8(
		    networks.items[i].credential ? networks.items[i].credential : "");
		row.priority = networks.items[i].priority;
		row.autoconnect = networks.items[i].autoconnect != 0;
		row.hidden = networks.items[i].hidden != 0;
		out->append(row);
	}
	ncfg_saved_networks_free(&networks);
	return true;
}

bool ncfg_connection::dns(ncfg_dns_row *out, QString *error)
{
	if (!out) {
		return false;
	}
	*out = ncfg_dns_row();
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_dns_t answer = {};
	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_dns(client, &answer, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	out->mode = QString::fromUtf8(answer.mode ? answer.mode : "");
	for (size_t i = 0; i < answer.server_count; i++) {
		out->servers << QString::fromUtf8(answer.servers[i] ? answer.servers[i] : "");
	}
	for (size_t i = 0; i < answer.search_count; i++) {
		out->search << QString::fromUtf8(answer.search[i] ? answer.search[i] : "");
	}
	out->managing = answer.managing != 0;
	ncfg_dns_free(&answer);
	return true;
}

bool ncfg_connection::config_put(const QString &name, const QString &text, bool replace,
    QString *error)
{
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_config_put(client, name.toUtf8().constData(), text.toUtf8().constData(),
	    replace ? 1 : 0, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	return true;
}

bool ncfg_connection::probe_put(const QString &name, const QString &text, bool replace,
    QString *error)
{
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_probe_put(client, name.toUtf8().constData(), text.toUtf8().constData(),
	    replace ? 1 : 0, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	return true;
}

bool ncfg_connection::probes(QList<ncfg_probe_row> *out, QString *error)
{
	if (!out) {
		return false;
	}
	out->clear();
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_probes_t found = {};
	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_probes(client, &found, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	for (size_t i = 0; i < found.count; i++) {
		ncfg_probe_row row;
		row.name = from_c(found.items[i].name);
		row.directory = from_c(found.items[i].directory);
		row.text = from_c(found.items[i].text);
		row.editable = found.items[i].editable != 0;
		out->append(row);
	}
	ncfg_probes_free(&found);
	return true;
}

bool ncfg_connection::profile_set(const QString &name, QString *error)
{
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	char message[NCFG_ERROR_MAX];
	const QByteArray chosen = name.toUtf8();
	/* An empty name is "stop using a profile", which the client spells as no
	 * name at all rather than as an empty one. */
	const char *which = name.isEmpty() ? nullptr : chosen.constData();
	if (!ncfg_client_profile_set(client, which, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	return true;
}

bool ncfg_connection::rules(QList<ncfg_rule_row> *out, QString *error)
{
	if (!out) {
		return false;
	}
	out->clear();
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_rules_t found = {};
	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_rules(client, &found, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	for (size_t i = 0; i < found.count; i++) {
		ncfg_rule_row row;
		row.id = from_c(found.items[i].id);
		row.priority = found.items[i].priority;
		row.family = from_c(found.items[i].family);
		row.selector = from_c(found.items[i].selector);
		row.action = from_c(found.items[i].action);
		row.table = from_c(found.items[i].table);
		out->append(row);
	}
	ncfg_rules_free(&found);
	return true;
}

bool ncfg_connection::bluetooth(QList<ncfg_bluetooth_row> *out, QString *error)
{
	if (!out) {
		return false;
	}
	out->clear();
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_bluetooths_t found = {};
	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_bluetooth(client, &found, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	for (size_t i = 0; i < found.count; i++) {
		ncfg_bluetooth_row row;
		row.id = from_c(found.items[i].id);
		row.address = from_c(found.items[i].address);
		row.profile = from_c(found.items[i].profile);
		row.autoconnect = found.items[i].autoconnect != 0;
		out->append(row);
	}
	ncfg_bluetooths_free(&found);
	return true;
}

bool ncfg_connection::hooks(QList<ncfg_hook_row> *out, QString *error)
{
	if (!out) {
		return false;
	}
	out->clear();
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_hooks_t found = {};
	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_hooks(client, &found, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	for (size_t i = 0; i < found.count; i++) {
		ncfg_hook_row row;
		row.interface = from_c(found.items[i].interface);
		row.phase = from_c(found.items[i].phase);
		row.path = from_c(found.items[i].path);
		row.run_as = from_c(found.items[i].run_as);
		row.timeout = found.items[i].timeout;
		out->append(row);
	}
	ncfg_hooks_free(&found);
	return true;
}

bool ncfg_connection::modems(QList<ncfg_modem_row> *out, QString *error)
{
	if (!out) {
		return false;
	}
	out->clear();
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_modems_t found = {};
	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_modems(client, &found, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	for (size_t i = 0; i < found.count; i++) {
		ncfg_modem_row row;
		row.device = from_c(found.items[i].device);
		row.selected = from_c(found.items[i].selected);
		row.apn = from_c(found.items[i].apn);
		row.cycle_pending = found.items[i].cycle_pending != 0;
		for (size_t j = 0; j < found.items[i].sim_count; j++) {
			row.sim << from_c(found.items[i].sim[j]);
		}
		out->append(row);
	}
	ncfg_modems_free(&found);
	return true;
}

bool ncfg_connection::profiles(QList<ncfg_profile_row> *out, QString *chosen, QString *error)
{
	if (!out) {
		return false;
	}
	out->clear();
	if (chosen) {
		chosen->clear();
	}
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_profiles_t found = {};
	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_profiles(client, &found, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	for (size_t i = 0; i < found.count; i++) {
		ncfg_profile_row row;
		row.name = from_c(found.items[i].name);
		row.shipped = found.items[i].shipped != 0;
		out->append(row);
	}
	if (chosen) {
		*chosen = from_c(found.chosen);
	}
	ncfg_profiles_free(&found);
	return true;
}

bool ncfg_connection::radios(QList<ncfg_radio_row> *out, QString *error)
{
	if (!out) {
		return false;
	}
	out->clear();
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_radios_t radios = {};
	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_radios(client, &radios, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	for (size_t i = 0; i < radios.count; i++) {
		ncfg_radio_row row;
		row.name = QString::fromUtf8(radios.items[i].interface);
		row.activated = radios.items[i].activated != 0;
		row.supplicant = radios.items[i].supplicant != 0;
		out->append(row);
	}
	ncfg_radios_free(&radios);
	return true;
}

bool ncfg_connection::set_radio(const QString &interface, bool activate, QString *error)
{
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	char message[NCFG_ERROR_MAX];
	const QByteArray name = interface.toUtf8();
	if (!ncfg_client_radio_set(client, name.constData(), activate ? 1 : 0, message,
	              sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	return true;
}

bool ncfg_connection::wifi_scan(const QString &interface, QList<ncfg_access_point_row> *out,
                QString *error)
{
	if (!out) {
		return false;
	}
	out->clear();

	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_scan_t scan = {};
	char message[NCFG_ERROR_MAX];
	const QByteArray name = interface.toUtf8();

	if (!ncfg_client_wifi_scan(client, name.constData(), &scan, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	for (size_t i = 0; i < scan.count; i++) {
		const ncfg_access_point_t &point = scan.items[i];
		ncfg_access_point_row row;

		row.bssid = from_c(point.bssid);
		row.ssid = from_c(point.ssid);
		row.configured = from_c(point.configured);
		row.frequency = point.frequency;
		row.signal = point.signal;
		row.secured = point.secured != 0;
		row.enterprise = point.enterprise != 0;
		/* Rendered below the seam, not here. The three cases -- text,
		 * `(hidden)`, `hex:<ssid>` -- are vocabulary every client has to
		 * share, and this file held a fourth spelling of them until it
		 * moved down. What is left is a copy. */
		row.display = from_c(point.display);
		out->append(row);
	}

	ncfg_scan_free(&scan);
	return true;
}

bool ncfg_connection::wifi_status(const QString &interface, ncfg_wifi_status_row *out,
                  QString *error)
{
	if (!out) {
		return false;
	}
	*out = ncfg_wifi_status_row();

	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	ncfg_wifi_status_t status = {};
	char message[NCFG_ERROR_MAX];
	const QByteArray name = interface.toUtf8();

	if (!ncfg_client_wifi_status(client, name.constData(), &status, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	out->interface = from_c(status.interface);
	out->state = from_c(status.state);
	out->bssid = from_c(status.bssid);
	out->network = from_c(status.network);
	out->display = from_c(status.name);
	if (out->display.isEmpty() && status.ssid[0] != '\0') {
		out->display = QStringLiteral("hex:%1").arg(from_c(status.ssid));
	}

	ncfg_wifi_status_free(&status);
	return true;
}

bool ncfg_connection::wifi_connect(const QString &interface, const QString &network,
                   QString *error)
{
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	char message[NCFG_ERROR_MAX];
	const QByteArray name = interface.toUtf8();
	const QByteArray id = network.toUtf8();

	if (!ncfg_client_wifi_connect(client, name.constData(), id.constData(), message,
	                  sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	return true;
}

bool ncfg_connection::wifi_disconnect(const QString &interface, QString *error)
{
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	char message[NCFG_ERROR_MAX];
	const QByteArray name = interface.toUtf8();

	if (!ncfg_client_wifi_disconnect(client, name.constData(), message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	return true;
}

bool ncfg_connection::confirm(QString *error)
{
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_confirm(client, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	return true;
}

bool ncfg_connection::revert(QString *error)
{
	if (!client) {
		if (error) {
			*error = QStringLiteral("not connected");
		}
		return false;
	}

	char message[NCFG_ERROR_MAX];
	if (!ncfg_client_revert(client, message, sizeof(message))) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}
	return true;
}
