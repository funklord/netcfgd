/*
 * ncfg_connection.cpp -- the conversion described in ncfg_connection.h.
 */
#include "ncfg_connection.h"

#include <QHash>

namespace {

/* A counted JSON string into a QString. UTF-8 because the reader below the
 * seam has already unescaped into it, surrogate pairs included -- so this is a
 * decode of known-good bytes rather than a place that has to be careful. */
QString to_qstring(const ncfg_json_doc_t *doc, uint32_t node)
{
	size_t length = 0;
	const char *text = ncfg_json_string(doc, node, &length);

	if (!text) {
		return QString();
	}
	return QString::fromUtf8(text, static_cast<int>(length));
}

QString member_string(const ncfg_json_doc_t *doc, uint32_t object, const char *name)
{
	return to_qstring(doc, ncfg_json_member(doc, object, name));
}

/*
 * What a device is doing, in one word.
 *
 * netcfgd reports `up` and `carrier` separately, and the difference is the
 * whole of "no cable" versus "not configured" -- 0011 and the shim's device
 * states both turn on it, so flattening them into "up" here would throw away
 * the distinction an operator most needs at a glance.
 */
QString state_of(const ncfg_json_doc_t *doc, uint32_t link)
{
	const bool up = ncfg_json_bool(doc, ncfg_json_member(doc, link, "up"), false);
	const bool carrier = ncfg_json_bool(doc, ncfg_json_member(doc, link, "carrier"), true);

	if (!up) {
		return QStringLiteral("down");
	}
	if (!carrier) {
		return QStringLiteral("no cable");
	}
	return QStringLiteral("up");
}

} /* namespace */

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

	char message[NCFG_ERROR_MAX];
	ncfg_json_doc_t *doc = ncfg_client_status(client, message, sizeof(message));
	if (!doc) {
		if (error) {
			*error = QString::fromUtf8(message);
		}
		return false;
	}

	/* A refusal is the daemon answering. The tiers in 0013 mean an
	 * unprivileged client can be told no, and the message says which tier --
	 * so it is shown rather than replaced with something of this program's
	 * own invention. */
	size_t refusal_length = 0;
	if (const char *refusal = ncfg_client_error_message(doc, &refusal_length)) {
		if (error) {
			*error = QString::fromUtf8(refusal, static_cast<int>(refusal_length));
		}
		ncfg_json_free(doc);
		return false;
	}

	const uint32_t root = ncfg_json_root(doc);
	const uint32_t links_node = ncfg_json_member(doc, root, "links");
	const uint32_t addresses_node = ncfg_json_member(doc, root, "addresses");

	/* Addresses arrive as their own list keyed by interface, because that is
	 * what the observation is -- one flat list, sorted. Gathering them per
	 * interface here rather than in the table keeps the widget a view of
	 * rows and nothing else. */
	QHash<QString, QStringList> by_interface;
	for (uint32_t i = 0; i < ncfg_json_count(doc, addresses_node); i++) {
		const uint32_t entry = ncfg_json_at(doc, addresses_node, i);
		const QString interface = member_string(doc, entry, "interface");
		const QString address = member_string(doc, entry, "address");
		if (!interface.isEmpty() && !address.isEmpty()) {
			by_interface[interface].append(address);
		}
	}

	for (uint32_t i = 0; i < ncfg_json_count(doc, links_node); i++) {
		const uint32_t link = ncfg_json_at(doc, links_node, i);
		ncfg_link_row row;

		row.name = member_string(doc, link, "name");
		/* An empty kind is what the kernel reports for a real NIC, and
		 * the shim already learned not to guess from the name -- `eth0`
		 * is a convention, not a fact. */
		row.kind = member_string(doc, link, "kind");
		if (row.kind.isEmpty()) {
			row.kind = QStringLiteral("device");
		}
		row.state = state_of(doc, link);
		row.mac = member_string(doc, link, "mac");
		row.mtu = static_cast<int>(ncfg_json_int(doc, ncfg_json_member(doc, link, "mtu"), 0));
		row.addresses = by_interface.value(row.name).join(QStringLiteral(", "));
		out->append(row);
	}

	ncfg_json_free(doc);
	return true;
}
