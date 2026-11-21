#include "dns_view.h"

#include "ncfg_connection.h"

#include <QComboBox>
#include <QRegularExpression>
#include <QLineEdit>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

/*
 * The modes netcfgd accepts, with what each one does.
 *
 * Spelled out rather than left as bare keys, because the difference between
 * them is who ends up owning /etc/resolv.conf and that is the whole question
 * somebody opens this tab to answer.
 */
struct mode_row {
	const char *key;
	const char *says;
};

const mode_row modes[] = {
	{ "none", "none -- netcfgd does not touch resolution" },
	{ "write_resolv_conf", "write_resolv_conf -- netcfgd writes /etc/resolv.conf itself" },
	{ "resolvconf", "resolvconf -- hand servers to whatever provides resolvconf" },
	{ "openresolv", "openresolv -- openresolv specifically" },
	{ "resolved", "resolved -- systemd-resolved" },
	{ "dnsmasq", "dnsmasq -- as a local caching resolver" },
	{ "unbound", "unbound -- likewise" },
};
constexpr int mode_count = static_cast<int>(sizeof(modes) / sizeof(modes[0]));

/* The drop-in this tab owns. Named with a number so it sorts among the others
 * the way the config directory expects, and fixed so that setting the mode
 * twice edits one file rather than accumulating them. */
const char *const drop_in_name = "50-dns";

} // namespace

ncfg_dns_view::ncfg_dns_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	auto *layout = new QVBoxLayout(this);

	current = new QLabel(this);
	current->setObjectName(QStringLiteral("dns_current"));
	current->setWordWrap(true);
	current->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(current);

	detail = new QLabel(this);
	detail->setWordWrap(true);
	detail->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(detail);

	auto *controls = new QHBoxLayout();
	controls->addWidget(new QLabel(QStringLiteral("mode"), this));
	mode = new QComboBox(this);
	mode->setObjectName(QStringLiteral("dns_mode"));
	for (int i = 0; i < mode_count; i++) {
		mode->addItem(QString::fromLatin1(modes[i].says), QString::fromLatin1(modes[i].key));
	}
	controls->addWidget(mode);

	apply_button = new QPushButton(QStringLiteral("set"), this);
	apply_button->setObjectName(QStringLiteral("dns_apply"));
	controls->addWidget(apply_button);
	controls->addStretch();
	layout->addLayout(controls);

	/* The servers and search domains every interface's own are added to.
	 * Shown from the document and written with the mode, so pressing set
	 * without touching them writes back what is there. */
	auto *lists = new QFormLayout();
	servers = new QLineEdit(this);
	servers->setObjectName(QStringLiteral("dns_servers"));
	servers->setPlaceholderText(QStringLiteral("9.9.9.9, 2620:fe::fe -- blank for none"));
	lists->addRow(QStringLiteral("servers"), servers);
	search = new QLineEdit(this);
	search->setObjectName(QStringLiteral("dns_search"));
	search->setPlaceholderText(QStringLiteral("home.example -- blank for none"));
	lists->addRow(QStringLiteral("search"), search);
	layout->addLayout(lists);

	/* Said in the tab rather than in a dialog afterwards, because taking over
	 * /etc/resolv.conf on a machine that is working is the sort of thing an
	 * operator should read before pressing rather than after. */
	auto *warning = new QLabel(
	    QStringLiteral("Setting a mode other than `none` makes netcfgd the owner of "
	           "/etc/resolv.conf. Whatever writes it now will stop being "
	           "authoritative. Apply... shows what would change before it does."),
	    this);
	warning->setWordWrap(true);
	layout->addWidget(warning);

	layout->addStretch();

	connect(apply_button, &QPushButton::clicked, this, &ncfg_dns_view::apply_mode);
}

void ncfg_dns_view::refresh()
{
	ncfg_dns_row row;
	QString error;

	if (!connection->dns(&row, &error)) {
		current->setText(error);
		detail->clear();
		return;
	}

	current->setText(QStringLiteral("resolution: %1").arg(row.summary()));

	QStringList parts;
	if (!row.servers.isEmpty()) {
		parts << QStringLiteral("servers the document names: %1")
		         .arg(row.servers.join(QStringLiteral(", ")));
	}
	if (!row.search.isEmpty()) {
		parts << QStringLiteral("search: %1").arg(row.search.join(QStringLiteral(", ")));
	}
	/* The configured mode and whether it is in effect are different facts, and
	 * a mode that has not taken effect is the interesting case: it means the
	 * document asks for something the machine is not doing. */
	if (!row.mode.isEmpty() && row.mode != QStringLiteral("none") && !row.managing) {
		parts << QStringLiteral("netcfgd holds no resolver state, so this has not taken "
		           "effect yet -- Apply... shows why");
	}
	detail->setText(parts.join(QStringLiteral("\n")));

	/* The box shows what is set, so that opening the tab and pressing the
	 * button without reading it changes nothing. */
	const int at = mode->findData(row.mode.isEmpty() ? QStringLiteral("none") : row.mode);
	if (at >= 0) {
		mode->setCurrentIndex(at);
	}
	servers->setText(row.servers.join(QStringLiteral(", ")));
	search->setText(row.search.join(QStringLiteral(", ")));
	unmodelled = row.unmodelled;
}

void ncfg_dns_view::apply_mode()
{
	const QString chosen = mode->currentData().toString();
	if (chosen.isEmpty()) {
		return;
	}
	/* The block is written whole, so what it cannot hold would be deleted:
	 * refused, naming it, as the dialogs refuse a block they cannot carry. */
	if (!unmodelled.isEmpty()) {
		emit reported(QStringLiteral("the global dns block holds %1, which this tab does not "
		                             "edit and would delete: change it in the file").arg(unmodelled));
		return;
	}

	/* **Composed here, from a mode out of a fixed list and values that cannot
	 * leave their strings**: an address in its own characters, a search
	 * domain in letters, digits, dots and dashes. */
	const QRegularExpression split(QStringLiteral("[,\\s]+"));
	QStringList              server_list;
	QStringList              search_list;
	/* The characters an address is made of and no others, so nothing typed
	 * can close the string; whether it is an address the compiler says, as it
	 * does for every dialog's. */
	const QRegularExpression address(QStringLiteral("^[0-9A-Fa-f.:]+$"));
	for (const QString &one : servers->text().split(split, Qt::SkipEmptyParts)) {
		if (!address.match(one).hasMatch()) {
			emit reported(QStringLiteral("\"%1\" is not an address: a server is an IPv4 or "
			                             "IPv6 address").arg(one));
			return;
		}
		server_list << QStringLiteral("\"%1\"").arg(one);
	}
	const QRegularExpression domain(QStringLiteral("^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$"));
	for (const QString &one : search->text().split(split, Qt::SkipEmptyParts)) {
		if (!domain.match(one).hasMatch()) {
			emit reported(QStringLiteral("\"%1\" is not a domain to search").arg(one));
			return;
		}
		search_list << QStringLiteral("\"%1\"").arg(one);
	}
	QString block = QStringLiteral("global {\n\tdns {\n\t\tmode = \"%1\"\n").arg(chosen);
	if (!server_list.isEmpty()) {
		block += QStringLiteral("\t\tservers = [%1]\n").arg(server_list.join(QStringLiteral(", ")));
	}
	if (!search_list.isEmpty()) {
		block += QStringLiteral("\t\tsearch = [%1]\n").arg(search_list.join(QStringLiteral(", ")));
	}
	const QString text = block + QStringLiteral("\t}\n}\n");

	QString error;
	/* `replace` because this file is this tab's own and setting the mode twice
	 * should edit it rather than fail on the second press. */
	if (!connection->config_put(QString::fromLatin1(drop_in_name), text, true, &error)) {
		emit reported(error);
		return;
	}

	emit reported(QStringLiteral("wrote %1: dns mode is now \"%2\"%3. netcfgd puts it in effect itself; Apply... shows anything it holds back.")
	          .arg(QString::fromLatin1(drop_in_name), chosen,
	              server_list.isEmpty() ? QString()
	                                    : QStringLiteral(", with %1 server(s)").arg(server_list.size())));
	emit changed();
	refresh();
}
