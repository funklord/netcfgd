#include "dns_view.h"

#include "ncfg_connection.h"

#include <QComboBox>
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

	apply_button = new QPushButton(QStringLiteral("set mode"), this);
	apply_button->setObjectName(QStringLiteral("dns_apply"));
	controls->addWidget(apply_button);
	controls->addStretch();
	layout->addLayout(controls);

	/* Said in the tab rather than in a dialog afterwards, because taking over
	 * /etc/resolv.conf on a machine that is working is the sort of thing an
	 * operator should read before pressing rather than after. */
	auto *warning = new QLabel(
	    QStringLiteral("Setting a mode other than `none` makes netcfgd the owner of "
	           "/etc/resolv.conf. Whatever writes it now will stop being "
	           "authoritative. `ncfg plan` shows what would change before it does."),
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
		           "effect -- `ncfg apply` is what does it");
	}
	detail->setText(parts.join(QStringLiteral("\n")));

	/* The box shows what is set, so that opening the tab and pressing the
	 * button without reading it changes nothing. */
	const int at = mode->findData(row.mode.isEmpty() ? QStringLiteral("none") : row.mode);
	if (at >= 0) {
		mode->setCurrentIndex(at);
	}
}

void ncfg_dns_view::apply_mode()
{
	const QString chosen = mode->currentData().toString();
	if (chosen.isEmpty()) {
		return;
	}

	/* Composed here, from a key this file chose out of a fixed list. Nothing
	 * an operator typed reaches the daemon, which is what keeps this inside
	 * the shape 0117 bounds rather than inside "a client sent configuration
	 * as text". */
	const QString text =
	    QStringLiteral("global {\n\tdns {\n\t\tmode = \"%1\"\n\t}\n}\n").arg(chosen);

	QString error;
	/* `replace` because this file is this tab's own and setting the mode twice
	 * should edit it rather than fail on the second press. */
	if (!connection->config_put(QString::fromLatin1(drop_in_name), text, true, &error)) {
		emit reported(error);
		return;
	}

	emit reported(QStringLiteral("wrote %1: dns mode is now `%2`. Run apply to make the "
	              "machine match it.")
	          .arg(QString::fromLatin1(drop_in_name), chosen));
	emit changed();
	refresh();
}
