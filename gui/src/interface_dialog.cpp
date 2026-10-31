#include "interface_dialog.h"

#include "address_editors.h"

#include "hook_dialog.h"
#include "probe_dialog.h"

#include "ncfg_connection.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QFileInfo>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QHeaderView>
#include <QListWidget>
#include <QSpinBox>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

/* An editable table with add and remove buttons under it, in the form. */
QTableWidget *a_table(QWidget *parent, QFormLayout *form, const QString &label,
    const QString &name, const QStringList &columns)
{
	auto *table = new QTableWidget(0, (int)columns.size(), parent);
	table->setObjectName(name);
	table->setHorizontalHeaderLabels(columns);
	table->verticalHeader()->setVisible(false);
	table->horizontalHeader()->setStretchLastSection(true);
	table->setSelectionBehavior(QAbstractItemView::SelectRows);
	table->setSelectionMode(QAbstractItemView::SingleSelection);
	table->setMaximumHeight(110);
	form->addRow(label, table);

	auto *row = new QHBoxLayout();
	auto *add = new QPushButton(QStringLiteral("add"), parent);
	add->setObjectName(name + QStringLiteral("_add"));
	auto *drop = new QPushButton(QStringLiteral("remove"), parent);
	drop->setObjectName(name + QStringLiteral("_drop"));
	row->addWidget(add);
	row->addWidget(drop);
	row->addStretch(1);
	form->addRow(QString(), row);
	QObject::connect(add, &QPushButton::clicked, table, [table]() {
		table->insertRow(table->rowCount());
		table->setCurrentCell(table->rowCount() - 1, 0);
	});
	QObject::connect(drop, &QPushButton::clicked, table, [table]() {
		if (table->currentRow() >= 0) {
			table->removeRow(table->currentRow());
		}
	});
	return table;
}

void put_row(QTableWidget *table, const QStringList &cells)
{
	const int row = table->rowCount();
	table->insertRow(row);
	for (int at = 0; at < cells.size(); at++) {
		table->setItem(row, at, new QTableWidgetItem(cells[at]));
	}
}

QString text_at(const QTableWidget *table, int row, int column)
{
	const QTableWidgetItem *item = table->item(row, column);
	return item ? item->text().trimmed() : QString();
}

/* A port, as the language takes one. */
bool is_port(const QString &text)
{
	bool ok = false;
	const int value = text.toInt(&ok);
	return ok && value >= 1 && value <= 65535;
}

/* A name, a MAC or an address in a cell: no quote, backslash, brace,
 * semicolon or space, which is everything a cell could use to say more than
 * its value. */
bool is_word(const QString &text)
{
	static const QString refused = QStringLiteral("\"\\{};= \t\n");
	if (text.isEmpty()) {
		return false;
	}
	for (const QChar one : text) {
		if (refused.contains(one)) {
			return false;
		}
	}
	return true;
}

struct choice {
	const char *shown;
	const char *key;
};

/* Name resolution for this interface. "leave to the global policy" is first
 * and is the ordinary answer: an interface that states no scope is one the
 * host-wide `dns` block answers for. */
const choice dns_modes[] = {
	{ "leave to the global policy", "" },
	{ "none -- netcfgd writes nothing", "none" },
	{ "write /etc/resolv.conf", "write_resolv_conf" },
	{ "resolvconf", "resolvconf" },
	{ "openresolv", "openresolv" },
	{ "systemd-resolved", "resolved" },
	{ "dnsmasq", "dnsmasq" },
	{ "unbound", "unbound" },
};

/* What netcfgd does when the machine stops matching this block. Empty is the
 * host-wide default, which is `reconcile` unless the global block says
 * otherwise. */
const choice drifts[] = {
	{ "the host default", "" },
	{ "reconcile -- put it back", "reconcile" },
	{ "report -- say so and change nothing", "report" },
	{ "ignore -- do not even look", "ignore" },
};

/*
 * How netcfgd decides this link works.
 *
 * "carrier only" is named as what it is rather than left as the absence of a
 * setting, because it is the answer that was wrong often enough to need
 * replacing: a cable into a switch with no uplink of its own has carrier and no
 * path. Decision 0119.
 *
 * The rest of the list is **read off the disk**, not written here. A probe is
 * a shell script that exits zero when the link works, so the set of them is a
 * directory listing -- which means this dialog, `ncfg` and any other front end
 * offer the same set without anyone keeping three lists in step.
 */
const choice detections[] = {
	{ "carrier only -- the cable is plugged in", "" },
	{ "run a command", "command" },
};

void fill(QComboBox *box, const choice *from, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		box->addItem(QString::fromLatin1(from[i].shown), QString::fromLatin1(from[i].key));
	}
}

bool safe_value(const QString &text)
{
	return !text.contains(QLatin1Char('"')) && !text.contains(QLatin1Char('\\')) &&
	       !text.contains(QLatin1Char('\n'));
}

} // namespace

ncfg_interface_dialog::ncfg_interface_dialog(ncfg_connection *connection, const QString &name,
    QWidget *parent)
    : QDialog(parent), connection(connection), interface(name)
{
	setWindowTitle(QStringLiteral("interface: %1").arg(name));

	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();
	form_layout = form;

	/* **The addressing list and the routes**, shared with the network dialog
	 * since 10.615 so the two cannot drift: the network dialog had one
	 * addressing choice and its own copy of a three-column route table. */
	addressing = new ncfg_addressing_editor(QStringLiteral("iface"), this);
	form->addRow(QStringLiteral("addressing"), addressing);
	route_editor = new ncfg_route_editor(QStringLiteral("iface"), this);
	form->addRow(QStringLiteral("routes"), route_editor);

	dns_mode = new QComboBox(this);
	dns_mode->setObjectName(QStringLiteral("iface_dns_mode"));
	fill(dns_mode, dns_modes, sizeof(dns_modes) / sizeof(dns_modes[0]));
	form->addRow(QStringLiteral("dns"), dns_mode);

	dns_servers = new QLineEdit(this);
	dns_servers->setObjectName(QStringLiteral("iface_dns_servers"));
	dns_servers->setPlaceholderText(QStringLiteral("1.1.1.1 9.9.9.9 -- blank takes the "
	            "lease's"));
	form->addRow(QStringLiteral("nameservers"), dns_servers);

	dns_search = new QLineEdit(this);
	dns_search->setObjectName(QStringLiteral("iface_dns_search"));
	dns_search->setPlaceholderText(QStringLiteral("corp.example lab.example"));
	form->addRow(QStringLiteral("search domains"), dns_search);

	dns_domains = new QLineEdit(this);
	dns_domains->setObjectName(QStringLiteral("iface_dns_domains"));
	dns_domains->setPlaceholderText(QStringLiteral("names under these go to this "
	            "interface's servers"));
	form->addRow(QStringLiteral("routing domains"), dns_domains);

	on_drift = new QComboBox(this);
	on_drift->setObjectName(QStringLiteral("iface_on_drift"));
	fill(on_drift, drifts, sizeof(drifts) / sizeof(drifts[0]));
	form->addRow(QStringLiteral("when it drifts"), on_drift);

	preference = new QSpinBox(this);
	preference->setObjectName(QStringLiteral("iface_preference"));
	preference->setRange(0, 4000);
	preference->setSpecialValueText(QStringLiteral("unset"));
	/* Said in the widget, because it is the opposite of a wifi network's
	 * metric and both are settable in this program -- and since 0154 they are
	 * the same scale, so this no longer has to warn about a second one. */
	preference->setToolTip(QStringLiteral(
	    "Which interface wins when several could carry the default route. LOWER is "
	    "better -- this is how a wired cable takes over from wifi. Note it is the "
	    "same scale as a wireless network's metric, so the two compare directly."));
	form->addRow(QStringLiteral("preference (lower wins)"), preference);

	/* **The MTU is not here any more.** It describes the adapter, not the
	 * networking on it, so it lives in the device editor with the rest of the
	 * hardware -- and two screens writing one `device` block into two drop-ins
	 * is a duplicate block the loader refuses. Decision 0250. */

	detection = new QComboBox(this);
	detection->setObjectName(QStringLiteral("iface_detection"));
	/*
	 * **Before `reload_detections`, which writes to it on its failure path.**
	 * It was constructed a hundred lines further down, so the branch its own
	 * comment calls "not fatal" dereferenced an uninitialised member pointer
	 * and segfaulted -- reached whenever the daemon will not list the probe
	 * scripts, which is every ordinary user on a machine whose `observe` tier
	 * is the default `root`. Found by a probe that opened this dialog as such
	 * a user.
	 */
	note = new QLabel(this);
	/* Named for the same reason the fields are: a probe that took
	 * `findChildren<QLabel *>().first()` would get whichever label was
	 * constructed first, which is a form caption. */
	note->setObjectName(QStringLiteral("iface_note"));
	note->setWordWrap(true);

	reload_detections(QString());

	/* The list, and the two things an operator does with it. `view / edit`
	 * because a probe is a shell script and reading the one that is judging
	 * your link is the first thing anybody wants; `new` because writing one
	 * should not mean leaving the program. */
	auto *detection_row = new QHBoxLayout();
	detection_row->addWidget(detection, 1);
	edit_detection_button = new QPushButton(QStringLiteral("view / edit"), this);
	edit_detection_button->setObjectName(QStringLiteral("iface_edit_probe"));
	detection_row->addWidget(edit_detection_button);
	auto *new_probe = new QPushButton(QStringLiteral("new"), this);
	new_probe->setObjectName(QStringLiteral("iface_new_probe"));
	detection_row->addWidget(new_probe);
	form->addRow(QStringLiteral("link detection"), detection_row);

	connect(edit_detection_button, &QPushButton::clicked, this,
	    &ncfg_interface_dialog::edit_detection);
	/* `this->connection`, because the constructor's parameter of that name
	 * shadows the member here and a lambda cannot capture a parameter it was
	 * not told about. */
	connect(new_probe, &QPushButton::clicked, this, [this]() {
		ncfg_probe_dialog dialog(this->connection, ncfg_probe_row(), this);
		if (dialog.exec() == QDialog::Accepted) {
			reload_detections(dialog.written_name());
			note->setText(dialog.outcome());
		}
	});

	probe_command = new QLineEdit(this);
	probe_command->setObjectName(QStringLiteral("iface_probe_command"));
	probe_command->setPlaceholderText(QStringLiteral("/usr/bin/curl"));
	form->addRow(QStringLiteral("command"), probe_command);

	probe_args = new QLineEdit(this);
	probe_args->setObjectName(QStringLiteral("iface_probe_args"));
	probe_args->setPlaceholderText(QStringLiteral("-fsS https://example.invalid"));
	form->addRow(QStringLiteral("arguments"), probe_args);

	probe_interval = new QSpinBox(this);
	probe_interval->setRange(0, 3600);
	probe_interval->setSpecialValueText(QStringLiteral("default (30s)"));
	form->addRow(QStringLiteral("interval, seconds"), probe_interval);

	probe_timeout = new QSpinBox(this);
	probe_timeout->setRange(0, 600);
	probe_timeout->setSpecialValueText(QStringLiteral("default (5s)"));
	form->addRow(QStringLiteral("timeout, seconds"), probe_timeout);

	/* **When a result counts** (10.617): how many in a row take the link down
	 * or bring it back, how long it stays down, and whether it needs a lease
	 * before a pass means anything. The language has had all four; a Save
	 * dropped them, so a probe tuned not to flap was reset to the defaults. */
	probe_down_after = new QSpinBox(this);
	probe_down_after->setObjectName(QStringLiteral("iface_probe_down_after"));
	probe_down_after->setRange(1, 1000);
	probe_down_after->setValue(3);
	form->addRow(QStringLiteral("failures before down"), probe_down_after);
	probe_up_after = new QSpinBox(this);
	probe_up_after->setObjectName(QStringLiteral("iface_probe_up_after"));
	probe_up_after->setRange(1, 1000);
	probe_up_after->setValue(2);
	form->addRow(QStringLiteral("passes before up"), probe_up_after);
	probe_hold_down = new QSpinBox(this);
	probe_hold_down->setObjectName(QStringLiteral("iface_probe_hold_down"));
	probe_hold_down->setRange(0, 86400);
	probe_hold_down->setSpecialValueText(QStringLiteral("none"));
	form->addRow(QStringLiteral("held down, seconds"), probe_hold_down);
	probe_require_lease = new QCheckBox(QStringLiteral("only count a pass once there is a lease"), this);
	probe_require_lease->setObjectName(QStringLiteral("iface_probe_require_lease"));
	probe_require_lease->setChecked(true);
	form->addRow(QString(), probe_require_lease);

	enabled = new QCheckBox(QStringLiteral("configure this interface"), this);
	enabled->setObjectName(QStringLiteral("iface_enabled"));
	enabled->setChecked(true);
	enabled->setToolTip(QStringLiteral(
	    "Unchecked keeps the configuration and leaves the link down."));
	form->addRow(QString(), enabled);

	forwarding = new QCheckBox(QStringLiteral("forward packets through it"), this);
	forwarding->setObjectName(QStringLiteral("iface_forwarding"));
	form->addRow(QString(), forwarding);

	nat = new QCheckBox(QStringLiteral("NAT -- share this uplink with other interfaces"), this);
	nat->setObjectName(QStringLiteral("iface_nat"));
	form->addRow(QString(), nat);

	/* **The router's other half, beside forwarding and NAT** (0297). It serves
	 * the network of this interface's static IPv4 address, so it needs one,
	 * which the compiler says when it is missing. */
	dhcp_server = new QCheckBox(QStringLiteral("serve DHCP to the hosts behind it"), this);
	dhcp_server->setObjectName(QStringLiteral("iface_dhcp_server"));
	form->addRow(QString(), dhcp_server);

	dhcp_range = new QLineEdit(this);
	dhcp_range->setObjectName(QStringLiteral("iface_dhcp_range"));
	dhcp_range->setPlaceholderText(QStringLiteral("default: the 100th host to the 249th"));
	form->addRow(QStringLiteral("range"), dhcp_range);

	dhcp_lease = new QSpinBox(this);
	dhcp_lease->setObjectName(QStringLiteral("iface_dhcp_lease"));
	dhcp_lease->setRange(0, 604800);
	dhcp_lease->setSuffix(QStringLiteral(" s"));
	dhcp_lease->setSpecialValueText(QStringLiteral("default (12 hours)"));
	form->addRow(QStringLiteral("lease"), dhcp_lease);

	dhcp_dns = new QLineEdit(this);
	dhcp_dns->setObjectName(QStringLiteral("iface_dhcp_dns"));
	/* Never guessed (0297): the router's own address answers only if
	 * something on it resolves -- which is what the forwarder below is -- so
	 * an empty field with the forwarder off offers none and the plan says so. */
	dhcp_dns->setPlaceholderText(QStringLiteral("DNS servers to offer, separated by spaces "
	            "-- the router if it answers, else none"));
	form->addRow(QStringLiteral("offer DNS"), dhcp_dns);

	/* **The LAN's DNS forwarder** (0301): the same dnsmasq answers names on
	 * this interface, forwarding to what the router itself resolves with,
	 * and the hosts' lease names resolve too. */
	dhcp_dns_forward = new QCheckBox(QStringLiteral("answer DNS for this network"), this);
	dhcp_dns_forward->setObjectName(QStringLiteral("iface_dhcp_dns_forward"));
	dhcp_dns_forward->setToolTip(QStringLiteral(
	    "The hosts are offered this router as their DNS server, and it forwards what "
	    "it cannot answer to the servers the router uses. Names the DHCP server handed "
	    "out resolve too."));
	form->addRow(QString(), dhcp_dns_forward);
	/* 0305: what a device with its own DNS server asks is answered here too,
	 * so a block list reaches it. */
	dhcp_dns_intercept = new QCheckBox(QStringLiteral("answer DNS sent to any server"), this);
	dhcp_dns_intercept->setObjectName(QStringLiteral("iface_dhcp_dns_intercept"));
	dhcp_dns_intercept->setToolTip(QStringLiteral(
	    "A device that ignores the DNS server offered -- a TV, a streaming stick -- is "
	    "answered by this router anyway, so block lists reach it. IPv4."));
	form->addRow(QString(), dhcp_dns_intercept);

	/* The standard options (0303), each blank for none -- the gateway blank
	 * for this router. The compiler checks each shape and names the one it
	 * refuses. */
	const struct {
		QLineEdit **field;
		const char *object;
		const char *label;
		const char *placeholder;
	} options[] = {
		{ &dhcp_gateway, "iface_dhcp_gateway", "gateway", "blank for this router" },
		{ &dhcp_domain, "iface_dhcp_domain", "domain", "home.lan -- names answer under it" },
		{ &dhcp_ntp, "iface_dhcp_ntp", "NTP servers", "IPv4 addresses, separated by spaces" },
		{ &dhcp_boot_file, "iface_dhcp_boot_file", "network boot file", "pxelinux.0" },
		{ &dhcp_boot_server, "iface_dhcp_boot_server", "boot server",
		    "the TFTP server's address, with a boot file" },
		{ &dhcp_tftp_server, "iface_dhcp_tftp_server", "TFTP server (66)",
		    "a name or address" },
		{ &dhcp_wpad, "iface_dhcp_wpad", "proxy autoconfig (WPAD)",
		    "http://wpad.home.lan/wpad.dat" },
		{ &dhcp_range6, "iface_dhcp_range6", "DHCPv6 range",
		    "::100-::1ff -- suffixes in this interface's prefix; blank for none" },
		{ &dhcp_relay, "iface_dhcp_relay", "relay to",
		    "DHCP servers to pass requests to, by address -- instead of serving" },
		{ &dhcp_block, "iface_dhcp_block", "block lists",
		    "block lists to apply, by name -- needs DNS answered here" },
	};
	for (const auto &one : options) {
		*one.field = new QLineEdit(this);
		(*one.field)->setObjectName(QString::fromLatin1(one.object));
		(*one.field)->setPlaceholderText(QString::fromLatin1(one.placeholder));
		form->addRow(QString::fromLatin1(one.label), *one.field);
	}

	const auto serving = [this](bool on) {
		dhcp_range->setEnabled(on);
		dhcp_lease->setEnabled(on);
		dhcp_dns->setEnabled(on);
		dhcp_dns_forward->setEnabled(on);
		dhcp_dns_intercept->setEnabled(on);
		for (QLineEdit *field : { dhcp_gateway, dhcp_domain, dhcp_ntp, dhcp_boot_file,
		         dhcp_boot_server, dhcp_tftp_server, dhcp_wpad, dhcp_range6, dhcp_relay,
		         dhcp_block }) {
			field->setEnabled(on);
		}
	};
	connect(dhcp_server, &QCheckBox::toggled, this, serving);
	serving(false);

	reservations = a_table(this, form, QStringLiteral("reservations"),
	    QStringLiteral("iface_reservations"),
	    { QStringLiteral("name"), QStringLiteral("mac"), QStringLiteral("address") });
	reservations->setToolTip(QStringLiteral(
	    "A fixed address for a named host, served with the range above."));

	/* Custom options (0303), typed as UniFi types them: the type is how the
	 * value is put on the wire, never a guess. */
	dhcp_options = a_table(this, form, QStringLiteral("DHCP options"),
	    QStringLiteral("iface_dhcp_options"),
	    { QStringLiteral("name"), QStringLiteral("code"), QStringLiteral("type"),
	        QStringLiteral("value") });
	dhcp_options->setToolTip(QStringLiteral(
	    "type is ip, text, u8, u16, u32, bool or hex. ip takes addresses separated by "
	    "spaces, bool true or false, hex octets as 01:a2:03."));

	/* Port forwards (0298) beside NAT, where the language puts them: traffic
	 * arriving on this interface for a port goes to a host behind it. */
	forwards = a_table(this, form, QStringLiteral("port forwards"),
	    QStringLiteral("iface_forwards"),
	    { QStringLiteral("name"), QStringLiteral("protocol"), QStringLiteral("port"),
	        QStringLiteral("to"), QStringLiteral("to port"), QStringLiteral("hairpin") });
	forwards->setToolTip(QStringLiteral(
	    "protocol is tcp or udp; to port blank for the same port; hairpin blank or yes for "
	    "reachable from inside too (0299), no to turn that off."));

	advertise = new QCheckBox(QStringLiteral("advertise a prefix to the hosts behind it"), this);
	advertise->setObjectName(QStringLiteral("iface_advertise"));
	form->addRow(QString(), advertise);
	advertise_prefixes = new QLineEdit(this);
	advertise_prefixes->setObjectName(QStringLiteral("iface_advertise_prefixes"));
	advertise_prefixes->setPlaceholderText(QStringLiteral("@pd:wan0/1 -- a delegated prefix, "
	                                     "and which subnet of it"));
	form->addRow(QStringLiteral("prefixes"), advertise_prefixes);
	advertise_backend = new QComboBox(this);
	advertise_backend->setObjectName(QStringLiteral("iface_advertise_backend"));
	advertise_backend->addItem(QStringLiteral("whichever is installed"), QStringLiteral("auto"));
	advertise_backend->addItem(QStringLiteral("radvd"), QStringLiteral("radvd"));
	advertise_backend->addItem(QStringLiteral("odhcpd"), QStringLiteral("odhcpd"));
	form->addRow(QStringLiteral("advertised by"), advertise_backend);
	advertise_managed = new QCheckBox(QStringLiteral("addresses come from DHCPv6 (managed)"), this);
	form->addRow(QString(), advertise_managed);
	advertise_other = new QCheckBox(QStringLiteral("other settings come from DHCPv6"), this);
	form->addRow(QString(), advertise_other);
	advertise_dns = new QCheckBox(QStringLiteral("advertise this router as a DNS server"), this);
	advertise_dns->setChecked(true);
	form->addRow(QString(), advertise_dns);
	advertise_lifetime = new QSpinBox(this);
	advertise_lifetime->setRange(0, 9000);
	advertise_lifetime->setSuffix(QStringLiteral(" s"));
	advertise_lifetime->setSpecialValueText(QStringLiteral("default"));
	form->addRow(QStringLiteral("router lifetime"), advertise_lifetime);
	const auto advertising = [this](bool on) {
		advertise_prefixes->setEnabled(on);
		advertise_backend->setEnabled(on);
		advertise_managed->setEnabled(on);
		advertise_other->setEnabled(on);
		advertise_dns->setEnabled(on);
		advertise_lifetime->setEnabled(on);
	};
	connect(advertise, &QCheckBox::toggled, this, advertising);
	advertising(false);

	/* Wired 802.1X (0008): a campus port that will not pass traffic until
	 * the machine has authenticated. */
	dot1x = new QCheckBox(QStringLiteral("authenticate this port with 802.1X"), this);
	dot1x->setObjectName(QStringLiteral("iface_dot1x"));
	form->addRow(QString(), dot1x);
	dot1x_method = new QComboBox(this);
	dot1x_method->setObjectName(QStringLiteral("iface_dot1x_method"));
	dot1x_method->addItem(QStringLiteral("PEAP"), QStringLiteral("peap"));
	dot1x_method->addItem(QStringLiteral("TTLS"), QStringLiteral("ttls"));
	dot1x_method->addItem(QStringLiteral("TLS (certificate)"), QStringLiteral("tls"));
	dot1x_method->addItem(QStringLiteral("PWD"), QStringLiteral("pwd"));
	form->addRow(QStringLiteral("eap method"), dot1x_method);
	const auto line = [this, form](QLineEdit **into, const char *name, const QString &label,
	                      const QString &hint) {
		*into = new QLineEdit(this);
		(*into)->setObjectName(QString::fromLatin1(name));
		(*into)->setPlaceholderText(hint);
		form->addRow(label, *into);
	};
	line(&dot1x_identity, "iface_dot1x_identity", QStringLiteral("identity"), QString());
	line(&dot1x_anonymous_identity, "iface_dot1x_anonymous", QStringLiteral("anonymous identity"),
	    QStringLiteral("optional, sent in the clear"));
	line(&dot1x_phase2, "iface_dot1x_phase2", QStringLiteral("phase 2"),
	    QStringLiteral("mschapv2, for example"));
	line(&dot1x_ca_cert, "iface_dot1x_ca_cert", QStringLiteral("ca certificate"),
	    QStringLiteral("a path, or @secret:NAME"));
	line(&dot1x_domain_suffix_match, "iface_dot1x_server", QStringLiteral("server name"),
	    QStringLiteral("the name the server's certificate must carry"));
	line(&dot1x_client_cert, "iface_dot1x_client_cert", QStringLiteral("client certificate"),
	    QStringLiteral("a path, or @secret:NAME"));
	line(&dot1x_private_key, "iface_dot1x_private_key", QStringLiteral("private key"),
	    QStringLiteral("a path, or @secret:NAME"));
	line(&dot1x_reference, "iface_dot1x_reference", QStringLiteral("password from"),
	    QStringLiteral("@secret:NAME -- blank for @secret:dot1x-") + interface);
	line(&dot1x_password, "iface_dot1x_password", QStringLiteral("password"),
	    QStringLiteral("blank keeps the stored one"));
	dot1x_password->setEchoMode(QLineEdit::Password);
	const auto authenticating = [this](bool on) {
		QWidget *fields[] = { dot1x_method, dot1x_identity, dot1x_anonymous_identity,
			dot1x_phase2, dot1x_ca_cert, dot1x_domain_suffix_match, dot1x_client_cert,
			dot1x_private_key, dot1x_reference, dot1x_password };
		for (QWidget *field : fields) {
			field->setEnabled(on);
		}
	};
	connect(dot1x, &QCheckBox::toggled, this, authenticating);
	authenticating(false);

	ipv6_token = new QLineEdit(this);
	ipv6_token->setObjectName(QStringLiteral("iface_ipv6_token"));
	ipv6_token->setPlaceholderText(QStringLiteral("::5 -- the host part of a SLAAC address"));
	form->addRow(QStringLiteral("IPv6 token"), ipv6_token);
	guard = new QLineEdit(this);
	guard->setObjectName(QStringLiteral("iface_guard"));
	guard->setPlaceholderText(QStringLiteral("why this must not be disrupted -- an NFS root, "
	                        "say; blank for no guard"));
	form->addRow(QStringLiteral("guard"), guard);

	/* **Every program netcfgd runs for this interface**, as a list: the shared
	 * editor since 10.616, when the network dialog gained one too. */
	hooks = new ncfg_hooks_editor(QStringLiteral("iface"), this);
	form->addRow(QStringLiteral("hooks"), hooks);

	/* In a scroll area since 10.612: the router keys made the form taller
	 * than a laptop's screen, and a row below the edge is a row nobody can
	 * reach. */
	auto *holder = new QWidget(this);
	holder->setLayout(form);
	auto *scroll = new QScrollArea(this);
	scroll->setWidgetResizable(true);
	scroll->setFrameShape(QFrame::NoFrame);
	scroll->setWidget(holder);
	layout->addWidget(scroll, 1);

	/* Constructed near the top rather than here; see the comment there. */
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("iface_save"));
	layout->addWidget(buttons);

	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_interface_dialog::submit);
	connect(addressing, &ncfg_addressing_editor::noted, note, &QLabel::setText);
	connect(hooks, &ncfg_hooks_editor::noted, note, &QLabel::setText);
	connect(detection, &QComboBox::currentIndexChanged, this,
	    &ncfg_interface_dialog::detection_changed);

	load_existing();
	load_hooks();
	detection_changed();
}

/*
 * Put the interface's current configuration into the form.
 *
 * **Without this the dialog was an empty form that overwrites.** It read
 * nothing about the interface it was opened on, so every field sat at its
 * constructed default -- DHCP, no address, no gateway, preference and MTU
 * unset, forwarding and NAT off, detection on carrier -- and `submit()` writes
 * the composed block with `replace = true`. Opening a configured interface and
 * pressing Save replaced its drop-in with that. Measured: a static
 * 192.0.2.10/24, a default route, `preference = 50`, forwarding, NAT and a
 * link probe, all gone, with the note reporting that netcfgd had re-read its
 * configuration.
 *
 * The values come from the daemon's document rather than from the drop-in
 * text, because a form is a set of fields and the file is a language: parsing
 * it here would be a second implementation of the compiler, in C++, in a
 * window.
 *
 * `unmodelled` is why this cannot be only a load. An `interface` block carries
 * things this form has no field for, and a dialog that loaded the six it knows
 * and saved the whole block would still delete the rest. Save is refused
 * instead, naming them.
 */
void ncfg_interface_dialog::load_existing()
{
	QString error;
	if (!connection->interface_config(interface, &existing, &error)) {
		/* No daemon, or it would not answer. The form stays at its defaults,
		 * and `submit()` refuses for the same reason: what is on the machine
		 * is unknown, so overwriting it is not something to do quietly. */
		unknown = true;
		return;
	}
	if (!existing.present) {
		return;
	}

	addressing->load(existing.sources);
	route_editor->load(existing.routes);
	const int mode = dns_mode->findData(existing.dns.mode);
	if (mode >= 0) {
		dns_mode->setCurrentIndex(mode);
	}
	dns_servers->setText(existing.dns.servers);
	dns_search->setText(existing.dns.search);
	dns_domains->setText(existing.dns.domains);
	const int drift = on_drift->findData(existing.on_drift);
	if (drift >= 0) {
		on_drift->setCurrentIndex(drift);
	}
	if (existing.preference >= 0) {
		preference->setValue(existing.preference);
	}
	enabled->setChecked(existing.enabled);
	forwarding->setChecked(existing.forwarding);
	nat->setChecked(existing.nat);
	dhcp_server->setChecked(existing.dhcp_server);
	dhcp_range->setText(existing.dhcp_range);
	dhcp_lease->setValue(existing.dhcp_lease > 0 ? existing.dhcp_lease : 0);
	dhcp_dns->setText(existing.dhcp_dns);
	dhcp_dns_forward->setChecked(existing.dhcp_dns_forward);
	dhcp_dns_intercept->setChecked(existing.dhcp_dns_intercept);
	dhcp_gateway->setText(existing.dhcp_gateway);
	dhcp_domain->setText(existing.dhcp_domain);
	dhcp_ntp->setText(existing.dhcp_ntp);
	dhcp_boot_file->setText(existing.dhcp_boot_file);
	dhcp_boot_server->setText(existing.dhcp_boot_server);
	dhcp_tftp_server->setText(existing.dhcp_tftp_server);
	dhcp_wpad->setText(existing.dhcp_wpad);
	dhcp_range6->setText(existing.dhcp_range6);
	dhcp_relay->setText(existing.dhcp_relay);
	dhcp_block->setText(existing.dhcp_block);
	for (const auto &one : existing.dhcp_options) {
		put_row(dhcp_options, { one.name, QString::number(one.code), one.kind, one.value });
	}
	for (const auto &one : existing.reservations) {
		put_row(reservations, { one.name, one.mac, one.address });
	}
	for (const auto &one : existing.port_forwards) {
		put_row(forwards, { one.name, one.protocol, QString::number(one.port), one.to,
		    one.to_port > 0 ? QString::number(one.to_port) : QString(),
		    one.hairpin < 0 ? QString() : (one.hairpin ? QStringLiteral("yes")
		                                               : QStringLiteral("no")) });
	}
	advertise->setChecked(existing.advertise);
	advertise_prefixes->setText(existing.advertise_prefixes);
	{
		const int at = advertise_backend->findData(existing.advertise_backend);
		if (at >= 0) {
			advertise_backend->setCurrentIndex(at);
		}
	}
	advertise_managed->setChecked(existing.advertise_managed);
	advertise_other->setChecked(existing.advertise_other);
	advertise_dns->setChecked(existing.advertise_dns);
	advertise_lifetime->setValue(existing.advertise_lifetime > 0 ? existing.advertise_lifetime : 0);
	ipv6_token->setText(existing.ipv6_token);
	guard->setText(existing.guard);
	dot1x->setChecked(existing.dot1x);
	{
		const int at = dot1x_method->findData(existing.dot1x_method);
		if (at >= 0) {
			dot1x_method->setCurrentIndex(at);
		}
	}
	dot1x_identity->setText(existing.dot1x_identity);
	dot1x_anonymous_identity->setText(existing.dot1x_anonymous_identity);
	dot1x_phase2->setText(existing.dot1x_phase2);
	dot1x_ca_cert->setText(existing.dot1x_ca_cert);
	dot1x_domain_suffix_match->setText(existing.dot1x_domain_suffix_match);
	dot1x_client_cert->setText(existing.dot1x_client_cert);
	dot1x_private_key->setText(existing.dot1x_private_key);
	dot1x_reference->setText(existing.dot1x_password);

	if (!existing.probe_command.isEmpty()) {
		const int known = detection->findData(existing.probe_command);
		if (known >= 0) {
			detection->setCurrentIndex(known);
		} else {
			const int custom = detection->findData(QStringLiteral("command"));
			if (custom >= 0) {
				detection->setCurrentIndex(custom);
			}
			probe_command->setText(existing.probe_command);
			probe_args->setText(existing.probe_args);
		}
		probe_interval->setValue(existing.probe_interval);
		probe_timeout->setValue(existing.probe_timeout);
		probe_down_after->setValue(existing.probe_down_after);
		probe_up_after->setValue(existing.probe_up_after);
		probe_hold_down->setValue(existing.probe_hold_down);
		probe_require_lease->setChecked(existing.probe_require_lease);
	}
}

/*
 * This interface's hooks, and their scripts: how many the document declares,
 * which is `observe`, and then the bodies, which are `admin` -- the editor's
 * `load` says why both are needed.
 */
void ncfg_interface_dialog::load_hooks()
{
	QList<ncfg_hook_row> declared;
	QString error;
	if (!connection->hooks(&declared, &error)) {
		hooks_unknown = true;
		return;
	}
	int mine = 0;
	for (const ncfg_hook_row &row : declared) {
		if (row.interface == interface) {
			mine++;
		}
	}
	const QString said = hooks->load(connection, interface, false, mine);
	if (!said.isEmpty()) {
		note->setText(said);
	}
}

/*
 * The scripts on disk, rebuilt.
 *
 * A method rather than constructor code because the editor can create one, and
 * a list read before that script existed would not contain it -- which reads as
 * the save having failed.
 *
 * Inserted before "run a command" so the escape hatch stays last, and keyed by
 * absolute path because that is what gets written: the model requires an
 * absolute command, and a name resolved later could resolve to something else.
 * A name seen in /etc wins over the same name in /usr/share, so an operator who
 * copied an example and edited it gets theirs.
 */
void ncfg_interface_dialog::reload_detections(const QString &select)
{
	const QString had = select.isEmpty() ? detection->currentData().toString() : QString();
	detection->clear();
	fill(detection, detections, sizeof(detections) / sizeof(detections[0]));

	/*
	 * **Asked of the daemon, not read off this machine.** A client only ever
	 * talks to netcfgd, and these files belong to the machine netcfgd runs on.
	 * Listing the local /etc would show the operator's own laptop while
	 * configuring a remote one -- and the editor would then save an edit of
	 * one machine's script onto another.
	 *
	 * The daemon has already resolved the shadowing, so each name appears once
	 * and is the one netcfgd would run.
	 */
	QString error;
	scripts.clear();
	if (!connection->probes(&scripts, &error)) {
		/* Not fatal: the rest of the dialog works, and carrier-only and a
		 * hand-written command are both still reachable. */
		note->setText(error);
	}

	for (const ncfg_probe_row &script : scripts) {
		/* Keyed by absolute path, which is what gets written: the model
		 * requires an absolute command, and a name resolved later could
		 * resolve to something else. */
		detection->insertItem(detection->count() - 1,
		    QStringLiteral("%1 -- %2").arg(script.name, script.directory),
		    QStringLiteral("%1/%2").arg(script.directory, script.name));
	}

	QString chosen;
	if (!select.isEmpty()) {
		for (const ncfg_probe_row &script : scripts) {
			if (script.name == select) {
				chosen = QStringLiteral("%1/%2").arg(script.directory, script.name);
				break;
			}
		}
	}
	const QString want = chosen.isEmpty() ? had : chosen;
	const int at = detection->findData(want);
	if (at >= 0) {
		detection->setCurrentIndex(at);
	}
}

void ncfg_interface_dialog::edit_detection()
{
	const QString chosen = detection->currentData().toString();
	/* Only a script can be opened. "Carrier only" is not a program, and "run a
	 * command" names one this dialog did not put there and does not own. */
	if (chosen.isEmpty() || chosen == QStringLiteral("command")) {
		note->setText(QStringLiteral(
		    "choose a script to view it. `run a command` names a program this dialog "
		    "did not write, so there is nothing here to open."));
		return;
	}

	/* The text is already in hand from the listing, so the editor is given it
	 * rather than a path to open: reading the file here would be the same
	 * mistake in the other direction. */
	ncfg_probe_row opening;
	for (const ncfg_probe_row &script : scripts) {
		if (QStringLiteral("%1/%2").arg(script.directory, script.name) == chosen) {
			opening = script;
			break;
		}
	}
	ncfg_probe_dialog dialog(connection, opening, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	/* An edit of a shipped example is saved as a copy in /etc, so the list has
	 * gained an entry and the selection should follow it there. */
	reload_detections(dialog.written_name());
	note->setText(dialog.outcome());
}

void ncfg_interface_dialog::detection_changed()
{
	const QString how = detection->currentData().toString();
	const bool custom = how == QStringLiteral("command");
	/* Kept as a member: the form is inside a scroll area since 10.612, so the
	 * dialog's first layout item is that area, not the form. */
	QFormLayout *form = form_layout;
	if (form) {
		form->setRowVisible(probe_command, custom);
		form->setRowVisible(probe_args, custom);
		form->setRowVisible(probe_interval, !how.isEmpty());
		form->setRowVisible(probe_timeout, !how.isEmpty());
		form->setRowVisible(probe_down_after, !how.isEmpty());
		form->setRowVisible(probe_up_after, !how.isEmpty());
		form->setRowVisible(probe_hold_down, !how.isEmpty());
		form->setRowVisible(probe_require_lease, !how.isEmpty());
	}

	if (how.isEmpty()) {
		note->setText(QStringLiteral(
		    "Carrier alone. A cable into a switch that has lost its own uplink has "
		    "carrier and no path, and netcfgd will keep preferring it."));
	} else if (custom) {
		note->setText(QStringLiteral(
		    "Exit status zero means the link works. It runs as root, on an "
		    "interval, and what it prints on standard error is shown here and in "
		    "`ncfg status`. Do not background anything: netcfgd kills the process "
		    "it started, and a child left running outlives it."));
	} else {
		/* The exact command line, because a probe is a program netcfgd runs as
		 * root on an interval and an operator should be able to read what that
		 * is rather than trust a friendly word for it. The interface is passed
		 * as an argument because netcfgd binds nothing: a script that did not
		 * take it would answer about whichever interface the route table
		 * happened to pick. */
		note->setText(QStringLiteral(
		    "netcfgd will run:  %1 %2\n"
		    "Exit zero means the link works. A failing probe withholds this "
		    "interface's routes, exactly as an unplugged cable does -- and what "
		    "the script prints on standard error is shown as the reason. It is an "
		    "ordinary shell script: copy it into /etc/netcfgd/probe and edit it.")
		          .arg(how, interface));
	}
}

QString ncfg_interface_dialog::block_text() const
{
	QStringList body;

	/* **The list, in its order.** `config` is a composition and every entry
	 * contributes; a fixed address is written as the address itself, which is
	 * how the language spells that source. An empty list is `null`, which is
	 * what a bridge member wants and what "no address at all" means. */
	const QStringList entries = addressing->entries();
	if (entries.isEmpty()) {
		body << QStringLiteral("\tconfig = \"null\"");
	} else {
		body << QStringLiteral("\tconfig = [%1]").arg(entries.join(QStringLiteral(", ")));
	}

	const QStringList lines = route_editor->lines();
	if (!lines.isEmpty()) {
		body << QStringLiteral("\troutes = [%1]").arg(lines.join(QStringLiteral(", ")));
	}

	/* A scope only where the operator asked for one: an interface that states
	 * nothing is one the host-wide policy answers for, and writing an empty
	 * `dns { }` would be saying something different from saying nothing. */
	const QString mode = dns_mode->currentData().toString();
	const bool scoped = !mode.isEmpty() || !dns_servers->text().trimmed().isEmpty()
	    || !dns_search->text().trimmed().isEmpty() || !dns_domains->text().trimmed().isEmpty();
	if (scoped) {
		body << QStringLiteral("\tdns {");
		if (!mode.isEmpty()) {
			body << QStringLiteral("\t\tmode = \"%1\"").arg(mode);
		}
		const struct {
			const char *key;
			QString     value;
		} scopes[] = {
			{ "servers", dns_servers->text().trimmed() },
			{ "search", dns_search->text().trimmed() },
			{ "domains", dns_domains->text().trimmed() },
		};
		for (const auto &one : scopes) {
			if (one.value.isEmpty()) {
				continue;
			}
			QStringList quoted;
			const QStringList words = one.value.split(QLatin1Char(' '), Qt::SkipEmptyParts);
			for (const QString &word : words) {
				quoted << QStringLiteral("\"%1\"").arg(word);
			}
			body << QStringLiteral("\t\t%1 = [%2]")
			        .arg(QString::fromLatin1(one.key), quoted.join(QStringLiteral(", ")));
		}
		body << QStringLiteral("\t}");
	}

	if (!on_drift->currentData().toString().isEmpty()) {
		body << QStringLiteral("\ton_drift = \"%1\"").arg(on_drift->currentData().toString());
	}

	if (preference->value() > 0) {
		body << QStringLiteral("\tpreference = %1").arg(preference->value());
	}
	/* Only when false: enabled is true unless a document says otherwise, and a
	 * block restating every default is one nobody can read for what is
	 * unusual. */
	if (!enabled->isChecked()) {
		body << QStringLiteral("\tenabled = false");
	}
	if (forwarding->isChecked()) {
		body << QStringLiteral("\tforwarding = true");
	}
	if (nat->isChecked()) {
		body << QStringLiteral("\tnat = true");
	}
	if (dhcp_server->isChecked()) {
		QStringList served;
		if (!dhcp_range->text().trimmed().isEmpty()) {
			served << QStringLiteral("\t\trange = \"%1\"").arg(dhcp_range->text().trimmed());
		}
		if (dhcp_lease->value() > 0) {
			served << QStringLiteral("\t\tlease = %1").arg(dhcp_lease->value());
		}
		QStringList offered;
		const QStringList each = dhcp_dns->text().split(QLatin1Char(' '), Qt::SkipEmptyParts);
		for (const QString &one : each) {
			offered << QStringLiteral("\"%1\"").arg(one);
		}
		if (!offered.isEmpty()) {
			served << QStringLiteral("\t\tdns = [%1]").arg(offered.join(QStringLiteral(", ")));
		}
		if (dhcp_dns_forward->isChecked()) {
			served << QStringLiteral("\t\tdns_forward = true");
		}
		if (dhcp_dns_intercept->isChecked()) {
			served << QStringLiteral("\t\tdns_intercept = true");
		}
		const struct {
			const char *key;
			QLineEdit  *field;
		} texts[] = {
			{ "gateway", dhcp_gateway },
			{ "domain", dhcp_domain },
			{ "boot_file", dhcp_boot_file },
			{ "boot_server", dhcp_boot_server },
			{ "tftp_server", dhcp_tftp_server },
			{ "wpad", dhcp_wpad },
			{ "range6", dhcp_range6 },
		};
		for (const auto &one : texts) {
			if (!one.field->text().trimmed().isEmpty()) {
				served << QStringLiteral("\t\t%1 = \"%2\"")
				              .arg(QString::fromLatin1(one.key), one.field->text().trimmed());
			}
		}
		QStringList clocks;
		for (const QString &one : dhcp_ntp->text().split(QLatin1Char(' '), Qt::SkipEmptyParts)) {
			clocks << QStringLiteral("\"%1\"").arg(one);
		}
		if (!clocks.isEmpty()) {
			served << QStringLiteral("\t\tntp = [%1]").arg(clocks.join(QStringLiteral(", ")));
		}
		QStringList relays;
		for (const QString &one : dhcp_relay->text().split(QLatin1Char(' '), Qt::SkipEmptyParts)) {
			relays << QStringLiteral("\"%1\"").arg(one);
		}
		if (!relays.isEmpty()) {
			served << QStringLiteral("\t\trelay = [%1]").arg(relays.join(QStringLiteral(", ")));
		}
		QStringList blocks;
		for (const QString &one : dhcp_block->text().split(QLatin1Char(' '), Qt::SkipEmptyParts)) {
			blocks << QStringLiteral("\"%1\"").arg(one);
		}
		if (!blocks.isEmpty()) {
			served << QStringLiteral("\t\tblock = [%1]").arg(blocks.join(QStringLiteral(", ")));
		}
		body << QStringLiteral("\tdhcp_server {");
		for (int row = 0; row < dhcp_options->rowCount(); row++) {
			const QString kind = text_at(dhcp_options, row, 2);
			const QString value = text_at(dhcp_options, row, 3);
			QString       written = value;
			if (kind == QLatin1String("ip")) {
				QStringList quoted;
				for (const QString &one : value.split(QLatin1Char(' '), Qt::SkipEmptyParts)) {
					quoted << QStringLiteral("\"%1\"").arg(one);
				}
				written = QStringLiteral("[%1]").arg(quoted.join(QStringLiteral(", ")));
			} else if (kind == QLatin1String("text") || kind == QLatin1String("hex")) {
				written = QStringLiteral("\"%1\"").arg(value);
			}
			served << QStringLiteral("\t\toption \"%1\" { code = %2; %3 = %4 }")
			              .arg(text_at(dhcp_options, row, 0), text_at(dhcp_options, row, 1), kind,
			                  written);
		}
		for (int row = 0; row < reservations->rowCount(); row++) {
			served << QStringLiteral("\t\thost \"%1\" { mac = \"%2\"; address = \"%3\" }")
			              .arg(text_at(reservations, row, 0), text_at(reservations, row, 1),
			                  text_at(reservations, row, 2));
		}
		body << served;
		body << QStringLiteral("\t}");
	}
	for (int row = 0; row < forwards->rowCount(); row++) {
		QString line = QStringLiteral("\tport_forward \"%1\" { protocol = \"%2\"; port = %3; "
		                              "to = \"%4\"")
		                   .arg(text_at(forwards, row, 0), text_at(forwards, row, 1),
		                       text_at(forwards, row, 2), text_at(forwards, row, 3));
		if (!text_at(forwards, row, 4).isEmpty()) {
			line += QStringLiteral("; to_port = %1").arg(text_at(forwards, row, 4));
		}
		if (!text_at(forwards, row, 5).isEmpty()) {
			line += QStringLiteral("; hairpin = %1")
			            .arg(text_at(forwards, row, 5) == QLatin1String("no")
			                    ? QStringLiteral("false") : QStringLiteral("true"));
		}
		body << line + QStringLiteral(" }");
	}
	if (advertise->isChecked()) {
		QStringList quoted;
		for (const QString &one :
		    advertise_prefixes->text().split(QLatin1Char(' '), Qt::SkipEmptyParts)) {
			quoted << QStringLiteral("\"%1\"").arg(one);
		}
		body << QStringLiteral("\tadvertise {");
		if (advertise_backend->currentData().toString() != QLatin1String("auto")) {
			body << QStringLiteral("\t\tbackend = \"%1\"")
			            .arg(advertise_backend->currentData().toString());
		}
		body << QStringLiteral("\t\tprefixes = [%1]").arg(quoted.join(QStringLiteral(", ")));
		if (advertise_managed->isChecked()) {
			body << QStringLiteral("\t\tmanaged = true");
		}
		if (advertise_other->isChecked()) {
			body << QStringLiteral("\t\tother_config = true");
		}
		if (!advertise_dns->isChecked()) {
			body << QStringLiteral("\t\tdns = false");
		}
		if (advertise_lifetime->value() > 0) {
			body << QStringLiteral("\t\tlifetime = %1").arg(advertise_lifetime->value());
		}
		body << QStringLiteral("\t}");
	}
	if (dot1x->isChecked()) {
		const QLineEdit *keys[] = { dot1x_identity, dot1x_anonymous_identity,
			dot1x_domain_suffix_match, dot1x_ca_cert, dot1x_client_cert, dot1x_private_key,
			dot1x_phase2 };
		static const char *const words[] = { "identity", "anonymous_identity",
			"domain_suffix_match", "ca_cert", "client_cert", "private_key", "phase2" };
		body << QStringLiteral("\tdot1x {");
		body << QStringLiteral("\t\teap = \"%1\"").arg(dot1x_method->currentData().toString());
		for (size_t at = 0; at < sizeof(words) / sizeof(words[0]); at++) {
			if (!keys[at]->text().trimmed().isEmpty()) {
				body << QStringLiteral("\t\t%1 = \"%2\"")
				            .arg(QString::fromLatin1(words[at]), keys[at]->text().trimmed());
			}
		}
		/* A password for every method but TLS, and for TLS where one is
		 * already referred to. */
		if (dot1x_method->currentData().toString() != QLatin1String("tls") ||
		    !dot1x_reference->text().trimmed().isEmpty()) {
			body << QStringLiteral("\t\tpassword = \"%1\"").arg(dot1x_reference_text());
		}
		body << QStringLiteral("\t}");
	}
	if (!ipv6_token->text().trimmed().isEmpty()) {
		body << QStringLiteral("\tipv6_token = \"%1\"").arg(ipv6_token->text().trimmed());
	}
	if (!guard->text().trimmed().isEmpty()) {
		body << QStringLiteral("\tguard = \"%1\"").arg(guard->text().trimmed());
	}

	const QString how = detection->currentData().toString();
	if (!how.isEmpty()) {
		QString command;
		QString args;
		if (how != QStringLiteral("command")) {
			/* A script from the list. The interface is its only argument, and
			 * it is not optional: netcfgd runs the command as given and binds
			 * nothing. */
			command = how;
			args = QStringLiteral("\"%1\"").arg(interface);
		} else {
			command = probe_command->text().trimmed();
			QStringList each;
			const QStringList given = probe_args->text().split(QLatin1Char(' '),
			    Qt::SkipEmptyParts);
			for (const QString &one : given) {
				each << QStringLiteral("\"%1\"").arg(one);
			}
			args = each.join(QStringLiteral(", "));
		}
		body << QStringLiteral("\tprobe {");
		body << QStringLiteral("\t\tcommand = \"%1\"").arg(command);
		if (!args.isEmpty()) {
			body << QStringLiteral("\t\targs = [%1]").arg(args);
		}
		if (probe_interval->value() > 0) {
			body << QStringLiteral("\t\tinterval = %1").arg(probe_interval->value());
		}
		if (probe_timeout->value() > 0) {
			body << QStringLiteral("\t\ttimeout = %1").arg(probe_timeout->value());
		}
		/* Only what differs from the parser's default, as the renderer
		 * writes a probe: `require_lease` therefore only when it is off. */
		if (probe_down_after->value() != 3) {
			body << QStringLiteral("\t\tdown_after = %1").arg(probe_down_after->value());
		}
		if (probe_up_after->value() != 2) {
			body << QStringLiteral("\t\tup_after = %1").arg(probe_up_after->value());
		}
		if (probe_hold_down->value() > 0) {
			body << QStringLiteral("\t\thold_down = %1").arg(probe_hold_down->value());
		}
		if (!probe_require_lease->isChecked()) {
			body << QStringLiteral("\t\trequire_lease = false");
		}
		body << QStringLiteral("\t}");
	}

	/* **Last in the block, and verbatim.** A hook body is raw shell that the
	 * language keeps byte for byte, so it is written unindented -- see
	 * `ncfg_hook_block`, where the reason is that an indented `#!/bin/sh` is
	 * not a shebang and the materialiser would add another on every save. */
	body << hooks->blocks();

	QStringList block;
	block << QStringLiteral("# Written by netcfgd's gui. Ordinary netcfgd configuration:");
	block << QStringLiteral("# edit it, diff it, commit it, or delete it.");
	block << QString();
	/* **No `device` block here any more.** It used to write the MTU as a
	 * second block in this file; the device editor writes the whole of a
	 * device now, and two drop-ins declaring one `device` is a duplicate block
	 * the loader refuses -- correctly. Decision 0250. */
	block << QStringLiteral("interface %1 {").arg(interface);
	block << body;
	block << QStringLiteral("}");
	return block.join(QStringLiteral("\n")) + QStringLiteral("\n");
}

QString ncfg_interface_dialog::dot1x_reference_text() const
{
	const QString written = dot1x_reference->text().trimmed();
	return written.isEmpty() ? QStringLiteral("@secret:dot1x-%1").arg(interface) : written;
}

void ncfg_interface_dialog::submit()
{
	const QLineEdit *values[] = { dns_servers, dns_search, dns_domains,
		probe_command, probe_args, dhcp_range, dhcp_dns, dhcp_gateway, dhcp_domain, dhcp_ntp,
		dhcp_boot_file, dhcp_boot_server, dhcp_tftp_server, dhcp_wpad, dhcp_range6, dhcp_relay,
		dhcp_block, advertise_prefixes,
		ipv6_token,
		guard, dot1x_identity, dot1x_anonymous_identity, dot1x_phase2, dot1x_ca_cert,
		dot1x_domain_suffix_match, dot1x_client_cert, dot1x_private_key, dot1x_reference };
	for (const QLineEdit *value : values) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash "
			              "or a newline"));
			return;
		}
	}
	/* An option's name, code and type are words, its value text: a text
	 * value may hold a space, never what would end the quote it is put in. */
	static const QStringList option_kinds = { QStringLiteral("ip"), QStringLiteral("text"),
		QStringLiteral("u8"), QStringLiteral("u16"), QStringLiteral("u32"),
		QStringLiteral("bool"), QStringLiteral("hex") };
	for (int row = 0; row < dhcp_options->rowCount(); row++) {
		bool          number = false;
		const QString value = text_at(dhcp_options, row, 3);
		text_at(dhcp_options, row, 1).toInt(&number);
		if (!is_word(text_at(dhcp_options, row, 0)) || !number ||
		    !option_kinds.contains(text_at(dhcp_options, row, 2)) || value.isEmpty() ||
		    !safe_value(value)) {
			note->setText(QStringLiteral("DHCP option %1 needs a name, a numeric code, a type "
			              "-- ip, text, u8, u16, u32, bool or hex -- and a value with no quote "
			              "or backslash").arg(row + 1));
			return;
		}
	}
	/* Each cell as the word or number it must be (10.612): a cell is text
	 * written into the block, so one that could close it is refused here. */
	for (int row = 0; row < reservations->rowCount(); row++) {
		if (!is_word(text_at(reservations, row, 0)) || !is_word(text_at(reservations, row, 1)) ||
		    !is_word(text_at(reservations, row, 2))) {
			note->setText(QStringLiteral("reservation %1 needs a name, a MAC and an address, "
			              "each one word").arg(row + 1));
			return;
		}
	}
	for (int row = 0; row < forwards->rowCount(); row++) {
		const QString protocol = text_at(forwards, row, 1);
		const QString hairpin = text_at(forwards, row, 5);
		if (!is_word(text_at(forwards, row, 0)) || !is_word(text_at(forwards, row, 3)) ||
		    (protocol != QLatin1String("tcp") && protocol != QLatin1String("udp")) ||
		    !is_port(text_at(forwards, row, 2)) ||
		    (!text_at(forwards, row, 4).isEmpty() && !is_port(text_at(forwards, row, 4))) ||
		    (!hairpin.isEmpty() && hairpin != QLatin1String("yes") &&
		    hairpin != QLatin1String("no"))) {
			note->setText(QStringLiteral("port forward %1 needs a name, tcp or udp, a port, a "
			              "host and optionally its port, and hairpin blank, yes or no")
			                  .arg(row + 1));
			return;
		}
	}
	if (!route_editor->refusal().isEmpty()) {
		note->setText(route_editor->refusal());
		return;
	}
	if (detection->currentData().toString() == QStringLiteral("command") &&
	    !probe_command->text().trimmed().startsWith(QLatin1Char('/'))) {
		/* The model says the command is absolute, and a relative one would be
		 * resolved against whatever directory netcfgd happens to be in. */
		note->setText(QStringLiteral("a probe command must be an absolute path"));
		return;
	}

	/* **Refused rather than approximated.** `submit` writes the whole block
	 * with `replace = true`, so anything the form has no field for is deleted
	 * by saving. The keys are named because "this dialog cannot edit that" is
	 * a sentence an operator can act on, where a silently shortened block is
	 * one they find days later. */
	if (unknown) {
		note->setText(QStringLiteral(
		    "netcfgd could not say what this interface is configured with, so saving "
		    "would overwrite something unknown. Check the daemon is running."));
		return;
	}
	/* **A hook whose body this form does not have.** The block is written
	 * whole, so saving would write the hook with nothing in it -- which is to
	 * say, delete the script. The tier is usually why: reading a hook body is
	 * `admin`, and a client below it could not have saved this anyway. */
	if (hooks_unknown || hooks->withheld()) {
		note->setText(QStringLiteral(
		    "this interface declares a hook whose script netcfgd would not hand over, "
		    "so saving would write the hook empty. Editing a hook needs root, which is "
		    "what runs it. Use `ncfg config edit interface-%1` instead.")
		        .arg(interface));
		return;
	}
	if (!existing.unmodelled.isEmpty()) {
		note->setText(QStringLiteral(
		    "this interface's configuration carries %1, which this dialog has no field "
		    "for -- saving would delete it. Edit the file instead: "
		    "`ncfg config edit interface-%2`.")
		        .arg(existing.unmodelled, interface));
		return;
	}

	QString error;
	if (dot1x->isChecked() && dot1x_identity->text().trimmed().isEmpty()) {
		note->setText(QStringLiteral("802.1X needs an identity: every method sends one"));
		return;
	}
	/* A typed password into the store the reference names, under its name,
	 * first -- so a block is never written pointing at nothing. The keyring
	 * and `pass` are read by netcfgd and not written, as in the network
	 * dialog (10.611). */
	if (dot1x->isChecked() && !dot1x_password->text().isEmpty()) {
		const QString reference = dot1x_reference_text();
		const QString stored = reference.mid(QStringLiteral("@secret:").size());
		if (!reference.startsWith(QStringLiteral("@secret:")) || stored.contains(QLatin1Char(':'))) {
			note->setText(QStringLiteral("the 802.1X password is %1, which netcfgd reads and does "
			              "not write: change it there, and leave the field here blank")
			                  .arg(reference));
			return;
		}
		if (!connection->secret_put(stored, dot1x_password->text(), true, &error)) {
			note->setText(error);
			return;
		}
	}
	if (!connection->config_put(QStringLiteral("interface-%1").arg(interface), block_text(),
	    true, &error)) {
		note->setText(error);
		return;
	}

	summary = QStringLiteral("wrote interface-%1: netcfgd re-read its configuration. "
	              "Run apply to make the machine match it.")
	          .arg(interface);
	accept();
}
