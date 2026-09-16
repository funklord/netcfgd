#include "interface_dialog.h"

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
#include <QHeaderView>
#include <QListWidget>
#include <QSpinBox>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {

struct choice {
	const char *shown;
	const char *key;
};

/* What an interface may be given. `dhcp` first because it is what a wired port
 * almost always wants, and "none" last because it is the deliberate one. */
/* The sources an `addressing` list can hold, spelled as the config language
 * spells them. `null` is deliberately absent: "no address" is an empty list
 * rather than a source, which is what `config = "null"` compiles to. */
const choice sources[] = {
	{ "DHCP (IPv4)", "dhcp" },
	{ "DHCPv6", "dhcp6" },
	{ "SLAAC (IPv6)", "slaac" },
	{ "a fixed address", "static" },
	{ "link-local only", "link-local" },
	{ "reported by a helper", "reported" },
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

	/* **The addressing list, as a list.** An interface composes its addresses
	 * out of several sources -- a lease and a fixed address, DHCP and SLAAC,
	 * a helper's report -- and the order is applied in. One combo naming a
	 * handful of arrangements could not carry that, and everything it could
	 * not carry was refused rather than shown. */
	this->sources = new QListWidget(this);
	this->sources->setObjectName(QStringLiteral("iface_sources"));
	this->sources->setSelectionMode(QAbstractItemView::SingleSelection);
	this->sources->setMaximumHeight(110);
	form->addRow(QStringLiteral("addressing"), this->sources);

	auto *source_row = new QHBoxLayout();
	source_kind = new QComboBox(this);
	source_kind->setObjectName(QStringLiteral("iface_source_kind"));
	fill(source_kind, ::sources, sizeof(::sources) / sizeof(::sources[0]));
	source_address = new QLineEdit(this);
	source_address->setObjectName(QStringLiteral("iface_source_address"));
	source_address->setPlaceholderText(QStringLiteral("192.0.2.10/24"));
	source_add = new QPushButton(QStringLiteral("add"), this);
	source_add->setObjectName(QStringLiteral("iface_source_add"));
	source_drop = new QPushButton(QStringLiteral("remove"), this);
	source_drop->setObjectName(QStringLiteral("iface_source_drop"));
	source_up = new QPushButton(QStringLiteral("up"), this);
	source_up->setObjectName(QStringLiteral("iface_source_up"));
	source_down = new QPushButton(QStringLiteral("down"), this);
	source_down->setObjectName(QStringLiteral("iface_source_down"));
	source_row->addWidget(source_kind);
	source_row->addWidget(source_address, 1);
	source_row->addWidget(source_add);
	source_row->addWidget(source_drop);
	source_row->addWidget(source_up);
	source_row->addWidget(source_down);
	form->addRow(QString(), source_row);

	/* Routes, as a table rather than one gateway box. A machine with a second
	 * subnet behind it has a static route to it, and the one box could only
	 * hold a default -- so an interface with any other route was refused. */
	this->routes = new QTableWidget(0, 3, this);
	this->routes->setObjectName(QStringLiteral("iface_routes"));
	QStringList route_columns;
	route_columns << QStringLiteral("destination") << QStringLiteral("via")
	              << QStringLiteral("metric");
	this->routes->setHorizontalHeaderLabels(route_columns);
	this->routes->verticalHeader()->setVisible(false);
	this->routes->horizontalHeader()->setStretchLastSection(true);
	this->routes->setSelectionBehavior(QAbstractItemView::SelectRows);
	this->routes->setSelectionMode(QAbstractItemView::SingleSelection);
	this->routes->setMaximumHeight(110);
	form->addRow(QStringLiteral("routes"), this->routes);

	auto *route_row = new QHBoxLayout();
	route_add = new QPushButton(QStringLiteral("add route"), this);
	route_add->setObjectName(QStringLiteral("iface_route_add"));
	route_drop = new QPushButton(QStringLiteral("remove route"), this);
	route_drop->setObjectName(QStringLiteral("iface_route_drop"));
	route_row->addWidget(route_add);
	route_row->addWidget(route_drop);
	route_row->addStretch(1);
	form->addRow(QString(), route_row);

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

	layout->addLayout(form);

	/* Constructed near the top rather than here; see the comment there. */
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	save_button = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save_button->setObjectName(QStringLiteral("iface_save"));
	layout->addWidget(buttons);

	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save_button, &QPushButton::clicked, this, &ncfg_interface_dialog::submit);
	connect(source_add, &QPushButton::clicked, this, &ncfg_interface_dialog::add_source);
	connect(source_drop, &QPushButton::clicked, this, &ncfg_interface_dialog::drop_source);
	connect(source_up, &QPushButton::clicked, this, &ncfg_interface_dialog::move_source_up);
	connect(source_down, &QPushButton::clicked, this, &ncfg_interface_dialog::move_source_down);
	connect(route_add, &QPushButton::clicked, this, &ncfg_interface_dialog::add_route);
	connect(route_drop, &QPushButton::clicked, this, &ncfg_interface_dialog::drop_route);
	connect(source_kind, &QComboBox::currentIndexChanged, this,
	    &ncfg_interface_dialog::addressing_changed);
	connect(this->sources, &QListWidget::itemSelectionChanged, this,
	    &ncfg_interface_dialog::addressing_changed);
	connect(detection, &QComboBox::currentIndexChanged, this,
	    &ncfg_interface_dialog::detection_changed);

	load_existing();
	addressing_changed();
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

	for (const ncfg_address_source_row &source : existing.sources) {
		/* The document's word for a source is not always the config
		 * language's: it compiles `dhcp` into `dhcp4`, and writing that back
		 * would be writing a spelling the file never had. */
		const QString kind = source.source == QLatin1String("dhcp4")
		    ? QStringLiteral("dhcp")
		    : source.source;
		put_source(kind, source.address);
	}
	for (const ncfg_route_row &route : existing.routes) {
		put_route(route.destination, route.via, route.metric);
	}
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

void ncfg_interface_dialog::addressing_changed()
{
	/* The address box belongs to one kind of source. Enabled rather than
	 * hidden, so the row does not jump about while somebody is using it. */
	const bool fixed = source_kind->currentData().toString() == QStringLiteral("static");
	source_address->setEnabled(fixed);
	const int row = sources->currentRow();
	source_drop->setEnabled(row >= 0);
	source_up->setEnabled(row > 0);
	source_down->setEnabled(row >= 0 && row + 1 < sources->count());
}

/* One entry in the addressing list: the kind, and the address where it has
 * one. The kind is kept on the item rather than parsed back out of its text,
 * which is the mistake that would make a translated label unwritable. */
void ncfg_interface_dialog::put_source(const QString &kind, const QString &address)
{
	const QString shown = address.isEmpty()
	    ? kind
	    : QStringLiteral("%1  %2").arg(kind, address);
	auto *item = new QListWidgetItem(shown, sources);
	item->setData(Qt::UserRole, kind);
	item->setData(Qt::UserRole + 1, address);
}

void ncfg_interface_dialog::put_route(const QString &destination, const QString &via, int metric)
{
	const int row = routes->rowCount();
	routes->insertRow(row);
	routes->setItem(row, 0, new QTableWidgetItem(destination));
	routes->setItem(row, 1, new QTableWidgetItem(via));
	routes->setItem(row, 2,
	    new QTableWidgetItem(metric >= 0 ? QString::number(metric) : QString()));
}

void ncfg_interface_dialog::add_source()
{
	const QString kind = source_kind->currentData().toString();
	const QString address = source_address->text().trimmed();

	if (kind == QLatin1String("static") && address.isEmpty()) {
		note->setText(QStringLiteral("a fixed address needs an address"));
		return;
	}
	put_source(kind, kind == QLatin1String("static") ? address : QString());
	source_address->clear();
	addressing_changed();
}

void ncfg_interface_dialog::drop_source()
{
	delete sources->takeItem(sources->currentRow());
	addressing_changed();
}

void ncfg_interface_dialog::move_source_up()
{
	const int row = sources->currentRow();
	if (row <= 0) {
		return;
	}
	sources->insertItem(row - 1, sources->takeItem(row));
	sources->setCurrentRow(row - 1);
	addressing_changed();
}

void ncfg_interface_dialog::move_source_down()
{
	const int row = sources->currentRow();
	if (row < 0 || row + 1 >= sources->count()) {
		return;
	}
	sources->insertItem(row + 1, sources->takeItem(row));
	sources->setCurrentRow(row + 1);
	addressing_changed();
}

void ncfg_interface_dialog::add_route()
{
	/* An empty row rather than a dialog: three cells the operator fills in,
	 * and `submit` refuses one with no destination. */
	put_route(QStringLiteral("default"), QString(), -1);
	routes->setCurrentCell(routes->rowCount() - 1, 1);
}

void ncfg_interface_dialog::drop_route()
{
	const int row = routes->currentRow();
	if (row >= 0) {
		routes->removeRow(row);
	}
}

void ncfg_interface_dialog::detection_changed()
{
	const QString how = detection->currentData().toString();
	const bool custom = how == QStringLiteral("command");
	auto *form = qobject_cast<QFormLayout *>(layout()->itemAt(0)->layout());
	if (form) {
		form->setRowVisible(probe_command, custom);
		form->setRowVisible(probe_args, custom);
		form->setRowVisible(probe_interval, !how.isEmpty());
		form->setRowVisible(probe_timeout, !how.isEmpty());
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

/* One cell of the routes table, trimmed, empty where there is none. */
QString ncfg_interface_dialog::cell(int row, int column) const
{
	const QTableWidgetItem *item = routes->item(row, column);
	return item ? item->text().trimmed() : QString();
}

QString ncfg_interface_dialog::block_text() const
{
	QStringList body;

	/* **The list, in its order.** `config` is a composition and every entry
	 * contributes; a fixed address is written as the address itself, which is
	 * how the language spells that source. An empty list is `null`, which is
	 * what a bridge member wants and what "no address at all" means. */
	QStringList entries;
	for (int row = 0; row < sources->count(); row++) {
		const QString kind = sources->item(row)->data(Qt::UserRole).toString();
		const QString address = sources->item(row)->data(Qt::UserRole + 1).toString();
		entries << QStringLiteral("\"%1\"").arg(kind == QLatin1String("static") ? address
		                                                                       : kind);
	}
	if (entries.isEmpty()) {
		body << QStringLiteral("\tconfig = \"null\"");
	} else {
		body << QStringLiteral("\tconfig = [%1]").arg(entries.join(QStringLiteral(", ")));
	}

	QStringList lines;
	for (int row = 0; row < routes->rowCount(); row++) {
		const QString destination = cell(row, 0);
		if (destination.isEmpty()) {
			continue;
		}
		QString line = destination;
		if (!cell(row, 1).isEmpty()) {
			line += QStringLiteral(" via %1").arg(cell(row, 1));
		}
		if (!cell(row, 2).isEmpty()) {
			line += QStringLiteral(" metric %1").arg(cell(row, 2));
		}
		lines << QStringLiteral("\"%1\"").arg(line);
	}
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
		body << QStringLiteral("\t}");
	}

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

void ncfg_interface_dialog::submit()
{
	const QLineEdit *values[] = { source_address, dns_servers, dns_search, dns_domains,
		probe_command, probe_args };
	for (const QLineEdit *value : values) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash "
			              "or a newline"));
			return;
		}
	}
	for (int row = 0; row < routes->rowCount(); row++) {
		if (cell(row, 0).isEmpty()) {
			note->setText(QStringLiteral("a route needs a destination: `default`, or a "
			              "network like 10.0.0.0/8"));
			return;
		}
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
	if (!existing.unmodelled.isEmpty()) {
		note->setText(QStringLiteral(
		    "this interface's configuration carries %1, which this dialog has no field "
		    "for -- saving would delete it. Edit the file instead: "
		    "`ncfg config edit interface-%2`.")
		        .arg(existing.unmodelled, interface));
		return;
	}

	QString error;
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
