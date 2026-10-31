/*
 * mesh_dialog.cpp -- the editor described in mesh_dialog.h.
 */
#include "mesh_dialog.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace {

bool safe_value(const QString &text)
{
	return !text.contains(QLatin1Char('"')) && !text.contains(QLatin1Char('\\')) &&
	       !text.contains(QLatin1Char('\n'));
}

} // namespace

QString ncfg_mesh_block(const ncfg_mesh_row &mesh)
{
	QStringList body;
	body << QStringLiteral("mesh \"%1\" {").arg(mesh.id);
	body << QStringLiteral("\tdevice = \"%1\"").arg(mesh.device);
	if (mesh.channel > 0) {
		body << QStringLiteral("\tchannel = %1").arg(mesh.channel);
	}
	if (!mesh.band.isEmpty()) {
		body << QStringLiteral("\tband = \"%1\"").arg(mesh.band);
	}
	/* Always a `wifi` block: the compiler refuses a mesh without one rather
	 * than read silence as open. */
	body << QStringLiteral("\twifi {");
	if (mesh.security == QLatin1String("psk")) {
		body << QStringLiteral("\t\tpsk = \"%1\"").arg(mesh.credential);
	} else {
		body << QStringLiteral("\t\topen = true");
	}
	body << QStringLiteral("\t}");
	body << QStringLiteral("}");
	return body.join(QLatin1Char('\n')) + QLatin1Char('\n');
}

ncfg_mesh_dialog::ncfg_mesh_dialog(ncfg_connection *connection, const ncfg_mesh_row &existing,
    QWidget *parent)
    : QDialog(parent), connection(connection), before(existing)
{
	setWindowTitle(before.id.isEmpty() ? QStringLiteral("New mesh")
	                                   : QStringLiteral("Mesh %1").arg(before.id));
	auto *layout = new QVBoxLayout(this);
	auto *form = new QFormLayout();

	id = new QLineEdit(existing.id, this);
	id->setObjectName(QStringLiteral("mesh_id"));
	id->setPlaceholderText(QStringLiteral("backhaul -- the same on every node"));
	id->setReadOnly(!before.id.isEmpty());
	form->addRow(QStringLiteral("mesh ID"), id);

	device = new QLineEdit(existing.device, this);
	device->setObjectName(QStringLiteral("mesh_device"));
	device->setPlaceholderText(QStringLiteral("wlan1 -- given to the mesh, and nothing else"));
	form->addRow(QStringLiteral("radio"), device);

	channel = new QSpinBox(this);
	channel->setObjectName(QStringLiteral("mesh_channel"));
	channel->setRange(0, 233);
	channel->setSpecialValueText(QStringLiteral("choose one"));
	channel->setValue(existing.channel > 0 ? existing.channel : 0);
	channel->setToolTip(QStringLiteral(
	    "Required, and the same on every node: mesh points meet on the channel they are "
	    "given rather than searching for each other."));
	form->addRow(QStringLiteral("channel"), channel);

	band = new QComboBox(this);
	band->setObjectName(QStringLiteral("mesh_band"));
	band->addItem(QStringLiteral("from the channel"), QString());
	band->addItem(QStringLiteral("2.4 GHz"), QStringLiteral("2.4"));
	band->addItem(QStringLiteral("5 GHz"), QStringLiteral("5"));
	band->addItem(QStringLiteral("6 GHz"), QStringLiteral("6"));
	band->setCurrentIndex(qMax(0, band->findData(existing.band)));
	form->addRow(QStringLiteral("band"), band);

	security = new QComboBox(this);
	security->setObjectName(QStringLiteral("mesh_security"));
	security->addItem(QStringLiteral("SAE -- a shared password"), QStringLiteral("psk"));
	security->addItem(QStringLiteral("open -- any node may join"), QStringLiteral("open"));
	security->setCurrentIndex(qMax(0, security->findData(existing.security)));
	form->addRow(QStringLiteral("security"), security);

	credential = new QLineEdit(existing.credential, this);
	credential->setObjectName(QStringLiteral("mesh_credential"));
	credential->setPlaceholderText(
	    QStringLiteral("@secret:mesh -- `ncfg secret set mesh` stores it"));
	form->addRow(QStringLiteral("password"), credential);
	layout->addLayout(form);

	note = new QLabel(this);
	note->setObjectName(QStringLiteral("mesh_note"));
	note->setWordWrap(true);
	note->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(note);

	auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
	QPushButton *save = buttons->addButton(QStringLiteral("Save"), QDialogButtonBox::AcceptRole);
	save->setObjectName(QStringLiteral("mesh_save"));
	if (!before.id.isEmpty()) {
		QPushButton *drop = buttons->addButton(QStringLiteral("delete"),
		    QDialogButtonBox::DestructiveRole);
		drop->setObjectName(QStringLiteral("mesh_remove"));
		connect(drop, &QPushButton::clicked, this, &ncfg_mesh_dialog::remove);
	}
	connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
	connect(save, &QPushButton::clicked, this, &ncfg_mesh_dialog::submit);
	connect(security, &QComboBox::currentIndexChanged, this,
	    &ncfg_mesh_dialog::security_changed);
	layout->addWidget(buttons);
	resize(520, 320);
	security_changed();

	/* A block this form cannot say all of is not saved over (10.606). */
	if (!before.unmodelled.isEmpty()) {
		save->setEnabled(false);
		note->setText(QStringLiteral("This mesh carries %1, which this form cannot write: "
		              "edit it in the configuration instead.").arg(before.unmodelled));
	}
}

void ncfg_mesh_dialog::security_changed()
{
	credential->setEnabled(security->currentData().toString() == QLatin1String("psk"));
}

void ncfg_mesh_dialog::submit()
{
	if (!before.unmodelled.isEmpty()) {
		return;
	}
	for (const QLineEdit *value : { id, device, credential }) {
		if (!safe_value(value->text())) {
			note->setText(QStringLiteral("a value cannot carry a quote, a backslash or a "
			              "newline"));
			return;
		}
	}
	ncfg_mesh_row mesh;
	mesh.id = id->text().trimmed();
	mesh.device = device->text().trimmed();
	mesh.channel = channel->value();
	mesh.band = band->currentData().toString();
	mesh.security = security->currentData().toString();
	mesh.credential = credential->text().trimmed();
	if (mesh.id.isEmpty() || mesh.device.isEmpty()) {
		note->setText(QStringLiteral("a mesh needs an ID, which every node shares, and the "
		              "radio this node gives to it"));
		return;
	}
	if (mesh.channel <= 0) {
		note->setText(QStringLiteral("a mesh needs a channel: its nodes meet on it rather "
		              "than searching for each other"));
		return;
	}
	if (mesh.security == QLatin1String("psk") &&
	    !mesh.credential.startsWith(QLatin1String("@secret:"))) {
		note->setText(QStringLiteral("the password is a reference, `@secret:NAME`, never the "
		              "password itself: `ncfg secret set NAME` stores it"));
		return;
	}

	QString error;
	if (!connection->config_put(QStringLiteral("mesh-%1").arg(mesh.id), ncfg_mesh_block(mesh),
	        true, &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("wrote mesh-%1: netcfgd re-read its configuration. Run apply to "
	              "make the machine match it.")
	              .arg(mesh.id);
	accept();
}

void ncfg_mesh_dialog::remove()
{
	QMessageBox box(QMessageBox::Question, QStringLiteral("netcfgd"),
	    QStringLiteral("Delete the mesh `%1`?\n\nThis node leaves it on the next apply; the "
	                   "others keep meshing with each other.")
	        .arg(before.id),
	    QMessageBox::Cancel | QMessageBox::Yes, this);
	box.setDefaultButton(QMessageBox::Cancel);
	if (box.exec() != QMessageBox::Yes) {
		return;
	}
	QString error;
	if (!connection->config_delete(QStringLiteral("mesh-%1").arg(before.id), &error)) {
		note->setText(error);
		return;
	}
	summary = QStringLiteral("removed mesh-%1: netcfgd re-read its configuration.")
	              .arg(before.id);
	accept();
}
