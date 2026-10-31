/*
 * meshes_view.cpp -- the table described in meshes_view.h.
 */
#include "meshes_view.h"

#include "mesh_dialog.h"
#include "table_view.h"

#include <QPushButton>
#include <QVBoxLayout>

ncfg_meshes_view::ncfg_meshes_view(ncfg_connection *connection, QWidget *parent)
    : QWidget(parent), connection(connection)
{
	QStringList columns;
	columns << QStringLiteral("mesh ID") << QStringLiteral("radio") << QStringLiteral("channel")
	        << QStringLiteral("security");
	table = new ncfg_table_view(columns, QStringLiteral("meshes_note"), this);

	edit_button = new QPushButton(QStringLiteral("view / change"), this);
	edit_button->setObjectName(QStringLiteral("edit_mesh"));
	edit_button->setEnabled(false);
	table->add_control(edit_button);
	auto *new_button = new QPushButton(QStringLiteral("new mesh..."), this);
	new_button->setObjectName(QStringLiteral("new_mesh"));
	table->add_control(new_button);

	auto *layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->addWidget(table);

	connect(edit_button, &QPushButton::clicked, this, &ncfg_meshes_view::edit_selected);
	connect(new_button, &QPushButton::clicked, this, &ncfg_meshes_view::new_mesh);
	connect(table, &ncfg_table_view::activated, this, &ncfg_meshes_view::edit_selected);
	connect(table, &ncfg_table_view::selection_changed, this,
	    [this]() { edit_button->setEnabled(table->selected_row() >= 0); });
}

void ncfg_meshes_view::open(const ncfg_mesh_row &mesh)
{
	ncfg_mesh_dialog dialog(connection, mesh, this);
	if (dialog.exec() != QDialog::Accepted) {
		return;
	}
	emit reported(dialog.outcome());
	refresh();
	emit changed();
}

void ncfg_meshes_view::edit_selected()
{
	const int row = table->selected_row();
	if (row >= 0 && row < meshes.size()) {
		open(meshes.at(row));
	}
}

void ncfg_meshes_view::new_mesh()
{
	open(ncfg_mesh_row());
}

void ncfg_meshes_view::refresh()
{
	QString error;
	if (!connection->meshes(&meshes, &error)) {
		meshes.clear();
		table->show_error(error);
		emit reported(error);
		return;
	}

	QList<QStringList> rows;
	for (const ncfg_mesh_row &mesh : meshes) {
		rows << QStringList { mesh.id, mesh.device,
			mesh.channel > 0 ? QString::number(mesh.channel) : QString(),
			mesh.security == QLatin1String("psk")
			    ? QStringLiteral("SAE, %1").arg(mesh.credential)
			    : mesh.security };
	}
	table->show_rows(rows);
	if (rows.isEmpty()) {
		table->set_note(QStringLiteral(
		    "No `mesh` block. A mesh links radios to each other with no access point and no "
		    "cable -- the backhaul between two rooms -- and every node is configured the "
		    "same way. The radio also needs an `interface` block for its address."));
		emit reported(QStringLiteral("no meshes configured"));
		return;
	}
	table->set_note(QStringLiteral(
	    "Each radio here is given to its mesh and does nothing else. Every node of a mesh "
	    "needs the same ID, channel and security."));
	emit reported(QStringLiteral("%1 meshes").arg(rows.size()));
}
