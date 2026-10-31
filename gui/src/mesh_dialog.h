/*
 * mesh_dialog.h -- one 802.11s mesh: the radio given to it, the channel its
 * nodes meet on, and how they authenticate (10.588).
 *
 * Every node of a mesh is configured the same way and peers with any other
 * that is, so this is the whole of what a node says: no address (that is the
 * radio's `interface` block, as for an access point) and no role. The mesh ID
 * is the block's label, so it is fixed once written -- a new ID is a new mesh,
 * written to its own `mesh-ID` drop-in.
 *
 * Security is SAE or nothing, because 802.11s has no other: the passphrase is
 * a secret reference, as everywhere, and is kept as written, provider and all
 * -- the access point dialog lost the provider until 10.628.
 *
 * `admin`, because it writes configuration.
 */
#ifndef NCFG_MESH_DIALOG_H
#define NCFG_MESH_DIALOG_H

#include "ncfg_connection.h"

#include <QDialog>
#include <QString>

class QComboBox;
class QLabel;
class QLineEdit;
class QSpinBox;

/* The `mesh` block for one mesh, as configuration text. */
QString ncfg_mesh_block(const ncfg_mesh_row &mesh);

class ncfg_mesh_dialog : public QDialog {
	Q_OBJECT

public:
	/* `existing` with an empty id means a mesh being written. */
	ncfg_mesh_dialog(ncfg_connection *connection, const ncfg_mesh_row &existing,
	    QWidget *parent = nullptr);

	QString outcome() const { return summary; }

private slots:
	void submit();
	void remove();
	void security_changed();

private:
	ncfg_connection *connection;
	ncfg_mesh_row    before;
	QString          summary;

	QLineEdit *id;
	QLineEdit *device;
	QSpinBox  *channel;
	QComboBox *band;
	QComboBox *security;
	QLineEdit *credential;
	QLabel    *note;
};

#endif /* NCFG_MESH_DIALOG_H */
