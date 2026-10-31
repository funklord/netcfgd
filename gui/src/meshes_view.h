/*
 * meshes_view.h -- the 802.11s meshes the configuration declares (10.588).
 *
 * A mesh is a fundamental thing and there may be several -- one per radio --
 * which is this program's rule for what earns a tab. From the document: whether
 * the radio has found its peers is the wifi tab's question.
 */
#ifndef NCFG_MESHES_VIEW_H
#define NCFG_MESHES_VIEW_H

#include "ncfg_connection.h"

#include <QList>
#include <QWidget>

class QPushButton;
class ncfg_table_view;

class ncfg_meshes_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_meshes_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

private slots:
	void edit_selected();
	void new_mesh();

signals:
	void reported(const QString &summary);
	/* The configuration changed, so anything showing a plan is stale. */
	void changed();

private:
	void open(const ncfg_mesh_row &mesh);

	ncfg_connection          *connection;
	QList<ncfg_mesh_row> meshes;
	QPushButton              *edit_button;
	ncfg_table_view          *table;
};

#endif /* NCFG_MESHES_VIEW_H */
