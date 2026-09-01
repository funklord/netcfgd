/*
 * modems_view.h -- the cellular modems, and which SIM each one is on.
 *
 * A tab of its own because a modem is a fundamental thing and there is a list
 * of them, which is this program's rule for what earns one. Simplifying the
 * shape of the window comes after every control exists, not before: a control
 * that is missing cannot be found by anybody, while one in the wrong tab can.
 *
 * **The two SIM columns are not redundant.** `sim` is the operator's ordered
 * preference, from the document, and never moves on its own. `in use` is where
 * netcfgd has got to, which changes when a probe says the link does not work
 * (decision 0152). An operator looking at a modem that will not attach needs
 * to see both -- "it is on the SIM I asked for and that SIM is dead" and "it
 * has fallen through to the spare" are different problems.
 *
 * Read-only, and unlike the devices table that is not only a house style.
 * There is no verb to choose a SIM source: which one is in use is netcfgd's
 * answer to a failing probe, and letting a client pin it is a design question
 * about what then happens to the fallback. The tab shows; it does not steer.
 */
#ifndef NCFG_MODEMS_VIEW_H
#define NCFG_MODEMS_VIEW_H

#include <QWidget>

class ncfg_connection;
class ncfg_table_view;

class ncfg_modems_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_modems_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

signals:
	void reported(const QString &summary);

private:
	ncfg_connection *connection;
	/* The shared read-only table, which carries the note that says why an
	 * empty one is empty. What is this view's own is turning a modem into
	 * strings -- the three states below are the whole subject. */
	ncfg_table_view *table;
};

#endif /* NCFG_MODEMS_VIEW_H */
