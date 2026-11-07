/*
 * fleet_view.h -- every node of the estate at once (project.md 10.710).
 *
 * The node box moves the window to one node, so a person minding ten routers
 * had to visit ten to learn which one was down. This is the look across: one
 * row a node, by the name it gives itself, saying whether it answers, whether
 * it is online and on what, with a double click to go there.
 *
 * **Child `ncfg status --at` processes, not the client library.** A request
 * of a node waits on the estate, and `ncfg_connection` waits on the window's
 * thread: one node off the air would freeze the window for as long as the
 * call took, multiplied by the nodes. A process can be waited for without
 * blocking and killed when it takes too long, and a thread in the client
 * cannot.
 *
 * **Asked only while it is looked at**, and at most four at a time, so an open
 * window costs the estate nothing until somebody turns to this tab. A row
 * keeps the name a node last gave when it stops answering, since "router-3 has
 * no answer" is the sentence wanted, and a key alone cannot say it.
 *
 * **And what an operator does to many at once** (10.713): reload them all, name
 * a node a member of a group, seal a value to a group. These are `ncfg`'s own
 * verbs, so what they refuse and what they print is theirs. A sealed value goes
 * to the child's standard input and is never on a command line, where any user
 * of the machine could read it.
 */
#ifndef NCFG_FLEET_VIEW_H
#define NCFG_FLEET_VIEW_H

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QStringList>
#include <QWidget>

#include <functional>

class ncfg_table_view;
class QTimer;

struct ncfg_fleet_row {
	QString   host;
	QString   state;
	QString   connectivity;
	QString   primary;
	QString   links;
	QDateTime answered;
};

class ncfg_fleet_view : public QWidget {
	Q_OBJECT

public:
	/* `members` lists the estate's other nodes by key, asked at each round,
	 * so a node that joined appears without a restart. */
	explicit ncfg_fleet_view(std::function<QStringList()> members, QWidget *parent = nullptr);
	~ncfg_fleet_view() override;

	/* Fill a row from `ncfg status --json`; false for what is not one. */
	static bool read_status(const QByteArray &json, ncfg_fleet_row *row);

	/* How long one node is waited for. A probe shortens it. */
	void set_wait(int milliseconds);

	/* What the buttons do once they have asked. False while another runs. */
	bool reload_all();
	bool add_member(const QString &key, const QString &group);
	bool seal(const QString &group, const QString &key, const QString &value);

public slots:
	/* One round, unless one is still going: a slow node must not stack up
	 * rounds behind it. */
	void refresh();

signals:
	void reported(const QString &summary);
	/* The operator asked to go to this node. */
	void opened(const QString &key);
	/* A node said what it is called. */
	void named(const QString &key, const QString &host);
	/* A round has every answer in. */
	void finished_round();
	/* An action has ended, `said` being what the operator is shown. */
	void acted(bool worked, const QString &said);

protected:
	void showEvent(QShowEvent *event) override;
	void hideEvent(QHideEvent *event) override;

private:
	void start_next();
	void answered(const QString &key, int code, const QByteArray &out, const QByteArray &err);
	void draw();
	void open_selected();
	void ask_reload();
	void ask_member();
	void ask_seal();
	void ask_pair();
	bool act(const QStringList &arguments, const QByteArray &input);

	std::function<QStringList()>  members;
	ncfg_table_view              *table;
	QTimer                       *timer;
	QStringList                   keys;
	QStringList                   waiting;
	QHash<QString, ncfg_fleet_row> rows;
	/* What the last action said, under the table until the next. */
	QString                       action_said;
	bool                          acting = false;
	int                           asking = 0;
	int                           wait = 35000;
};

#endif /* NCFG_FLEET_VIEW_H */
