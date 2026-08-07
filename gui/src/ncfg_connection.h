/*
 * ncfg_connection.h -- the C client, wrapped for Qt.
 *
 * WHERE THE SEAM IS
 *   gui/project.md sec 3: connection handling, framing, the reader and the
 *   models behind interfaces/wifi/plan are in client/, in C, because a second
 *   frontend would want all of it and none of it is visual. This file is the
 *   thin layer on the Qt side of that seam: it turns the C model structs into
 *   the types a widget can use, and owns nothing else.
 *
 *   If a function here grows logic that is not "call the C layer and convert",
 *   it is on the wrong side and belongs below. The first commit walked the
 *   `status` JSON here, which was exactly that mistake; the models moved down
 *   and this file lost the walking rather than keeping it as a precedent.
 *
 * WHY NOT QLocalSocket
 *   Qt has a perfectly good unix socket class, and using it would mean the
 *   framing, the reader and the request vocabulary living here in C++ -- where
 *   an ncurses client, an Android service or a headless probe could not reach
 *   them. The transport being replaceable later (an encrypted datagram one is
 *   sec 6) is the other half: the swap happens in client/, and nothing in this
 *   directory should notice.
 */
#ifndef NCFG_CONNECTION_H
#define NCFG_CONNECTION_H

#include <QList>
#include <QStringList>
#include <QObject>
#include <QString>

extern "C" {
#include "ncfg_client.h"
}

/* One row of the devices table. Qt types because it is on this side of the
 * seam; the names are netcfgd's own so that a reader of both sees one word per
 * concept. */
struct ncfg_link_row {
	QString name;
	QString kind;
	QString state;
	QString mac;
	QString addresses;
	int     mtu = 0;
	/* Whether the wifi tab should offer this one. Answered below the seam so
	 * that the rule lives with the other models rather than in a table. */
	bool    wireless = false;
};

/*
 * One action of a plan, with its reason attached and not beside it.
 *
 * `field`, `desired` and `observed` are in the same struct as `op` because
 * project.md constraint 7 is that netcfgd is not a black box: a screen that
 * could hold an action without its reason would eventually show one. Keeping
 * them together means the only way to draw an action is to have the reason in
 * hand.
 */
struct ncfg_action_row {
	qlonglong id = 0;
	QString   op;
	QString   interface;
	QString   field;
	QString   desired;
	QString   observed;
	bool      reversible = true;
};

/* A warning, a refusal or a stranded credential. One shape for three lists
 * because they are one thing to the reader -- something the operator has to
 * know -- differing only in how hard they stop the apply, which is the list a
 * row is in rather than a field on it. */
struct ncfg_note_row {
	QString message;
	QString interface;
	QString detail;
	/* Two remedies, because they are two answers: `remedy` is the config
	 * change that makes the situation not arise, `consent` the flag that
	 * proceeds anyway. Shown in that order for the reason `ncfg` prints them
	 * in it -- a flag offered first reads as the fix. */
	QString remedy;
	QString consent;
	/* What the refused action would have been. Empty for a warning and for a
	 * stranded credential, neither of which is a dropped action. */
	QString field;
	QString desired;
	QString observed;
};

struct ncfg_plan_data {
	QList<ncfg_action_row> actions;
	QList<ncfg_note_row>   warnings;
	QList<ncfg_note_row>   refusals;
	QList<ncfg_note_row>   stranded;

	/* A plan with a refusal in it is a plan that will not run. The screen
	 * asks this rather than counting the list itself, so that "is this a
	 * stop" has one answer in one place. */
	bool blocked() const { return !refusals.isEmpty(); }
};

/* One line of what an apply did. `outcome` is the daemon's own word -- "done",
 * "failed", "skipped" -- because a client that renamed them would make two
 * vocabularies for one thing. */
struct ncfg_record_row {
	qlonglong id = 0;
	QString   op;
	QString   interface;
	QString   outcome;
	QString   detail;
};

/*
 * One access point a scan found.
 *
 * `display` is what a row shows and is built below the seam's rules rather than
 * by the table: a network whose SSID is not valid UTF-8 has no text name at all,
 * and one that is hidden has a name that is genuinely empty. Those are different
 * networks and a table that printed both as blank would merge them, so the
 * distinction is resolved once, here, into something a cell can hold.
 *
 * `configured` is the network id and empty means the configuration has no
 * `network` block for it. That is the difference between an entry this client
 * can join and one that needs a config file written first (0013, 0069) -- shown
 * rather than discovered by pressing a button and being refused.
 */
struct ncfg_access_point_row {
	QString bssid;
	QString ssid; /* hex, the canonical name */
	QString display;
	QString configured;
	int     frequency = 0;
	int     signal = 0;
	bool    secured = false;

	bool joinable() const { return !configured.isEmpty(); }
};

/* What a radio is doing. `state` is the supplicant's own word, kept rather than
 * translated so that this window and every other tool on the machine say the
 * same thing about the same condition. */
struct ncfg_wifi_status_row {
	QString interface;
	QString state;
	QString display;
	QString bssid;
	QString network;

	/*
	 * The one line that says what a radio is doing.
	 *
	 * On the struct rather than in a view because two things draw it -- the
	 * wifi tab and the tray -- and a second copy is how three clients came to
	 * spell one access point's name three ways. One spelling, one place.
	 *
	 * An associated radio whose network the document does not name is called
	 * out rather than hidden: after 0015 the supplicant holds no profiles of
	 * its own, so something else put it there, and a client that said nothing
	 * would hide the only sign of it.
	 */
	QString summary() const;
};

/* One event off a monitor stream. `raw` travels with the rest because an event
 * netcfgd grows a field for should not become invisible to a client built
 * before it. */
struct ncfg_event_row {
	QString kind;
	QString interface;
	QString summary;
	QString raw;
};

/* What the operator has agreed to, beyond the plan itself.
 *
 * Two lists and never one switch, because the daemon asks two questions: an
 * operator who accepted a brief outage on one interface has not agreed to leave
 * a private key on another. `ncfg` spells them `--allow-disruption IFACE` and
 * `--strand-credentials DEV`, both repeatable and "deliberately not a blanket
 * --force" -- and a single checkbox marked "override refusals" would be exactly
 * the blanket that wording rules out.
 *
 * Each entry names the one interface or device the operator ticked. */
struct ncfg_consent_rows {
	QStringList disrupt;
	QStringList strand;

	bool isEmpty() const { return disrupt.isEmpty() && strand.isEmpty(); }
};

class ncfg_connection : public QObject {
	Q_OBJECT

public:
	explicit ncfg_connection(QObject *parent = nullptr);
	~ncfg_connection() override;

	/* `socket_path` empty means the default -- $NCFG_RUN_DIR or the
	 * installed location, resolved by the C layer so that this client and
	 * `ncfg` cannot disagree about which daemon they are talking to. */
	bool open(const QString &socket_path, QString *error);
	void close();
	bool is_open() const { return client != nullptr; }

	/* Which machine this is. A client that can configure a router across the
	 * room must never leave the operator unsure whose network it is about to
	 * change (gui/project.md sec 4), so the window shows this. It is also
	 * what a monitor stream is opened against, since that takes a connection
	 * of its own. */
	QString where() const;

	/*
	 * Each of these returns false and fills `error` with the daemon's own
	 * words when the daemon refused, and with the C layer's when it could
	 * not be reached. The two are not distinguished here on purpose: the
	 * caller shows the sentence either way, and a refusal already names the
	 * tier that would have been needed (0013) -- a screen that replaced it
	 * with wording of its own would throw away the one part that says what
	 * to do about it.
	 */
	bool links(QList<ncfg_link_row> *out, QString *error);
	bool plan(ncfg_plan_data *out, QString *error);

	/*
	 * The wireless half, on one named interface.
	 *
	 * A scan blocks for as long as the radio takes to visit its channels,
	 * which on real hardware is seconds. It is called from the pane's own
	 * action rather than from a timer for that reason: a window that scanned
	 * on a refresh tick would freeze on a cadence nobody asked for.
	 *
	 * `wifi_connect` names a network by its id in the document and carries no
	 * credential, which is not this class being careful -- it is the only
	 * shape the socket offers (0013), and the reason no passphrase can leak
	 * through a client. Joining a network the configuration does not describe
	 * is writing a file (0069) and is not available here at all.
	 */
	bool wifi_scan(const QString &interface, QList<ncfg_access_point_row> *out, QString *error);
	bool wifi_status(const QString &interface, ncfg_wifi_status_row *out, QString *error);
	bool wifi_connect(const QString &interface, const QString &network, QString *error);
	bool wifi_disconnect(const QString &interface, QString *error);

	/*
	 * Apply, with a confirm window in seconds or 0 for none.
	 *
	 * The window is an argument rather than a policy for the reason the C
	 * header gives: a change can cut off the person making it, and neither
	 * "always arm one" nor "never arm one" is right for every apply. The
	 * screen asks, and passes the answer through.
	 *
	 * `consent` is the same shape of argument and for a stronger version of
	 * the same reason: the plan says what is refused and this says which of
	 * those the person at the screen agreed to, and the two must not be one
	 * value. An empty one is the ordinary apply.
	 */
	bool apply(unsigned confirm_seconds, const ncfg_consent_rows &consent,
	       QList<ncfg_record_row> *out, QString *error);
	/*
	 * What this connection may do, asked once at the handshake.
	 *
	 * Three independent answers rather than a level: netcfgd's tiers are three
	 * group memberships, and a machine may grant `admin` to a group the
	 * operator is in while `wifi` goes to one they are not.
	 *
	 * A daemon that does not answer -- one older than the field -- grants
	 * nothing here, and the caller decides what to make of that. This window
	 * treats "could not tell" as permitted: the daemon refusing produces a
	 * sentence naming the tier that was needed, and a greyed-out button
	 * produces nothing at all.
	 */
	ncfg_tiers_t tiers();

	/* The machine's own commit-confirm window in seconds, or 0 if its
	 * configuration names none. Asked rather than assumed: a client with a
	 * default of its own would disagree with `ncfg apply` on the same machine
	 * about how long an operator has to confirm. */
	unsigned confirm_default();

	bool confirm(QString *error);
	bool revert(QString *error);

private:
	ncfg_client_t *client = nullptr;
	QString        path;
};

#endif /* NCFG_CONNECTION_H */
