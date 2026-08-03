/*
 * ncfg_connection.h -- the C client, wrapped for Qt.
 *
 * WHERE THE SEAM IS
 *   gui/project.md sec 3: connection handling, framing and the reader are in
 *   client/, in C, because a second frontend would want all of it and none of
 *   it is visual. This file is the thin layer on the Qt side of that seam: it
 *   turns a `ncfg_json_doc_t *` into the types a widget can use, and owns
 *   nothing else.
 *
 *   If a function here grows logic that is not "call the C layer and convert",
 *   it is on the wrong side and belongs below.
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
	 * change (gui/project.md sec 4), so the window shows this. */
	QString where() const;

	/* One `status`, converted. Returns false and fills `error` when the
	 * daemon could not be reached or refused -- and a refusal is the
	 * daemon's answer rather than a failure to reach it, so the message is
	 * the daemon's own words. */
	bool links(QList<ncfg_link_row> *out, QString *error);

private:
	ncfg_client_t *client = nullptr;
	QString        path;
};

#endif /* NCFG_CONNECTION_H */
