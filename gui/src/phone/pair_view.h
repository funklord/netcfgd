/*
 * pair_view.h -- the first thing a phone shows (project.md 10.720).
 *
 * The holder, 2026-11-05: on a phone, pairing by QR code is the first thing a
 * person does, because it is the main platform for this use, and files do not
 * move easily to a phone, nor does auth data between apps. So what joins a
 * phone is one code, read off the host's screen or typed from it: no file, and
 * nothing asked of another app. The code says where the host is too, which is
 * how a phone finds one.
 *
 * Nothing else of the app is reachable until this is done: a phone that is no
 * member of an estate has nothing to look at.
 */
#ifndef NCFG_GUI_PAIR_VIEW_H
#define NCFG_GUI_PAIR_VIEW_H

#include <QByteArray>
#include <QString>
#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class QTimer;
class ncfg_code_reader;

class ncfg_pair_view : public QWidget {
	Q_OBJECT

public:
	/* `socket` is this device's node; `scratch` a private directory, for a
	 * code longer than one line to the node. */
	ncfg_pair_view(const QString &socket, const QString &scratch, QWidget *parent = nullptr);

	/* A code, however it came: refused here with a sentence, or asked of the
	 * node. Public so a probe can hand one in without a camera. */
	void take_code(const QByteArray &code);

	/* The host this node has joined, or empty. */
	static QString joined_host(const QString &socket);

signals:
	/* Joined, and the node back up: `host` is what `open_at` wants. */
	void paired(const QString &host);
	/* Back pressed, or the window closed, with nothing paired. */
	void left();

protected:
	void closeEvent(QCloseEvent *event) override;

private:
	void asked(bool ok, const QString &answer);
	void look_for_node();
	void busy(bool on);

	QString           socket_path;
	QString           scratch_dir;
	QLabel           *status_line;
	QLineEdit        *typed;
	QPushButton      *scan;
	QPushButton      *use;
	ncfg_code_reader *reader;
	QTimer           *waiting;
	int               looks = 0;
};

/* The host to open: this node's, or, where it has none, what a person pairs in
 * the view this shows. Empty when they closed it. */
QString ncfg_phone_host(const QString &socket, const QString &scratch);

#endif
