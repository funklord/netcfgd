/*
 * Name resolution: what it is set to, and setting it.
 *
 * **The tab exists because the default is correct and invisible.** `dns { mode
 * }` is `none` unless a document says otherwise, and `none` means netcfgd does
 * not touch resolution at all -- the right answer on a machine where something
 * else owns /etc/resolv.conf, and indistinguishable from a fault when that
 * something else has since been stopped. A machine whose resolv.conf was
 * written by a NetworkManager that is no longer running keeps working off a
 * stale file for as long as those servers answer, and nothing anywhere said
 * netcfgd was deliberately leaving it alone. That was a real report.
 *
 * The modes are a fixed list rather than a text box, and that is a privilege
 * decision rather than a convenience: this writes a drop-in through the daemon
 * at the `admin` tier, and a box that let somebody type a block would be
 * 0117's remote code execution with a nicer font. Composing the text here
 * means the shape of what can be written is bounded by this file.
 */

#ifndef NCFG_DNS_VIEW_H
#define NCFG_DNS_VIEW_H

#include <QWidget>

class QComboBox;
class QLabel;
class QPushButton;
class ncfg_connection;

class ncfg_dns_view : public QWidget {
	Q_OBJECT

public:
	explicit ncfg_dns_view(ncfg_connection *connection, QWidget *parent = nullptr);

public slots:
	void refresh();

signals:
	/* What happened, for the window's status line. The same channel the other
	 * tabs report on, so a refusal reads the same wherever it came from. */
	void reported(const QString &summary);
	/* The configuration changed, so anything showing a plan is now stale. */
	void changed();

private slots:
	void apply_mode();

private:
	ncfg_connection *connection;
	QComboBox       *mode;
	QLabel          *current;
	QLabel          *detail;
	QPushButton     *apply_button;
};

#endif
