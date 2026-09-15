/*
 * tray.cpp -- the tray applet described in tray.h.
 */
#include "tray.h"

#include "ncfg_connection.h"

#include <QAction>
#include <QIcon>
#include <QActionGroup>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPixmap>
#include <QSystemTrayIcon>

/*
 * An icon, drawn rather than shipped.
 *
 * The theme's own `network-wireless` is used where the desktop has one, so
 * that netcfgd looks like everything else on the panel. Where it does not --
 * a bare window manager, a minimal image, the offscreen platform -- the
 * fallback is painted here.
 *
 * Painted and not a file because this tree ships no image assets and adding
 * the first one means a resource system, an install rule and a licence
 * question for a drawing nobody will look at closely. Three arcs and a dot is
 * what a wifi indicator is.
 */
QIcon ncfg_tray::painted_icon(ncfg_reach reach)
{
	QPixmap pixmap(22, 22);
	pixmap.fill(Qt::transparent);

	QPainter painter(&pixmap);
	painter.setRenderHint(QPainter::Antialiasing, true);
	/* Grey when there is nothing, amber when the machine is configured but
	 * has nowhere to send traffic, green when it has. The middle one is the
	 * state this icon used to draw as connected, and it is the one an
	 * operator most needs to see: a radio that joined a network and never
	 * got a usable route looks identical to a working one from every other
	 * angle. A colour of its own would be wrong on half the panels it lands
	 * on, so these stay close to the conventional three. */
	QColor ink(0x88, 0x88, 0x88);
	if (reach == ncfg_reach::routed) {
		ink = QColor(0x33, 0x99, 0x33);
	} else if (reach == ncfg_reach::local) {
		ink = QColor(0xcc, 0x88, 0x22);
	}
	QPen pen(ink);
	pen.setWidth(2);
	painter.setPen(pen);

	for (int arc = 0; arc < 3; arc++) {
		const int inset = 3 + arc * 4;
		const int size = 22 - inset * 2;
		painter.drawArc(inset, inset + 2, size, size, 30 * 16, 120 * 16);
	}
	painter.setBrush(pen.color());
	painter.drawEllipse(9, 15, 4, 4);
	painter.end();

	return QIcon(pixmap);
}

QIcon ncfg_tray::state_icon(ncfg_reach reach)
{
	QString name = QStringLiteral("network-offline");
	if (reach == ncfg_reach::routed) {
		name = QStringLiteral("network-wireless");
	} else if (reach == ncfg_reach::local) {
		/* The themed name for "joined, not usable". Falls through to the
		 * painted icon on a theme without it, which is the common case and
		 * why the painted one carries three colours of its own. */
		name = QStringLiteral("network-wireless-acquiring");
	}
	const QIcon themed = QIcon::fromTheme(name);
	return themed.isNull() ? painted_icon(reach) : themed;
}

ncfg_tray *ncfg_tray::create(ncfg_connection *connection, QObject *parent)
{
	if (!QSystemTrayIcon::isSystemTrayAvailable()) {
		return nullptr;
	}
	return new ncfg_tray(connection, parent);
}

ncfg_tray::ncfg_tray(ncfg_connection *connection, QObject *parent)
    : QObject(parent), connection(connection)
{
	menu = new QMenu();

	/* The state is the first thing in the menu and is not clickable: a menu
	 * whose first entry is a fact reads better than a tooltip nobody hovers
	 * for, and making it an action would invite a click that does nothing. */
	state_action = menu->addAction(QStringLiteral("netcfgd"));
	state_action->setEnabled(false);
	menu->addSeparator();

	QAction *show = menu->addAction(QStringLiteral("Show window"));
	connect(show, &QAction::triggered, this, &ncfg_tray::window_requested);

	disconnect_action = menu->addAction(QStringLiteral("Disconnect wifi"));
	connect(disconnect_action, &QAction::triggered, this, &ncfg_tray::disconnect_radio);

	/* Empty until the first refresh fills it. A submenu rather than a flat
	 * list: a machine may have several profiles and they would otherwise
	 * crowd out the two entries somebody opens this menu for. */
	profile_menu = menu->addMenu(QStringLiteral("Profile"));

	menu->addSeparator();
	QAction *quit = menu->addAction(QStringLiteral("Quit"));
	connect(quit, &QAction::triggered, this, &ncfg_tray::quit_requested);

	icon = new QSystemTrayIcon(this);
	icon->setContextMenu(menu);
	icon->setIcon(state_icon(ncfg_reach::offline));
	connect(icon, &QSystemTrayIcon::activated, this,
	    [this](QSystemTrayIcon::ActivationReason reason) { activated(reason); });
	icon->show();

	refresh();
}

void ncfg_tray::refresh()
{
	/* Before the link check, and unconditionally: a daemon that refuses
	 * `links` refuses `profiles` too, and the submenu then carries the same
	 * sentence rather than being silently empty. */
	rebuild_profiles();

	QList<ncfg_link_row> links;
	QString error;

	if (!connection->links(&links, &error)) {
		/* The daemon's own words, including a refusal naming the tier. A
		 * tray that said "unavailable" would throw away the sentence that
		 * says what to do about it. */
		state_action->setText(error);
		icon->setToolTip(error);
		icon->setIcon(state_icon(ncfg_reach::offline));
		disconnect_action->setEnabled(false);
		radio.clear();
		return;
	}

	radio.clear();
	for (const ncfg_link_row &link : links) {
		if (link.wireless) {
			radio = link.name;
			break;
		}
	}

	/* **Asked, not worked out.** This function used to derive the rung from
	 * the links -- an address here, a default route there, a radio's
	 * association somewhere else -- and so did the TDE tray, in its own
	 * transcription, and the NetworkManager shim in a coarser vocabulary.
	 * 0146 settled what the rungs mean; it did not settle where they are
	 * computed, and four copies drifted. The daemon answers now (0243).
	 *
	 * Two faults went with the derivation and are gone with it. Every
	 * addressed interface that was not `lo` counted, including one that is
	 * administratively down -- so a wired-only machine with docker installed
	 * reported itself locally connected and named a bridge to nowhere. And
	 * the probe verdict netcfgd already computes was consulted by nothing, so
	 * a captive portal read as connected here. */
	ncfg_connectivity_row state;
	if (!connection->connectivity(&state, &error)) {
		state_action->setText(error);
		icon->setToolTip(error);
		icon->setIcon(state_icon(ncfg_reach::offline));
		disconnect_action->setEnabled(false);
		return;
	}

	const ncfg_reach reach = reach_of(state.rung);
	QString line = line_for(state);
	state_action->setText(line);
	icon->setToolTip(line);
	icon->setIcon(state_icon(reach));
	/* Only a radio can be disconnected, and only when there is one. */
	disconnect_action->setEnabled(!radio.isEmpty());
}

/*
 * The daemon's rung as the three the icon draws.
 *
 * `online` and `routed` are one picture: both mean traffic can leave, and the
 * difference between them is whether anybody checked. An operator who wants
 * that difference reads the tooltip, which says it in words.
 */
ncfg_reach ncfg_tray::reach_of(ncfg_rung_t rung)
{
	switch (rung) {
	case ncfg_rung_online:
	case ncfg_rung_routed:
		return ncfg_reach::routed;
	case ncfg_rung_local:
		return ncfg_reach::local;
	case ncfg_rung_offline:
	default:
		return ncfg_reach::offline;
	}
}

/*
 * What the tooltip says.
 *
 * The label first, because it is what somebody opened the menu to read -- the
 * network's name where the machine is on a radio, the interface otherwise. The
 * rung is spelled out after it rather than left to the icon's colour, since
 * the two states that share a picture are exactly the ones worth telling
 * apart in words.
 */
QString ncfg_tray::line_for(const ncfg_connectivity_row &state)
{
	if (state.label.isEmpty()) {
		return QStringLiteral("offline");
	}
	switch (state.rung) {
	case ncfg_rung_online:
		return QStringLiteral("%1 -- reachable").arg(state.label);
	case ncfg_rung_routed:
		return state.label;
	case ncfg_rung_local:
		return QStringLiteral("%1 -- no default route").arg(state.label);
	case ncfg_rung_offline:
	default:
		return QStringLiteral("offline");
	}
}

void ncfg_tray::activated(int reason)
{
	if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
		emit window_requested();
	}
}

void ncfg_tray::disconnect_radio()
{
	if (radio.isEmpty()) {
		return;
	}
	QString error;
	if (!connection->wifi_disconnect(radio, &error)) {
		state_action->setText(error);
		icon->setToolTip(error);
		return;
	}
	refresh();
	emit changed();
}

void ncfg_tray::rebuild_profiles()
{
	profile_menu->clear();

	QList<ncfg_profile_row> found;
	QString chosen;
	QString error;
	if (!connection->profiles(&found, &chosen, &error)) {
		/* The daemon's own words, including a refusal naming the tier --
		 * disabled rather than hidden, because a menu that silently loses an
		 * entry looks like a machine with no profiles. */
		QAction *why = profile_menu->addAction(error);
		why->setEnabled(false);
		return;
	}

	/* Exclusive, because a machine is on one profile or none. The group is
	 * parented to the menu so it goes when the menu is cleared. */
	QActionGroup *group = new QActionGroup(profile_menu);
	group->setExclusive(true);

	/* First, and named for what it is. 0151: an absent selection is the
	 * default and is not a profile called "none" -- the machine runs its own
	 * configuration. Saying "None chosen" rather than "None" is the whole
	 * distinction, in the one place an operator meets it. */
	QAction *none = profile_menu->addAction(QStringLiteral("None chosen"));
	none->setCheckable(true);
	none->setChecked(chosen.isEmpty());
	group->addAction(none);
	connect(none, &QAction::triggered, this, [this] { choose_profile(QString()); });

	if (found.isEmpty()) {
		QAction *empty =
		    profile_menu->addAction(QStringLiteral("no profiles on this machine"));
		empty->setEnabled(false);
		return;
	}

	profile_menu->addSeparator();
	for (const ncfg_profile_row &profile : found) {
		/* The shipped ones say so. An operator with their own `offline`
		 * beside the packaged one should be able to tell which they are
		 * about to select. */
		const QString label = profile.shipped
		    ? QStringLiteral("%1  (shipped)").arg(profile.name)
		    : profile.name;
		QAction *action = profile_menu->addAction(label);
		action->setCheckable(true);
		action->setChecked(profile.name == chosen);
		group->addAction(action);
		const QString name = profile.name;
		connect(action, &QAction::triggered, this, [this, name] { choose_profile(name); });
	}
}

void ncfg_tray::choose_profile(const QString &name)
{
	/* **Asked first, and this is the menu's stand-in for the plan.** The
	 * daemon reconciles a changed configuration on its own, so writing the
	 * selection is the change -- there is no later step at which somebody
	 * would get to look. A profile switch is the strongest case for that
	 * caution: it can take down the link the operator is connected over. */
	const QString what = name.isEmpty()
	    ? QStringLiteral("Stop using a profile, and run this machine's own configuration?")
	    : QStringLiteral("Switch to the `%1` profile?").arg(name);
	const QMessageBox::StandardButton answer = QMessageBox::question(nullptr,
	    QStringLiteral("netcfgd"),
	    what + QStringLiteral("\n\nThe network is reconfigured as soon as this is "
	                          "written. Over a remote connection, this can take the "
	                          "link down."),
	    QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
	if (answer != QMessageBox::Yes) {
		/* Put the ticks back where they were: the menu already moved the
		 * check to what was clicked, and nothing was written. */
		rebuild_profiles();
		return;
	}

	/* The gui never spells netcfgd's own drop-in name: `profile_set` is a verb
	 * and the daemon owns where the selection is written. An empty name is
	 * "stop using a profile". */
	QString error;
	if (!connection->profile_set(name, &error)) {
		/* The daemon's words, which name the tier when the refusal is one. */
		QMessageBox::warning(nullptr, QStringLiteral("netcfgd"), error);
	}
	refresh();
	emit changed();
}
