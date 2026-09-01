/*
 * main_window.cpp -- the three tabs, and the two things beside them.
 */
#include "main_window.h"

#include "access_view.h"
#include "dns_view.h"
#include "apply_dialog.h"
#include "devices_view.h"
#include "global_view.h"
#include "modems_view.h"
#include "profiles_view.h"
#include "rules_view.h"
#include "bluetooth_view.h"
#include "hooks_view.h"
#include "events_view.h"
#include "ncfg_connection.h"
#include "plan_view.h"
#include "tray.h"
#include "wifi_view.h"

#include <QApplication>
#include <QCloseEvent>
#include <QLabel>
#include <QPushButton>
#include <QStatusBar>
#include <QTabWidget>
#include <QTimer>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

ncfg_main_window::ncfg_main_window(ncfg_connection *connection, QWidget *parent)
    : QMainWindow(parent), connection(connection)
{
	setWindowTitle(QStringLiteral("netcfgd"));

	auto *central = new QWidget(this);
	auto *layout = new QVBoxLayout(central);

	/* Which machine this is, on screen and not in a menu. A client that can
	 * configure a router across the room must never leave the operator
	 * unsure whose network they are about to change. Above the tabs, so it
	 * is true of every one of them. */
	where = new QLabel(central);
	where->setTextInteractionFlags(Qt::TextSelectableByMouse);
	layout->addWidget(where);

	tabs = new QTabWidget(central);
	devices = new ncfg_devices_view(connection, tabs);
	modems = new ncfg_modems_view(connection, tabs);
	global = new ncfg_global_view(connection, tabs);
	profiles = new ncfg_profiles_view(connection, tabs);
	rules = new ncfg_rules_view(connection, tabs);
	bluetooth = new ncfg_bluetooth_view(connection, tabs);
	hooks = new ncfg_hooks_view(connection, tabs);
	wifi = new ncfg_wifi_view(connection, tabs);
	access = new ncfg_access_view(connection, tabs);
	dns = new ncfg_dns_view(connection, tabs);
	plan = new ncfg_plan_view(connection, tabs);
	events = new ncfg_events_view(connection, tabs);
	tabs->addTab(devices, QStringLiteral("devices"));
	tabs->addTab(wifi, QStringLiteral("wifi"));
	/* Beside wifi rather than after the diagnostic tabs: a modem is the
	 * other way this machine reaches a network, and an operator looking
	 * for one looks where the radios are. */
	tabs->addTab(modems, QStringLiteral("modems"));
	/* The configuration's own lists, between what the machine is doing and
	 * the diagnostic tabs. A tab per fundamental thing, especially where
	 * the thing is a list: a control that is missing cannot be found by
	 * anybody, while one in the wrong tab can. Simplifying the window is a
	 * pass of its own, once every control exists. */
	/* Last of the configuration tabs and first alphabetically by accident:
	 * it is the host-wide policy, so it reads as the frame the others sit
	 * in rather than as another list. */
	tabs->addTab(global, QStringLiteral("global"));
	tabs->addTab(profiles, QStringLiteral("profiles"));
	tabs->addTab(rules, QStringLiteral("rules"));
	tabs->addTab(bluetooth, QStringLiteral("bluetooth"));
	tabs->addTab(hooks, QStringLiteral("hooks"));
	tabs->addTab(plan, QStringLiteral("plan"));
	tabs->addTab(events, QStringLiteral("events"));
	/* Last, because it is the one tab that is useful while every other is
	 * saying no -- and the one an operator is sent to when it is. */
	tabs->addTab(dns, QStringLiteral("dns"));
	tabs->addTab(access, QStringLiteral("access"));
	layout->addWidget(tabs);

	connect(devices, &ncfg_devices_view::reported, this, &ncfg_main_window::note);
	connect(modems, &ncfg_modems_view::reported, this, &ncfg_main_window::note);
	connect(global, &ncfg_global_view::reported, this, &ncfg_main_window::note);
	connect(global, &ncfg_global_view::changed, this, &ncfg_main_window::reload);
	connect(profiles, &ncfg_profiles_view::reported, this, &ncfg_main_window::note);
	connect(rules, &ncfg_rules_view::reported, this, &ncfg_main_window::note);
	connect(bluetooth, &ncfg_bluetooth_view::reported, this, &ncfg_main_window::note);
	connect(hooks, &ncfg_hooks_view::reported, this, &ncfg_main_window::note);
	connect(profiles, &ncfg_profiles_view::changed, this, &ncfg_main_window::reload);
	connect(devices, &ncfg_devices_view::changed, this, &ncfg_main_window::reload);
	connect(wifi, &ncfg_wifi_view::reported, this, &ncfg_main_window::note);
	connect(wifi, &ncfg_wifi_view::changed, this, &ncfg_main_window::reload);
	connect(access, &ncfg_access_view::reported, this, &ncfg_main_window::note);
	connect(access, &ncfg_access_view::changed, this, &ncfg_main_window::reload);
	connect(dns, &ncfg_dns_view::reported, this, &ncfg_main_window::note);
	connect(dns, &ncfg_dns_view::changed, this, &ncfg_main_window::reload);
	connect(plan, &ncfg_plan_view::reported, this, &ncfg_main_window::note);
	connect(events, &ncfg_events_view::reported, this, &ncfg_main_window::note);
	connect(tabs, &QTabWidget::currentChanged, this, &ncfg_main_window::tab_changed);

	setCentralWidget(central);

	auto *tools = addToolBar(QStringLiteral("main"));
	auto *refresh_button = new QPushButton(QStringLiteral("Refresh"), tools);
	connect(refresh_button, &QPushButton::clicked, this, &ncfg_main_window::refresh);
	tools->addWidget(refresh_button);
	/* The button says "Apply..." with the ellipsis the platform uses for "this
	 * opens something first", because that is the promise: it shows the plan
	 * and applies nothing until somebody has read it. */
	auto *apply_button = new QPushButton(QStringLiteral("Apply..."), tools);
	connect(apply_button, &QPushButton::clicked, this, &ncfg_main_window::open_apply);
	tools->addWidget(apply_button);

	/*
	 * Do not offer what will be refused. gui/project.md sec 4 asks for exactly
	 * this: a connection holding `observe` should not have an apply button
	 * whose first effect is a refusal.
	 *
	 * Asked once, at startup, because it cannot change for a connection -- the
	 * peer credentials are fixed when the socket is opened, and re-asking would
	 * suggest otherwise.
	 *
	 * A daemon that answers nothing leaves the button enabled. That is the safe
	 * direction here and it is worth saying why, because the instinct is the
	 * other one: being refused produces a sentence naming the tier that was
	 * needed, which the window shows, and a disabled button produces silence.
	 * Guessing "not allowed" against an older daemon would make this client
	 * useless on it.
	 */
	const ncfg_tiers_t held = connection->tiers();
	const bool asked = held.observe || held.wifi || held.admin;
	if (asked && !held.admin) {
		apply_button->setEnabled(false);
		apply_button->setToolTip(QStringLiteral(
		    "This connection does not hold the `admin` control tier, so netcfgd "
		    "would refuse an apply from it."));
	}

	/* Long enough that a bring-up settles into one refresh, short enough that
	 * a table is not visibly behind the events list beside it. */
	settle = new QTimer(this);
	settle->setSingleShot(true);
	settle->setInterval(400);
	connect(settle, &QTimer::timeout, this, &ncfg_main_window::refresh);
	connect(events, &ncfg_events_view::moved, this, &ncfg_main_window::moved);

	status = new QLabel(this);
	statusBar()->addWidget(status);

	resize(880, 560);

	where->setText(QStringLiteral("netcfgd at %1").arg(connection->where()));
	devices->refresh();
	plan->refresh();
	/* Subscribed from the start rather than when the tab is first opened: an
	 * event that arrived while somebody was looking at the devices table is
	 * exactly the one they will want to find when they go looking for why it
	 * changed. */
	events->refresh();
	tab_changed();
}

void ncfg_main_window::attach_tray(ncfg_tray *adopted)
{
	tray = adopted;
	connect(tray, &ncfg_tray::window_requested, this, [this]() {
		showNormal();
		raise();
		activateWindow();
	});
	connect(tray, &ncfg_tray::quit_requested, this, []() { QApplication::quit(); });
	/* The tray changed the machine, so the tabs are stale. Same path an event
	 * takes, so there is one answer to "something moved". */
	connect(tray, &ncfg_tray::changed, this, &ncfg_main_window::reload);
}

void ncfg_main_window::closeEvent(QCloseEvent *event)
{
	if (tray && !QApplication::quitOnLastWindowClosed()) {
		hide();
		event->ignore();
		return;
	}
	QMainWindow::closeEvent(event);
}

void ncfg_main_window::refresh()
{
	where->setText(QStringLiteral("netcfgd at %1").arg(connection->where()));

	if (tray) {
		tray->refresh();
	}

	QWidget *current = tabs->currentWidget();
	if (current == devices) {
		devices->refresh();
	} else if (current == wifi) {
		/* Re-reads the radios and what they are doing. Never scans: a scan
		 * blocks for seconds and a refresh button is not consent to that. */
		wifi->refresh();
	} else if (current == modems) {
		modems->refresh();
	} else if (current == global) {
		global->refresh();
	} else if (current == profiles) {
		profiles->refresh();
	} else if (current == rules) {
		rules->refresh();
	} else if (current == bluetooth) {
		bluetooth->refresh();
	} else if (current == hooks) {
		hooks->refresh();
	} else if (current == dns) {
		dns->refresh();
	} else if (current == access) {
		access->refresh();
	} else if (current == plan) {
		plan->refresh();
	} else if (current == events) {
		events->refresh();
	}
}

void ncfg_main_window::reload()
{
	devices->refresh();
	plan->refresh();
	tab_changed();
}

void ncfg_main_window::open_apply()
{
	ncfg_apply_dialog dialog(connection, this);

	/* Both tables describe the machine before the apply, and a confirm or a
	 * revert changes it again -- so this is connected rather than done once
	 * after exec(), which would leave the window stale for as long as the
	 * dialog stayed open. */
	connect(&dialog, &ncfg_apply_dialog::changed, this, &ncfg_main_window::reload);
	dialog.exec();
}

void ncfg_main_window::note(const QString &summary)
{
	auto *from = qobject_cast<QWidget *>(sender());

	if (!from) {
		return;
	}
	summaries.insert(from, summary);

	/* Only the tab in front of the operator gets the status bar. The events
	 * pane reports on every event that arrives, and without this it would
	 * overwrite the devices count seconds after anybody read it. */
	if (from == tabs->currentWidget()) {
		status->setText(summary);
	}
}

void ncfg_main_window::tab_changed()
{
	status->setText(summaries.value(tabs->currentWidget()));
	/* And ask again for the tab now in front of the operator. Without this a
	 * pane that went stale while another was showing stays stale until the
	 * next event, and "the tab I am looking at is current" is the property
	 * worth having. */
	refresh();
}

void ncfg_main_window::moved()
{
	/* Restarted, not started: a link coming up produces a run of events, and
	 * refreshing per event would make the client's cost scale with the
	 * kernel's chattiness -- which is the reason the daemon's own loop
	 * collapses a burst into one pass. */
	settle->start();
}
